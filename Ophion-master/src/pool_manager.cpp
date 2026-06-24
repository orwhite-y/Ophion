/*
*   pool_manager.cpp - pre-allocated memory pool for VMX-root mode
*
*   VMX-root mode cannot call ExAllocatePool. This module pre-allocates
*   memory blocks at PASSIVE_LEVEL that can be handed out during VM-exits.
*   Used for EPT hook dynamic splits, hooked page info, function info,
*   and trampoline buffers.
*/
#include "hv.h"
#include "log.h"

#define POOL_MAX_ENTRIES     256
#define TRAMPOLINE_BUF_SIZE  128    // enough for overwritten instructions + abs jmp

typedef enum _POOL_TYPE_TAG {
    POOL_TAG_SPLIT        = 0,    // VMM_EPT_DYNAMIC_SPLIT
    POOL_TAG_HOOKED_PAGE  = 1,    // EPT_HOOKED_PAGE_INFO
    POOL_TAG_HOOKED_FUNC  = 2,    // EPT_HOOKED_FUNCTION_INFO
    POOL_TAG_TRAMPOLINE   = 3,    // executable trampoline buffer
    POOL_TAG_STEALTH_INFO = 4,    // EPT_STEALTH_PAGE_INFO (small tracking struct, ~200 bytes)
    POOL_TAG_STEALTH_FAKEPT = 5,  // STEALTH_FAKE_PT (shared fake PT page info, ~100 bytes)
    POOL_TAG_MAX
} POOL_TYPE_TAG;

typedef struct _POOL_ENTRY {
    LIST_ENTRY  list;
    PVOID       address;
    UINT64      physical_address;   // pre-computed at PASSIVE_LEVEL
    SIZE_T      size;
    BOOLEAN     in_use;
    POOL_TYPE_TAG type;
} POOL_ENTRY;

static LIST_ENTRY g_pool_list;
static BOOLEAN    g_pool_initialized = FALSE;
static volatile LONG g_pool_lock = 0;

static VOID
pool_spinlock_acquire(volatile LONG * lock)
{
    unsigned int wait = 1;
    while (_InterlockedCompareExchange(lock, 1, 0) != 0)
    {
        for (unsigned int i = 0; i < wait; i++)
            _mm_pause();
        if (wait < 65536)
            wait <<= 1;
    }
}

static VOID
pool_spinlock_release(volatile LONG * lock)
{
    _InterlockedExchange(lock, 0);
}

static BOOLEAN
pool_add_entry(POOL_TYPE_TAG type, SIZE_T size)
{
    POOL_ENTRY * entry = (POOL_ENTRY *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(POOL_ENTRY), HV_POOL_TAG);
    if (!entry)
        return FALSE;

    if (type == POOL_TAG_SPLIT || type == POOL_TAG_HOOKED_PAGE)
    {
        //
        // split buffer: PML1 数组必须页对齐
        // hooked_page: needs physical address for PFN calculation
        // 用 MmAllocateContiguousMemory 保证物理连续 + 页对齐
        //
        PHYSICAL_ADDRESS max_phys;
        max_phys.QuadPart = MAXULONG64;
        // PITFALL #6: Must be page-aligned for EPT PML1 table. ExAllocatePool2 doesn't guarantee alignment.
        entry->address = MmAllocateContiguousMemory(size, max_phys);
    }
    else if (type == POOL_TAG_TRAMPOLINE)
    {
        // PITFALL #10: Trampolines contain executable code. ExAllocatePool2 has no execute flag.
#pragma warning(suppress: 4996)
        entry->address = ExAllocatePoolWithTag(NonPagedPoolExecute, size, HV_POOL_TAG);
    }
    else
    {
        entry->address = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, HV_POOL_TAG);
    }

    if (!entry->address)
    {
        ExFreePoolWithTag(entry, HV_POOL_TAG);
        return FALSE;
    }

    RtlZeroMemory(entry->address, size);

    // PITFALL #7: Pre-compute at PASSIVE_LEVEL. MmGetPhysicalAddress unsafe in VMX-root.
    entry->physical_address = MmGetPhysicalAddress(entry->address).QuadPart;

    entry->size   = size;
    entry->in_use = FALSE;
    entry->type   = type;
    InsertTailList(&g_pool_list, &entry->list);

    return TRUE;
}

BOOLEAN
pool_manager_init(VOID)
{
    if (g_pool_initialized)
        return TRUE;

    InitializeListHead(&g_pool_list);

    //
    // pre-allocate pools for EPT hooks
    // split buffers: need cpu_count per hooked page (each CPU has its own EPT)
    // hooked_page/func/trampoline: shared, only 1 per hook
    //
    UINT32 split_count = g_cpu_count * 64;   // 64 hooks × cpu_count splits (~2MB NPP)
    if (split_count < 256) split_count = 256;

    for (UINT32 i = 0; i < split_count; i++)
    {
        if (!pool_add_entry(POOL_TAG_SPLIT, sizeof(VMM_EPT_DYNAMIC_SPLIT)))
        {
            HYPERPLATFORM_LOG_ERROR("[hv] Pool: split alloc %u/%u failed", i, split_count);
            return FALSE;
        }
    }

    for (UINT32 i = 0; i < 64; i++)
    {
        if (!pool_add_entry(POOL_TAG_HOOKED_PAGE, sizeof(EPT_HOOKED_PAGE_INFO)))
        {
            HYPERPLATFORM_LOG_ERROR("[hv] Pool: hooked_page alloc %u failed", i);
            return FALSE;
        }
    }

    for (UINT32 i = 0; i < 128; i++)
    {
        if (!pool_add_entry(POOL_TAG_HOOKED_FUNC, sizeof(EPT_HOOKED_FUNCTION_INFO)))
        {
            HYPERPLATFORM_LOG_ERROR("[hv] Pool: hooked_func alloc %u failed", i);
            return FALSE;
        }
    }

    for (UINT32 i = 0; i < 64; i++)
    {
        if (!pool_add_entry(POOL_TAG_TRAMPOLINE, TRAMPOLINE_BUF_SIZE))
        {
            HYPERPLATFORM_LOG_ERROR("[hv] Pool: trampoline alloc %u failed", i);
            return FALSE;
        }
    }

    //
    // stealth pages: page-aligned (shadow_page[4096] needs alignment)
    // pre-allocate 16 stealth page info structures
    //
    //
    // stealth tracking structs: ~200 bytes each (no embedded PAGE_SIZE arrays)
    // shadow/fake pages come from contiguous region instead.
    // 4096 entries → supports up to 16MB of stealth memory.
    //
    for (UINT32 i = 0; i < 4096; i++)
    {
        if (!pool_add_entry(POOL_TAG_STEALTH_INFO, sizeof(EPT_STEALTH_PAGE_INFO)))
        {
            HYPERPLATFORM_LOG_ERROR("[hv] Pool: stealth_info alloc %u failed", i);
            return FALSE;
        }
    }

    //
    // shared fake PT page tracking: one per unique physical PT page (~100 bytes)
    // 256 entries covers 256 × 2MB = 512MB of VA space.
    //
    for (UINT32 i = 0; i < 256; i++)
    {
        if (!pool_add_entry(POOL_TAG_STEALTH_FAKEPT, sizeof(STEALTH_FAKE_PT)))
        {
            HYPERPLATFORM_LOG_ERROR("[hv] Pool: stealth_fakept alloc %u failed", i);
            return FALSE;
        }
    }

    g_pool_initialized = TRUE;
    HYPERPLATFORM_LOG_INFO("[hv] Pool manager initialized");
    return TRUE;
}

PVOID
pool_manager_request(UINT32 type, SIZE_T size)
{
    UNREFERENCED_PARAMETER(size);

    pool_spinlock_acquire(&g_pool_lock);

    PLIST_ENTRY current = g_pool_list.Flink;
    while (current != &g_pool_list)
    {
        POOL_ENTRY * entry = CONTAINING_RECORD(current, POOL_ENTRY, list);
        if (entry->type == (POOL_TYPE_TAG)type && !entry->in_use)
        {
            entry->in_use = TRUE;
            RtlZeroMemory(entry->address, entry->size);
            pool_spinlock_release(&g_pool_lock);
            return entry->address;
        }
        current = current->Flink;
    }

    pool_spinlock_release(&g_pool_lock);
    return NULL;
}

UINT64
pool_manager_get_physical(PVOID address)
{
    if (!address) return 0;

    pool_spinlock_acquire(&g_pool_lock);

    PLIST_ENTRY current = g_pool_list.Flink;
    while (current != &g_pool_list)
    {
        POOL_ENTRY * entry = CONTAINING_RECORD(current, POOL_ENTRY, list);
        if (entry->address == address)
        {
            UINT64 pa = entry->physical_address;
            pool_spinlock_release(&g_pool_lock);
            return pa;
        }
        current = current->Flink;
    }

    pool_spinlock_release(&g_pool_lock);
    return 0;
}

VOID
pool_manager_release(PVOID address)
{
    if (!address)
        return;

    pool_spinlock_acquire(&g_pool_lock);

    PLIST_ENTRY current = g_pool_list.Flink;
    while (current != &g_pool_list)
    {
        POOL_ENTRY * entry = CONTAINING_RECORD(current, POOL_ENTRY, list);
        if (entry->address == address)
        {
            entry->in_use = FALSE;
            pool_spinlock_release(&g_pool_lock);
            return;
        }
        current = current->Flink;
    }

    pool_spinlock_release(&g_pool_lock);
}

VOID
pool_manager_destroy(VOID)
{
    if (!g_pool_initialized)
        return;

    while (!IsListEmpty(&g_pool_list))
    {
        PLIST_ENTRY item = RemoveHeadList(&g_pool_list);
        POOL_ENTRY * entry = CONTAINING_RECORD(item, POOL_ENTRY, list);
        if (entry->address)
        {
            if (entry->type == POOL_TAG_SPLIT || entry->type == POOL_TAG_HOOKED_PAGE)
                MmFreeContiguousMemory(entry->address);
            else
                ExFreePoolWithTag(entry->address, HV_POOL_TAG);
        }
        ExFreePoolWithTag(entry, HV_POOL_TAG);
    }

    g_pool_initialized = FALSE;
}

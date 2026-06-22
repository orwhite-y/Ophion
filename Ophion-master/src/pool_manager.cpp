/*
*   pool_manager.cpp - pre-allocated memory pool for VMX-root mode
*
*   VMX-root mode cannot call ExAllocatePool. This module pre-allocates
*   memory blocks at PASSIVE_LEVEL that can be handed out during VM-exits.
*   Used for EPT hook dynamic splits, hooked page info, function info,
*   and trampoline buffers.
*/
#include "hv.h"

#define POOL_MAX_ENTRIES     256
#define TRAMPOLINE_BUF_SIZE  128    // enough for overwritten instructions + abs jmp

typedef enum _POOL_TYPE_TAG {
    POOL_TAG_SPLIT       = 0,    // VMM_EPT_DYNAMIC_SPLIT
    POOL_TAG_HOOKED_PAGE = 1,    // EPT_HOOKED_PAGE_INFO
    POOL_TAG_HOOKED_FUNC = 2,    // EPT_HOOKED_FUNCTION_INFO
    POOL_TAG_TRAMPOLINE  = 3,    // executable trampoline buffer
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
        // hooked_page: fake_page_contents (DECLSPEC_ALIGN(PAGE_SIZE)) 必须页对齐
        // 用 MmAllocateContiguousMemory 保证物理连续 + 页对齐
        //
        PHYSICAL_ADDRESS max_phys;
        max_phys.QuadPart = MAXULONG64;
        entry->address = MmAllocateContiguousMemory(size, max_phys);
    }
    else if (type == POOL_TAG_TRAMPOLINE)
    {
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

    // 在 PASSIVE_LEVEL 预计算物理地址 — VMX-root 不再需要调 MmGetPhysicalAddress
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
    UINT32 split_count = g_cpu_count * 8;    // 8 hooks × cpu_count splits
    if (split_count < 64) split_count = 64;

    for (UINT32 i = 0; i < split_count; i++)
    {
        if (!pool_add_entry(POOL_TAG_SPLIT, sizeof(VMM_EPT_DYNAMIC_SPLIT)))
        {
            DbgPrintEx(0, 0, "[hv] Pool: split alloc %u/%u failed\n", i, split_count);
            return FALSE;
        }
    }

    for (UINT32 i = 0; i < 32; i++)
    {
        if (!pool_add_entry(POOL_TAG_HOOKED_PAGE, sizeof(EPT_HOOKED_PAGE_INFO)))
        {
            DbgPrintEx(0, 0, "[hv] Pool: hooked_page alloc %u failed\n", i);
            return FALSE;
        }
    }

    for (UINT32 i = 0; i < 64; i++)
    {
        if (!pool_add_entry(POOL_TAG_HOOKED_FUNC, sizeof(EPT_HOOKED_FUNCTION_INFO)))
        {
            DbgPrintEx(0, 0, "[hv] Pool: hooked_func alloc %u failed\n", i);
            return FALSE;
        }
    }

    for (UINT32 i = 0; i < 32; i++)
    {
        if (!pool_add_entry(POOL_TAG_TRAMPOLINE, TRAMPOLINE_BUF_SIZE))
        {
            DbgPrintEx(0, 0, "[hv] Pool: trampoline alloc %u failed\n", i);
            return FALSE;
        }
    }

    g_pool_initialized = TRUE;
    DbgPrintEx(0, 0, "[hv] Pool manager initialized\n");
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

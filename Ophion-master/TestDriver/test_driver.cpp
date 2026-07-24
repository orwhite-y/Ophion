/*
*   test_driver.cpp - stealth injection via pure VMCALL
*
*   communicates with Ophion hypervisor ONLY through VMCALL.
*   zero link dependency on Ophion.sys 鈥?completely standalone .sys.
*
*   flow:
*     1. ring-3 sends IOCTL_INJECT(PID) to this driver
*     2. driver attaches to target process
*     3. allocates PAGE_READWRITE memory
*     4. writes shellcode into the page
*     5. DPC broadcast 鈫?each CPU issues VMCALL_STEALTH_ALLOC to Ophion HV
*        鈫?Ophion copies page content to shadow page (execute view)
*        鈫?sets up EPT split + fake PT page + #PF interception
*     6. zeroes original page (read view = clean for anti-cheat)
*     7. creates thread at shellcode VA
*     8. thread runs 鈫?#PF 鈫?HV swaps EPT 鈫?TLB created 鈫?shellcode executes
*/
#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>
#include <ntimage.h>
#include "log.h"

// ---- undocumented PEB structures for user-mode module walk ----

extern "C" NTKERNELAPI PPEB PsGetProcessPeb(PEPROCESS Process);
extern "C" NTKERNELAPI NTSTATUS PsGetProcessExitStatus(PEPROCESS Process);
extern "C" NTSYSAPI NTSTATUS NTAPI ZwProtectVirtualMemory(
    HANDLE ProcessHandle, PVOID * BaseAddress, PSIZE_T RegionSize,
    ULONG NewProtect, PULONG OldProtect);
extern "C" NTSYSAPI PVOID NTAPI RtlPcToFileHeader(PVOID PcValue, PVOID * BaseOfImage);
extern "C" NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);

typedef ULONG (NTAPI * fn_KeResumeThread)(PKTHREAD Thread);
static fn_KeResumeThread g_pKeResumeThread = NULL;

typedef NTSTATUS (NTAPI * fn_PsResumeThread)(PETHREAD Thread, PULONG PreviousSuspendCount);
static fn_PsResumeThread g_pPsResumeThread = NULL;

static BOOLEAN TdAsciiEqualI(const char * a, const char * b);
static NTSTATUS TdNtResumeThreadBySSDT(HANDLE thread_h, PULONG previous_count);

typedef struct _TD_SYSTEM_SERVICE_DESCRIPTOR_TABLE {
    PULONG ServiceTableBase;
    PULONG ServiceCounterTableBase;
    ULONG_PTR NumberOfServices;
    PUCHAR ParamTableBase;
} TD_SYSTEM_SERVICE_DESCRIPTOR_TABLE, *PTD_SYSTEM_SERVICE_DESCRIPTOR_TABLE;

typedef struct _TD_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWCH   Buffer;
} TD_UNICODE_STRING;

typedef struct _TD_LDR_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    TD_UNICODE_STRING FullDllName;
    TD_UNICODE_STRING BaseDllName;
} TD_LDR_ENTRY, *PTD_LDR_ENTRY;

typedef struct _TD_PEB_LDR_DATA {
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
} TD_PEB_LDR_DATA;

// ---- VMCALL interface (must match Ophion hv_types.h) ----

#define VMCALL_STEALTH_ALLOC    0x00000006
#define VMCALL_STEALTH_FREE     0x00000007
#define VMCALL_EPT_HOOK_INJECT  0x00000008
#define VMCALL_EPT_SET_EXTERNAL_FIRED 0x00000009
#define VMCALL_EPT_UNHOOK_BY_CR3 0x0000000A   // retire all R3 hooks for a CR3 (no CR3 switch - safe from process-exit callback)

//
// EPT hook inject param 鈥?pre-built at PASSIVE_LEVEL, passed to VMX-root.
// must match Ophion's EPT_HOOK_INJECT_PARAM.
//
#pragma pack(push, 8)
typedef struct _TD_HOOK_INJECT_PARAM {
    UINT64  target_va;              // user VA of shellcode entry
    UINT64  target_phys;            // pre-computed PA of target page
    UINT64  handler_va;             // trampoline VA (VMCALL redirects here)
    PVOID   fake_page_buffer;       // kernel buffer: pre-built fake page
    UINT32  hook_size;              // bytes overwritten by VMCALL (from LDE)
    BOOLEAN force_read_access;
    //
    // pre-computed guest PT page info (for fake PT / NX hiding)
    //
    UINT64  pt_page_pfn;            // PFN of guest PT page containing target PTE
    UINT32  pt_pte_index;           // index within PT page (0-511)
    PVOID   pt_page_copy;           // kernel buffer with PT page content (4KB)
    PVOID   pt_page_va;             // system VA of real PT page (hostcr3-mapped)
    volatile LONG installed;
    BOOLEAN result;
    BOOLEAN fake_pt_ok;
    volatile LONG * dbg_pf_counter;
} TD_HOOK_INJECT_PARAM;
#pragma pack(pop)

//
// param struct passed via VMCALL rdx pointer
// must match Ophion's EPT_STEALTH_ALLOC_PARAM exactly
//
#pragma pack(push, 8)
typedef struct _TD_STEALTH_PARAM {
    UINT64  caller_cr3;
    UINT64  target_pid;
    PVOID   target_va;
    PVOID   handler_function;
    UINT64  target_phys;
    PVOID   shellcode_buffer;
    UINT32  shellcode_size;
    BOOLEAN resident;
    BOOLEAN intercept_write;
    //
    // pre-computed guest PT info (filled at PASSIVE/DISPATCH level).
    // avoids MmGetVirtualForPhysical (pa_to_va) in VMX-root which deadlocks
    // when KeGenericCallDpc puts all CPUs into VMX-root simultaneously.
    //
    UINT64  pt_page_pfn;        // PFN of guest PT page containing target PTE
    UINT32  pt_pte_index;       // index within PT page (0-511)
    PVOID   pt_page_copy;       // NonPaged buffer with PT page content (4KB)
    PVOID   pt_page_va;         // shadow mode: shadow PT page VA; else real PT page VA (for MTF resync)
    PVOID   target_page_copy;   // NonPaged buffer with target page content (4KB)
    BOOLEAN pt_precomputed;     // TRUE = caller filled above fields at PASSIVE_LEVEL
    BOOLEAN use_fake_pt;        // TRUE = create fake PT page (NX hiding)
    UINT64  shadow_cr3_phys;    // physical address of shadow PML4 (0 = no shadow CR3)
    BOOLEAN no_ept_split;       // TRUE = shadow CR3 only, keep target EPT mapping unchanged
    PVOID   shadow_pte_va;      // VA of this page's shadow PTE (NonPaged pool, computed via TdResolveShadowPte at PASSIVE); HV writes it directly on #PF (NULL = none)
    PVOID   real_page_map;      // ptr to STEALTH_REAL_PAGE_ENTRY[real_page_count] (MDL-mapped real PT pages, NULL = none)
    UINT32  real_page_count;    // number of entries in real_page_map
    volatile LONG installed;
    BOOLEAN result;
} TD_STEALTH_PARAM;
#pragma pack(pop)

#define PFN_MASK_  0x000FFFFFFFFFF000ULL
#define NX_BIT_    (1ULL << 63)

extern "C" {
    NTKERNELAPI VOID KeGenericCallDpc(PKDEFERRED_ROUTINE Routine, PVOID Context);
    NTKERNELAPI VOID KeSignalCallDpcDone(PVOID SystemArgument1);
    NTKERNELAPI LOGICAL KeSignalCallDpcSynchronize(PVOID SystemArgument2);
}

// =========================================================================
//  shadow CR3: build shadow page tables with NX=0 for a VA range.
//  supports multi-megabyte ranges spanning multiple PT/PD pages.
//  only duplicates pages along the path 鈥?all other entries share real pages.
//  must be called at PASSIVE_LEVEL while attached to target process.
// =========================================================================

#define MAX_SHADOW_PAGES_PER_CR3 256
#define MAX_SHADOW_CR3_ALLOCS    64

//
// Real page-table page map entry -- MUST match hv_types.h STEALTH_REAL_PAGE_ENTRY.
// The HV walks the guest's REAL page tables in VMX-root under g_system_cr3 where
// pa_to_va is broken (reads System's self-map); the TestDriver maps each real PT
// page along the protected range's path (MDL + MmMapLockedPagesSpecifyCache) and
// passes the system VAs. MmMapIoSpace is NOT used: it returns NULL for system-RAM
// page-table pages on modern Windows. MmCached matches the WB attribute of RAM so
// a persistent mapping is safe (no cache conflict).
//
typedef struct _STEALTH_REAL_PAGE_ENTRY {
    UINT64  pa;     // physical address (page-aligned) of a real guest PT page
    PVOID   va;     // MmMapLockedPagesSpecifyCache system VA, valid under g_system_cr3
    PVOID   mdl;    // PMDL for this page (TestDriver-only; HV ignores it)
} STEALTH_REAL_PAGE_ENTRY, *PSTEALTH_REAL_PAGE_ENTRY;

#define MAX_REAL_PAGES_PER_SHADOW  64   // PML4 + PDPT + PDs + PTs along the range

typedef struct _TD_SHADOW_BUILD_CONTEXT {
    PVOID  pages[MAX_SHADOW_PAGES_PER_CR3];
    UINT32 page_count;
    STEALTH_REAL_PAGE_ENTRY real_pages[MAX_REAL_PAGES_PER_SHADOW];
    UINT32 real_page_count;
} TD_SHADOW_BUILD_CONTEXT;

typedef struct _TD_SHADOW_CR3_ALLOCATION {
    BOOLEAN active;
    UINT64  shadow_cr3_phys;
    UINT32  page_count;
    PVOID   pages[MAX_SHADOW_PAGES_PER_CR3];
    PSTEALTH_REAL_PAGE_ENTRY real_page_map;  // NonPaged buffer shared with HV (NULL = none)
    UINT32  real_page_count;
    LONG    refcount;     // #tracked ranges sharing this CR3 (multi-range per process); freed at 0
} TD_SHADOW_CR3_ALLOCATION;

static KSPIN_LOCK g_shadow_alloc_lock;
static TD_SHADOW_CR3_ALLOCATION g_shadow_allocs[MAX_SHADOW_CR3_ALLOCS] = {};

static VOID
TdShadowFreePageList(PVOID * pages, UINT32 page_count)
{
    for (UINT32 i = 0; i < page_count; i++)
    {
        if (pages[i])
        {
            RtlSecureZeroMemory(pages[i], PAGE_SIZE);
            ExFreePoolWithTag(pages[i], 'wdhS');
            pages[i] = NULL;
        }
    }
}

static PVOID
TdShadowAllocPage(TD_SHADOW_BUILD_CONTEXT * ctx)
{
    if (!ctx || ctx->page_count >= MAX_SHADOW_PAGES_PER_CR3)
        return NULL;

    //
    // NonPaged pool. The HV accesses shadow pages in VMX-root under g_system_cr3
    // via pa_to_va(): shadow pages are NOT registered page-table pages in the PFN
    // database (they are plain pool pages used as page tables only by the shadow
    // CR3), so pa_to_va resolves them through their system PTE -- CR3-independent,
    // and the returned system VA is in kernel space which g_system_cr3 maps. This
    // is the asymmetry that lets us map ONLY the real page-table pages (which ARE
    // registered, so pa_to_va resolves them through the CR3 self-map and reads the
    // wrong tables under g_system_cr3) and leave the shadow pages to pa_to_va.
    //
    PVOID page = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'wdhS');
    if (!page) return NULL;
    RtlZeroMemory(page, PAGE_SIZE);
    ctx->pages[ctx->page_count++] = page;
    return page;
}

//
// Map a REAL guest page-table page (PML4/PDPT/PD/PT) into system space so the HV
// can read it in VMX-root under g_system_cr3. pa_to_va (MmGetVirtualForPhysical)
// resolves registered page-table pages through the current CR3's self-map, so
// under g_system_cr3 it reads the System process's tables -- unusable for the
// guest's real PT walk. We need a CR3-independent system VA for the page.
//
// Technique: manual-PFN MDL with the MDL_IO_SPACE flag (the "winpmem" technique
// for full-RAM dumps on modern Windows). MDL_IO_SPACE tells the MM "these are
// I/O pages, do NOT touch the PFN DB" -- which is the key, because:
//   * MmMapIoSpace (any cache type) returns NULL for system-RAM page-table pages
//     on modern Windows 10+ -- it has a RAM pre-check that refuses to alias RAM
//     as I/O space. (This is why stealth_read_phys64's pattern is NOT a working
//     reference -- it was never exercised on RAM PT pages at runtime.)
//   * A manual-PFN MDL WITHOUT MDL_IO_SPACE fails because the MM tries to manage
//     the PFN DB (PteAddress / cache-attribute chain) for a page-table page and
//     refuses -- the earlier MmMapLockedPagesSpecifyCache(MmCached) NULL failure.
//   * WITH MDL_IO_SPACE, the MM skips PFN DB management entirely and creates a
//     pure system-PTE alias valid under ANY CR3. This maps ARBITRARY physical
//     pages, including page-table pages.
//
// Cache type: try UC (MmNonCached) first, fall back to WB (MmCached). MDL_IO_SPACE
// skips PFN cache-attribute tracking, so neither triggers a conflict/bugcheck. x64
// keeps UC reads coherent with the OS's WB self-map writes (MESI snoop), and the HV
// only ever READS real pages (writes go to shadow pages), so a persistent mapping
// of either type is correct.
//
// Refcount: MDL_IO_SPACE + manual-PFN means no PFN refcount was touched (the MM
// treated the PFN as I/O). MmUnmapLockedPages only frees the system PTEs -- there
// is no MmUnlockPages to call (no MmProbeAndLockPages to balance). Pure alias.
//
// Context: this runs at PASSIVE in the guest (TdBuildShadowCR3, Box.exe context).
// No MM calls happen in VMX-root (MmMapLockedPages deadlocks there per
// ept_stealth.cpp); only the resulting system VA is dereferenced in VMX-root.
//
// Dedupes by PA (PML4/PDPT/PD visited once; PTs once per 2MB). Released via
// TdShadowUnmapRealPage (MmUnmapLockedPages + IoFreeMdl, NO MmUnlockPages).
//
static VOID
TdShadowUnmapRealPage(STEALTH_REAL_PAGE_ENTRY * e)
{
    if (!e || !e->va || !e->mdl)
        return;
    MmUnmapLockedPages(e->va, (PMDL)e->mdl);
    // NO MmUnlockPages: MDL_IO_SPACE + manual-PFN touched no PFN refcount. The
    // page-table page's refcount is untouched (pure read-only alias).
    IoFreeMdl((PMDL)e->mdl);
    e->va  = NULL;
    e->mdl = NULL;
}

static BOOLEAN
TdShadowMapRealPage(TD_SHADOW_BUILD_CONTEXT * ctx, UINT64 pa)
{
    if (!ctx || !pa)
        return FALSE;
    UINT64 page_pa = pa & PFN_MASK_;

    for (UINT32 i = 0; i < ctx->real_page_count; i++)
    {
        if ((ctx->real_pages[i].pa & PFN_MASK_) == page_pa)
            return TRUE;  // already mapped (dedup)
    }
    if (ctx->real_page_count >= MAX_REAL_PAGES_PER_SHADOW)
    {
        HYPERPLATFORM_LOG_ERROR("[td-rw] real-page map FAIL pa=%llx: map full (%u)",
                                page_pa, ctx->real_page_count);
        return FALSE;
    }

    PMDL mdl = IoAllocateMdl(NULL, PAGE_SIZE, FALSE, FALSE, NULL);
    if (!mdl)
    {
        HYPERPLATFORM_LOG_ERROR("[td-rw] real-page map FAIL pa=%llx: IoAllocateMdl NULL",
                                page_pa);
        return FALSE;
    }
    mdl->StartVa    = NULL;
    mdl->ByteOffset = 0;
    mdl->ByteCount  = PAGE_SIZE;
    mdl->MdlFlags  |= MDL_PAGES_LOCKED | MDL_IO_SPACE;
    PPFN_NUMBER pfns = MmGetMdlPfnArray(mdl);
    pfns[0] = (PFN_NUMBER)(page_pa >> PAGE_SHIFT);

    // UC first (winpmem default); fall back to WB. MDL_IO_SPACE skips PFN
    // cache-attribute tracking, so neither conflicts/bugchecks.
    PVOID va = MmMapLockedPagesSpecifyCache(
        mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    if (!va)
    {
        va = MmMapLockedPagesSpecifyCache(
            mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
    }
    if (!va)
    {
        HYPERPLATFORM_LOG_ERROR(
            "[td-rw] real-page map FAIL pa=%llx pfn=%llx: MDL_IO_SPACE map NULL (UC+WB)",
            page_pa, (UINT64)pfns[0]);
        IoFreeMdl(mdl);
        return FALSE;
    }

    // one-shot confirmation that the MDL_IO_SPACE path works at runtime.
    static volatile LONG s_first_log = 0;
    if (!_InterlockedExchange(&s_first_log, 1))
    {
        HYPERPLATFORM_LOG_INFO(
            "[td-rw] real-page MDL_IO_SPACE map ok: pa=%llx va=%llx",
            page_pa, (UINT64)va);
    }

    ctx->real_pages[ctx->real_page_count].pa  = page_pa;
    ctx->real_pages[ctx->real_page_count].va  = va;
    ctx->real_pages[ctx->real_page_count].mdl = mdl;
    ctx->real_page_count++;
    return TRUE;
}

static BOOLEAN
TdShadowRegisterCr3(UINT64 shadow_cr3_phys, TD_SHADOW_BUILD_CONTEXT * ctx)
{
    if (!shadow_cr3_phys || !ctx || !ctx->page_count)
        return FALSE;

    //
    // allocate the shared real-page map buffer (passed to the HV by pointer) at
    // PASSIVE OUTSIDE the spinlock -- ExAllocatePool2 must not run at DISPATCH.
    //
    PSTEALTH_REAL_PAGE_ENTRY map_buf = NULL;
    UINT32 map_count = ctx->real_page_count;
    if (map_count)
    {
        map_buf = (PSTEALTH_REAL_PAGE_ENTRY)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(STEALTH_REAL_PAGE_ENTRY) * map_count, 'lmrS');
        if (!map_buf)
            return FALSE;
        RtlCopyMemory(map_buf, ctx->real_pages,
                      sizeof(STEALTH_REAL_PAGE_ENTRY) * map_count);
    }

    KIRQL old_irql;
    KeAcquireSpinLock(&g_shadow_alloc_lock, &old_irql);

    TD_SHADOW_CR3_ALLOCATION * slot = NULL;
    for (UINT32 i = 0; i < MAX_SHADOW_CR3_ALLOCS; i++)
    {
        if (!g_shadow_allocs[i].active)
        {
            slot = &g_shadow_allocs[i];
            break;
        }
    }

    if (slot)
    {
        RtlZeroMemory(slot, sizeof(*slot));
        slot->shadow_cr3_phys = shadow_cr3_phys;
        slot->page_count = ctx->page_count;
        for (UINT32 i = 0; i < ctx->page_count; i++)
            slot->pages[i] = ctx->pages[i];
        slot->real_page_map  = map_buf;
        slot->real_page_count = map_count;
        slot->active = TRUE;
        slot->refcount = 0;     // TdStealthTrackAdd AddRef's each tracked range
    }

    KeReleaseSpinLock(&g_shadow_alloc_lock, old_irql);

    if (!slot)
    {
        if (map_buf) ExFreePoolWithTag(map_buf, 'lmrS');
        return FALSE;
    }

    RtlZeroMemory(ctx, sizeof(*ctx));
    return TRUE;
}

// AddRef the shared shadow CR3 (one per tracked range). Callers may hold
// g_stealth_track_lock; this acquires g_shadow_alloc_lock => lock order: track then alloc.
static VOID
TdShadowCr3AddRef(UINT64 shadow_cr3_phys)
{
    if (!shadow_cr3_phys) return;
    KIRQL old_irql;
    KeAcquireSpinLock(&g_shadow_alloc_lock, &old_irql);
    for (UINT32 i = 0; i < MAX_SHADOW_CR3_ALLOCS; i++)
    {
        TD_SHADOW_CR3_ALLOCATION * e = &g_shadow_allocs[i];
        if (e->active && e->shadow_cr3_phys == shadow_cr3_phys)
        {
            e->refcount++;
            break;
        }
    }
    KeReleaseSpinLock(&g_shadow_alloc_lock, old_irql);
}

// Decrement refcount. If this was the last reference, set *out_to_free to the
// shadow_cr3_phys so the caller can TdShadowFreeCr3 it (outside any held lock).
// Returns TRUE if the shadow_cr3 was found.
static BOOLEAN
TdShadowCr3Release(UINT64 shadow_cr3_phys, UINT64 * out_to_free)
{
    if (out_to_free) *out_to_free = 0;
    if (!shadow_cr3_phys) return FALSE;
    BOOLEAN found = FALSE;
    KIRQL old_irql;
    KeAcquireSpinLock(&g_shadow_alloc_lock, &old_irql);
    for (UINT32 i = 0; i < MAX_SHADOW_CR3_ALLOCS; i++)
    {
        TD_SHADOW_CR3_ALLOCATION * e = &g_shadow_allocs[i];
        if (e->active && e->shadow_cr3_phys == shadow_cr3_phys)
        {
            found = TRUE;
            if (e->refcount > 0)
                e->refcount--;
            if (e->refcount == 0 && out_to_free)
                *out_to_free = shadow_cr3_phys;
            break;
        }
    }
    KeReleaseSpinLock(&g_shadow_alloc_lock, old_irql);
    return found;
}

static PVOID
TdShadowVaFromPhys(UINT64 phys)
{
    UINT64 wanted = phys & PFN_MASK_;
    PVOID result = NULL;

    KIRQL old_irql;
    KeAcquireSpinLock(&g_shadow_alloc_lock, &old_irql);

    for (UINT32 i = 0; i < MAX_SHADOW_CR3_ALLOCS && !result; i++)
    {
        TD_SHADOW_CR3_ALLOCATION * entry = &g_shadow_allocs[i];
        if (!entry->active)
            continue;

        for (UINT32 p = 0; p < entry->page_count; p++)
        {
            PVOID page = entry->pages[p];
            if (!page)
                continue;

            UINT64 page_phys = MmGetPhysicalAddress(page).QuadPart & PFN_MASK_;
            if (page_phys == wanted)
            {
                result = page;
                break;
            }
        }
    }

    KeReleaseSpinLock(&g_shadow_alloc_lock, old_irql);
    return result;
}

static BOOLEAN
TdResolveShadowPT(UINT64 shadow_cr3, UINT64 va, UINT64 * out_pt_pfn, UINT32 * out_pte_idx, PVOID * out_pt_va)
{
    if (!shadow_cr3 || !out_pt_pfn || !out_pte_idx || !out_pt_va)
        return FALSE;

    PUINT64 table = (PUINT64)TdShadowVaFromPhys(shadow_cr3);
    if (!table) return FALSE;
    UINT64 pml4e = table[(va >> 39) & 0x1FF];
    if (!(pml4e & 1)) return FALSE;

    table = (PUINT64)TdShadowVaFromPhys(pml4e);
    if (!table) return FALSE;
    UINT64 pdpe = table[(va >> 30) & 0x1FF];
    if (!(pdpe & 1) || (pdpe & (1ULL << 7))) return FALSE;

    table = (PUINT64)TdShadowVaFromPhys(pdpe);
    if (!table) return FALSE;
    UINT64 pde = table[(va >> 21) & 0x1FF];
    if (!(pde & 1) || (pde & (1ULL << 7))) return FALSE;

    table = (PUINT64)TdShadowVaFromPhys(pde);
    if (!table) return FALSE;

    *out_pt_pfn = (pde & PFN_MASK_) >> 12;
    *out_pte_idx = (UINT32)((va >> 12) & 0x1FF);
    *out_pt_va = table;
    return TRUE;
}

static PUINT64
TdResolveShadowPte(UINT64 shadow_cr3, UINT64 va)
{
    UINT64 pt_pfn = 0;
    UINT32 pte_idx = 0;
    PVOID pt_va = NULL;

    if (!TdResolveShadowPT(shadow_cr3, va, &pt_pfn, &pte_idx, &pt_va) || !pt_va)
        return NULL;

    UNREFERENCED_PARAMETER(pt_pfn);
    return &((PUINT64)pt_va)[pte_idx];
}

static BOOLEAN
TdShadowFreeCr3(UINT64 shadow_cr3_phys)
{
    if (!shadow_cr3_phys)
        return FALSE;

    PVOID pages[MAX_SHADOW_PAGES_PER_CR3] = {};
    UINT32 page_count = 0;
    PSTEALTH_REAL_PAGE_ENTRY map_buf = NULL;
    UINT32 map_count = 0;

    KIRQL old_irql;
    KeAcquireSpinLock(&g_shadow_alloc_lock, &old_irql);

    for (UINT32 i = 0; i < MAX_SHADOW_CR3_ALLOCS; i++)
    {
        TD_SHADOW_CR3_ALLOCATION * entry = &g_shadow_allocs[i];
        if (entry->active && entry->shadow_cr3_phys == shadow_cr3_phys)
        {
            page_count = entry->page_count;
            for (UINT32 j = 0; j < page_count; j++)
                pages[j] = entry->pages[j];
            map_buf   = entry->real_page_map;
            map_count = entry->real_page_count;
            RtlZeroMemory(entry, sizeof(*entry));
            break;
        }
    }

    KeReleaseSpinLock(&g_shadow_alloc_lock, old_irql);

    if (!page_count)
        return FALSE;

    TdShadowFreePageList(pages, page_count);

    // release the MDL-mapped real page-table page mappings (PASSIVE here:
    // TdShadowFreeCr3 runs at PASSIVE from the process-exit / teardown path).
    if (map_buf)
    {
        for (UINT32 i = 0; i < map_count; i++)
            TdShadowUnmapRealPage(&map_buf[i]);
        ExFreePoolWithTag(map_buf, 'lmrS');
    }

    HYPERPLATFORM_LOG_INFO("[td-rw] shadow CR3 freed: PA=0x%llX pages=%u real=%u",
               shadow_cr3_phys, page_count, map_count);
    return TRUE;
}

//
// look up the shared real-page map for a shadow CR3 (for filling the VMCALL
// param). returns the buffer pointer + count; *out_map is NULL if none.
//
static VOID
TdShadowGetRealMap(UINT64 shadow_cr3_phys,
                   PVOID * out_map, UINT32 * out_count)
{
    if (out_map)  *out_map  = NULL;
    if (out_count) *out_count = 0;
    if (!shadow_cr3_phys)
        return;

    KIRQL old_irql;
    KeAcquireSpinLock(&g_shadow_alloc_lock, &old_irql);

    for (UINT32 i = 0; i < MAX_SHADOW_CR3_ALLOCS; i++)
    {
        TD_SHADOW_CR3_ALLOCATION * entry = &g_shadow_allocs[i];
        if (entry->active && entry->shadow_cr3_phys == shadow_cr3_phys)
        {
            if (out_map)  *out_map  = entry->real_page_map;
            if (out_count) *out_count = entry->real_page_count;
            break;
        }
    }

    KeReleaseSpinLock(&g_shadow_alloc_lock, old_irql);
}

static PUINT64
TdMapPhys(UINT64 phys_page)
{
    PHYSICAL_ADDRESS pa;
    pa.QuadPart = (LONGLONG)(phys_page & PFN_MASK_);
    return (PUINT64)MmGetVirtualForPhysical(pa);
}

//
// build shadow CR3 for a VA range [base_va, base_va + size).
// clears NX for every 4KB page in the range.
// handles spanning across multiple PT pages (each 2MB) and PD pages (each 1GB).
// assumes all VAs are within the same 512GB PML4 entry (user-mode always is).
// returns physical address of shadow PML4, or 0 on failure.
//
static UINT64
TdBuildShadowCR3(UINT64 cr3, UINT64 base_va, SIZE_T size)
{
    TD_SHADOW_BUILD_CONTEXT ctx = {};
    UINT64 va_start = base_va & ~0xFFFULL;
    UINT64 va_end   = (base_va + size + 0xFFF) & ~0xFFFULL;
    if (va_end <= va_start)
        return 0;

    // all user VAs share the same PML4 entry (< 512GB)
    UINT32 pml4_idx = (UINT32)((va_start >> 39) & 0x1FF);

    // --- shadow PML4 ---
    PUINT64 real_pml4 = TdMapPhys(cr3);
    if (!real_pml4) goto Fail;
    // No real-page MDL map: the HV heals under sp->guest_cr3 (this kernel CR3),
    // where pa_to_va resolves the guest's real PT pages directly. See vmx_enter_cr3.

    PUINT64 shadow_pml4 = (PUINT64)TdShadowAllocPage(&ctx);
    if (!shadow_pml4) goto Fail;
    RtlCopyMemory(shadow_pml4, real_pml4, PAGE_SIZE);

    // --- shadow PDPT ---
    UINT64 pml4e = real_pml4[pml4_idx];
    if (!(pml4e & 1)) goto Fail;
    PUINT64 real_pdpt = TdMapPhys(pml4e);
    if (!real_pdpt) goto Fail;

    PUINT64 shadow_pdpt = (PUINT64)TdShadowAllocPage(&ctx);
    if (!shadow_pdpt) goto Fail;
    RtlCopyMemory(shadow_pdpt, real_pdpt, PAGE_SIZE);
    shadow_pml4[pml4_idx] = (pml4e & ~PFN_MASK_) | MmGetPhysicalAddress(shadow_pdpt).QuadPart;

    //
    // iterate over each 2MB range that the VA range touches.
    // for each: clone the PD entry (if not yet) and the PT page, clear NX.
    //
    UINT32 last_pdpt_idx = 0xFFFFFFFF;
    UINT32 last_pd_idx   = 0xFFFFFFFF;
    PUINT64 shadow_pd = NULL;
    PUINT64 shadow_pt = NULL;
    UINT32  nx_cleared = 0;

    for (UINT64 va = va_start; va < va_end; va += PAGE_SIZE)
    {
        UINT32 pdpt_idx = (UINT32)((va >> 30) & 0x1FF);
        UINT32 pd_idx   = (UINT32)((va >> 21) & 0x1FF);
        UINT32 pt_idx   = (UINT32)((va >> 12) & 0x1FF);

        // --- new 1GB range? clone PD ---
        if (pdpt_idx != last_pdpt_idx)
        {
            UINT64 pdpe = real_pdpt[pdpt_idx];
            if (!(pdpe & 1) || (pdpe & (1ULL << 7))) goto Fail;  // 1GB large page
            PUINT64 real_pd = TdMapPhys(pdpe);
            if (!real_pd) goto Fail;

            shadow_pd = (PUINT64)TdShadowAllocPage(&ctx);
            if (!shadow_pd) goto Fail;
            RtlCopyMemory(shadow_pd, real_pd, PAGE_SIZE);
            shadow_pdpt[pdpt_idx] = (pdpe & ~PFN_MASK_) | MmGetPhysicalAddress(shadow_pd).QuadPart;

            last_pdpt_idx = pdpt_idx;
            last_pd_idx = 0xFFFFFFFF;  // force PT re-clone
        }

        // --- new 2MB range? clone PT ---
        if (pd_idx != last_pd_idx)
        {
            PUINT64 cur_pd = shadow_pd;
            UINT64 pde = cur_pd[pd_idx];
            if (!(pde & 1) || (pde & (1ULL << 7))) goto Fail;  // 2MB large page
            PUINT64 real_pt = TdMapPhys(pde);
            if (!real_pt) goto Fail;

            shadow_pt = (PUINT64)TdShadowAllocPage(&ctx);
            if (!shadow_pt) goto Fail;
            RtlCopyMemory(shadow_pt, real_pt, PAGE_SIZE);
            cur_pd[pd_idx] = (pde & ~PFN_MASK_) | MmGetPhysicalAddress(shadow_pt).QuadPart;

            last_pd_idx = pd_idx;
        }

        // --- clear NX for this PTE ---
        shadow_pt[pt_idx] = shadow_pt[pt_idx] & ~NX_BIT_;
        nx_cleared++;
    }

    UINT64 shadow_pml4_pa = MmGetPhysicalAddress(shadow_pml4).QuadPart;
    if (!TdShadowRegisterCr3(shadow_pml4_pa, &ctx))
        goto Fail;

    HYPERPLATFORM_LOG_INFO("[td-rw] shadow CR3 built: PA=0x%llX (VA=%p size=0x%llX, %u pages NX cleared)",
               shadow_pml4_pa, (PVOID)base_va, (UINT64)size, nx_cleared);

    return shadow_pml4_pa;

Fail:
    HYPERPLATFORM_LOG_ERROR(
        "[td-rw] TdBuildShadowCR3 FAIL (va=%p size=0x%llx cr3=%llx)",
        (PVOID)base_va, (UINT64)size, cr3);
    TdShadowFreePageList(ctx.pages, ctx.page_count);
    for (UINT32 i = 0; i < ctx.real_page_count; i++)
        TdShadowUnmapRealPage(&ctx.real_pages[i]);
    return 0;
}

// Add the freshly-forked shadow pages collected in ctx to an EXISTING shadow
// CR3's g_shadow_allocs slot (so TdShadowVaFromPhys/TdResolveShadowPte can find
// them, and they are freed when the CR3 is freed). Used by TdExtendShadowCR3.
static BOOLEAN
TdShadowExtendCr3Pages(UINT64 shadow_cr3_phys, TD_SHADOW_BUILD_CONTEXT * ctx)
{
    if (!shadow_cr3_phys || !ctx) return FALSE;
    if (!ctx->page_count) return TRUE;   // nothing to add; CR3 already covers the range
    KIRQL old_irql;
    KeAcquireSpinLock(&g_shadow_alloc_lock, &old_irql);
    BOOLEAN ok = FALSE;
    for (UINT32 i = 0; i < MAX_SHADOW_CR3_ALLOCS; i++)
    {
        TD_SHADOW_CR3_ALLOCATION * e = &g_shadow_allocs[i];
        if (e->active && e->shadow_cr3_phys == shadow_cr3_phys)
        {
            if ((UINT64)e->page_count + ctx->page_count > MAX_SHADOW_PAGES_PER_CR3)
            {
                HYPERPLATFORM_LOG_ERROR("[td-rw] extend FAIL: CR3 page cap overflow %u+%u > %u",
                                        e->page_count, ctx->page_count, MAX_SHADOW_PAGES_PER_CR3);
                break;
            }
            for (UINT32 j = 0; j < ctx->page_count; j++)
                e->pages[e->page_count++] = ctx->pages[j];
            ok = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_shadow_alloc_lock, old_irql);
    return ok;
}

//
// Extend an EXISTING shadow CR3 to cover an additional VA range [base_va, +size).
// Walks the REAL page tables (cr3) for the CURRENT PDEs -- the shadow PD/PT pages
// are snapshots from build time and may be stale (the range may have been allocated
// AFTER the shadow CR3 was first built, so a shadow PD entry could be not-present).
// At each level, if the shadow already has a forked page (TdShadowVaFromPhys finds
// it) it is reused; otherwise the current real page is forked and the parent shadow
// entry repointed. Clears NX on each PTE (matches TdBuildShadowCR3).
// Must be called at PASSIVE_LEVEL while attached to the target process.
// Returns shadow_cr3_phys on success, 0 on failure.
//
static UINT64
TdExtendShadowCR3(UINT64 shadow_cr3_phys, UINT64 cr3, UINT64 base_va, SIZE_T size)
{
    TD_SHADOW_BUILD_CONTEXT ctx = {};
    UINT64 va_start = base_va & ~0xFFFULL;
    UINT64 va_end   = (base_va + size + 0xFFF) & ~0xFFFULL;
    if (va_end <= va_start)
        return 0;

    PUINT64 shadow_pml4 = (PUINT64)TdShadowVaFromPhys(shadow_cr3_phys);
    if (!shadow_pml4) return 0;

    PUINT64 real_pml4 = TdMapPhys(cr3);
    if (!real_pml4) goto Fail;

    UINT32 pml4_idx = (UINT32)((va_start >> 39) & 0x1FF);
    UINT64 pml4e_real = real_pml4[pml4_idx];
    if (!(pml4e_real & 1)) goto Fail;

    // PDPT: reuse if already forked, else fork from the CURRENT real PDPT.
    PUINT64 shadow_pdpt = (PUINT64)TdShadowVaFromPhys(shadow_pml4[pml4_idx]);
    if (!shadow_pdpt)
    {
        PUINT64 real_pdpt = TdMapPhys(pml4e_real);
        if (!real_pdpt) goto Fail;
        shadow_pdpt = (PUINT64)TdShadowAllocPage(&ctx);
        if (!shadow_pdpt) goto Fail;
        RtlCopyMemory(shadow_pdpt, real_pdpt, PAGE_SIZE);
        shadow_pml4[pml4_idx] = (pml4e_real & ~PFN_MASK_) | MmGetPhysicalAddress(shadow_pdpt).QuadPart;
    }

    UINT32 last_pdpt_idx = 0xFFFFFFFF;
    UINT32 last_pd_idx   = 0xFFFFFFFF;
    PUINT64 shadow_pd = NULL;
    PUINT64 shadow_pt = NULL;

    for (UINT64 va = va_start; va < va_end; va += PAGE_SIZE)
    {
        UINT32 pdpt_idx = (UINT32)((va >> 30) & 0x1FF);
        UINT32 pd_idx   = (UINT32)((va >> 21) & 0x1FF);

        if (pdpt_idx != last_pdpt_idx)
        {
            // Read the CURRENT real PDPT (the shadow PDPT is a stale snapshot).
            PUINT64 real_pdpt = TdMapPhys(pml4e_real);
            if (!real_pdpt) goto Fail;
            UINT64 pdpe_real = real_pdpt[pdpt_idx];
            if (!(pdpe_real & 1) || (pdpe_real & (1ULL << 7))) goto Fail;  // 1GB large page
            shadow_pd = (PUINT64)TdShadowVaFromPhys(shadow_pdpt[pdpt_idx]);
            if (!shadow_pd)
            {
                PUINT64 real_pd = TdMapPhys(pdpe_real);
                if (!real_pd) goto Fail;
                shadow_pd = (PUINT64)TdShadowAllocPage(&ctx);
                if (!shadow_pd) goto Fail;
                RtlCopyMemory(shadow_pd, real_pd, PAGE_SIZE);
                shadow_pdpt[pdpt_idx] = (pdpe_real & ~PFN_MASK_) | MmGetPhysicalAddress(shadow_pd).QuadPart;
            }
            last_pdpt_idx = pdpt_idx;
            last_pd_idx = 0xFFFFFFFF;
        }

        if (pd_idx != last_pd_idx)
        {
            // Read the CURRENT real PD (shadow PD may be stale; the range may
            // have been allocated after the shadow CR3 was first built).
            PUINT64 real_pdpt = TdMapPhys(pml4e_real);
            if (!real_pdpt) goto Fail;
            UINT64 pdpe_real = real_pdpt[pdpt_idx];
            PUINT64 real_pd = TdMapPhys(pdpe_real);
            if (!real_pd) goto Fail;
            UINT64 pde_real = real_pd[pd_idx];
            if (!(pde_real & 1) || (pde_real & (1ULL << 7))) goto Fail;  // 2MB large page
            shadow_pt = (PUINT64)TdShadowVaFromPhys(shadow_pd[pd_idx]);
            if (!shadow_pt)
            {
                PUINT64 real_pt = TdMapPhys(pde_real);
                if (!real_pt) goto Fail;
                shadow_pt = (PUINT64)TdShadowAllocPage(&ctx);
                if (!shadow_pt) goto Fail;
                RtlCopyMemory(shadow_pt, real_pt, PAGE_SIZE);
                shadow_pd[pd_idx] = (pde_real & ~PFN_MASK_) | MmGetPhysicalAddress(shadow_pt).QuadPart;
            }
            last_pd_idx = pd_idx;
        }
        // Clear NX on this PTE (matches TdBuildShadowCR3). need_execute allocs
        // require the range executable in the shadow CR3; the HV's code-PTE
        // refresh preserves the NX bit, so it must be cleared here. The protect
        // handler's tracked block overwrites with new_protect afterwards, so
        // this is a no-op for the protect path.
        shadow_pt[(va >> 12) & 0x1FF] &= ~NX_BIT_;
    }

    if (!TdShadowExtendCr3Pages(shadow_cr3_phys, &ctx))
        goto Fail;

    HYPERPLATFORM_LOG_INFO("[td-rw] shadow CR3 extended: PA=0x%llX (VA=%p size=0x%llx, %u new pages)",
               shadow_cr3_phys, (PVOID)base_va, (UINT64)size, ctx.page_count);
    return shadow_cr3_phys;

Fail:
    HYPERPLATFORM_LOG_ERROR("[td-rw] TdExtendShadowCR3 FAIL (va=%p size=0x%llx shadow=0x%llX)",
               (PVOID)base_va, (UINT64)size, shadow_cr3_phys);
    TdShadowFreePageList(ctx.pages, ctx.page_count);
    return 0;
}

//
// walk guest page tables at PASSIVE/DISPATCH level (safe, no VMX-root).
// returns FALSE if the VA is not mapped or uses large pages.
//
static BOOLEAN
TdResolveGuestPT(UINT64 cr3, UINT64 va, UINT64 * out_pt_pfn, UINT32 * out_pte_idx)
{
    PHYSICAL_ADDRESS pa;
    PUINT64 table;

    // PML4
    pa.QuadPart = (LONGLONG)(cr3 & PFN_MASK_);
    table = (PUINT64)MmGetVirtualForPhysical(pa);
    if (!table) return FALSE;
    UINT64 pml4e = table[(va >> 39) & 0x1FF];
    if (!(pml4e & 1)) return FALSE;

    // PDPT
    pa.QuadPart = (LONGLONG)(pml4e & PFN_MASK_);
    table = (PUINT64)MmGetVirtualForPhysical(pa);
    if (!table) return FALSE;
    UINT64 pdpe = table[(va >> 30) & 0x1FF];
    if (!(pdpe & 1) || (pdpe & (1ULL << 7))) return FALSE;  // 1GB page

    // PD
    pa.QuadPart = (LONGLONG)(pdpe & PFN_MASK_);
    table = (PUINT64)MmGetVirtualForPhysical(pa);
    if (!table) return FALSE;
    UINT64 pde = table[(va >> 21) & 0x1FF];
    if (!(pde & 1) || (pde & (1ULL << 7))) return FALSE;  // 2MB page

    *out_pt_pfn  = (pde & PFN_MASK_) >> 12;
    *out_pte_idx = (UINT32)((va >> 12) & 0x1FF);
    return TRUE;
}

static PUINT64
TdResolveGuestPte(UINT64 cr3, UINT64 va)
{
    PHYSICAL_ADDRESS pa;
    PUINT64 table;

    pa.QuadPart = (LONGLONG)(cr3 & PFN_MASK_);
    table = (PUINT64)MmGetVirtualForPhysical(pa);
    if (!table) return NULL;
    UINT64 pml4e = table[(va >> 39) & 0x1FF];
    if (!(pml4e & 1)) return NULL;

    pa.QuadPart = (LONGLONG)(pml4e & PFN_MASK_);
    table = (PUINT64)MmGetVirtualForPhysical(pa);
    if (!table) return NULL;
    UINT64 pdpe = table[(va >> 30) & 0x1FF];
    if (!(pdpe & 1) || (pdpe & (1ULL << 7))) return NULL;

    pa.QuadPart = (LONGLONG)(pdpe & PFN_MASK_);
    table = (PUINT64)MmGetVirtualForPhysical(pa);
    if (!table) return NULL;
    UINT64 pde = table[(va >> 21) & 0x1FF];
    if (!(pde & 1) || (pde & (1ULL << 7))) return NULL;

    pa.QuadPart = (LONGLONG)(pde & PFN_MASK_);
    table = (PUINT64)MmGetVirtualForPhysical(pa);
    if (!table) return NULL;
    return &table[(va >> 12) & 0x1FF];
}

static BOOLEAN
TdNormalizeShadowProtect(ULONG protect, ULONG * out_protect)
{
    if (!out_protect)
        return FALSE;

    protect &= 0xFF;
    switch (protect)
    {
    case PAGE_READONLY:
    case PAGE_READWRITE:
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
        *out_protect = protect;
        return TRUE;
    default:
        return FALSE;
    }
}

static ULONG
TdProtectFromPte(UINT64 pte)
{
    BOOLEAN writable = (pte & (1ULL << 1)) != 0;
    BOOLEAN executable = (pte & NX_BIT_) == 0;

    if (executable)
        return writable ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
    return writable ? PAGE_READWRITE : PAGE_READONLY;
}

static VOID
TdApplyProtectToPte(PUINT64 pte, ULONG protect)
{
    if (!pte)
        return;

    UINT64 v = *pte;
    switch (protect)
    {
    case PAGE_READONLY:
        v &= ~(1ULL << 1);
        v |= NX_BIT_;
        break;
    case PAGE_READWRITE:
        v |= (1ULL << 1);
        v |= NX_BIT_;
        break;
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
        v &= ~(1ULL << 1);
        v &= ~NX_BIT_;
        break;
    case PAGE_EXECUTE_READWRITE:
        v |= (1ULL << 1);
        v &= ~NX_BIT_;
        break;
    }
    *pte = v;
}

typedef struct _TD_TLB_FLUSH_RANGE {
    UINT64 base;
    UINT64 size;
    UINT64 target_cr3;
    UINT64 shadow_cr3;
} TD_TLB_FLUSH_RANGE;

static VOID
TdFlushAddressRangeForCr3(UINT64 base, UINT64 size, UINT64 cr3)
{
    if (!cr3)
        return;

    UINT64 saved_cr3 = __readcr3();
    if ((saved_cr3 & PFN_MASK_) != (cr3 & PFN_MASK_))
        __writecr3(cr3);

    UINT64 end = base + size;
    for (UINT64 page = base; page < end; page += PAGE_SIZE)
        __invlpg((PVOID)page);

    __writecr3(saved_cr3);
}

static VOID
TdFlushAddressRange(UINT64 base_va, SIZE_T size, UINT64 target_cr3, UINT64 shadow_cr3)
{
    if (!base_va || !size)
        return;

    UINT64 start = base_va & ~0xFFFULL;
    UINT64 end = (base_va + size + PAGE_SIZE - 1) & ~0xFFFULL;
    for (UINT64 page = start; page < end; page += PAGE_SIZE)
        __invlpg((PVOID)page);

    if (shadow_cr3)
        TdFlushAddressRangeForCr3(start, end - start, shadow_cr3);

    TD_TLB_FLUSH_RANGE range = { start, end - start, target_cr3, shadow_cr3 };
    KeGenericCallDpc([](PKDPC, PVOID Ctx, PVOID A1, PVOID A2) {
        auto * r = (TD_TLB_FLUSH_RANGE *)Ctx;
        TdFlushAddressRangeForCr3(r->base, r->size, r->target_cr3);
        TdFlushAddressRangeForCr3(r->base, r->size, r->shadow_cr3);
        KeSignalCallDpcSynchronize(A2);
        KeSignalCallDpcDone(A1);
    }, &range);
}

// ---- forward declarations ----
static BOOLEAN TdStealthTrackAdd(UINT64 pid, PVOID va, SIZE_T size, UINT64 shadow_cr3);
static UINT64 TdStealthTrackRemove(UINT64 pid, PVOID va);
static BOOLEAN TdStealthTrackFindOverlap(UINT64 pid, PVOID base_va, SIZE_T size, PVOID * out_base, SIZE_T * out_size, UINT64 * out_shadow_cr3);
static BOOLEAN TdStealthTrackHasPartialOverlap(UINT64 pid, PVOID base_va, SIZE_T size);
static UINT64 TdStealthFindShadowCr3ForPid(UINT64 pid);
static BOOLEAN TdStealthFreePage(PVOID target_va);
static BOOLEAN g_process_notify_registered = FALSE;
static BOOLEAN g_process_notify_ex_registered = FALSE;

// 前向声明：TdInjectRenderdocShadow 在 HookedNtCreateFile 之后定义
static NTSTATUS TdInjectRenderdocShadow(PEPROCESS proc, PCUNICODE_STRING renderdoc_path, const char * log_prefix, BOOLEAN wait_for_completion);

// =========================================================================
//  inject target tracking (for LoadImage callback)
// =========================================================================

#ifndef TD_INJECT_TARGET_NAME
#define TD_INJECT_TARGET_NAME   L"Box.exe"
#endif
#ifndef TD_INJECT_LOADER_NAME
#define TD_INJECT_LOADER_NAME   L"ophion_loader.dll"
#endif
#ifndef MAX_PATH
#define MAX_PATH 260
#endif

#define TD_MAX_INJECT_TARGETS 16
typedef struct _TD_INJECT_TARGET {
    HANDLE  pid;
    BOOLEAN active;
    BOOLEAN injected;
    WCHAR   loader_nt_path[MAX_PATH];
} TD_INJECT_TARGET;

static TD_INJECT_TARGET g_inject_targets[TD_MAX_INJECT_TARGETS];
static KSPIN_LOCK g_inject_target_lock;
static BOOLEAN g_inject_target_lock_init = FALSE;
static BOOLEAN g_loadimage_registered = FALSE;

// match the basename of a full image path against a wide name (case-insensitive)
static BOOLEAN TdInjectMatchBasename(PCUNICODE_STRING image, const WCHAR * target, USHORT target_chars)
{
    if (!image || !image->Buffer || !target) return FALSE;
    const WCHAR * buf = image->Buffer;
    USHORT len = image->Length / sizeof(WCHAR);
    USHORT base_off = 0;
    for (USHORT i = 0; i < len; i++)
        if (buf[i] == L'\\') base_off = (USHORT)(i + 1);
    USHORT base_len = (USHORT)(len - base_off);
    if (base_len != target_chars) return FALSE;
    const WCHAR * b = buf + base_off;
    for (USHORT i = 0; i < target_chars; i++)
    {
        WCHAR ca = b[i], cb = target[i];
        if (ca >= L'a' && ca <= L'z') ca -= 32;
        if (cb >= L'a' && cb <= L'z') cb -= 32;
        if (ca != cb) return FALSE;
    }
    return TRUE;
}

// Build the loader NT path from the target exe full path:
//   "\??\C:\dir\Box.exe" -> "\??\C:\dir\ophion_loader.dll"
static BOOLEAN TdInjectBuildLoaderPath(PCUNICODE_STRING exe_path, WCHAR * out, ULONG out_chars)
{
    if (!exe_path || !exe_path->Buffer || !out || out_chars < 8) return FALSE;
    const WCHAR * src = exe_path->Buffer;
    USHORT src_chars = exe_path->Length / sizeof(WCHAR);
    if (src_chars == 0 || src_chars >= out_chars) return FALSE;
    USHORT last_slash = 0;
    for (USHORT i = 0; i < src_chars; i++)
    {
        out[i] = src[i];
        if (src[i] == L'\\') last_slash = (USHORT)(i + 1);
    }
    static const WCHAR loader[] = TD_INJECT_LOADER_NAME;
    USHORT loader_chars = (USHORT)((sizeof(loader) / sizeof(WCHAR)) - 1);
    if ((ULONG)last_slash + loader_chars + 1 > out_chars) return FALSE;
    for (USHORT i = 0; i < loader_chars; i++) out[last_slash + i] = loader[i];
    out[last_slash + loader_chars] = L'\0';
    return TRUE;
}

static void TdInjectTargetAdd(HANDLE pid, PCUNICODE_STRING exe_path)
{
    KIRQL old;
    KeAcquireSpinLock(&g_inject_target_lock, &old);
    for (ULONG i = 0; i < TD_MAX_INJECT_TARGETS; i++)
    {
        if (!g_inject_targets[i].active)
        {
            g_inject_targets[i].pid = pid;
            g_inject_targets[i].injected = FALSE;
            if (TdInjectBuildLoaderPath(exe_path, g_inject_targets[i].loader_nt_path, MAX_PATH))
                g_inject_targets[i].active = TRUE;
            KeReleaseSpinLock(&g_inject_target_lock, old);
            HYPERPLATFORM_LOG_INFO("[td-inj] target recorded: pid=%llu loader=%ws",
                (UINT64)pid, g_inject_targets[i].loader_nt_path);
            return;
        }
    }
    KeReleaseSpinLock(&g_inject_target_lock, old);
}

static void TdInjectTargetRemove(HANDLE pid)
{
    KIRQL old;
    KeAcquireSpinLock(&g_inject_target_lock, &old);
    for (ULONG i = 0; i < TD_MAX_INJECT_TARGETS; i++)
    {
        if (g_inject_targets[i].active && g_inject_targets[i].pid == pid)
        {
            g_inject_targets[i].active = FALSE;
            g_inject_targets[i].injected = FALSE;
            break;
        }
    }
    KeReleaseSpinLock(&g_inject_target_lock, old);
}

// claim a not-yet-injected target; copies loader path out under the lock.
static BOOLEAN TdInjectTargetClaim(HANDLE pid, WCHAR * out_path, ULONG path_chars)
{
    BOOLEAN claimed = FALSE;
    KIRQL old;
    KeAcquireSpinLock(&g_inject_target_lock, &old);
    for (ULONG i = 0; i < TD_MAX_INJECT_TARGETS; i++)
    {
        if (g_inject_targets[i].active && !g_inject_targets[i].injected && g_inject_targets[i].pid == pid)
        {
            g_inject_targets[i].injected = TRUE;
            if (out_path && path_chars)
            {
                ULONG j = 0;
                for (; j < path_chars - 1 && g_inject_targets[i].loader_nt_path[j]; j++)
                    out_path[j] = g_inject_targets[i].loader_nt_path[j];
                out_path[j] = L'\0';
            }
            claimed = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_inject_target_lock, old);
    return claimed;
}

// ---------------------------------------------------------------------------
// Per-process cached PE info for manually-mapped renderdoc.
// TdManualMapInProcess caches the resource + export directory RVAs (read from
// the intact raw_dll NT headers) before the mapped image's headers are erased.
// R3 queries it via IOCTL_GET_SELF_PE_INFO to walk .rsrc / resolve exports
// post-erasure. Freed at process exit (TdCleanupSelfPeInfo).
// ---------------------------------------------------------------------------
#define TD_SELF_PE_INFO_MAX 16
typedef struct _TD_SELF_PE_INFO_ENTRY {
    UINT64 pid;
    UINT64 module_base;
    UINT64 rsrc_rva;
    UINT64 rsrc_size;
    UINT64 export_dir_rva;
    UINT64 export_dir_size;
    UINT64 size_of_image;
} TD_SELF_PE_INFO_ENTRY;

static TD_SELF_PE_INFO_ENTRY g_SelfPeInfoCache[TD_SELF_PE_INFO_MAX];
static KSPIN_LOCK g_SelfPeInfoLock;
static BOOLEAN g_SelfPeInfoLockInit = FALSE;

// Cache PE info (read from intact raw_dll NT headers) for (pid, mapped base).
// Called from TdManualMapInProcess before header erasure.
static void TdCacheSelfPeInfo(UINT64 pid, UINT64 module_base, PIMAGE_NT_HEADERS64 nt)
{
    if (!pid || !module_base || !nt) return;
    KIRQL old;
    KeAcquireSpinLock(&g_SelfPeInfoLock, &old);
    // Overwrite an existing entry for (pid, module_base); else take first free slot.
    ULONG slot = TD_SELF_PE_INFO_MAX;
    for (ULONG i = 0; i < TD_SELF_PE_INFO_MAX; i++)
    {
        if (g_SelfPeInfoCache[i].pid == pid &&
            g_SelfPeInfoCache[i].module_base == module_base)
        {
            slot = i;
            break;
        }
        if (slot == TD_SELF_PE_INFO_MAX && g_SelfPeInfoCache[i].pid == 0)
            slot = i;
    }
    if (slot < TD_SELF_PE_INFO_MAX)
    {
        g_SelfPeInfoCache[slot].pid = pid;
        g_SelfPeInfoCache[slot].module_base = module_base;
        g_SelfPeInfoCache[slot].rsrc_rva =
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
        g_SelfPeInfoCache[slot].rsrc_size =
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
        g_SelfPeInfoCache[slot].export_dir_rva =
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        g_SelfPeInfoCache[slot].export_dir_size =
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        g_SelfPeInfoCache[slot].size_of_image = nt->OptionalHeader.SizeOfImage;
    }
    KeReleaseSpinLock(&g_SelfPeInfoLock, old);
}

// Look up cached PE info for (pid, module_base). Returns TRUE and fills *out.
static BOOLEAN TdLookupSelfPeInfo(UINT64 pid, UINT64 module_base, TD_SELF_PE_INFO_ENTRY * out)
{
    if (!pid || !module_base || !out) return FALSE;
    BOOLEAN found = FALSE;
    KIRQL old;
    KeAcquireSpinLock(&g_SelfPeInfoLock, &old);
    for (ULONG i = 0; i < TD_SELF_PE_INFO_MAX; i++)
    {
        if (g_SelfPeInfoCache[i].pid == pid &&
            g_SelfPeInfoCache[i].module_base == module_base)
        {
            *out = g_SelfPeInfoCache[i];
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_SelfPeInfoLock, old);
    return found;
}

// Free all cached entries for a process (called at process exit).
static void TdCleanupSelfPeInfo(UINT64 pid)
{
    if (!pid) return;
    KIRQL old;
    KeAcquireSpinLock(&g_SelfPeInfoLock, &old);
    for (ULONG i = 0; i < TD_SELF_PE_INFO_MAX; i++)
    {
        if (g_SelfPeInfoCache[i].pid == pid)
            g_SelfPeInfoCache[i].pid = 0;
    }
    KeReleaseSpinLock(&g_SelfPeInfoLock, old);
}

// Read a file from kernel into a NonPaged buffer.
static NTSTATUS TdReadFileKernel(PCUNICODE_STRING nt_path, PUINT8 * out_buf, SIZE_T * out_size)
{
    *out_buf = NULL; *out_size = 0;
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, (PUNICODE_STRING)nt_path,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    IO_STATUS_BLOCK iosb = {};
    HANDLE h = NULL;
    NTSTATUS st = ZwCreateFile(&h, GENERIC_READ | SYNCHRONIZE, &oa, &iosb, NULL,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
    if (!NT_SUCCESS(st)) return st;

    FILE_STANDARD_INFORMATION fsi = {};
    st = ZwQueryInformationFile(h, &iosb, &fsi, sizeof(fsi), FileStandardInformation);
    if (!NT_SUCCESS(st)) { ZwClose(h); return st; }

    SIZE_T size = (SIZE_T)fsi.EndOfFile.QuadPart;
    if (size == 0 || size > 64 * 1024 * 1024) { ZwClose(h); return STATUS_FILE_TOO_LARGE; }

    PUINT8 buf = (PUINT8)ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'fRdO');
    if (!buf) { ZwClose(h); return STATUS_INSUFFICIENT_RESOURCES; }

    LARGE_INTEGER off = {};
    iosb = {};
    st = ZwReadFile(h, NULL, NULL, NULL, &iosb, buf, (ULONG)size, &off, NULL);
    ZwClose(h);
    if (!NT_SUCCESS(st)) { ExFreePoolWithTag(buf, 'fRdO'); return st; }

    *out_buf = buf;
    *out_size = (SIZE_T)iosb.Information;
    return STATUS_SUCCESS;
}

// ---- assembly VMCALL (vmcall.asm) ----

extern "C" {
    NTSYSCALLAPI NTSTATUS NTAPI RtlCreateUserThread(
        HANDLE ProcessHandle, PSECURITY_DESCRIPTOR SecurityDescriptor,
        BOOLEAN CreateSuspended, ULONG StackZeroBits,
        SIZE_T StackReserve, SIZE_T StackCommit,
        PVOID StartAddress, PVOID Parameter,
        PHANDLE ThreadHandle, PCLIENT_ID ClientId);

    NTSTATUS hv_vmcall_ex(
        UINT64 vmcall_reason, UINT64 param1, UINT64 param2, UINT64 param3,
        UINT64 param4, UINT64 param5, UINT64 param6,
        UINT64 param7, UINT64 param8, UINT64 param9);

    // simple 4-param vmcall 鈥?no r12-r15 push/pop, no stack args.
    // safe for DPC callbacks (doesn't clobber A1/A2 save slots).
    NTSTATUS hv_vmcall_simple(
        UINT64 vmcall_reason, UINT64 param1, UINT64 param2, UINT64 param3);

    NTKERNELAPI VOID    KeGenericCallDpc(PKDEFERRED_ROUTINE, PVOID);
    NTKERNELAPI VOID    KeSignalCallDpcDone(PVOID);
    NTKERNELAPI LOGICAL KeSignalCallDpcSynchronize(PVOID);
}

// ---- undocumented API ----

#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001

typedef NTSTATUS (NTAPI * fn_ZwCreateThreadEx)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE,
    PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);


typedef NTSTATUS (NTAPI * fn_ZwResumeThread)(HANDLE, PULONG);

static fn_ZwCreateThreadEx g_pZwCreateThreadEx = NULL;
static fn_ZwResumeThread   g_pZwResumeThread   = NULL;

//
// resolve a function by name from ntoskrnl.exe's export table.
// this finds APIs that MmGetSystemRoutineAddress cannot see
// (e.g. PsResumeThread, KeResumeThread, etc.).
// Blackbone uses the same technique.
//
static PVOID
TdResolveNtoskrnlExport(const char * func_name)
{
    static PVOID g_ntoskrnl_base = NULL;
    if (!g_ntoskrnl_base)
    {
        UNICODE_STRING fn_name;
        PVOID known_routine = NULL;
        PVOID image_base = NULL;

        RtlInitUnicodeString(&fn_name, L"NtClose");
        known_routine = (PVOID)MmGetSystemRoutineAddress(&fn_name);
        if (!known_routine)
        {
            RtlInitUnicodeString(&fn_name, L"ZwClose");
            known_routine = (PVOID)MmGetSystemRoutineAddress(&fn_name);
        }

        if (known_routine)
            RtlPcToFileHeader(known_routine, &image_base);

        g_ntoskrnl_base = image_base;
        if (!g_ntoskrnl_base)
        {
            HYPERPLATFORM_LOG_WARN("[td] TdResolveNtoskrnlExport: failed to locate ntoskrnl base");
        }
    }

    if (!g_ntoskrnl_base || !func_name)
        return NULL;

    __try
    {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)g_ntoskrnl_base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return NULL;

        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((PUINT8)g_ntoskrnl_base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
            return NULL;

        ULONG exp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        ULONG exp_sz  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        if (!exp_rva || exp_sz < sizeof(IMAGE_EXPORT_DIRECTORY))
            return NULL;

        PIMAGE_EXPORT_DIRECTORY exp_dir = (PIMAGE_EXPORT_DIRECTORY)((PUINT8)g_ntoskrnl_base + exp_rva);
        PULONG names = (PULONG)((PUINT8)g_ntoskrnl_base + exp_dir->AddressOfNames);
        PUSHORT ords = (PUSHORT)((PUINT8)g_ntoskrnl_base + exp_dir->AddressOfNameOrdinals);
        PULONG funcs = (PULONG)((PUINT8)g_ntoskrnl_base + exp_dir->AddressOfFunctions);

        for (ULONG i = 0; i < exp_dir->NumberOfNames; i++)
        {
            const char * fn = (const char *)((PUINT8)g_ntoskrnl_base + names[i]);
            if (fn && TdAsciiEqualI(fn, func_name))
            {
                USHORT ord = ords[i];
                if (ord < exp_dir->NumberOfFunctions)
                {
                    ULONG func_rva = funcs[ord];
                    if (func_rva >= exp_rva && func_rva < exp_rva + exp_sz)
                        return NULL;  // forwarded export 鈥?skip
                    PVOID resolved = (PUINT8)g_ntoskrnl_base + func_rva;
                    HYPERPLATFORM_LOG_INFO("[td] nt export %s = %p", func_name, resolved);
                    return resolved;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        HYPERPLATFORM_LOG_WARN("[td] TdResolveNtoskrnlExport exception for %s", func_name);
    }

    return NULL;
}

static PVOID
TdGetNtoskrnlBase(ULONG * image_size)
{
    static PVOID g_nt_base = NULL;
    static ULONG g_nt_size = 0;

    if (!g_nt_base)
    {
        UNICODE_STRING fn_name;
        PVOID known_routine = NULL;
        PVOID image_base = NULL;

        RtlInitUnicodeString(&fn_name, L"NtClose");
        known_routine = (PVOID)MmGetSystemRoutineAddress(&fn_name);
        if (!known_routine)
        {
            RtlInitUnicodeString(&fn_name, L"ZwClose");
            known_routine = (PVOID)MmGetSystemRoutineAddress(&fn_name);
        }

        if (known_routine)
            RtlPcToFileHeader(known_routine, &image_base);

        if (image_base)
        {
            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)image_base;
            PIMAGE_NT_HEADERS64 nt = NULL;
            if (dos->e_magic == IMAGE_DOS_SIGNATURE)
                nt = (PIMAGE_NT_HEADERS64)((PUINT8)image_base + dos->e_lfanew);
            g_nt_base = image_base;
            if (nt && nt->Signature == IMAGE_NT_SIGNATURE)
                g_nt_size = nt->OptionalHeader.SizeOfImage;
        }
    }

    if (image_size)
        *image_size = g_nt_size;
    return g_nt_base;
}

static PVOID
TdSearchPattern(const UCHAR * pattern, UCHAR wildcard, SIZE_T length, PUCHAR base, SIZE_T size)
{
    if (!pattern || !base || !length || size < length)
        return NULL;

    for (SIZE_T i = 0; i <= size - length; i++)
    {
        BOOLEAN match = TRUE;
        for (SIZE_T j = 0; j < length; j++)
        {
            if (pattern[j] != wildcard && base[i + j] != pattern[j])
            {
                match = FALSE;
                break;
            }
        }
        if (match)
            return base + i;
    }

    return NULL;
}

static PTD_SYSTEM_SERVICE_DESCRIPTOR_TABLE
TdGetSSDTBase()
{
    static PTD_SYSTEM_SERVICE_DESCRIPTOR_TABLE g_ssdt = NULL;
    if (g_ssdt)
        return g_ssdt;

    PUCHAR nt_base = (PUCHAR)TdGetNtoskrnlBase(NULL);
    if (!nt_base)
        return NULL;

    PIMAGE_DOS_HEADER dos_h = (PIMAGE_DOS_HEADER)nt_base;
    PIMAGE_NT_HEADERS64 nt = NULL;
    if (dos_h->e_magic == IMAGE_DOS_SIGNATURE)
        nt = (PIMAGE_NT_HEADERS64)(nt_base + dos_h->e_lfanew);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    PIMAGE_SECTION_HEADER first_sec = IMAGE_FIRST_SECTION(nt);
    for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER sec = &first_sec[i];
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) ||
            !(sec->Characteristics & IMAGE_SCN_MEM_NOT_PAGED) ||
            (sec->Characteristics & IMAGE_SCN_MEM_DISCARDABLE))
        {
            continue;
        }

        if (*(PULONG)sec->Name == 'TINI' || *(PULONG)sec->Name == 'EGAP')
            continue;

        static const UCHAR pattern[] = {
            0x4C, 0x8D, 0x15, 0xCC, 0xCC, 0xCC, 0xCC,
            0x4C, 0x8D, 0x1D, 0xCC, 0xCC, 0xCC, 0xCC, 0xF7
        };

        PUCHAR found = (PUCHAR)TdSearchPattern(pattern, 0xCC, sizeof(pattern),
            nt_base + sec->VirtualAddress, sec->Misc.VirtualSize);
        if (found)
        {
            g_ssdt = (PTD_SYSTEM_SERVICE_DESCRIPTOR_TABLE)
                (found + *(PLONG)(found + 3) + 7);
            return g_ssdt;
        }
    }

    return NULL;
}

static PVOID
TdGetSSDTEntry(ULONG index)
{
    PTD_SYSTEM_SERVICE_DESCRIPTOR_TABLE ssdt = TdGetSSDTBase();
    if (!ssdt || !ssdt->ServiceTableBase || index >= ssdt->NumberOfServices)
        return NULL;

    return (PUCHAR)ssdt->ServiceTableBase + (((PLONG)ssdt->ServiceTableBase)[index] >> 4);
}

static ULONG
TdGetPreviousModeOffset()
{
    static ULONG g_prev_mode_offset = 0;
    if (g_prev_mode_offset)
        return g_prev_mode_offset;

    UNICODE_STRING fn_name;
    RtlInitUnicodeString(&fn_name, L"ExGetPreviousMode");
    PUCHAR p = (PUCHAR)MmGetSystemRoutineAddress(&fn_name);
    if (!p)
        return 0;

    for (SIZE_T i = 0; i + 6 < 0x40; i++)
    {
        if (p[i] == 0x0F && p[i + 1] == 0xB6)
        {
            UCHAR modrm = p[i + 2];
            if ((modrm & 0xC0) == 0x80)
            {
                g_prev_mode_offset = *(ULONG UNALIGNED *)(p + i + 3);
                break;
            }
        }
    }

    return g_prev_mode_offset;
}

static NTSTATUS
TdResumeThreadHandle(HANDLE thread_h, PULONG previous_count)
{
    if (!thread_h)
        return STATUS_INVALID_PARAMETER;

    ULONG local_prev = 0;
    PULONG prev = previous_count ? previous_count : &local_prev;

    if (g_pZwResumeThread)
        return g_pZwResumeThread(thread_h, prev);

    if (!g_pPsResumeThread && !g_pKeResumeThread)
        return TdNtResumeThreadBySSDT(thread_h, prev);

    PETHREAD thread_obj = NULL;
    NTSTATUS st = ObReferenceObjectByHandle(thread_h, THREAD_ALL_ACCESS,
        *PsThreadType, KernelMode, (PVOID *)&thread_obj, NULL);
    if (!NT_SUCCESS(st))
        return st;

    if (g_pPsResumeThread)
    {
        st = g_pPsResumeThread(thread_obj, prev);
    }
    else if (g_pKeResumeThread)
    {
        *prev = g_pKeResumeThread((PKTHREAD)thread_obj);
        st = STATUS_SUCCESS;
    }
    else
    {
        st = TdNtResumeThreadBySSDT(thread_h, prev);
    }

    ObDereferenceObject(thread_obj);
    return st;
}

static NTSTATUS
TdMakeKernelThreadHandle(HANDLE thread_h, HANDLE * kernel_thread_h, UINT64 * thread_id)
{
    if (!thread_h || !kernel_thread_h)
        return STATUS_INVALID_PARAMETER;

    *kernel_thread_h = NULL;
    if (thread_id)
        *thread_id = 0;

    PETHREAD thread_obj = NULL;
    NTSTATUS st = ObReferenceObjectByHandle(thread_h, THREAD_ALL_ACCESS,
        *PsThreadType, KernelMode, (PVOID *)&thread_obj, NULL);
    if (!NT_SUCCESS(st))
        return st;

    if (thread_id)
        *thread_id = (UINT64)(ULONG_PTR)PsGetThreadId(thread_obj);

    st = ObOpenObjectByPointer(
        thread_obj,
        OBJ_KERNEL_HANDLE,
        NULL,
        THREAD_ALL_ACCESS,
        *PsThreadType,
        KernelMode,
        kernel_thread_h);

    ObDereferenceObject(thread_obj);
    return st;
}

static VOID
TdCloseCreatedThreadHandle(HANDLE thread_h, BOOLEAN thread_started)
{
    UNREFERENCED_PARAMETER(thread_started);

    if (!thread_h)
        return;

    ZwClose(thread_h);
}

// ---- device / IOCTL ----

// forward declarations for globals defined at driver entry / unload section.
// NOT static - extern matches the non-static definitions below.
extern PDEVICE_OBJECT g_dev_obj;
extern BOOLEAN g_device_hidden;

#define TD_DEVICE_NAME  L"\\Device\\OphionTest"
#define TD_SYMLINK_NAME L"\\DosDevices\\OphionTest"

#define TD_IOCTL_BASE   0x900
#define IOCTL_INJECT    CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EPT_HOOK    CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EPT_UNHOOK  CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EPT_HOOK_R3 CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EPT_UNHOOK_R3 CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_RESOLVE_EXPORT CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 12, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_MODULE_BASE CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 13, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HIDE_DEVICE     CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 14, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_SELF_PE_INFO CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 15, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 8)
typedef struct _TD_RESOLVE_EXPORT_PARAMS {
    UINT64 target_pid;          // [in]  target process PID
    UINT64 messageboxa_va;      // [out] user32!MessageBoxA VA in target process
    UINT64 sleepex_va;          // [out] kernel32!SleepEx VA in target process
    UINT64 status;              // [out] NTSTATUS
} TD_RESOLVE_EXPORT_PARAMS;

typedef struct _TD_GET_MODULE_BASE_PARAMS {
    UINT64 target_pid;          // [in]  target process PID
    char   module_name[256];    // [in]  module name (e.g. "user32.dll"), ASCII, null-terminated
    UINT64 module_base;         // [out] base address of the module (0 = not found)
    UINT64 module_size;         // [out] size of image in bytes
    UINT64 status;              // [out] NTSTATUS
} TD_GET_MODULE_BASE_PARAMS;

// Query cached PE info for a manually-mapped renderdoc module whose headers
// were erased after mapping. The driver caches this at map time (before
// erasure); R3 queries it to walk .rsrc / resolve exports post-erasure.
typedef struct _TD_GET_SELF_PE_INFO_PARAMS {
    UINT64 target_pid;          // [in]  caller process PID
    UINT64 module_base;         // [in]  renderdoc mapped base
    UINT64 rsrc_rva;            // [out] DataDirectory[RESOURCE].VirtualAddress
    UINT64 rsrc_size;           // [out] DataDirectory[RESOURCE].Size
    UINT64 export_dir_rva;      // [out] DataDirectory[EXPORT].VirtualAddress
    UINT64 export_dir_size;     // [out] DataDirectory[EXPORT].Size
    UINT64 size_of_image;       // [out] OptionalHeader.SizeOfImage
    UINT64 status;              // [out] NTSTATUS (0 = ok)
} TD_GET_SELF_PE_INFO_PARAMS;

typedef struct _TD_INJECT_PARAMS {
    UINT64 target_pid;
    UINT64 alloc_size;
    UINT64 trigger_va;      // [in]  R3 function to hook as trigger (0 = auto NtTestAlert)
    UINT64 shellcode_va;    // [out]
    UINT64 actual_size;     // [out]
} TD_INJECT_PARAMS;

//
// R3 EPT hook params 鈥?from user-mode app via DeviceIoControl
//
typedef struct _TD_R3_HOOK_PARAMS {
    UINT64 target_pid;          // [in]  target process PID
    UINT64 target_function_va;  // [in]  R3 VA to hook (e.g. NtCreateFile in ntdll)
    UINT64 proxy_function_va;   // [in]  R3 VA of proxy function in target process
    UINT64 hook_type;           // [in]  0=abs jmp, 1=VMCALL, 2=INT3
    UINT64 trampoline_va;       // [out] receives trampoline VA (R3, callable)
    UINT64 status;              // [out] NTSTATUS
} TD_R3_HOOK_PARAMS;

typedef struct _TD_R3_UNHOOK_PARAMS {
    UINT64 target_pid;          // [in]
    UINT64 target_function_va;  // [in]  same VA passed to hook
    UINT64 status;              // [out]
} TD_R3_UNHOOK_PARAMS;
#pragma pack(pop)

// ---- MessageBoxA shellcode (x64 PIC) ----
//
// flow:
//   PEB 鈫?kernel32 base 鈫?parse exports 鈫?find GetProcAddress (hash-based)
//   GetProcAddress(kernel32, "LoadLibraryA") 鈫?LoadLibraryA("user32.dll")
//   GetProcAddress(user32, "MessageBoxA") 鈫?MessageBoxA(0, text, title, 0)
//   ret
//
// this shellcode is assembled from the following NASM source:
//
//   bits 64
//   ; --- prologue ---
//   sub rsp, 0x28
//
//   ; --- PEB 鈫?kernel32 ---
//   mov rax, [gs:0x60]        ; PEB
//   mov rax, [rax+0x18]       ; Ldr
//   mov rax, [rax+0x20]       ; InMemoryOrderModuleList head
//   mov rax, [rax]            ; ntdll
//   mov rax, [rax]            ; kernel32
//   mov rbx, [rax+0x20]      ; kernel32 DllBase
//
//   ; --- find_export(rbx=base, r12d=hash) 鈫?rax=funcVA ---
//   ; uses ROR13-add hash of function name
//   ;   GetProcAddress hash = 0x7C0DFCAA
//   ;   LoadLibraryA  hash = 0xEC0E4E8E  (resolved via GetProcAddress)
//   ;   MessageBoxA   hash = 0x1E380A6A  (resolved via GetProcAddress)
//
//   (see byte array below 鈥?hand-assembled and verified)
//

// ---- DLL name matching helpers (used by PIC shellcode + gap finder) ----

static const WCHAR g_ntdll_name[] = L"ntdll.dll";
static const WCHAR g_k32_name[]  = L"kernel32.dll";

static BOOLEAN TdMatchDllName(const WCHAR * buf, USHORT buf_len, const WCHAR * target, USHORT target_len)
{
    USHORT i;
    WCHAR c;
    if (buf_len < target_len * sizeof(WCHAR)) return FALSE;
    for (i = 0; i < target_len; i++)
    {
        c = buf[i];
        if (c >= L'A' && c <= L'Z') c += 32;
        if (c != target[i]) return FALSE;
    }
    return TRUE;
}

// ---- PIC shellcode (zero API calls) ----
//
// finds MessageBoxA by PEB walk at BUILD TIME (driver side).
// shellcode itself only calls the pre-resolved function pointer.
// no LoadLibrary, no GetProcAddress, no runtime PEB walk.
//
// patch offset:
//   +6: pMessageBoxA (8 bytes, mov r12 imm64)
//
static const UINT8 g_shellcode_pic[] = {
    // --- prologue ---
    0x48, 0x83, 0xEC, 0x28,                                     // sub rsp, 28h

    // mov r12, pMessageBoxA (patched at offset 6)
    0x49, 0xBC,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,             // [6..13]

    // mov r13, pSleepEx (patched at offset 16)
    0x49, 0xBD,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,             // [16..23]

    // sub rsp, 40h (strings on stack)
    0x48, 0x83, 0xEC, 0x40,                                      // [24..27]

    // --- build "Ophion\0" at [rsp+20h] ---
    0xC7, 0x44, 0x24, 0x20,  0x4F, 0x70, 0x68, 0x69,            // "Ophi"
    0x66, 0xC7, 0x44, 0x24, 0x24,  0x6F, 0x6E,                  // "on"
    0xC6, 0x44, 0x24, 0x26,  0x00,                               // \0

    // --- build "Stealth OK\0" at [rsp+30h] ---
    0xC7, 0x44, 0x24, 0x30,  0x53, 0x74, 0x65, 0x61,            // "Stea"
    0xC7, 0x44, 0x24, 0x34,  0x6C, 0x74, 0x68, 0x20,            // "lth "
    0x66, 0xC7, 0x44, 0x24, 0x38,  0x4F, 0x4B,                  // "OK"
    0xC6, 0x44, 0x24, 0x3A,  0x00,                               // \0

    // --- loop_start (offset 76) ---
    // --- MessageBoxA(NULL, "Stealth OK", "Ophion", 0) ---
    0x48, 0x31, 0xC9,                                            // xor rcx, rcx
    0x48, 0x8D, 0x54, 0x24, 0x30,                                // lea rdx, [rsp+30h]
    0x4C, 0x8D, 0x44, 0x24, 0x20,                                // lea r8, [rsp+20h]
    0x45, 0x31, 0xC9,                                            // xor r9d, r9d
    0x41, 0xFF, 0xD4,                                            // call r12  (MessageBoxA)

    // --- SleepEx(3000, FALSE) ---
    0xB9, 0xB8, 0x0B, 0x00, 0x00,                               // mov ecx, 3000
    0x31, 0xD2,                                                   // xor edx, edx  (FALSE)
    0x41, 0xFF, 0xD5,                                            // call r13  (SleepEx)

    // --- jmp loop_start ---
    0xEB, 0xE1,                                                   // jmp -31 (back to loop_start at offset 76)
};

#define PIC_PATCH_MESSAGEBOX   6       // offset of pMessageBoxA imm64
#define PIC_PATCH_SLEEPEX      16      // offset of pSleepEx imm64

static const WCHAR g_user32_name[]  = L"user32.dll";
static const WCHAR g_kernel32_name[] = L"kernel32.dll";

//
// build PIC shellcode: resolve user32!MessageBoxA + kernel32!SleepEx
// via PEB walk + export table.
// zero runtime API calls 鈥?all resolution done here at PASSIVE_LEVEL.
// must be called while attached to the target process.
//
static BOOLEAN
TdBuildShellcodePIC(PVOID buf, SIZE_T buf_size)
{
    if (buf_size < sizeof(g_shellcode_pic)) return FALSE;

    RtlZeroMemory(buf, buf_size);
    RtlCopyMemory(buf, g_shellcode_pic, sizeof(g_shellcode_pic));

    PPEB peb = PsGetProcessPeb(PsGetCurrentProcess());
    if (!peb) return FALSE;

    UINT64 pMsgBox = 0;
    UINT64 pSleepEx = 0;
    PVOID user32_base = NULL;
    PVOID kernel32_base = NULL;

    __try {
        TD_PEB_LDR_DATA * ldr = *(TD_PEB_LDR_DATA **)((PUINT8)peb + 0x18);
        if (!ldr) return FALSE;

        PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
        PLIST_ENTRY cur = head->Flink;

        // find user32.dll and kernel32.dll in PEB module list
        while (cur != head)
        {
            TD_LDR_ENTRY * e = CONTAINING_RECORD(cur, TD_LDR_ENTRY, InMemoryOrderLinks);
            if (e->BaseDllName.Buffer)
            {
                if (!user32_base &&
                    TdMatchDllName(e->BaseDllName.Buffer, e->BaseDllName.Length, g_user32_name, 10))
                    user32_base = e->DllBase;

                if (!kernel32_base &&
                    TdMatchDllName(e->BaseDllName.Buffer, e->BaseDllName.Length, g_kernel32_name, 12))
                    kernel32_base = e->DllBase;
            }
            if (user32_base && kernel32_base) break;
            cur = cur->Flink;
        }

        if (!user32_base)
        {
            HYPERPLATFORM_LOG_ERROR("[td] PIC: user32.dll not found in target process");
            return FALSE;
        }
        if (!kernel32_base)
        {
            HYPERPLATFORM_LOG_ERROR("[td] PIC: kernel32.dll not found in target process");
            return FALSE;
        }

        // walk user32 export table to find MessageBoxA
        {
            PIMAGE_DOS_HEADER dos_h = (PIMAGE_DOS_HEADER)user32_base;
            PIMAGE_NT_HEADERS64 nt_h = (PIMAGE_NT_HEADERS64)((PUINT8)user32_base + dos_h->e_lfanew);
            ULONG exp_rva = nt_h->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            PIMAGE_EXPORT_DIRECTORY exp_d = (PIMAGE_EXPORT_DIRECTORY)((PUINT8)user32_base + exp_rva);
            PULONG names_arr = (PULONG)((PUINT8)user32_base + exp_d->AddressOfNames);
            PUSHORT ords_arr = (PUSHORT)((PUINT8)user32_base + exp_d->AddressOfNameOrdinals);
            PULONG funcs_arr = (PULONG)((PUINT8)user32_base + exp_d->AddressOfFunctions);

            for (ULONG i = 0; i < exp_d->NumberOfNames; i++)
            {
                const char * fn = (const char *)((PUINT8)user32_base + names_arr[i]);
                if (fn[0] == 'M' && fn[1] == 'e' && fn[2] == 's' && fn[3] == 's' &&
                    fn[4] == 'a' && fn[5] == 'g' && fn[6] == 'e' && fn[7] == 'B' &&
                    fn[8] == 'o' && fn[9] == 'x' && fn[10] == 'A' && fn[11] == '\0')
                {
                    pMsgBox = (UINT64)user32_base + funcs_arr[ords_arr[i]];
                    break;
                }
            }
        }

        // walk kernel32 export table to find SleepEx
        {
            PIMAGE_DOS_HEADER dos_h = (PIMAGE_DOS_HEADER)kernel32_base;
            PIMAGE_NT_HEADERS64 nt_h = (PIMAGE_NT_HEADERS64)((PUINT8)kernel32_base + dos_h->e_lfanew);
            ULONG exp_rva = nt_h->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            PIMAGE_EXPORT_DIRECTORY exp_d = (PIMAGE_EXPORT_DIRECTORY)((PUINT8)kernel32_base + exp_rva);
            PULONG names_arr = (PULONG)((PUINT8)kernel32_base + exp_d->AddressOfNames);
            PUSHORT ords_arr = (PUSHORT)((PUINT8)kernel32_base + exp_d->AddressOfNameOrdinals);
            PULONG funcs_arr = (PULONG)((PUINT8)kernel32_base + exp_d->AddressOfFunctions);

            for (ULONG i = 0; i < exp_d->NumberOfNames; i++)
            {
                const char * fn = (const char *)((PUINT8)kernel32_base + names_arr[i]);
                if (fn[0] == 'S' && fn[1] == 'l' && fn[2] == 'e' && fn[3] == 'e' &&
                    fn[4] == 'p' && fn[5] == 'E' && fn[6] == 'x' && fn[7] == '\0')
                {
                    pSleepEx = (UINT64)kernel32_base + funcs_arr[ords_arr[i]];
                    break;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        HYPERPLATFORM_LOG_ERROR("[td] PIC: exception walking PEB/exports");
        return FALSE;
    }

    if (!pMsgBox)
    {
        HYPERPLATFORM_LOG_ERROR("[td] PIC: MessageBoxA not found in user32 exports");
        return FALSE;
    }
    if (!pSleepEx)
    {
        HYPERPLATFORM_LOG_ERROR("[td] PIC: SleepEx not found in kernel32 exports");
        return FALSE;
    }

    // patch addresses
    *(PUINT64)((PUINT8)buf + PIC_PATCH_MESSAGEBOX) = pMsgBox;
    *(PUINT64)((PUINT8)buf + PIC_PATCH_SLEEPEX)    = pSleepEx;

    HYPERPLATFORM_LOG_INFO("[td] PIC: user32=%p MessageBoxA=%llx kernel32=%p SleepEx=%llx size=%u (resident loop)",
               user32_base, pMsgBox, kernel32_base, pSleepEx, (UINT32)sizeof(g_shellcode_pic));
    return TRUE;
}

// =========================================================================
//  DPC broadcast 鈫?VMCALL per CPU
// =========================================================================

//
// set up EPT stealth for one page 鈥?single VMCALL from current CPU.
// HV internally loops all g_vcpu[i].ept_page_table to split + set PTE.
// NO KeGenericCallDpc 鈥?avoids 0x101 CLOCK_WATCHDOG when a CPU is
// stuck in VMX-root (Ophion HV pre-existing bug).
//
#ifndef TD_MAX_DPC_CPUS
#define TD_MAX_DPC_CPUS 64
#endif
#define TD_STEALTH_DPC_TAG 'dStT'
#define TD_STEALTH_REQ_TAG 'rStT'

typedef struct _TD_STEALTH_ALLOC_DPC_CTX {
    KEVENT           done_event;
    KDPC             dpcs[TD_MAX_DPC_CPUS];
    TD_STEALTH_PARAM * req;
    PVOID            pt_buf;
    PVOID            tgt_buf;
    volatile LONG    pending_count;
    volatile LONG    ref_count;
    volatile LONG    success_count;
    volatile LONG    failure_count;
    volatile LONG    cleanup_on_complete;
} TD_STEALTH_ALLOC_DPC_CTX;

static VOID
TdStealthAllocReleaseCtx(TD_STEALTH_ALLOC_DPC_CTX * ctx)
{
    if (_InterlockedDecrement(&ctx->ref_count) != 0)
        return;

    if (ctx->cleanup_on_complete)
    {
        if (ctx->pt_buf)
            ExFreePoolWithTag(ctx->pt_buf, 'htpS');
        if (ctx->tgt_buf)
            ExFreePoolWithTag(ctx->tgt_buf, 'htpS');
        if (ctx->req)
            ExFreePoolWithTag(ctx->req, TD_STEALTH_REQ_TAG);
    }

    ExFreePoolWithTag(ctx, TD_STEALTH_DPC_TAG);
}

static VOID
TdStealthAllocDpc(PKDPC Dpc, PVOID Ctx, PVOID, PVOID)
{
    UNREFERENCED_PARAMETER(Dpc);
    TD_STEALTH_ALLOC_DPC_CTX * ctx = (TD_STEALTH_ALLOC_DPC_CTX *)Ctx;
    NTSTATUS st = hv_vmcall_simple(VMCALL_STEALTH_ALLOC, (UINT64)ctx->req, 0, 0);

    if (NT_SUCCESS(st))
        _InterlockedIncrement(&ctx->success_count);
    else
        _InterlockedIncrement(&ctx->failure_count);

    if (_InterlockedDecrement(&ctx->pending_count) == 0)
        KeSetEvent(&ctx->done_event, IO_NO_INCREMENT, FALSE);
    TdStealthAllocReleaseCtx(ctx);
}

static NTSTATUS
TdRunStealthAllocOnCpus(TD_STEALTH_PARAM * req, PVOID pt_buf, PVOID tgt_buf)
{
    ULONG active_count = KeQueryActiveProcessorCount(NULL);
    if (active_count == 0)
        return STATUS_UNSUCCESSFUL;
    if (active_count > TD_MAX_DPC_CPUS)
        active_count = TD_MAX_DPC_CPUS;

    TD_STEALTH_ALLOC_DPC_CTX * ctx = (TD_STEALTH_ALLOC_DPC_CTX *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(TD_STEALTH_ALLOC_DPC_CTX), TD_STEALTH_DPC_TAG);
    if (!ctx)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(ctx, sizeof(*ctx));
    ctx->req = req;
    ctx->pt_buf = pt_buf;
    ctx->tgt_buf = tgt_buf;
    ctx->pending_count = (LONG)active_count;
    ctx->ref_count = (LONG)active_count + 1;
    KeInitializeEvent(&ctx->done_event, NotificationEvent, FALSE);

    for (ULONG cpu = 0; cpu < active_count; cpu++)
    {
        KeInitializeDpc(&ctx->dpcs[cpu], TdStealthAllocDpc, ctx);
        KeSetTargetProcessorDpc(&ctx->dpcs[cpu], (CCHAR)cpu);
        if (!KeInsertQueueDpc(&ctx->dpcs[cpu], NULL, NULL))
        {
            _InterlockedIncrement(&ctx->failure_count);
            if (_InterlockedDecrement(&ctx->pending_count) == 0)
                KeSetEvent(&ctx->done_event, IO_NO_INCREMENT, FALSE);
            TdStealthAllocReleaseCtx(ctx);
        }
    }

    LARGE_INTEGER timeout;
    timeout.QuadPart = -2LL * 1000LL * 10000LL;
    NTSTATUS wait_st = KeWaitForSingleObject(
        &ctx->done_event,
        Executive,
        KernelMode,
        FALSE,
        &timeout);

    if (wait_st == STATUS_TIMEOUT)
    {
        HYPERPLATFORM_LOG_ERROR("[td-rw] stealth alloc timeout: done=%d/%u fail=%d",
            (LONG)(active_count - ctx->pending_count), active_count, ctx->failure_count);
        _InterlockedExchange(&ctx->cleanup_on_complete, 1);
        TdStealthAllocReleaseCtx(ctx);
        return STATUS_IO_TIMEOUT;
    }

    NTSTATUS st = (ctx->failure_count == 0 && ctx->success_count != 0) ?
        STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    TdStealthAllocReleaseCtx(ctx);
    return st;
}

static NTSTATUS
TdStealthAllocPage(
    UINT64  caller_cr3,
    PVOID   page_va,        // page-aligned target VA
    UINT64  page_phys,      // physical address of page
    PVOID   sc_buf,         // shellcode chunk for this page (or NULL for resident)
    UINT32  sc_size,        // shellcode size for this page
    BOOLEAN resident,
    UINT64  pt_pfn,         // pre-computed PT page PFN (from TdResolveGuestPT)
    UINT32  pt_idx,         // pre-computed PTE index within PT page
    BOOLEAN use_fake_pt = FALSE,  // TRUE = create fake PT (NX hiding)
    UINT64  shadow_cr3_phys = 0,  // shadow CR3 phys (NX=0 for target, 0=not used)
    BOOLEAN no_ept_split = FALSE, // TRUE = shadow CR3 only, no EPT page split
    BOOLEAN intercept_write = FALSE)
{
    TD_STEALTH_PARAM * req = (TD_STEALTH_PARAM *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(TD_STEALTH_PARAM), TD_STEALTH_REQ_TAG);
    if (!req)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(req, sizeof(*req));

    UINT64 effective_pt_pfn = pt_pfn;
    UINT32 effective_pt_idx = pt_idx;
    PVOID effective_pt_va = NULL;
    PVOID shadow_pte_va = NULL;

    if (no_ept_split && shadow_cr3_phys)
    {
        if (!TdResolveShadowPT(shadow_cr3_phys, (UINT64)page_va,
            &effective_pt_pfn, &effective_pt_idx, &effective_pt_va))
        {
            ExFreePoolWithTag(req, TD_STEALTH_REQ_TAG);
            return STATUS_UNSUCCESSFUL;
        }
        // shadow PT page VA is a system-global NonPaged-pool VA (the original
        // ExAllocatePool2 VA tracked in g_shadow_allocs by TdShadowVaFromPhys).
        // Pass the exact shadow PTE VA so the HV writes *shadow_pte_va =
        // (real_pte & ~NX) on #PF WITHOUT pa_to_va: MmGetVirtualForPhysical
        // returns NULL for these NonPaged-pool pages in VMX-root, so the old
        // HV shadow-walk always bailed and the stale snapshot PTE (pre-DLL-load
        // PFN) survived -> CPU fetched wrong bytes -> execute AV.
        if (effective_pt_va)
            shadow_pte_va = &((PUINT64)effective_pt_va)[effective_pt_idx];
    }

    req->caller_cr3       = caller_cr3;
    req->target_pid       = 0;
    req->target_va        = page_va;
    req->handler_function = NULL;
    req->target_phys      = page_phys;
    req->shellcode_buffer = sc_buf;
    req->shellcode_size   = sc_size;
    req->resident         = resident;
    req->pt_page_pfn      = effective_pt_pfn;
    req->pt_pte_index     = effective_pt_idx;
    req->use_fake_pt      = use_fake_pt;
    req->shadow_cr3_phys  = shadow_cr3_phys;
    req->no_ept_split     = no_ept_split;
    req->shadow_pte_va    = shadow_pte_va;
    req->intercept_write  = intercept_write;

    // pass the shared real-page map (MDL-mapped real PT pages) so the HV can
    // walk the guest's real page tables under g_system_cr3 without pa_to_va.
    // (NULL/0 when no shadow CR3 or map build failed -- HV falls back to pa_to_va.)
    TdShadowGetRealMap(shadow_cr3_phys, &req->real_page_map, &req->real_page_count);

    //
    // copy PT page and target page content into NonPaged kernel buffers.
    // VMX-root accesses these buffers (always valid under any CR3).
    // MmGetVirtualForPhysical returns process-relative VAs that are
    // invalid under system CR3 in VMX-root 鈥?so we copy the content here.
    //
    PVOID pt_buf  = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'htpS');
    PVOID tgt_buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'htpS');
    if (!pt_buf || !tgt_buf)
    {
        if (pt_buf)  ExFreePoolWithTag(pt_buf,  'htpS');
        if (tgt_buf) ExFreePoolWithTag(tgt_buf, 'htpS');
        ExFreePoolWithTag(req, TD_STEALTH_REQ_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    {
        PHYSICAL_ADDRESS pa;
        pa.QuadPart = (LONGLONG)(effective_pt_pfn << 12);
        PVOID pt_va = effective_pt_va ? effective_pt_va : MmGetVirtualForPhysical(pa);
        PVOID target_page_base = (PVOID)((UINT64)page_va & ~0xFFFULL);

        __try
        {
            if (pt_va)
                RtlCopyMemory(pt_buf, pt_va, PAGE_SIZE);
            else
                RtlZeroMemory(pt_buf, PAGE_SIZE);

            //
            // We are still attached to the target process here, so copy the
            // target page through its current process VA instead of trying to
            // re-derive a transient VA from the physical page.
            //
            if (target_page_base)
                RtlCopyMemory(tgt_buf, target_page_base, PAGE_SIZE);
            else
                RtlZeroMemory(tgt_buf, PAGE_SIZE);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            ExFreePoolWithTag(pt_buf, 'htpS');
            ExFreePoolWithTag(tgt_buf, 'htpS');
            ExFreePoolWithTag(req, TD_STEALTH_REQ_TAG);
            HYPERPLATFORM_LOG_ERROR("[td-rw] TdStealthAllocPage copy fault: page_va=%p pt_va=%p",
                target_page_base, pt_va);
            return GetExceptionCode();
        }

        if (!effective_pt_va)
            effective_pt_va = pt_va;

        req->pt_page_va = effective_pt_va;  // shadow mode: shadow PT page VA; else real PT page VA
    }

    req->pt_page_copy     = pt_buf;
    req->target_page_copy = tgt_buf;
    req->pt_precomputed   = TRUE;

    // DPC broadcast 鈥?every CPU does VMCALL, each splits its own EPT.
    // same pattern as EPT hook's KeGenericCallDpc.
    NTSTATUS run_st = TdRunStealthAllocOnCpus(req, pt_buf, tgt_buf);
    if (run_st == STATUS_IO_TIMEOUT)
        return run_st;

    ExFreePoolWithTag(pt_buf,  'htpS');
    ExFreePoolWithTag(tgt_buf, 'htpS');
    ExFreePoolWithTag(req, TD_STEALTH_REQ_TAG);
    return run_st;
}

//
// set up EPT stealth for a multi-page shellcode buffer
// shellcode is written into the original page BEFORE VMCALL,
// so VMX-root copies it into the shadow page (execute view).
// after VMCALL, the original page is zeroed (read view = clean).
//
static BOOLEAN
TdStealthInjectPages(
    PVOID   base_va,
    PVOID   shellcode,
    UINT32  shellcode_size,
    BOOLEAN resident)
{
    UINT64  caller_cr3 = __readcr3();
    UINT64  base       = (UINT64)base_va;
    UINT32  done       = 0;
    UINT32  page_count = 0;

    while (done < shellcode_size)
    {
        UINT64 cur_va     = base + done;
        UINT64 page_va    = cur_va & ~0xFFFULL;
        UINT64 off_in_pg  = cur_va & 0xFFF;
        UINT32 space      = (UINT32)(PAGE_SIZE - off_in_pg);
        UINT32 chunk      = (shellcode_size - done < space) ? (shellcode_size - done) : space;

        //
        // page already has content from TdBuildShellcodePage 鈥?no need to touch.
        // (touching would overwrite first byte of shellcode with 0)
        // MmGetPhysicalAddress works because the page was already committed+written.
        //

        UINT64 page_phys = MmGetPhysicalAddress((PVOID)page_va).QuadPart;
        if (!page_phys)
        {
            HYPERPLATFORM_LOG_ERROR("[td] stealth page %u: MmGetPhysicalAddress=0 for VA=%p",
                       page_count, (PVOID)page_va);
            return FALSE;
        }

        //
        // pre-compute guest PT page info at PASSIVE/DISPATCH level (safe).
        // this avoids calling pa_to_va (MmGetVirtualForPhysical) in VMX-root
        // which deadlocks when KeGenericCallDpc puts all CPUs into VMX-root
        // and another CPU holds an OS internal lock.
        //
        UINT64 pt_pfn = 0;
        UINT32 pt_idx = 0;
        if (!TdResolveGuestPT(caller_cr3, page_va, &pt_pfn, &pt_idx))
        {
            HYPERPLATFORM_LOG_ERROR("[td] stealth page %u: PT walk failed for VA=%p",
                       page_count, (PVOID)page_va);
            return FALSE;
        }

        //
        // NX bit in real PTE is NOT cleared 鈥?Windows' MiAgeWorkingSet
        // can restore it at any time. the fake/exec PT pages handle NX hiding.
        //

        //
        // shellcode mode: pass the buffer directly so VMX-root copies it
        //
        NTSTATUS stealth_st = TdStealthAllocPage(
            caller_cr3,
            (PVOID)cur_va,
            page_phys + off_in_pg,
            (PUINT8)shellcode + done,
            chunk,
            resident,
            pt_pfn,
            pt_idx,
            FALSE,
            0,
            FALSE,
            FALSE);

        if (!NT_SUCCESS(stealth_st))
        {
            HYPERPLATFORM_LOG_ERROR("[td] stealth page %u failed: 0x%08X", page_count, stealth_st);
            return FALSE;
        }

        done += chunk;
        page_count++;
    }

    HYPERPLATFORM_LOG_INFO("[td] stealth inject: %u pages set up via VMCALL", page_count);
    return TRUE;
}

// =========================================================================
//  EPT Hook: NtCreateFile
// =========================================================================

#define VMCALL_EPT_HOOK     0x00000003
#define VMCALL_EPT_UNHOOK   0x00000004

//
// original NtCreateFile pointer (set by hook install, used by proxy)
//
typedef NTSTATUS (NTAPI * fn_NtCreateFile)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
    PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);

static fn_NtCreateFile g_orig_NtCreateFile = NULL;
static PVOID           g_hooked_target     = NULL;
static volatile LONG   g_hook_log_count    = 0;

//
// proxy function — called instead of NtCreateFile when EPT hook is active.
// logs the file path via DbgPrint, then calls original via trampoline.
//
// Pid of the Box.exe process we injected via CreateFile("test"). Re-armed on
// process exit (TdProcessNotify / TdProcessNotifyLegacy) so every new Box.exe
// instance injects again, instead of the old driver-lifetime flag that only
// injected the very first one.
static volatile LONG64 g_test_injected_pid = 0;

static NTSTATUS NTAPI
HookedNtCreateFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength)
{
    //
    // 匹配文件名是否为 "test"，触发 renderdoc 注入
    //
    if (ObjectAttributes && ObjectAttributes->ObjectName &&
        ObjectAttributes->ObjectName->Buffer && ObjectAttributes->ObjectName->Length >= 4 * sizeof(WCHAR))
    {
        USHORT name_len = ObjectAttributes->ObjectName->Length / sizeof(WCHAR);
        PWCHAR buf = ObjectAttributes->ObjectName->Buffer;
        // 不区分大小写匹配末尾文件名是否为 "test"
        if (name_len >= 4 &&
            (buf[name_len - 4] == L't' || buf[name_len - 4] == L'T') &&
            (buf[name_len - 3] == L'e' || buf[name_len - 3] == L'E') &&
            (buf[name_len - 2] == L's' || buf[name_len - 2] == L'S') &&
            (buf[name_len - 1] == L't' || buf[name_len - 1] == L'T'))
        {
            // 确认前面是路径分隔符或开头（避免匹配到 "test.exe" 等）
            if (name_len == 4 || buf[name_len - 5] == L'\\')
            {
                HYPERPLATFORM_LOG_WARN_SAFE("[td-hook] CreateFile(\"test\") detected — triggering renderdoc injection!");

                PEPROCESS current_proc = PsGetCurrentProcess();
                HANDLE current_pid = PsGetProcessId(current_proc);

                // 检查是否是 Box.exe
                BOOLEAN is_box = FALSE;
                {
                    static const char box_a[] = "Box.exe";
                    PCHAR img_name = (PCHAR)current_proc + 0x5a8;
                    BOOLEAN match = TRUE;
                    for (int i = 0; i < (int)(sizeof(box_a) - 1); i++)
                        if ((img_name[i] | 0x20) != (box_a[i] | 0x20)) { match = FALSE; break; }
                    is_box = match;
                }

                if (is_box)
                {
                    // 每个 Box.exe 进程只注入一次: 记录已注入的 pid;该进程退出时在
                    // TdProcessNotify 里重置,这样关闭 Box 再开新 Box 会重新注入
                    // (原来的 g_test_file_fired 是 driver 生命周期 flag,只注入第一次)。
                    LONG64 prev_pid = _InterlockedExchange64(&g_test_injected_pid, (LONG64)current_pid);
                    if (prev_pid != (LONG64)current_pid)
                    {
                        HYPERPLATFORM_LOG_INFO("[td-hook] Box.exe pid=%llu — starting renderdoc inject via shadow CR3",
                            (UINT64)current_pid);

                        // 直接用固定路径 C:\Users\q\Desktop\d\renderdoc.dll
                        WCHAR renderdoc_path_buf[MAX_PATH];
                        static const WCHAR kRenderdocPath[] = L"\\??\\C:\\Users\\q\\Desktop\\d\\renderdoc.dll";
                        USHORT rd_len = (USHORT)((sizeof(kRenderdocPath) / sizeof(WCHAR)) - 1);
                        RtlCopyMemory(renderdoc_path_buf, kRenderdocPath, rd_len * sizeof(WCHAR));
                        renderdoc_path_buf[rd_len] = L'\0';

                        UNICODE_STRING renderdoc_nt;
                        RtlInitUnicodeString(&renderdoc_nt, renderdoc_path_buf);

                        NTSTATUS inj_st = TdInjectRenderdocShadow(
                            current_proc, &renderdoc_nt, "td-hook-shadow", TRUE);
                        if (!NT_SUCCESS(inj_st))
                        {
                            HYPERPLATFORM_LOG_ERROR("[td-hook] TdInjectRenderdocShadow failed: 0x%08X", inj_st);
                        }
                    }
                    else
                    {
                        HYPERPLATFORM_LOG_INFO("[td-hook] Box.exe pid=%llu already injected this process - skip",
                            (UINT64)current_pid);
                    }
                }
            }
        }
    }

    //
    // log every 100th call to avoid flooding DbgPrint
    //
    LONG count = _InterlockedIncrement(&g_hook_log_count);
    if ((count % 100) == 1 && ObjectAttributes && ObjectAttributes->ObjectName)
    {
        HYPERPLATFORM_LOG_INFO_SAFE("[td-hook] NtCreateFile #%d: %wZ",
                   count, ObjectAttributes->ObjectName);
    }

    //
    // call original via trampoline
    //
    if (g_orig_NtCreateFile)
    {
        return g_orig_NtCreateFile(
            FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
            AllocationSize, FileAttributes, ShareAccess,
            CreateDisposition, CreateOptions, EaBuffer, EaLength);
    }

    return STATUS_UNSUCCESSFUL;
}

//
// DPC callback: each CPU issues VMCALL to install EPT hook
//
static VOID
DpcEptHook(PKDPC Dpc, PVOID Ctx, PVOID A1, PVOID A2)
{
    UNREFERENCED_PARAMETER(Dpc);

    struct _EPT_HOOK_CTX {
        PVOID   target;
        PVOID   proxy;
        PVOID * origin;
        UINT64  caller_cr3;
        UINT32  hook_type;
        NTSTATUS result;
    } * ctx = (struct _EPT_HOOK_CTX *)Ctx;

    //
    // hv_vmcall_ex: rax = OPHION_VMCALL_ID
    //   rcx = VMCALL_EPT_HOOK
    //   rdx = target_function
    //   r8  = proxy_function
    //   r9  = &origin_function
    //   r10 = caller_cr3
    //   r11 = hook_type
    //   r12 = target_cr3 (0 = R0 hook)
    //   r13 = user_trampoline (NULL = kernel pool)
    //   r14 = user_trampoline_pa (0)
    //
    ctx->result = hv_vmcall_ex(
        VMCALL_EPT_HOOK,
        (UINT64)ctx->target,
        (UINT64)ctx->proxy,
        (UINT64)ctx->origin,
        ctx->caller_cr3,
        (UINT64)ctx->hook_type,
        0,   // target_cr3 = 0 (R0 hook, all processes)
        0,   // user_trampoline = NULL (use kernel pool)
        0,   // user_trampoline_pa = 0
        0);

    KeSignalCallDpcSynchronize(A2);
    KeSignalCallDpcDone(A1);
}

static VOID
DpcEptUnhook(PKDPC Dpc, PVOID Ctx, PVOID A1, PVOID A2)
{
    UNREFERENCED_PARAMETER(Dpc);

    struct _EPT_UNHOOK_CTX {
        PVOID    target;
        UINT64   caller_cr3;
        NTSTATUS result;
    } * ctx = (struct _EPT_UNHOOK_CTX *)Ctx;

    ctx->result = hv_vmcall_ex(
        VMCALL_EPT_UNHOOK,
        (UINT64)ctx->target,
        0, 0,
        ctx->caller_cr3,
        0, 0, 0, 0, 0);

    KeSignalCallDpcSynchronize(A2);
    KeSignalCallDpcDone(A1);
}

// DPC broadcast for VMCALL_EPT_UNHOOK_BY_CR3. r10 (caller_cr3) = 0, so the HV
// does NOT __writecr3 -> safe to issue from the process-exit notify callback
// (where loading the dying CR3 on every CPU deadlocks). rdx = target_cr3,
// used only as a match value to retire this process's hooks.
static VOID
DpcEptUnhookByCr3(PKDPC Dpc, PVOID Ctx, PVOID A1, PVOID A2)
{
    UNREFERENCED_PARAMETER(Dpc);

    struct _EPT_UNHOOK_BY_CR3_CTX {
        UINT64 target_cr3;
    } * ctx = (struct _EPT_UNHOOK_BY_CR3_CTX *)Ctx;

    hv_vmcall_ex(
        VMCALL_EPT_UNHOOK_BY_CR3,
        ctx->target_cr3,
        0, 0, 0,
        0, 0, 0, 0, 0);

    KeSignalCallDpcSynchronize(A2);
    KeSignalCallDpcDone(A1);
}

static NTSTATUS
TdEptHookNtCreateFile(VOID)
{
    UNICODE_STRING fn_name;
    RtlInitUnicodeString(&fn_name, L"NtCreateFile");
    PVOID target = MmGetSystemRoutineAddress(&fn_name);
    if (!target)
    {
        HYPERPLATFORM_LOG_ERROR("[td] NtCreateFile not found");
        return STATUS_NOT_FOUND;
    }

    HYPERPLATFORM_LOG_INFO("[td] NtCreateFile = %p, proxy = %p", target, (PVOID)HookedNtCreateFile);

    struct {
        PVOID   target;
        PVOID   proxy;
        PVOID * origin;
        UINT64  caller_cr3;
        UINT32  hook_type;
        NTSTATUS result;
    } ctx = {};

    ctx.target     = target;
    ctx.proxy      = (PVOID)HookedNtCreateFile;
    ctx.origin     = (PVOID *)&g_orig_NtCreateFile;
    ctx.caller_cr3 = __readcr3();
    ctx.hook_type  = 0;   // absolute jump (14 bytes)

    KeGenericCallDpc(DpcEptHook, &ctx);

    if (NT_SUCCESS(ctx.result))
    {
        g_hooked_target = target;
        HYPERPLATFORM_LOG_INFO("[td] EPT hook installed! trampoline = %p", (PVOID)g_orig_NtCreateFile);
    }
    else
    {
        HYPERPLATFORM_LOG_ERROR("[td] EPT hook FAILED: 0x%08X", ctx.result);
    }

    return ctx.result;
}

static NTSTATUS
TdEptUnhookNtCreateFile(VOID)
{
    if (!g_hooked_target)
        return STATUS_NOT_FOUND;

    struct {
        PVOID    target;
        UINT64   caller_cr3;
        NTSTATUS result;
    } ctx = {};

    ctx.target     = g_hooked_target;
    ctx.caller_cr3 = __readcr3();

    KeGenericCallDpc(DpcEptUnhook, &ctx);

    if (NT_SUCCESS(ctx.result))
    {
        HYPERPLATFORM_LOG_INFO("[td] EPT hook removed. total calls logged: %d", g_hook_log_count);
        g_hooked_target = NULL;
        g_orig_NtCreateFile = NULL;
        g_hook_log_count = 0;
    }
    else
    {
        HYPERPLATFORM_LOG_ERROR("[td] EPT unhook FAILED: 0x%08X", ctx.result);
    }

    return ctx.result;
}

// =========================================================================
//  R3 EPT Hook 鈥?per-process, user-mode trampoline, MDL-locked
// =========================================================================

//
// tracking for active R3 hooks (simple array, max 16 concurrent R3 hooks)
//
#define MAX_R3_HOOKS 16

typedef struct _R3_HOOK_ENTRY {
    BOOLEAN     active;
    UINT64      target_pid;
    PVOID       target_va;
    PVOID       trampoline_va;      // R3 VA in target process
    SIZE_T      trampoline_size;
    PMDL        target_mdl;         // locks target page in physical memory
    UINT64      target_cr3;         // target process CR3 (PFN only)
} R3_HOOK_ENTRY;

static R3_HOOK_ENTRY g_r3_hooks[MAX_R3_HOOKS] = {};

static R3_HOOK_ENTRY *
R3HookFindFree(VOID)
{
    for (int i = 0; i < MAX_R3_HOOKS; i++)
        if (!g_r3_hooks[i].active) return &g_r3_hooks[i];
    return NULL;
}

static R3_HOOK_ENTRY *
R3HookFind(UINT64 pid, PVOID target_va)
{
    for (int i = 0; i < MAX_R3_HOOKS; i++)
        if (g_r3_hooks[i].active && g_r3_hooks[i].target_pid == pid &&
            g_r3_hooks[i].target_va == target_va)
            return &g_r3_hooks[i];
    return NULL;
}

//
// DPC callback for R3 EPT hook install
//
typedef struct _R3_HOOK_DPC_CTX {
    PVOID    target;
    PVOID    proxy;
    PVOID *  origin;
    UINT64   caller_cr3;
    UINT32   hook_type;
    UINT64   target_cr3;
    PVOID    user_trampoline;
    UINT64   user_trampoline_pa;
    UINT64   flags;             // bit 0 = force_read_access (shellcode self-read)
    UINT64   expected_tid;      // 0 = any thread
    NTSTATUS result;
} R3_HOOK_DPC_CTX;

static VOID
DpcEptHookR3(PKDPC Dpc, PVOID Ctx, PVOID A1, PVOID A2)
{
    UNREFERENCED_PARAMETER(Dpc);
    R3_HOOK_DPC_CTX * ctx = (R3_HOOK_DPC_CTX *)Ctx;

    ctx->result = hv_vmcall_ex(
        VMCALL_EPT_HOOK,
        (UINT64)ctx->target,
        (UINT64)ctx->proxy,
        (UINT64)ctx->origin,
        ctx->caller_cr3,
        (UINT64)ctx->hook_type | (ctx->flags << 32),
        ctx->target_cr3,
        (UINT64)ctx->user_trampoline,
        ctx->user_trampoline_pa,
        ctx->expected_tid);

    KeSignalCallDpcSynchronize(A2);
    KeSignalCallDpcDone(A1);
}

#ifndef TD_MAX_DPC_CPUS
#define TD_MAX_DPC_CPUS 64
#endif
#define TD_PERCPU_VMCALL_TAG 'cVdT'

typedef enum _TD_PERCPU_VMCALL_OP {
    TdPerCpuVmcallHookTrigger = 1,
    TdPerCpuVmcallUnhook      = 2,
} TD_PERCPU_VMCALL_OP;

typedef struct _TD_PERCPU_VMCALL_CTX {
    KEVENT                done_event;
    KDPC                  dpcs[TD_MAX_DPC_CPUS];
    TD_PERCPU_VMCALL_OP   op;
    volatile LONG         pending_count;
    volatile LONG         success_count;
    volatile LONG         failure_count;
    volatile LONG         first_failure;
    ULONG                 cpu_count;
    PVOID                 target;
    PVOID                 proxy;
    PVOID *               origin;
    UINT64                caller_cr3;
    UINT32                hook_type;
    UINT64                target_cr3;
    PVOID                 user_trampoline;
    UINT64                user_trampoline_pa;
    UINT64                flags;
    UINT64                expected_tid;
} TD_PERCPU_VMCALL_CTX;

static VOID
TdPerCpuVmcallDpc(PKDPC Dpc, PVOID Ctx, PVOID, PVOID)
{
    UNREFERENCED_PARAMETER(Dpc);
    TD_PERCPU_VMCALL_CTX * ctx = (TD_PERCPU_VMCALL_CTX *)Ctx;
    NTSTATUS st = STATUS_INVALID_DEVICE_REQUEST;

    if (ctx->op == TdPerCpuVmcallHookTrigger)
    {
        st = hv_vmcall_ex(
            VMCALL_EPT_HOOK,
            (UINT64)ctx->target,
            (UINT64)ctx->proxy,
            (UINT64)ctx->origin,
            ctx->caller_cr3,
            (UINT64)ctx->hook_type | (ctx->flags << 32),  // r11 = hook_type(low32) | flags(high32)
            ctx->target_cr3,                        // r12 = target_cr3
            (UINT64)ctx->user_trampoline,           // r13 = user_trampoline
            ctx->user_trampoline_pa,                // r14 = user_trampoline_pa
            ctx->expected_tid);                     // r15 = expected_tid (full 64-bit)
    }
    else if (ctx->op == TdPerCpuVmcallUnhook)
    {
        st = hv_vmcall_ex(
            VMCALL_EPT_UNHOOK,
            (UINT64)ctx->target,
            0, 0,
            ctx->caller_cr3,
            0, 0, 0, 0, 0);
    }

    if (NT_SUCCESS(st))
    {
        _InterlockedIncrement(&ctx->success_count);
    }
    else
    {
        _InterlockedIncrement(&ctx->failure_count);
        _InterlockedCompareExchange(&ctx->first_failure, (LONG)st, (LONG)STATUS_SUCCESS);
    }

    if (_InterlockedDecrement(&ctx->pending_count) == 0)
        KeSetEvent(&ctx->done_event, IO_NO_INCREMENT, FALSE);
}

static NTSTATUS
TdRunPerCpuVmcall(TD_PERCPU_VMCALL_CTX * ctx, ULONG timeout_ms)
{
    ULONG active_count = KeQueryActiveProcessorCount(NULL);
    if (active_count == 0)
        return STATUS_UNSUCCESSFUL;
    if (active_count > TD_MAX_DPC_CPUS)
        active_count = TD_MAX_DPC_CPUS;

    ctx->cpu_count = active_count;
    ctx->pending_count = (LONG)active_count;
    ctx->first_failure = STATUS_SUCCESS;
    KeInitializeEvent(&ctx->done_event, NotificationEvent, FALSE);

    for (ULONG cpu = 0; cpu < active_count; cpu++)
    {
        KeInitializeDpc(&ctx->dpcs[cpu], TdPerCpuVmcallDpc, ctx);
        KeSetTargetProcessorDpc(&ctx->dpcs[cpu], (CCHAR)cpu);
        if (!KeInsertQueueDpc(&ctx->dpcs[cpu], NULL, NULL))
        {
            _InterlockedIncrement(&ctx->failure_count);
            _InterlockedCompareExchange(&ctx->first_failure, (LONG)STATUS_UNSUCCESSFUL, (LONG)STATUS_SUCCESS);
            if (_InterlockedDecrement(&ctx->pending_count) == 0)
                KeSetEvent(&ctx->done_event, IO_NO_INCREMENT, FALSE);
        }
    }

    LARGE_INTEGER timeout;
    timeout.QuadPart = -((LONGLONG)timeout_ms * 10000LL);
    NTSTATUS wait_st = KeWaitForSingleObject(
        &ctx->done_event,
        Executive,
        KernelMode,
        FALSE,
        &timeout);

    if (wait_st == STATUS_TIMEOUT)
    {
        HYPERPLATFORM_LOG_ERROR("[td-rw] per-cpu vmcall timeout: op=%u done=%d/%u fail=%d",
            (UINT32)ctx->op,
            (LONG)(ctx->cpu_count - ctx->pending_count),
            ctx->cpu_count,
            ctx->failure_count);
        return STATUS_IO_TIMEOUT;
    }

    if (ctx->failure_count != 0)
        return (NTSTATUS)ctx->first_failure;
    return (ctx->success_count != 0) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

static NTSTATUS
TdInstallTriggerHookAllCpus(
    PVOID   trigger_fn,
    PVOID   proxy_va,
    UINT64  caller_cr3,
    UINT64  flags,
    UINT64  expected_tid,
    PVOID * origin,
    volatile LONG * fired_signal)
{
    TD_PERCPU_VMCALL_CTX * ctx = (TD_PERCPU_VMCALL_CTX *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(TD_PERCPU_VMCALL_CTX), TD_PERCPU_VMCALL_TAG);
    if (!ctx)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(ctx, sizeof(*ctx));
    ctx->op         = TdPerCpuVmcallHookTrigger;
    ctx->target     = trigger_fn;
    ctx->proxy      = proxy_va;
    ctx->origin     = origin;
    ctx->caller_cr3 = caller_cr3;
    ctx->hook_type  = 1;          // VMCALL (0F 01 C1)
    ctx->target_cr3 = caller_cr3; // per-process filter
    ctx->flags      = (flags ? flags : 2);
    ctx->expected_tid = expected_tid;

    NTSTATUS st = TdRunPerCpuVmcall(ctx, 2000);
    if (st != STATUS_IO_TIMEOUT)
        ExFreePoolWithTag(ctx, TD_PERCPU_VMCALL_TAG);

    if (NT_SUCCESS(st) && fired_signal)
    {
        NTSTATUS fired_st = hv_vmcall_ex(
            VMCALL_EPT_SET_EXTERNAL_FIRED,
            (UINT64)trigger_fn,
            (UINT64)fired_signal,
            caller_cr3,
            0, 0, 0, 0, 0, 0);
        if (!NT_SUCCESS(fired_st))
        {
            HYPERPLATFORM_LOG_ERROR("[td] TdInstallTriggerHookAllCpus: "
                "VMCALL_EPT_SET_EXTERNAL_FIRED failed for trigger=%p st=0x%08X",
                trigger_fn, fired_st);
        }
    }
    return st;
}

static NTSTATUS
TdUnhookTriggerAllCpus(PVOID trigger_fn, UINT64 caller_cr3)
{
    TD_PERCPU_VMCALL_CTX * ctx = (TD_PERCPU_VMCALL_CTX *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(TD_PERCPU_VMCALL_CTX), TD_PERCPU_VMCALL_TAG);
    if (!ctx)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(ctx, sizeof(*ctx));
    ctx->op         = TdPerCpuVmcallUnhook;
    ctx->target     = trigger_fn;
    ctx->caller_cr3 = caller_cr3;

    NTSTATUS st = TdRunPerCpuVmcall(ctx, 1000);
    if (st != STATUS_IO_TIMEOUT)
        ExFreePoolWithTag(ctx, TD_PERCPU_VMCALL_TAG);
    return st;
}

//
// install R3 EPT hook on a function in a target process.
// must be called at PASSIVE_LEVEL.
//
static NTSTATUS
TdEptHookR3(
    UINT64  target_pid,
    PVOID   target_va,
    PVOID   proxy_va,
    UINT32  hook_type,
    PVOID * out_trampoline)
{
    if (!target_va) return STATUS_INVALID_PARAMETER;

    R3_HOOK_ENTRY * entry = R3HookFindFree();
    if (!entry)
    {
        HYPERPLATFORM_LOG_ERROR("[td-r3] no free R3 hook slots");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // look up target process
    PEPROCESS proc = NULL;
    NTSTATUS st = PsLookupProcessByProcessId((HANDLE)target_pid, &proc);
    if (!NT_SUCCESS(st)) return st;

    KAPC_STATE apc;
    KeStackAttachProcess(proc, &apc);

    UINT64 target_cr3 = __readcr3();
    UINT64 caller_cr3 = target_cr3;

    //
    // 1. lock target page in physical memory via MDL
    //
    PVOID page_va = (PVOID)((UINT64)target_va & ~0xFFFULL);
    PMDL mdl = IoAllocateMdl(page_va, PAGE_SIZE, FALSE, FALSE, NULL);
    if (!mdl)
    {
        KeUnstackDetachProcess(&apc);
        ObDereferenceObject(proc);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {
        MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(mdl);
        KeUnstackDetachProcess(&apc);
        ObDereferenceObject(proc);
        HYPERPLATFORM_LOG_ERROR("[td-r3] MmProbeAndLockPages failed for %p", target_va);
        return STATUS_ACCESS_VIOLATION;
    }

    //
    // 2. allocate R3 trampoline in target process as PAGE_READWRITE (NX=1).
    // Stealth: no executable memory in the real PTE. The trampoline is made
    // executable only in the shadow CR3 (step 2.5 below), so scanners reading
    // the real CR3 see a non-executable private page. The proxy calls it under
    // the shadow CR3.
    //
    PVOID tramp_va = NULL;
    SIZE_T tramp_size = PAGE_SIZE;
    st = ZwAllocateVirtualMemory(
        ZwCurrentProcess(), &tramp_va, 0, &tramp_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!NT_SUCCESS(st) || !tramp_va)
    {
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        KeUnstackDetachProcess(&apc);
        ObDereferenceObject(proc);
        HYPERPLATFORM_LOG_ERROR("[td-r3] trampoline alloc failed: 0x%08X", st);
        return st;
    }

    RtlZeroMemory(tramp_va, tramp_size);
    UINT64 tramp_pa = MmGetPhysicalAddress(tramp_va).QuadPart;

    HYPERPLATFORM_LOG_INFO("[td-r3] target=%p proxy=%p tramp=%p(PA=%llx) cr3=%llx pid=%llu type=%u",
               target_va, proxy_va, tramp_va, tramp_pa, target_cr3, target_pid, hook_type);

    //
    // 2.5 shadow the trampoline page: clear NX in the process shadow CR3 so
    // the proxy can execute it, while the real PTE stays PAGE_READWRITE (NX=1)
    // for stealth. Done BEFORE the EPT-hook install so a shadow failure can
    // abort cleanly without leaving an installed hook. The HV writes the
    // trampoline content (saved bytes + jump) to the real page during the
    // VMCALL below; the shadow PTE aliases the same physical page, so the
    // content is visible under the shadow CR3.
    //
    {
        UINT64 existing_shadow = TdStealthFindShadowCr3ForPid(target_pid);
        UINT64 tramp_shadow = existing_shadow
            ? TdExtendShadowCR3(existing_shadow, caller_cr3, (UINT64)tramp_va, tramp_size)
            : TdBuildShadowCR3(caller_cr3, (UINT64)tramp_va, tramp_size);
        if (!tramp_shadow)
        {
            HYPERPLATFORM_LOG_ERROR("[td-r3] trampoline shadow CR3 failed (tramp=%p) - aborting hook",
                tramp_va);
            ZwFreeVirtualMemory(ZwCurrentProcess(), &tramp_va, &tramp_size, MEM_RELEASE);
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);
            KeUnstackDetachProcess(&apc);
            ObDereferenceObject(proc);
            return STATUS_UNSUCCESSFUL;
        }
        HYPERPLATFORM_LOG_INFO("[td-r3] trampoline shadowed: tramp=%p shadow=0x%llX (%s)",
            tramp_va, tramp_shadow, existing_shadow ? "extended" : "built");

        //
        // 2.6 register the trampoline as a stealth page (sp) so the HV #PF
        // handler (ept_stealth_handle_pf) activates the shadow CR3 window for
        // it. TdExtendShadowCR3/TdBuildShadowCR3 only fork the shadow PT and
        // clear NX on the shadow PTE -- they do NOT register an sp. The shadow
        // CR3 is per-instruction-on-demand, triggered by a #PF on a registered
        // sp (vmexit #PF -> ept_stealth_handle_pf -> sp match -> swap shadow
        // CR3 + MTF restore). Without an sp, the trampoline's NX-fetch #PF
        // (real PTE is PAGE_READWRITE, NX=1) is injected to the guest -> AV at
        // the trampoline (execute violation, op=8). The image pages work because
        // they go through TdStealthAllocPage (sp registered -> HV re-syncs the
        // shadow PTE via stealth_refresh_shadow_code_pte on #PF). Match that
        // here. no_ept_split=TRUE + shadow_cr3 -> TdResolveShadowPT computes
        // shadow_pte_va, which the HV writes (real_pte & ~NX) into on #PF.
        //
        {
            UINT64 pt_pfn = 0;
            UINT32 pt_idx = 0;
            if (!TdResolveGuestPT(caller_cr3, (UINT64)tramp_va, &pt_pfn, &pt_idx))
            {
                HYPERPLATFORM_LOG_ERROR(
                    "[td-r3] trampoline stealth PT resolve failed (tramp=%p) - aborting hook",
                    tramp_va);
                ZwFreeVirtualMemory(ZwCurrentProcess(), &tramp_va, &tramp_size, MEM_RELEASE);
                MmUnlockPages(mdl);
                IoFreeMdl(mdl);
                KeUnstackDetachProcess(&apc);
                ObDereferenceObject(proc);
                return STATUS_UNSUCCESSFUL;
            }
            NTSTATUS sp_st = TdStealthAllocPage(
                caller_cr3,
                (PVOID)((UINT64)tramp_va & ~0xFFFULL),
                tramp_pa,
                NULL, 0, TRUE,
                pt_pfn, pt_idx,
                FALSE, tramp_shadow, TRUE, FALSE);
            if (!NT_SUCCESS(sp_st))
            {
                HYPERPLATFORM_LOG_ERROR(
                    "[td-r3] trampoline stealth page register failed (tramp=%p st=0x%08X) - aborting hook",
                    tramp_va, sp_st);
                ZwFreeVirtualMemory(ZwCurrentProcess(), &tramp_va, &tramp_size, MEM_RELEASE);
                MmUnlockPages(mdl);
                IoFreeMdl(mdl);
                KeUnstackDetachProcess(&apc);
                ObDereferenceObject(proc);
                return STATUS_UNSUCCESSFUL;
            }
            HYPERPLATFORM_LOG_INFO(
                "[td-r3] trampoline stealth page registered: tramp=%p shadow=0x%llX",
                tramp_va, tramp_shadow);
        }
    }

    //
    // 3. DPC broadcast VMCALL to install hook on all CPUs
    //
    PVOID origin_ptr = NULL;

    R3_HOOK_DPC_CTX ctx = {};
    ctx.target              = target_va;
    ctx.proxy               = proxy_va;
    ctx.origin              = &origin_ptr;
    ctx.caller_cr3          = caller_cr3;
    ctx.hook_type           = hook_type;
    ctx.target_cr3          = target_cr3;
    ctx.user_trampoline     = tramp_va;
    ctx.user_trampoline_pa  = tramp_pa;

    KeGenericCallDpc(DpcEptHookR3, &ctx);

    KeUnstackDetachProcess(&apc);

    if (NT_SUCCESS(ctx.result))
    {
        entry->active           = TRUE;
        entry->target_pid       = target_pid;
        entry->target_va        = target_va;
        entry->trampoline_va    = tramp_va;
        entry->trampoline_size  = tramp_size;
        entry->target_mdl       = mdl;
        entry->target_cr3       = target_cr3;

        if (out_trampoline)
            *out_trampoline = origin_ptr;

        HYPERPLATFORM_LOG_INFO("[td-r3] R3 EPT hook installed! trampoline=%p", origin_ptr);
    }
    else
    {
        //
        // failed 鈥?clean up: free trampoline, unlock MDL
        //
        KeStackAttachProcess(proc, &apc);
        ZwFreeVirtualMemory(ZwCurrentProcess(), &tramp_va, &tramp_size, MEM_RELEASE);
        KeUnstackDetachProcess(&apc);

        MmUnlockPages(mdl);
        IoFreeMdl(mdl);

        HYPERPLATFORM_LOG_ERROR("[td-r3] R3 EPT hook FAILED: 0x%08X", ctx.result);
    }

    ObDereferenceObject(proc);
    return ctx.result;
}

//
// remove R3 EPT hook and clean up resources
//
static NTSTATUS
TdEptUnhookR3(UINT64 target_pid, PVOID target_va)
{
    R3_HOOK_ENTRY * entry = R3HookFind(target_pid, target_va);
    if (!entry)
    {
        HYPERPLATFORM_LOG_WARN("[td-r3] hook entry not found for pid=%llu va=%p", target_pid, target_va);
        return STATUS_NOT_FOUND;
    }

    //
    // 1. unhook via VMCALL (DPC broadcast)
    //
    PEPROCESS proc = NULL;
    NTSTATUS st = PsLookupProcessByProcessId((HANDLE)target_pid, &proc);
    if (!NT_SUCCESS(st)) return st;

    KAPC_STATE apc;
    KeStackAttachProcess(proc, &apc);

    struct {
        PVOID    target;
        UINT64   caller_cr3;
        NTSTATUS result;
    } unhook_ctx = {};
    unhook_ctx.target     = target_va;
    unhook_ctx.caller_cr3 = __readcr3();

    KeGenericCallDpc(DpcEptUnhook, &unhook_ctx);

    //
    // 2. free trampoline stealth page, then trampoline memory in target process
    //
    if (entry->trampoline_va)
    {
        // TdEptHookR3 registered the trampoline as a stealth page (target_pid=0,
        // so it is NOT in g_stealth_tracks). Free it here, otherwise the sp leaks
        // in g_ept->stealth_pages holding a reference to this process's
        // (soon-freed) shadow CR3. Must run while the trampoline page is still
        // mapped, i.e. before ZwFreeVirtualMemory.
        TdStealthFreePage((PVOID)((UINT64)entry->trampoline_va & ~0xFFFULL));

        SIZE_T sz = entry->trampoline_size;
        ZwFreeVirtualMemory(ZwCurrentProcess(), &entry->trampoline_va, &sz, MEM_RELEASE);
    }

    KeUnstackDetachProcess(&apc);

    //
    // 3. unlock MDL
    //
    if (entry->target_mdl)
    {
        MmUnlockPages(entry->target_mdl);
        IoFreeMdl(entry->target_mdl);
    }

    HYPERPLATFORM_LOG_INFO("[td-r3] R3 hook removed: pid=%llu va=%p", target_pid, target_va);

    RtlZeroMemory(entry, sizeof(*entry));
    ObDereferenceObject(proc);
    return unhook_ctx.result;
}

//
// unhook all active R3 hooks (called from unload)
//
static VOID
TdEptUnhookAllR3(VOID)
{
    for (int i = 0; i < MAX_R3_HOOKS; i++)
    {
        if (!g_r3_hooks[i].active) continue;

        //
        // for inject hooks (target_mdl == NULL): the target process may have
        // already exited. don't attach 鈥?just VMCALL unhook by VA + clear entry.
        // EPT unhook only needs the VA to find the PFN in the hooked_pages list.
        // the VMCALL runs under system CR3, which is fine for EPT-only operations.
        //
        // for real R3 hooks (target_mdl != NULL): use the full unhook path.
        //
        if (g_r3_hooks[i].target_mdl == NULL)
        {
            // inject hook 鈥?lightweight unhook (no attach needed)
            PEPROCESS proc = NULL;
            NTSTATUS st = PsLookupProcessByProcessId(
                (HANDLE)g_r3_hooks[i].target_pid, &proc);

            if (NT_SUCCESS(st))
            {
                // process still alive 鈥?attach to resolve VA 鈫?PA for unhook
                KAPC_STATE apc;
                KeStackAttachProcess(proc, &apc);

                struct { PVOID target; UINT64 caller_cr3; NTSTATUS result; } ctx = {};
                ctx.target     = g_r3_hooks[i].target_va;
                ctx.caller_cr3 = __readcr3();
                KeGenericCallDpc(DpcEptUnhook, &ctx);

                KeUnstackDetachProcess(&apc);
                ObDereferenceObject(proc);
            }
            // else: process dead 鈥?EPT pages are orphaned but harmless.
            // the PFN won't be reused for anything meaningful until
            // ept_unhook_all() on HV unload restores all PTEs to RWX.

            RtlZeroMemory(&g_r3_hooks[i], sizeof(g_r3_hooks[i]));
        }
        else
        {
            // real R3 hook 鈥?full cleanup
            TdEptUnhookR3(g_r3_hooks[i].target_pid, g_r3_hooks[i].target_va);
        }
    }
}

// =========================================================================
//  thread creation
// =========================================================================

static NTSTATUS
TdCreateThread(PEPROCESS process, PVOID entry)
{
    //
    // try function pointer (resolved at init), fallback to manual syscall stub
    //
    if (g_pZwCreateThreadEx)
    {
        HANDLE proc_h = NULL;
        NTSTATUS st = ObOpenObjectByPointer(
            process, OBJ_KERNEL_HANDLE, NULL,
            PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &proc_h);
        if (!NT_SUCCESS(st)) return st;

        //
        // create thread NOT suspended 鈥?runs immediately.
        // all CPUs have EPT split (DPC broadcast), no affinity pinning needed.
        // NtResumeThread/ZwResumeThread may not be exported by ntoskrnl,
        // so avoid suspend+resume pattern entirely.
        //
        HANDLE thread_h = NULL;
        st = g_pZwCreateThreadEx(
            &thread_h, THREAD_ALL_ACCESS, NULL, proc_h,
            entry, NULL,
            0,      // flags = 0: not suspended
            0, 0, 0, NULL);

        if (NT_SUCCESS(st) && thread_h)
            ZwClose(thread_h);
        ZwClose(proc_h);
        return st;
    }

    //
    // fallback: attach to process, use RtlCreateUserThread
    // create SUSPENDED 鈫?pin to install CPU 鈫?resume
    //
    KAPC_STATE apc;
    KeStackAttachProcess(process, &apc);

    HANDLE thread_h = NULL;
    CLIENT_ID cid = {};
    //
    // pin CURRENT kernel thread to install CPU first.
    // then create user thread (not suspended) 鈥?it inherits scheduling
    // affinity from the current processor context.
    //
    ULONG cpu = KeGetCurrentProcessorNumberEx(NULL);
    KAFFINITY old_affinity = KeSetSystemAffinityThreadEx((KAFFINITY)1 << cpu);

    NTSTATUS st = RtlCreateUserThread(
        ZwCurrentProcess(),
        NULL, FALSE, 0, 0, 0,
        entry, NULL, &thread_h, &cid);

    KeRevertToUserAffinityThreadEx(old_affinity);
    KeUnstackDetachProcess(&apc);

    if (NT_SUCCESS(st) && thread_h)
    {
        // also set the thread's own affinity to install CPU
        KAFFINITY mask = (KAFFINITY)1 << cpu;
        ZwSetInformationThread(thread_h, ThreadAffinityMask, &mask, sizeof(mask));
        ZwClose(thread_h);
    }

    return st;
}

// =========================================================================
//  IOCTL handler
// =========================================================================

static NTSTATUS TdCreateClose(PDEVICE_OBJECT, PIRP irp)
{
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// =========================================================================
//  DLL gap finder 鈥?find unused page-aligned gap in an image's VA range.
//
//  walks PE section headers to find alignment padding between sections
//  or after the last section. returns a committed page of zeros that
//  belongs to the DLL's VAD (MEM_IMAGE). no new allocation, no new VAD.
//
//  MUST be called while attached to the target process.
// =========================================================================

//
// find section tail padding in a DLL 鈥?unused zero bytes at the end of
// a section's last page. no full-page gap needed.
//
// returns page-aligned VA of the page containing padding.
// *out_offset = offset within page where padding starts (shellcode goes here).
// *out_avail  = available bytes from offset to end of page.
//
static PVOID
TdFindSectionPadding(PVOID image_base, SIZE_T min_size, ULONG * out_offset, ULONG * out_avail)
{
    PIMAGE_DOS_HEADER       dos;
    PIMAGE_NT_HEADERS64     nt;
    PIMAGE_SECTION_HEADER   sections, best_sec;
    ULONG num_sections, i, sec_end_raw, page_offset, avail, best_avail;
    PVOID page_va;

    if (!image_base || !out_offset || !out_avail) return NULL;

    best_sec = NULL;
    best_avail = 0;

    __try {
        dos = (PIMAGE_DOS_HEADER)image_base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

        nt = (PIMAGE_NT_HEADERS64)((PUINT8)image_base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

        num_sections = nt->FileHeader.NumberOfSections;
        sections = IMAGE_FIRST_SECTION(nt);

        //
        // find section with most tail padding on its last page.
        // prefer executable sections (.text) 鈥?shellcode blends in better.
        //
        for (i = 0; i < num_sections; i++)
        {
            sec_end_raw = sections[i].VirtualAddress + sections[i].Misc.VirtualSize;
            page_offset = sec_end_raw & (PAGE_SIZE - 1);

            // skip if section ends exactly on page boundary (no padding)
            if (page_offset == 0) continue;

            avail = PAGE_SIZE - page_offset;
            if (avail < min_size) continue;

            // prefer executable section, or largest padding
            if (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
            {
                if (!best_sec || !(best_sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) ||
                    avail > best_avail)
                {
                    best_sec = &sections[i];
                    best_avail = avail;
                }
            }
            else if (!best_sec || (!(best_sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
                     avail > best_avail))
            {
                best_sec = &sections[i];
                best_avail = avail;
            }
        }

        if (best_sec)
        {
            sec_end_raw = best_sec->VirtualAddress + best_sec->Misc.VirtualSize;
            page_offset = sec_end_raw & (PAGE_SIZE - 1);
            page_va = (PUINT8)image_base + (sec_end_raw & ~(PAGE_SIZE - 1));

            *out_offset = page_offset;
            *out_avail  = PAGE_SIZE - page_offset;

            HYPERPLATFORM_LOG_INFO("[td-gap] section padding: page=%p offset=0x%X avail=0x%X (section %.8s)",
                       page_va, page_offset, *out_avail, best_sec->Name);
            return page_va;
        }

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        HYPERPLATFORM_LOG_WARN("[td-gap] exception walking PE headers");
    }

    return NULL;
}

//
// find a DLL gap in the target process. tries ntdll first (always loaded,
// large image), then kernel32. must be called while attached.
//
static PVOID
TdFindGapInProcess(SIZE_T min_size, ULONG * out_offset, ULONG * out_avail)
{
    PPEB peb;
    TD_PEB_LDR_DATA * ldr;
    PLIST_ENTRY head, cur;
    TD_LDR_ENTRY * e;
    PVOID gap;

    peb = PsGetProcessPeb(PsGetCurrentProcess());
    if (!peb) return NULL;

    __try {
        ldr = *(TD_PEB_LDR_DATA **)((PUINT8)peb + 0x18);
        if (!ldr) return NULL;

        head = &ldr->InMemoryOrderModuleList;

        // first pass: try ntdll.dll
        cur = head->Flink;
        while (cur != head)
        {
            e = CONTAINING_RECORD(cur, TD_LDR_ENTRY, InMemoryOrderLinks);
            if (e->BaseDllName.Buffer &&
                TdMatchDllName(e->BaseDllName.Buffer, e->BaseDllName.Length, g_ntdll_name, 9))
            {
                gap = TdFindSectionPadding(e->DllBase, min_size, out_offset, out_avail);
                if (gap) return gap;
                break;
            }
            cur = cur->Flink;
        }

        // second pass: try kernel32.dll
        cur = head->Flink;
        while (cur != head)
        {
            e = CONTAINING_RECORD(cur, TD_LDR_ENTRY, InMemoryOrderLinks);
            if (e->BaseDllName.Buffer &&
                TdMatchDllName(e->BaseDllName.Buffer, e->BaseDllName.Length, g_k32_name, 12))
            {
                gap = TdFindSectionPadding(e->DllBase, min_size, out_offset, out_avail);
                if (gap) return gap;
                break;
            }
            cur = cur->Flink;
        }

        // third pass: any DLL with a gap
        cur = head->Flink;
        while (cur != head)
        {
            e = CONTAINING_RECORD(cur, TD_LDR_ENTRY, InMemoryOrderLinks);
            if (e->DllBase && e->SizeOfImage > PAGE_SIZE)
            {
                gap = TdFindSectionPadding(e->DllBase, min_size, out_offset, out_avail);
                if (gap) return gap;
            }
            cur = cur->Flink;
        }

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        HYPERPLATFORM_LOG_WARN("[td-gap] exception walking PEB");
    }

    return NULL;
}

// =========================================================================
//  PE Manual Mapper 鈥?kernel-side DLL loading, zero R3 API calls
//
//  flow:
//    1. injector reads DLL file 鈫?sends raw bytes via IOCTL_INJECT_DLL
//    2. driver attaches to target process
//    3. ZwAllocateVirtualMemory(PAGE_READWRITE) for image
//    4. copy sections, apply relocations, resolve imports (PEB walk)
//    5. build DllMain stub at image base (overwrites DOS header)
//    6. clear PE signature from header
//    7. ZwProtectVirtualMemory 鈫?PAGE_EXECUTE_READ for executable sections
//    8. EPT hook NtTestAlert 鈫?DllMain stub (oneshot, per-process CR3 filter)
//    9. create thread at NtTestAlert 鈫?DllMain runs 鈫?thread exits
//
//  result: DLL is loaded without LoadLibrary, no module list entry,
//  no load image notification, no file access from target process.
// =========================================================================

#define IOCTL_INJECT_DLL CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 5, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INJECT_RW  CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INJECT_RW_SHADOW CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ALLOC_SHADOW_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 8, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INSTALL_TRIGGER_JUMP CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 9, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FREE_SHADOW_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 10, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SHADOW_PROTECT_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 11, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define TD_MAX_INJECT_RW_SIZE (16ULL * 1024ULL * 1024ULL)

#pragma pack(push, 8)
typedef struct _TD_INJECT_RW_PARAMS {
    UINT64 target_pid;
    UINT64 trigger_va;      // [in]  R3 function to hook as trigger (0 = auto)
    UINT64 shellcode_va;    // [out] allocated VA
    UINT64 alloc_size;      // [out] allocated size
    UINT64 shellcode_size;  // [in] bytes appended after this struct
    UINT64 alloc_protect;   // [in] PAGE_READWRITE/PAGE_WRITECOPY, 0 = PAGE_READWRITE
} TD_INJECT_RW_PARAMS;

typedef struct _TD_ALLOC_SHADOW_MEMORY_PARAMS {
    UINT64 target_pid;      // [in]
    UINT64 size;            // [in/out] requested size, rounded to page size on success
    UINT64 need_execute;    // [in] 0=plain RW allocation, nonzero=shadow CR3 executable view
    UINT64 alloc_protect;   // [in] PAGE_READWRITE/PAGE_WRITECOPY, 0 = PAGE_READWRITE
    UINT64 base_va;         // [out]
    UINT64 shadow_cr3;      // [out] physical address of shadow PML4, 0 for plain RW
    UINT64 status;          // [out] NTSTATUS
} TD_ALLOC_SHADOW_MEMORY_PARAMS;

typedef struct _TD_SHADOW_PROTECT_PARAMS {
    UINT64 target_pid;      // [in]
    UINT64 base_va;         // [in]
    UINT64 size;            // [in/out] requested size, rounded to page size on success
    UINT64 new_protect;     // [in] PAGE_READONLY/PAGE_READWRITE/PAGE_EXECUTE*
    UINT64 old_protect;     // [out] previous shadow view protect, or real PTE protect
    UINT64 shadow_cr3;      // [out] active shadow CR3, 0 if restored to original view
    UINT64 status;          // [out] NTSTATUS
} TD_SHADOW_PROTECT_PARAMS;

typedef struct _TD_TRIGGER_JUMP_PARAMS {
    UINT64 target_pid;      // [in]
    UINT64 trigger_va;      // [in/out] 0 = auto ntdll trigger
    UINT64 jump_to_va;      // [in] destination RIP for VMCALL hook
    UINT64 flags;           // [in] bit1=oneshot, 0 uses default oneshot
    UINT64 target_tid;      // [in] 0 = any thread, non-0 = only this TID
    UINT64 status;          // [out] NTSTATUS
} TD_TRIGGER_JUMP_PARAMS;
#pragma pack(pop)

#pragma pack(push, 8)
typedef struct _TD_INJECT_DLL_PARAMS {
    UINT64 target_pid;
    UINT32 dll_offset;     // offset of DLL data within this buffer (after header)
    UINT32 dll_size;       // size of raw DLL file
    UINT64 out_base;       // [out] mapped image base
    UINT64 out_entry;      // [out] DllMain VA
    UINT64 out_size;       // [out] image size
} TD_INJECT_DLL_PARAMS;
#pragma pack(pop)

//
// inline case-insensitive ASCII compare (kernel-safe, no runtime dependency)
//
static __forceinline BOOLEAN
TdAsciiEqualI(const char * a, const char * b)
{
    while (*a && *b)
    {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return FALSE;
        a++; b++;
    }
    return (*a == *b);
}

static __forceinline BOOLEAN
TdAsciiEqualIBounded(const char * a, const char * b, ULONG max_len)
{
    for (ULONG i = 0; i < max_len; i++)
    {
        char ca = a[i], cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return FALSE;
        if (!ca) return TRUE;
    }
    return FALSE;
}

static __forceinline BOOLEAN
TdAsciiStartsWithI(const char * text, const char * prefix)
{
    while (*prefix)
    {
        char ca = *text, cb = *prefix;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return FALSE;
        text++;
        prefix++;
    }
    return TRUE;
}

//
// TdFindModuleBaseA 鈥?find loaded module by ASCII name via PEB walk.
// walks PEB 鈫?Ldr 鈫?InMemoryOrderModuleList. compares BaseDllName
// (Unicode) with the given ASCII name (case-insensitive).
// must be called while attached to the target process.
//
static PVOID
TdFindModuleBaseA(const char * name_ascii, ULONG * out_size)
{
    if (out_size)
        *out_size = 0;

    PPEB peb = PsGetProcessPeb(PsGetCurrentProcess());
    if (!peb) return NULL;

    // compute length of ASCII name
    USHORT name_len = 0;
    const char * p = name_ascii;
    while (*p) { name_len++; p++; }

    // check if name has ".dll" extension already
    BOOLEAN has_ext = FALSE;
    if (name_len >= 4)
    {
        const char * ext = name_ascii + name_len - 4;
        if ((ext[0] == '.') &&
            (ext[1] == 'd' || ext[1] == 'D') &&
            (ext[2] == 'l' || ext[2] == 'L') &&
            (ext[3] == 'l' || ext[3] == 'L'))
            has_ext = TRUE;
    }

    __try {
        TD_PEB_LDR_DATA * ldr = *(TD_PEB_LDR_DATA **)((PUINT8)peb + 0x18);
        if (!ldr) return NULL;

        PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
        PLIST_ENTRY cur = head->Flink;
        ULONG seen = 0;

        while (cur != head && seen++ < 512)
        {
            TD_LDR_ENTRY * e = CONTAINING_RECORD(cur, TD_LDR_ENTRY, InMemoryOrderLinks);
            if (e->BaseDllName.Buffer && e->BaseDllName.Length > 0)
            {
                USHORT wchar_count = e->BaseDllName.Length / sizeof(WCHAR);
                const WCHAR * wbuf = e->BaseDllName.Buffer;

                // compare Unicode BaseDllName with ASCII name
                BOOLEAN match = FALSE;

                if (has_ext)
                {
                    // exact match (with extension)
                    if (wchar_count == name_len)
                    {
                        match = TRUE;
                        for (USHORT i = 0; i < name_len; i++)
                        {
                            WCHAR wc = wbuf[i];
                            if (wc >= L'A' && wc <= L'Z') wc += 32;
                            char ac = name_ascii[i];
                            if (ac >= 'A' && ac <= 'Z') ac += 32;
                            if (wc != (WCHAR)ac) { match = FALSE; break; }
                        }
                    }
                }
                else
                {
                    // match without extension: BaseDllName could be "foo.dll"
                    // name_ascii is "foo" 鈥?compare first name_len chars,
                    // then check remaining is ".dll"
                    if (wchar_count == name_len + 4)
                    {
                        match = TRUE;
                        for (USHORT i = 0; i < name_len; i++)
                        {
                            WCHAR wc = wbuf[i];
                            if (wc >= L'A' && wc <= L'Z') wc += 32;
                            char ac = name_ascii[i];
                            if (ac >= 'A' && ac <= 'Z') ac += 32;
                            if (wc != (WCHAR)ac) { match = FALSE; break; }
                        }
                        if (match)
                        {
                            WCHAR c0 = wbuf[name_len];
                            WCHAR c1 = wbuf[name_len + 1]; if (c1 >= L'A' && c1 <= L'Z') c1 += 32;
                            WCHAR c2 = wbuf[name_len + 2]; if (c2 >= L'A' && c2 <= L'Z') c2 += 32;
                            WCHAR c3 = wbuf[name_len + 3]; if (c3 >= L'A' && c3 <= L'Z') c3 += 32;
                            if (c0 != L'.' || c1 != L'd' || c2 != L'l' || c3 != L'l')
                                match = FALSE;
                        }
                    }
                    // also try exact match (no extension on module name)
                    if (!match && wchar_count == name_len)
                    {
                        match = TRUE;
                        for (USHORT i = 0; i < name_len; i++)
                        {
                            WCHAR wc = wbuf[i];
                            if (wc >= L'A' && wc <= L'Z') wc += 32;
                            char ac = name_ascii[i];
                            if (ac >= 'A' && ac <= 'Z') ac += 32;
                            if (wc != (WCHAR)ac) { match = FALSE; break; }
                        }
                    }
                }

                if (match && e->DllBase)
                {
                    if (out_size)
                        *out_size = e->SizeOfImage;
                    return e->DllBase;
                }
            }
            cur = cur->Flink;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        HYPERPLATFORM_LOG_WARN("[td-map] exception in TdFindModuleBaseA(\"%s\")", name_ascii);
    }

    return NULL;
}

//
// TdFindExportByName 鈥?find export by name from a module's export table.
// walks PE export directory. returns function VA. skips forwarded exports
// (returns NULL for forwards).
//
static PVOID
TdFindExportByNameEx(PVOID module_base, const char * func_name, ULONG depth)
{
    if (!module_base || !func_name) return NULL;
    if (depth > 4) return NULL;

    __try {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module_base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((PUINT8)module_base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

        ULONG exp_rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        ULONG exp_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        if (!exp_rva || exp_size < sizeof(IMAGE_EXPORT_DIRECTORY)) return NULL;
        if (exp_rva + exp_size < exp_rva) return NULL;

        PIMAGE_EXPORT_DIRECTORY exp_dir = (PIMAGE_EXPORT_DIRECTORY)((PUINT8)module_base + exp_rva);
        if (!exp_dir->NumberOfNames || !exp_dir->NumberOfFunctions ||
            exp_dir->NumberOfNames > 0x10000 ||
            exp_dir->NumberOfFunctions > 0x10000 ||
            !exp_dir->AddressOfNames || !exp_dir->AddressOfNameOrdinals ||
            !exp_dir->AddressOfFunctions)
            return NULL;

        PULONG  names = (PULONG)((PUINT8)module_base + exp_dir->AddressOfNames);
        PUSHORT ords  = (PUSHORT)((PUINT8)module_base + exp_dir->AddressOfNameOrdinals);
        PULONG  funcs = (PULONG)((PUINT8)module_base + exp_dir->AddressOfFunctions);

        for (ULONG i = 0; i < exp_dir->NumberOfNames; i++)
        {
            const char * fn = (const char *)((PUINT8)module_base + names[i]);
            if (TdAsciiEqualIBounded(fn, func_name, 256))
            {
                USHORT ord = ords[i];
                if (ord >= exp_dir->NumberOfFunctions)
                    return NULL;

                ULONG func_rva = funcs[ord];
                if (!func_rva)
                    return NULL;

                if (func_rva >= exp_rva && func_rva < exp_rva + exp_size)
                {
                    const char * fwd = (const char *)((PUINT8)module_base + func_rva);
                    const char * exp_end = (const char *)((PUINT8)module_base + exp_rva + exp_size);
                    char dll_name[128] = {};
                    char export_name[128] = {};
                    ULONG dll_len = 0;
                    ULONG export_len = 0;
                    BOOLEAN saw_dot = FALSE;
                    BOOLEAN saw_null = FALSE;

                    for (const char * p = fwd; p < exp_end && (ULONG)(p - fwd) < 255; p++)
                    {
                        char c = *p;
                        if (!c) { saw_null = TRUE; break; }

                        if (!saw_dot)
                        {
                            if (c == '.')
                            {
                                saw_dot = TRUE;
                                continue;
                            }
                            if (dll_len + 1 >= sizeof(dll_name))
                                return NULL;
                            dll_name[dll_len++] = c;
                        }
                        else
                        {
                            if (export_len + 1 >= sizeof(export_name))
                                return NULL;
                            export_name[export_len++] = c;
                        }
                    }

                    if (!saw_dot || !saw_null || !dll_len || !export_len)
                        return NULL;

                    PVOID forward_base = TdFindModuleBaseA(dll_name, NULL);
                    if (!forward_base &&
                        (TdAsciiStartsWithI(dll_name, "api-") ||
                         TdAsciiStartsWithI(dll_name, "ext-")))
                    {
                        forward_base = TdFindModuleBaseA("kernelbase.dll", NULL);
                    }
                    if (!forward_base)
                        return NULL;

                    return TdFindExportByNameEx(forward_base, export_name, depth + 1);
                }

                // check for forwarded export (RVA points inside export directory)
                if (func_rva >= exp_rva && func_rva < exp_rva + exp_size)
                    return NULL;  // forwarded 鈥?skip

                return (PUINT8)module_base + func_rva;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        HYPERPLATFORM_LOG_WARN("[td-map] exception in TdFindExportByName");
    }

    return NULL;
}

static PVOID
TdFindExportByName(PVOID module_base, const char * func_name)
{
    return TdFindExportByNameEx(module_base, func_name, 0);
}

static BOOLEAN
TdExtractSyscallIndexFromStub(PVOID stub, PULONG index_out)
{
    if (!stub || !index_out)
        return FALSE;

    __try {
        PUCHAR p = (PUCHAR)stub;

        if (p[0] == 0xE9)
        {
            LONG rel = *(LONG UNALIGNED *)(p + 1);
            p = p + 5 + rel;
        }
        else if (p[0] == 0xFF && p[1] == 0x25)
        {
            LONG rel = *(LONG UNALIGNED *)(p + 2);
            PUCHAR * indirect = (PUCHAR *)(p + 6 + rel);
            p = *indirect;
        }

        for (SIZE_T i = 0; i + 7 < 0x20; i++)
        {
            if (p[i] == 0xB8)
            {
                ULONG idx = *(ULONG UNALIGNED *)(p + i + 1);
                for (SIZE_T j = i + 5; j + 1 < 0x20; j++)
                {
                    if (p[j] == 0x0F && p[j + 1] == 0x05)
                    {
                        *index_out = idx;
                        return TRUE;
                    }
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }

    return FALSE;
}

static BOOLEAN
TdResolveUserSyscallIndex(const char * export_name, PULONG index_out)
{
    if (!export_name || !index_out)
        return FALSE;

    PVOID ntdll_base = TdFindModuleBaseA("ntdll", NULL);
    if (!ntdll_base)
        ntdll_base = TdFindModuleBaseA("ntdll.dll", NULL);
    if (!ntdll_base)
        return FALSE;

    PVOID stub = TdFindExportByName(ntdll_base, export_name);
    if (!stub)
        return FALSE;

    return TdExtractSyscallIndexFromStub(stub, index_out);
}

typedef NTSTATUS (NTAPI * fn_NtResumeThreadSsdt)(HANDLE, PULONG);

static NTSTATUS
TdNtResumeThreadBySSDT(HANDLE thread_h, PULONG previous_count)
{
    static ULONG g_resume_index = (ULONG)-1;

    if (!thread_h)
        return STATUS_INVALID_PARAMETER;

    if (g_resume_index == (ULONG)-1)
    {
        ULONG idx = 0;
        if (!TdResolveUserSyscallIndex("NtResumeThread", &idx) &&
            !TdResolveUserSyscallIndex("ZwResumeThread", &idx))
        {
            HYPERPLATFORM_LOG_WARN("[td] TdNtResumeThreadBySSDT: failed to resolve syscall index");
            return STATUS_NOT_FOUND;
        }

        g_resume_index = idx;
        HYPERPLATFORM_LOG_INFO("[td] TdNtResumeThreadBySSDT: syscall index=0x%X", g_resume_index);
    }

    fn_NtResumeThreadSsdt nt_resume =
        (fn_NtResumeThreadSsdt)TdGetSSDTEntry(g_resume_index);
    if (!nt_resume)
    {
        HYPERPLATFORM_LOG_WARN("[td] TdNtResumeThreadBySSDT: SSDT entry lookup failed for 0x%X", g_resume_index);
        return STATUS_NOT_FOUND;
    }

    ULONG prev_mode_offset = TdGetPreviousModeOffset();
    if (!prev_mode_offset)
    {
        HYPERPLATFORM_LOG_WARN("[td] TdNtResumeThreadBySSDT: PreviousMode offset not found");
        return STATUS_NOT_FOUND;
    }

    PULONG prev_arg = previous_count;
    ULONG local_prev = 0;
    if (!prev_arg)
        prev_arg = &local_prev;

    PUCHAR p_prev_mode = (PUCHAR)PsGetCurrentThread() + prev_mode_offset;
    UCHAR saved_mode = *p_prev_mode;
    *p_prev_mode = KernelMode;
    NTSTATUS st = nt_resume(thread_h, prev_arg);
    *p_prev_mode = saved_mode;
    return st;
}

static PVOID
TdResolveDefaultTrigger(PEPROCESS proc, const char * log_prefix)
{
    static const char * trigger_candidates[] = {
        "NtTestAlert", "RtlSetCurrentTransaction", NULL
    };

    PVOID trigger_fn = NULL;
    PPEB peb = PsGetProcessPeb(proc);
    if (!peb)
        return NULL;

    __try {
        TD_PEB_LDR_DATA * ldr = *(TD_PEB_LDR_DATA **)((PUINT8)peb + 0x18);
        if (!ldr)
            return NULL;

        PLIST_ENTRY ldr_head = &ldr->InMemoryOrderModuleList;
        PLIST_ENTRY ldr_cur = ldr_head->Flink;
        while (ldr_cur != ldr_head)
        {
            TD_LDR_ENTRY * ldr_e = CONTAINING_RECORD(ldr_cur, TD_LDR_ENTRY, InMemoryOrderLinks);
            if (ldr_e->BaseDllName.Buffer &&
                TdMatchDllName(ldr_e->BaseDllName.Buffer, ldr_e->BaseDllName.Length,
                               g_ntdll_name, 9))
            {
                for (const char ** c = trigger_candidates; *c && !trigger_fn; c++)
                {
                    trigger_fn = TdFindExportByName(ldr_e->DllBase, *c);
                    if (trigger_fn)
                        HYPERPLATFORM_LOG_INFO("[%s] trigger=%s at %p", log_prefix, *c, trigger_fn);
                }
                break;
            }
            ldr_cur = ldr_cur->Flink;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        HYPERPLATFORM_LOG_WARN("[%s] exception resolving trigger", log_prefix);
    }

    return trigger_fn;
}

//
// TdFindExportByOrdinal 鈥?find export by ordinal from a module's export table.
//
static PVOID
TdFindExportByOrdinal(PVOID module_base, USHORT ordinal)
{
    if (!module_base) return NULL;

    __try {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module_base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((PUINT8)module_base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

        ULONG exp_rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        ULONG exp_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        if (!exp_rva) return NULL;

        PIMAGE_EXPORT_DIRECTORY exp_dir = (PIMAGE_EXPORT_DIRECTORY)((PUINT8)module_base + exp_rva);
        PULONG funcs = (PULONG)((PUINT8)module_base + exp_dir->AddressOfFunctions);

        ULONG index = ordinal - (USHORT)exp_dir->Base;
        if (index >= exp_dir->NumberOfFunctions)
            return NULL;

        ULONG func_rva = funcs[index];

        // check for forwarded export
        if (func_rva >= exp_rva && func_rva < exp_rva + exp_size)
            return NULL;

        return (PUINT8)module_base + func_rva;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        HYPERPLATFORM_LOG_WARN("[td-map] exception in TdFindExportByOrdinal");
    }

    return NULL;
}

//
// TdPeCopySections 鈥?copy PE headers and sections from raw DLL to mapped image.
//
static BOOLEAN
TdPeCopySections(PVOID mapped_base, PUINT8 raw_dll, SIZE_T raw_size)
{
    __try {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)raw_dll;
        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(raw_dll + dos->e_lfanew);

        // copy headers
        ULONG hdr_size = nt->OptionalHeader.SizeOfHeaders;
        if (hdr_size > raw_size) hdr_size = (ULONG)raw_size;
        RtlCopyMemory(mapped_base, raw_dll, hdr_size);

        // copy each section
        PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
        USHORT num_sec = nt->FileHeader.NumberOfSections;

        for (USHORT i = 0; i < num_sec; i++)
        {
            PVOID dst = (PUINT8)mapped_base + sec[i].VirtualAddress;

            if (sec[i].SizeOfRawData == 0)
            {
                // BSS 鈥?zero the virtual range
                ULONG virt_sz = sec[i].Misc.VirtualSize;
                if (virt_sz > 0)
                    RtlZeroMemory(dst, virt_sz);
                continue;
            }

            // validate raw data bounds
            if (sec[i].PointerToRawData + sec[i].SizeOfRawData > raw_size)
            {
                HYPERPLATFORM_LOG_WARN("[td-map] section %u raw data exceeds file size", i);
                continue;
            }

            PVOID src = raw_dll + sec[i].PointerToRawData;
            ULONG copy_size = sec[i].SizeOfRawData;

            RtlCopyMemory(dst, src, copy_size);

            // if VirtualSize > SizeOfRawData, zero the remainder
            if (sec[i].Misc.VirtualSize > copy_size)
                RtlZeroMemory((PUINT8)dst + copy_size, sec[i].Misc.VirtualSize - copy_size);
        }

        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        HYPERPLATFORM_LOG_ERROR("[td-map] exception in TdPeCopySections");
        return FALSE;
    }
}

//
// TdPeRelocate 鈥?apply base relocations.
// returns TRUE on success, FALSE if no relocation table and delta != 0.
//
static BOOLEAN
TdPeRelocate(PVOID mapped_base, PUINT8 raw_dll, UINT64 delta)
{
    if (delta == 0) return TRUE;

    __try {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)raw_dll;
        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(raw_dll + dos->e_lfanew);

        ULONG reloc_rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        ULONG reloc_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

        if (!reloc_rva || !reloc_size)
        {
            // no relocation table 鈥?check if DLL has RELOCS_STRIPPED
            if (nt->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
            {
                HYPERPLATFORM_LOG_ERROR("[td-map] no reloc table and delta != 0");
                return FALSE;
            }
            // relocation directory empty but delta != 0 and not stripped 鈥?fail
            HYPERPLATFORM_LOG_ERROR("[td-map] no reloc directory, delta=0x%llX", delta);
            return FALSE;
        }

        PIMAGE_BASE_RELOCATION block = (PIMAGE_BASE_RELOCATION)((PUINT8)mapped_base + reloc_rva);
        PIMAGE_BASE_RELOCATION end   = (PIMAGE_BASE_RELOCATION)((PUINT8)block + reloc_size);

        while (block < end && block->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
        {
            ULONG count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
            PUSHORT entries = (PUSHORT)((PUINT8)block + sizeof(IMAGE_BASE_RELOCATION));

            for (ULONG i = 0; i < count; i++)
            {
                USHORT type   = entries[i] >> 12;
                USHORT offset = entries[i] & 0x0FFF;
                PUINT8 target = (PUINT8)mapped_base + block->VirtualAddress + offset;

                switch (type)
                {
                case IMAGE_REL_BASED_ABSOLUTE:
                    // padding 鈥?skip
                    break;

                case IMAGE_REL_BASED_DIR64:
                    *(PUINT64)target += delta;
                    break;

                case IMAGE_REL_BASED_HIGHLOW:
                    *(PUINT32)target += (UINT32)delta;
                    break;

                default:
                    HYPERPLATFORM_LOG_WARN("[td-map] unsupported reloc type %u", type);
                    break;
                }
            }

            block = (PIMAGE_BASE_RELOCATION)((PUINT8)block + block->SizeOfBlock);
        }

        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        HYPERPLATFORM_LOG_ERROR("[td-map] exception in TdPeRelocate");
        return FALSE;
    }
}

//
// TdPeResolveImports 鈥?resolve imports manually via PEB walk.
// must be called while attached to the target process.
//
static BOOLEAN
TdPeResolveImports(PVOID mapped_base)
{
    __try {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mapped_base;
        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((PUINT8)mapped_base + dos->e_lfanew);

        ULONG imp_rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        ULONG imp_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

        if (!imp_rva || !imp_size)
        {
            HYPERPLATFORM_LOG_INFO("[td-map] no import directory 鈥?nothing to resolve");
            return TRUE;
        }

        PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)((PUINT8)mapped_base + imp_rva);

        while (imp->Name)
        {
            const char * dll_name = (const char *)((PUINT8)mapped_base + imp->Name);
            PVOID mod_base = TdFindModuleBaseA(dll_name, NULL);

            if (!mod_base)
            {
                HYPERPLATFORM_LOG_ERROR("[td-map] import DLL not found: %s", dll_name);
                imp++;
                continue;
            }

            HYPERPLATFORM_LOG_INFO("[td-map] resolving imports from %s (base=%p)", dll_name, mod_base);

            // OriginalFirstThunk = hint/name table, FirstThunk = IAT
            PIMAGE_THUNK_DATA64 oft = (PIMAGE_THUNK_DATA64)((PUINT8)mapped_base +
                (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
            PIMAGE_THUNK_DATA64 ft  = (PIMAGE_THUNK_DATA64)((PUINT8)mapped_base + imp->FirstThunk);

            while (oft->u1.AddressOfData)
            {
                PVOID resolved = NULL;

                if (oft->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                {
                    USHORT ordinal = (USHORT)(oft->u1.Ordinal & 0xFFFF);
                    resolved = TdFindExportByOrdinal(mod_base, ordinal);
                    if (!resolved)
                        HYPERPLATFORM_LOG_WARN("[td-map] unresolved import: %s!#%u", dll_name, ordinal);
                }
                else
                {
                    PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)((PUINT8)mapped_base + oft->u1.AddressOfData);
                    resolved = TdFindExportByName(mod_base, (const char *)ibn->Name);
                    if (!resolved)
                        HYPERPLATFORM_LOG_WARN("[td-map] unresolved import: %s!%s", dll_name, ibn->Name);
                }

                if (resolved)
                    ft->u1.Function = (UINT64)resolved;

                oft++;
                ft++;
            }

            imp++;
        }

        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        HYPERPLATFORM_LOG_ERROR("[td-map] exception in TdPeResolveImports");
        return FALSE;
    }
}

//
// TdBuildDllMainStub 鈥?build a small x64 stub that calls DllMain(base, DLL_PROCESS_ATTACH, NULL).
// placed at image base (overwrites DOS header). returns stub size.
//
// stub:
//   sub rsp, 28h
//   mov rcx, IMAGE_BASE
//   mov edx, 1              ; DLL_PROCESS_ATTACH
//   xor r8d, r8d            ; NULL
//   mov rax, ENTRY_POINT
//   call rax
//   add rsp, 28h
//   xor eax, eax
//   ret
//
static UINT32
TdBuildDllMainStub(PVOID stub_addr, UINT64 image_base, UINT64 entry_point)
{
    PUINT8 s = (PUINT8)stub_addr;
    UINT32 off = 0;

    // sub rsp, 28h  (align stack for call)
    s[off++] = 0x48; s[off++] = 0x83; s[off++] = 0xEC; s[off++] = 0x28;

    // mov rcx, image_base  (hinstDLL)
    s[off++] = 0x48; s[off++] = 0xB9;
    *(PUINT64)(s + off) = image_base; off += 8;

    // mov edx, 1  (DLL_PROCESS_ATTACH)
    s[off++] = 0xBA; s[off++] = 0x01; s[off++] = 0x00; s[off++] = 0x00; s[off++] = 0x00;

    // xor r8d, r8d  (lpvReserved = 0)
    s[off++] = 0x45; s[off++] = 0x31; s[off++] = 0xC0;

    // mov rax, entry_point
    s[off++] = 0x48; s[off++] = 0xB8;
    *(PUINT64)(s + off) = entry_point; off += 8;

    // call rax
    s[off++] = 0xFF; s[off++] = 0xD0;

    // add rsp, 28h
    s[off++] = 0x48; s[off++] = 0x83; s[off++] = 0xC4; s[off++] = 0x28;

    // xor eax, eax  (return TRUE)
    s[off++] = 0x31; s[off++] = 0xC0;

    // ret
    s[off++] = 0xC3;

    return off;
}

//
// TdManualMapInProcess 鈥?main manual map function.
// must be called while attached to the target process.
//
// parameters:
//   proc       鈥?PEPROCESS (already attached)
//   raw_dll    鈥?raw DLL file bytes (kernel buffer)
//   dll_size   鈥?size of raw DLL
//   out_base   鈥?receives mapped image base (user VA)
//   out_entry  鈥?receives DllMain VA (user VA)
//
static NTSTATUS
TdManualMapInProcess(
    PEPROCESS proc,
    PUINT8    raw_dll,
    SIZE_T    dll_size,
    PVOID *   out_base,
    PVOID *   out_entry)
{
    // `proc` is used below to cache per-process PE info (TdCacheSelfPeInfo)
    // before header erasure, so R3 can recover the resource/export RVAs.

    if (!raw_dll || dll_size < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64))
        return STATUS_INVALID_PARAMETER;

    __try {
        // 1. validate PE
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)raw_dll;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            HYPERPLATFORM_LOG_ERROR("[td-map] invalid DOS signature");
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(raw_dll + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
        {
            HYPERPLATFORM_LOG_ERROR("[td-map] invalid PE signature");
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        {
            HYPERPLATFORM_LOG_ERROR("[td-map] not AMD64 (machine=0x%04X)", nt->FileHeader.Machine);
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        if (!(nt->FileHeader.Characteristics & IMAGE_FILE_DLL))
        {
            HYPERPLATFORM_LOG_WARN("[td-map] image is not a DLL (characteristics=0x%04X)", nt->FileHeader.Characteristics);
        }

        // 2. get image size
        SIZE_T image_size = nt->OptionalHeader.SizeOfImage;
        if (image_size == 0 || image_size > 256 * 1024 * 1024)
        {
            HYPERPLATFORM_LOG_ERROR("[td-map] invalid SizeOfImage: 0x%llX", (UINT64)image_size);
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        // 3. allocate PAGE_READWRITE in target process (system chooses base)
        PVOID base = NULL;
        NTSTATUS st = ZwAllocateVirtualMemory(
            ZwCurrentProcess(), &base, 0, &image_size,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (!NT_SUCCESS(st) || !base)
        {
            HYPERPLATFORM_LOG_ERROR("[td-map] ZwAllocateVirtualMemory failed: 0x%08X", st);
            return st;
        }

        HYPERPLATFORM_LOG_INFO("[td-map] allocated image: base=%p size=0x%llX (preferred=0x%llX)",
                   base, (UINT64)image_size, nt->OptionalHeader.ImageBase);

        // 4. copy sections
        if (!TdPeCopySections(base, raw_dll, dll_size))
        {
            HYPERPLATFORM_LOG_ERROR("[td-map] TdPeCopySections failed");
            ZwFreeVirtualMemory(ZwCurrentProcess(), &base, &image_size, MEM_RELEASE);
            return STATUS_UNSUCCESSFUL;
        }

        // 5. apply relocations
        UINT64 delta = (UINT64)base - nt->OptionalHeader.ImageBase;
        if (!TdPeRelocate(base, raw_dll, delta))
        {
            HYPERPLATFORM_LOG_ERROR("[td-map] TdPeRelocate failed (delta=0x%llX)", delta);
            ZwFreeVirtualMemory(ZwCurrentProcess(), &base, &image_size, MEM_RELEASE);
            return STATUS_UNSUCCESSFUL;
        }

        // 6. resolve imports (requires PEB walk 鈥?must be attached)
        if (!TdPeResolveImports(base))
        {
            HYPERPLATFORM_LOG_WARN("[td-map] TdPeResolveImports had errors (continuing)");
        }

        // 6.5 cache PE info (resource + export dir RVAs) for this mapped image
        // BEFORE header erasure below. R3 queries it via IOCTL_GET_SELF_PE_INFO
        // to walk .rsrc / resolve exports after the headers are erased. `nt`
        // points into raw_dll (intact on-disk headers), so the DataDirectory
        // reads are always valid; key by the mapped `base` so R3 (which only
        // knows g_renderdoc_hModule == base) can look it up.
        TdCacheSelfPeInfo((UINT64)(ULONG_PTR)PsGetProcessId(proc), (UINT64)base, nt);

        // 7. build DllMain stub at base+0 (overwrites DOS header)
        PVOID entry = NULL;
        if (nt->OptionalHeader.AddressOfEntryPoint)
        {
            UINT64 entry_point_va = (UINT64)base + nt->OptionalHeader.AddressOfEntryPoint;
            UINT32 stub_size = TdBuildDllMainStub(base, (UINT64)base, entry_point_va);

            HYPERPLATFORM_LOG_INFO("[td-map] DllMain stub: base=%p entry=0x%llX stub_size=%u",
                       base, entry_point_va, stub_size);

            // 8. zero from stub end to SizeOfHeaders (clear remaining PE header data)
            ULONG hdr_size = nt->OptionalHeader.SizeOfHeaders;
            if (stub_size < hdr_size)
                RtlZeroMemory((PUINT8)base + stub_size, hdr_size - stub_size);

            entry = base;  // stub is at base+0
        }
        else
        {
            HYPERPLATFORM_LOG_WARN("[td-map] no entry point in DLL");
            // zero the entire header area
            RtlZeroMemory(base, nt->OptionalHeader.SizeOfHeaders);
            entry = NULL;
        }

        // set output before we lose access to nt headers (they're overwritten)
        *out_base  = base;
        *out_entry = entry;

        // 9. executable sections + header stub page: do NOT mark PAGE_EXECUTE_READ
        // in the REAL PTE. Stealth rule: any executable memory in the target
        // process must be shadowed. The real PTE stays PAGE_READWRITE (NX=1,
        // non-executable) so scanners reading the real CR3 see no executable
        // private memory. The shadow CR3 built later in TdInjectRenderdocShadow
        // (TdBuildShadowCR3 / TdExtendShadowCR3) clears NX on every PTE across
        // the whole image range, so .text and the header DllMain stub page
        // execute under the shadow CR3. Never modify real PTEs to executable
        // (matches the shadow-alloc pattern: "never modifies real PTEs - no
        // conflict with MiAgeWorkingSet").

        HYPERPLATFORM_LOG_INFO("[td-map] manual map complete: base=%p entry=%p", base, entry);
        return STATUS_SUCCESS;

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        HYPERPLATFORM_LOG_ERROR("[td-map] exception in TdManualMapInProcess");
        return STATUS_UNSUCCESSFUL;
    }
}

// =========================================================================
//  TdInjectRenderdocShadow 鈥?automated renderdoc injection via LoadImage callback
// =========================================================================
//
// Called from TdLoadImageNotify when user32.dll loads in a recorded target.
// Must be called at PASSIVE_LEVEL with proc referenced (not yet attached).
// Flow:
//   1. attach, read renderdoc.dll from disk
//   2. TdManualMapInProcess (alloc RW, copy sections, reloc, imports, DllMain stub)
//   3. build shadow CR3 for the mapped image range (NX cleared)
//   4. EPT stealth per page + track for process-exit cleanup
//   5. create SUSPENDED thread at mapped_base (DllMain stub entry, no trigger)
//   6. resume thread -> direct DllMain execution (shadow CR3 via stealth #PF)
//   7. async cleanup: release thread handle, keep inject resident
//
static NTSTATUS
TdInjectRenderdocShadow(PEPROCESS proc, PCUNICODE_STRING renderdoc_path, const char * log_prefix, BOOLEAN wait_for_completion)
{
    NTSTATUS st = STATUS_SUCCESS;
    KAPC_STATE apc_state;
    UINT64 caller_cr3 = 0;
    SIZE_T image_size = 0;
    PUINT8 raw_dll = NULL;
    SIZE_T dll_size = 0;
    PVOID mapped_base = NULL;
    PVOID mapped_entry = NULL;
    UINT64 shadow_cr3 = 0;
    BOOLEAN thread_started = FALSE;
    BOOLEAN stealth_tracked = FALSE;
    SIZE_T pages_installed = 0;
    SIZE_T total_pages = 0;
    UINT64 target_pid = (UINT64)PsGetProcessId(proc);
    PVOID trigger_fn = NULL;
    HANDLE cleanup_thr_h = NULL;
    UINT64 expected_tid = 0;
    BOOLEAN trigger_hooked = FALSE;

    // 1. attach to target
    KeStackAttachProcess(proc, &apc_state);
    caller_cr3 = __readcr3();

    // 2. read renderdoc.dll from disk
    st = TdReadFileKernel(renderdoc_path, &raw_dll, &dll_size);
    if (!NT_SUCCESS(st))
    {
        HYPERPLATFORM_LOG_ERROR("[%s] TdReadFileKernel failed: 0x%08X", log_prefix, st);
        KeUnstackDetachProcess(&apc_state);
        return st;
    }
    HYPERPLATFORM_LOG_INFO("[%s] read renderdoc: %wZ size=0x%llX", log_prefix, renderdoc_path, (UINT64)dll_size);

    // 3. manual map in target process (alloc RW, copy sections, reloc, imports, DllMain stub)
    st = TdManualMapInProcess(proc, raw_dll, dll_size, &mapped_base, &mapped_entry);
    if (!NT_SUCCESS(st) || !mapped_base)
    {
        HYPERPLATFORM_LOG_ERROR("[%s] TdManualMapInProcess failed: 0x%08X", log_prefix, st);
        ExFreePoolWithTag(raw_dll, 'fRdO');
        KeUnstackDetachProcess(&apc_state);
        return st;
    }

    // compute image size from raw PE headers
    {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)raw_dll;
        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(raw_dll + dos->e_lfanew);
        image_size = nt->OptionalHeader.SizeOfImage;
    }

    HYPERPLATFORM_LOG_INFO("[%s] manual map complete: base=%p entry=%p size=0x%llX",
        log_prefix, mapped_base, mapped_entry, (UINT64)image_size);

    // 4. build shadow CR3 for the mapped image range (NX cleared)
    //    image_size is already page-aligned from ZwAllocateVirtualMemory
    total_pages = (image_size + PAGE_SIZE - 1) / PAGE_SIZE;

    UINT64 existing = TdStealthFindShadowCr3ForPid(target_pid);
    shadow_cr3 = existing
        ? TdExtendShadowCR3(existing, caller_cr3, (UINT64)mapped_base, image_size)
        : TdBuildShadowCR3(caller_cr3, (UINT64)mapped_base, image_size);

    if (!shadow_cr3)
    {
        HYPERPLATFORM_LOG_ERROR("[%s] shadow CR3 build failed", log_prefix);
        ExFreePoolWithTag(raw_dll, 'fRdO');
        ZwFreeVirtualMemory(ZwCurrentProcess(), &mapped_base, &image_size, MEM_RELEASE);
        KeUnstackDetachProcess(&apc_state);
        return STATUS_UNSUCCESSFUL;
    }

    // 5. EPT stealth: shadow page = original (no zeroing needed since shadow CR3 handles NX)
    //    We need to set up per-page stealth so the shadow CR3 pages are recognized.
    for (SIZE_T off = 0; off < image_size; off += PAGE_SIZE)
    {
        PVOID page_va = (PUINT8)mapped_base + off;
        UINT64 page_phys = MmGetPhysicalAddress(page_va).QuadPart;
        UINT64 pt_pfn = 0;
        UINT32 pt_idx = 0;

        if (!page_phys || !TdResolveGuestPT(caller_cr3, (UINT64)page_va, &pt_pfn, &pt_idx))
        {
            HYPERPLATFORM_LOG_ERROR("[%s] PT/PA resolve failed VA=%p at off=0x%llX",
                log_prefix, page_va, (UINT64)off);
            break;
        }

        NTSTATUS ss = TdStealthAllocPage(
            caller_cr3, page_va, page_phys,
            NULL, 0, TRUE, pt_pfn, pt_idx,
            FALSE, shadow_cr3, TRUE, FALSE);

        if (!NT_SUCCESS(ss))
        {
            HYPERPLATFORM_LOG_ERROR("[%s] stealth setup failed VA=%p st=0x%08X", log_prefix, page_va, ss);
            break;
        }
        pages_installed++;
    }

    if (pages_installed != total_pages)
    {
        HYPERPLATFORM_LOG_ERROR("[%s] stealth setup incomplete: %llu/%llu pages",
            log_prefix, (UINT64)pages_installed, (UINT64)total_pages);
        for (SIZE_T i = 0; i < pages_installed; i++)
            TdStealthFreePage((PUINT8)mapped_base + (i * PAGE_SIZE));
        if (!existing)
            TdShadowFreeCr3(shadow_cr3);
        ZwFreeVirtualMemory(ZwCurrentProcess(), &mapped_base, &image_size, MEM_RELEASE);
        ExFreePoolWithTag(raw_dll, 'fRdO');
        KeUnstackDetachProcess(&apc_state);
        return STATUS_UNSUCCESSFUL;
    }

    if (!mapped_entry)
    {
        HYPERPLATFORM_LOG_ERROR("[%s] mapped entry is NULL", log_prefix);
        for (SIZE_T i = 0; i < total_pages; i++)
            TdStealthFreePage((PUINT8)mapped_base + (i * PAGE_SIZE));
        if (!existing)
            TdShadowFreeCr3(shadow_cr3);
        ZwFreeVirtualMemory(ZwCurrentProcess(), &mapped_base, &image_size, MEM_RELEASE);
        ExFreePoolWithTag(raw_dll, 'fRdO');
        KeUnstackDetachProcess(&apc_state);
        return STATUS_UNSUCCESSFUL;
    }

    // 6. track for process exit cleanup
    if (!TdStealthTrackAdd(target_pid, mapped_base, image_size, shadow_cr3))
    {
        HYPERPLATFORM_LOG_ERROR("[%s] stealth track table full", log_prefix);
        for (SIZE_T i = 0; i < pages_installed; i++)
            TdStealthFreePage((PUINT8)mapped_base + (i * PAGE_SIZE));
        if (!existing)
            TdShadowFreeCr3(shadow_cr3);
        ZwFreeVirtualMemory(ZwCurrentProcess(), &mapped_base, &image_size, MEM_RELEASE);
        ExFreePoolWithTag(raw_dll, 'fRdO');
        KeUnstackDetachProcess(&apc_state);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    stealth_tracked = TRUE;

    HYPERPLATFORM_LOG_INFO("[%s] shadow CR3 built: PA=0x%llX (VA=%p size=0x%llX, %llu pages NX cleared)",
        log_prefix, shadow_cr3, mapped_base, (UINT64)image_size, (UINT64)total_pages);

    // 7. resolve NtTestAlert (ntdll export) - the CFG-valid thread entry point.
    //    thread is created SUSPENDED at NtTestAlert, then EPT-hooked to redirect
    //    to mapped_base (DllMain stub), bypassing CFG on the manual-mapped image.
    {
        PPEB peb = PsGetProcessPeb(proc);
        if (peb)
        {
            __try {
                TD_PEB_LDR_DATA * ldr = *(TD_PEB_LDR_DATA **)((PUINT8)peb + 0x18);
                if (ldr)
                {
                    PLIST_ENTRY ldr_head = &ldr->InMemoryOrderModuleList;
                    PLIST_ENTRY ldr_cur = ldr_head->Flink;
                    while (ldr_cur != ldr_head)
                    {
                        TD_LDR_ENTRY * ldr_e = CONTAINING_RECORD(ldr_cur, TD_LDR_ENTRY, InMemoryOrderLinks);
                        if (ldr_e->BaseDllName.Buffer &&
                            TdMatchDllName(ldr_e->BaseDllName.Buffer, ldr_e->BaseDllName.Length,
                                           g_ntdll_name, 9))
                        {
                            trigger_fn = TdFindExportByName(ldr_e->DllBase, "NtTestAlert");
                            if (trigger_fn)
                                HYPERPLATFORM_LOG_INFO("[%s] NtTestAlert=%p (ntdll=%p)",
                                    log_prefix, trigger_fn, ldr_e->DllBase);
                            break;
                        }
                        ldr_cur = ldr_cur->Flink;
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                HYPERPLATFORM_LOG_WARN("[%s] exception resolving NtTestAlert", log_prefix);
            }
        }
    }

    if (!trigger_fn)
    {
        HYPERPLATFORM_LOG_ERROR("[%s] cannot resolve NtTestAlert", log_prefix);
        st = STATUS_NOT_FOUND;
    }

    // 8. create thread at trigger (SUSPENDED) - before hook, no race
    if (NT_SUCCESS(st))
    {
        if (g_pZwCreateThreadEx)
        {
            HANDLE thr_proc_h = NULL;
            NTSTATUS oh_st = ObOpenObjectByPointer(
                proc, OBJ_KERNEL_HANDLE, NULL,
                PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &thr_proc_h);

            if (NT_SUCCESS(oh_st))
            {
                HANDLE thr_h = NULL;
                NTSTATUS thr_st = g_pZwCreateThreadEx(
                    &thr_h, THREAD_ALL_ACCESS, NULL, thr_proc_h,
                    trigger_fn, NULL,
                    THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
                    0, 0, 0, NULL);

                if (NT_SUCCESS(thr_st) && thr_h)
                {
                    HANDLE kernel_thr_h = NULL;
                    NTSTATUS kh_st = TdMakeKernelThreadHandle(thr_h, &kernel_thr_h, &expected_tid);
                    ZwClose(thr_h);

                    if (!NT_SUCCESS(kh_st) || !kernel_thr_h || !expected_tid)
                    {
                        HYPERPLATFORM_LOG_ERROR("[%s] cannot convert created thread handle: st=0x%08X tid=%llu",
                            log_prefix, kh_st, expected_tid);
                        if (kernel_thr_h)
                            ZwClose(kernel_thr_h);
                        st = NT_SUCCESS(kh_st) ? STATUS_UNSUCCESSFUL : kh_st;
                    }
                    else
                    {
                        cleanup_thr_h = kernel_thr_h;
                        HYPERPLATFORM_LOG_INFO("[%s] thread SUSPENDED trigger=%p tid=%llu",
                            log_prefix, trigger_fn, expected_tid);
                    }
                }
                else
                {
                    HYPERPLATFORM_LOG_ERROR("[%s] ZwCreateThreadEx failed: 0x%08X", log_prefix, thr_st);
                    st = thr_st;
                }
                ZwClose(thr_proc_h);
            }
            else
            {
                HYPERPLATFORM_LOG_ERROR("[%s] ObOpenObjectByPointer failed: 0x%08X", log_prefix, oh_st);
                st = oh_st;
            }
        }
        else
        {
            // fallback: RtlCreateUserThread (suspended)
            KAPC_STATE thr_apc;
            KeStackAttachProcess(proc, &thr_apc);

            HANDLE thr_h = NULL;
            CLIENT_ID cid = {};
            NTSTATUS thr_st = RtlCreateUserThread(
                ZwCurrentProcess(), NULL, TRUE, 0, 0, 0,
                trigger_fn, NULL, &thr_h, &cid);

            if (NT_SUCCESS(thr_st) && thr_h)
            {
                expected_tid = (UINT64)(ULONG_PTR)cid.UniqueThread;

                HANDLE kernel_thr_h = NULL;
                UINT64 resolved_tid = expected_tid;
                NTSTATUS kh_st = TdMakeKernelThreadHandle(thr_h, &kernel_thr_h, &resolved_tid);
                ZwClose(thr_h);
                if (!expected_tid)
                    expected_tid = resolved_tid;

                if (!NT_SUCCESS(kh_st) || !kernel_thr_h || !expected_tid)
                {
                    HYPERPLATFORM_LOG_ERROR("[%s] cannot convert fallback thread handle: st=0x%08X tid=%llu",
                        log_prefix, kh_st, expected_tid);
                    if (kernel_thr_h)
                        ZwClose(kernel_thr_h);
                    st = !expected_tid ? STATUS_UNSUCCESSFUL : kh_st;
                }
                else
                {
                    cleanup_thr_h = kernel_thr_h;
                }
            }
            else
            {
                st = thr_st;
            }

            KeUnstackDetachProcess(&thr_apc);
            HYPERPLATFORM_LOG_INFO("[%s] fallback RtlCreateUserThread trigger=%p tid=%llu st=0x%08X",
                       log_prefix, trigger_fn, expected_tid, thr_st);
        }
    }

    // 9. prepare cleanup ctx before resume so we can signal immediate unhook
    struct _RW_CLEANUP_CTX {
        HANDLE          thread_handle;
        PVOID           trigger_fn;
        PVOID           shellcode_va;
        UINT64          target_cr3;
        UINT64          target_pid;
        PIO_WORKITEM    work_item;
        volatile LONG   fired_signal;
    };

    PIO_WORKITEM wi = NULL;
    struct _RW_CLEANUP_CTX * cleanup_ctx = NULL;

    if (cleanup_thr_h && NT_SUCCESS(st))
    {
        wi = IoAllocateWorkItem(g_dev_obj);
        if (wi)
        {
            cleanup_ctx = (struct _RW_CLEANUP_CTX *)
                ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(struct _RW_CLEANUP_CTX), 'wRcI');
        }
    }

    if (cleanup_ctx)
    {
        cleanup_ctx->thread_handle = cleanup_thr_h;
        cleanup_ctx->trigger_fn    = trigger_fn;
        cleanup_ctx->shellcode_va  = mapped_base;
        cleanup_ctx->target_cr3    = caller_cr3;
        cleanup_ctx->target_pid    = target_pid;
        cleanup_ctx->work_item     = wi;
        cleanup_ctx->fired_signal  = 0;
    }
    else if (cleanup_thr_h && NT_SUCCESS(st))
    {
        st = STATUS_INSUFFICIENT_RESOURCES;
        TdCloseCreatedThreadHandle(cleanup_thr_h, FALSE);
        cleanup_thr_h = NULL;
        if (wi)
        {
            IoFreeWorkItem(wi);
            wi = NULL;
        }
    }

    // 10. EPT hook trigger -> mapped_base (DllMain stub) (TID-filtered, oneshot)
    if (NT_SUCCESS(st) && expected_tid)
    {
        PVOID dummy_origin = NULL;
        volatile LONG * fired_ptr = cleanup_ctx ? &cleanup_ctx->fired_signal : NULL;
        NTSTATUS hook_st = TdInstallTriggerHookAllCpus(
            trigger_fn, mapped_base, caller_cr3, 2, expected_tid, &dummy_origin, fired_ptr);

        HYPERPLATFORM_LOG_INFO("[%s] trigger hook %s trigger=%p sc=%p tid=%llu st=0x%08X",
                   log_prefix, NT_SUCCESS(hook_st) ? "OK" : "FAILED",
                   trigger_fn, mapped_base, expected_tid, hook_st);

        if (!NT_SUCCESS(hook_st))
            st = hook_st;
        else
            trigger_hooked = TRUE;
    }

    KeUnstackDetachProcess(&apc_state);

    // 11. resume thread (now hook is active with correct TID)
    if (NT_SUCCESS(st) && cleanup_thr_h)
    {
        ULONG prev_count = 0;
        NTSTATUS resume_st = TdResumeThreadHandle(cleanup_thr_h, &prev_count);
        if (NT_SUCCESS(resume_st))
        {
            HYPERPLATFORM_LOG_INFO("[%s] thread RESUMED trigger=%p tid=%llu prev=%u",
                log_prefix, trigger_fn, expected_tid, prev_count);
            thread_started = TRUE;
            st = STATUS_SUCCESS;
        }
        else
        {
            HYPERPLATFORM_LOG_ERROR("[%s] thread resume failed: 0x%08X", log_prefix, resume_st);
            st = resume_st;
            TdCloseCreatedThreadHandle(cleanup_thr_h, FALSE);
            cleanup_thr_h = NULL;
            if (cleanup_ctx)
            {
                cleanup_ctx->fired_signal = 1;
                cleanup_ctx->thread_handle = NULL;
            }
        }
    }

    // 11.5 (NtCreateFile path only): synchronously wait for the DllMain thread
    // to EXIT so the D3D12/DXGI EPT hooks are guaranteed installed before we
    // return. renderdoc's DllMain is fully synchronous (win32_libentry.cpp:
    // VEH/UEF -> Initialise -> RegisterHooks, which places every EPT hook via
    // IOCTL_EPT_HOOK_R3 before returning) and the DllMain stub then `ret`s, so
    // thread exit == hooks installed. Without this wait, CreateFile("test")
    // returns before RegisterHooks finishes, and Box.exe's very next
    // D3D12CreateDevice misses the hook (race) -> no F12 overlay.
    // MUST NOT be used from the LoadImage notify path: that callback runs under
    // the loader lock and renderdoc DllMain calls LoadLibrary -> deadlock.
    if (wait_for_completion && NT_SUCCESS(st) && thread_started && cleanup_thr_h)
    {
        PETHREAD trig_thread = NULL;
        NTSTATUS ref_st = ObReferenceObjectByHandle(
            cleanup_thr_h, 0, *PsThreadType, KernelMode, (PVOID *)&trig_thread, NULL);
        if (NT_SUCCESS(ref_st) && trig_thread)
        {
            // KeWaitForSingleObject takes the object pointer, not the handle.
            // 30s ceiling only - DllMain + RegisterHooks normally finishes in
            // well under 1s. Bounds the damage if DllMain ever hangs instead of
            // blocking CreateFile("test") forever (a NULL timeout would).
            LARGE_INTEGER wait_to;
            wait_to.QuadPart = -30LL * 10000000LL;
            NTSTATUS wait_st = KeWaitForSingleObject(
                trig_thread, Executive, KernelMode, FALSE, &wait_to);
            HYPERPLATFORM_LOG_INFO("[%s] DllMain thread wait done st=0x%08X",
                log_prefix, wait_st);
            ObDereferenceObject(trig_thread);
        }
        else
        {
            HYPERPLATFORM_LOG_WARN("[%s] DllMain thread ref failed: 0x%08X",
                log_prefix, ref_st);
        }
    }

    // 12. async cleanup - unhook trigger immediately after first hit
    if (cleanup_ctx && NT_SUCCESS(st) && thread_started)
    {
        IoQueueWorkItem(wi, [](PDEVICE_OBJECT, PVOID context) {
            auto * c = (struct _RW_CLEANUP_CTX *)context;

            LARGE_INTEGER poll_interval;
            poll_interval.QuadPart = -1LL * 10000LL;

            for (ULONG i = 0; i < 10000 && c->fired_signal == 0; i++)
            {
                if (KeDelayExecutionThread(KernelMode, FALSE, &poll_interval) != STATUS_SUCCESS)
                    break;
            }

            if (c->thread_handle)
                TdCloseCreatedThreadHandle(c->thread_handle, TRUE);

            HYPERPLATFORM_LOG_INFO("[td-inj-shadow] cleanup: unhooking trigger (fired=%ld), inject stays resident",
                c->fired_signal);

            PEPROCESS proc2 = NULL;
            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)c->target_pid, &proc2)))
            {
                KAPC_STATE apc2;
                KeStackAttachProcess(proc2, &apc2);

                TdUnhookTriggerAllCpus(c->trigger_fn, c->target_cr3);
                KeUnstackDetachProcess(&apc2);
                ObDereferenceObject(proc2);

                HYPERPLATFORM_LOG_INFO("[td-inj-shadow] cleanup: trigger unhook=%p, inject RESIDENT=%p",
                    c->trigger_fn, c->shellcode_va);
            }

            IoFreeWorkItem(c->work_item);
            ExFreePoolWithTag(c, 'wRcI');
        }, DelayedWorkQueue, cleanup_ctx);

        cleanup_thr_h = NULL;
    }
    else
    {
        if (cleanup_ctx)
        {
            if (cleanup_ctx->thread_handle)
                TdCloseCreatedThreadHandle(cleanup_ctx->thread_handle, thread_started ? TRUE : FALSE);
            ExFreePoolWithTag(cleanup_ctx, 'wRcI');
            cleanup_ctx = NULL;
            cleanup_thr_h = NULL;
        }
        if (wi)
        {
            IoFreeWorkItem(wi);
            wi = NULL;
        }
    }

    if (cleanup_thr_h)
        TdCloseCreatedThreadHandle(cleanup_thr_h, thread_started ? TRUE : FALSE);

    if (NT_SUCCESS(st) && !thread_started)
        st = STATUS_UNSUCCESSFUL;

    if (!NT_SUCCESS(st) && stealth_tracked && !thread_started)
    {
        KAPC_STATE cleanup_apc;
        KeStackAttachProcess(proc, &cleanup_apc);
        if (trigger_hooked)
            TdUnhookTriggerAllCpus(trigger_fn, caller_cr3);
        UINT64 cleanup_shadow_cr3 = TdStealthTrackRemove(target_pid, mapped_base);
        for (SIZE_T i = 0; i < pages_installed; i++)
            TdStealthFreePage((PUINT8)mapped_base + (i * PAGE_SIZE));
        if (cleanup_shadow_cr3)
            TdShadowFreeCr3(cleanup_shadow_cr3);
        ZwFreeVirtualMemory(ZwCurrentProcess(), &mapped_base, &image_size, MEM_RELEASE);
        KeUnstackDetachProcess(&cleanup_apc);
        stealth_tracked = FALSE;
    }

    ExFreePoolWithTag(raw_dll, 'fRdO');
    return st;
}

static NTSTATUS TdIoControl(PDEVICE_OBJECT, PIRP irp)
{
    NTSTATUS st = STATUS_SUCCESS;
    PIO_STACK_LOCATION io = IoGetCurrentIrpStackLocation(irp);
    irp->IoStatus.Information = 0;

    HYPERPLATFORM_LOG_INFO("[td-ioctl] enter: code=0x%08X in=%u out=%u",
        io->Parameters.DeviceIoControl.IoControlCode,
        io->Parameters.DeviceIoControl.InputBufferLength,
        io->Parameters.DeviceIoControl.OutputBufferLength);

    switch (io->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_INJECT:
    {
        //
        // EPT hook-based shellcode injection 鈥?ALL pre-built at PASSIVE_LEVEL.
        // VMX-root only does EPT manipulation, NEVER touches user VA (SMAP safe).
        //
        // flow:
        //   1. alloc PAGE_READWRITE in target (NX=1 in PTE, clean VAD)
        //   2. build shellcode, copy to kernel buffer, patch VMCALL at entry
        //   3. build trampoline at PASSIVE_LEVEL: [saved bytes] + [abs jmp back]
        //   4. zero original page (COW may change PA), walk PT AFTER zero
        //   5. copy PT page to buffer, force NX=0 in buffer (NOT real PTE)
        //   6. VMCALL_EPT_HOOK_INJECT: EPT split + fake PT(NX=1) + exec PT(NX=0)
        //   7. create thread 鈫?#PF(NX) 鈫?HV swaps to exec PT 鈫?TLB(NX=0) 鈫?executes
        //
        if (io->Parameters.DeviceIoControl.InputBufferLength < sizeof(TD_INJECT_PARAMS) ||
            io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(TD_INJECT_PARAMS))
        { st = STATUS_BUFFER_TOO_SMALL; break; }

        TD_INJECT_PARAMS * p = (TD_INJECT_PARAMS *)irp->AssociatedIrp.SystemBuffer;

        PEPROCESS proc = NULL;
        st = PsLookupProcessByProcessId((HANDLE)p->target_pid, &proc);
        if (!NT_SUCCESS(st)) break;

        KAPC_STATE apc_state;
        KeStackAttachProcess(proc, &apc_state);

        ULONG gap_offset = 0, gap_avail = 0;

        //
        // try section tail padding first 鈥?shellcode goes into the zero-padded
        // tail of a section's last page. no new allocation, no new VAD.
        // original page content preserved (real DLL code stays in front).
        //
        PVOID base = TdFindGapInProcess(sizeof(g_shellcode_pic) + 32, &gap_offset, &gap_avail);
        if (base)
        {
            HYPERPLATFORM_LOG_INFO("[td] inject: section padding VA=%p+0x%X avail=0x%X pid=%llu",
                       base, gap_offset, gap_avail, p->target_pid);
        }

        if (!base)
        {
            //
            // no gap found 鈥?refuse to inject. never allocate new memory
            // (VirtualAlloc creates a visible VAD that anti-cheat can scan).
            //
            HYPERPLATFORM_LOG_ERROR("[td] inject: no section gap found, aborting (no VirtualAlloc fallback)");
            KeUnstackDetachProcess(&apc_state);
            ObDereferenceObject(proc);
            st = STATUS_NOT_FOUND;
            break;
        }

        HYPERPLATFORM_LOG_INFO("[td] inject: VA=%p offset=0x%X pid=%llu (gap mode)",
                   base, gap_offset, p->target_pid);

        UINT64 caller_cr3 = __readcr3();

        //
        // shellcode entry VA = base + gap_offset.
        // for gap mode: inside DLL section padding.
        // for fallback: at page start (gap_offset = 0).
        //
        PVOID entry_va = (PUINT8)base + gap_offset;

        // --- step 3: build fake_buf (shadow page content) ---
        //
        // gap mode:  copy original page (preserving DLL code) 鈫?write shellcode at gap_offset
        // fallback:  page starts empty 鈫?write shellcode at offset 0
        // original page is NOT zeroed in gap mode 鈥?DLL code stays intact.
        //
        PVOID fake_buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'kjnI');
        if (!fake_buf)
        {
            KeUnstackDetachProcess(&apc_state);
            ObDereferenceObject(proc);
            st = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        //
        // trigger COW to get a private physical page for this process.
        // the shared DLL page PA is used by ALL processes 鈥?EPT hooking
        // the shared PA would affect every process.
        //
        // direct PTE manipulation: set Write bit in PTE 鈫?write byte 鈫?COW.
        // no ZwProtectVirtualMemory call (AC can monitor that API).
        // user-visible page protection stays unchanged.
        //
        // COW: get a private physical page for this process
        {
            UINT64 pa_before = MmGetPhysicalAddress(base).QuadPart;

            //
            // walk guest page table to find PTE, set Write bit directly.
            // caller_cr3 is the target process CR3 (we're attached).
            //
            UINT64 cow_cr3 = __readcr3();
            UINT64 cow_va  = (UINT64)base;
            PHYSICAL_ADDRESS cow_pa;
            BOOLEAN cow_done = FALSE;

            // PML4
            cow_pa.QuadPart = (LONGLONG)((cow_cr3 & ~0xFFFULL) + ((cow_va >> 39) & 0x1FF) * 8);
            PUINT64 pml4e = (PUINT64)MmGetVirtualForPhysical(cow_pa);
            if (pml4e && (*pml4e & 1))
            {
                // PDPT
                cow_pa.QuadPart = (LONGLONG)((*pml4e & 0x000FFFFFFFFFF000ULL) + ((cow_va >> 30) & 0x1FF) * 8);
                PUINT64 pdpe = (PUINT64)MmGetVirtualForPhysical(cow_pa);
                if (pdpe && (*pdpe & 1) && !(*pdpe & (1ULL << 7)))
                {
                    // PD
                    cow_pa.QuadPart = (LONGLONG)((*pdpe & 0x000FFFFFFFFFF000ULL) + ((cow_va >> 21) & 0x1FF) * 8);
                    PUINT64 pde = (PUINT64)MmGetVirtualForPhysical(cow_pa);
                    if (pde && (*pde & 1) && !(*pde & (1ULL << 7)))
                    {
                        // PT 鈫?PTE
                        cow_pa.QuadPart = (LONGLONG)((*pde & 0x000FFFFFFFFFF000ULL) + ((cow_va >> 12) & 0x1FF) * 8);
                        PUINT64 pte = (PUINT64)MmGetVirtualForPhysical(cow_pa);
                        if (pte && (*pte & 1))
                        {
                            // set Write bit, write, restore
                            UINT64 orig_pte = *pte;
                            *pte = orig_pte | (1ULL << 1);  // set W bit
                            __invlpg((PVOID)cow_va);         // flush TLB for this VA

                            // write to padding 鈫?triggers COW
                            ((volatile UINT8 *)base)[gap_offset] = 0x01;
                            ((volatile UINT8 *)base)[gap_offset] = 0x00;

                            // restore PTE (COW already happened, PTE now points to private page)
                            // re-read PTE since COW may have changed it
                            // just clear W bit if it was originally clear
                            if (!(orig_pte & (1ULL << 1)))
                            {
                                UINT64 new_pte = *pte;
                                *pte = new_pte & ~(1ULL << 1);
                                __invlpg((PVOID)cow_va);
                            }
                            cow_done = TRUE;
                        }
                    }
                }
            }

            UINT64 pa_after = MmGetPhysicalAddress(base).QuadPart;
            HYPERPLATFORM_LOG_INFO("[td] inject: COW %s (PA %llx -> %llx) pte_method=%d",
                       (pa_before != pa_after) ? "OK" : "SAME", pa_before, pa_after, cow_done);
        }

        // copy original page content (DLL code in front, zeros in padding)
        RtlCopyMemory(fake_buf, base, PAGE_SIZE);

        // build PIC shellcode at gap_offset inside fake_buf
        if (!TdBuildShellcodePIC((PUINT8)fake_buf + gap_offset, PAGE_SIZE - gap_offset))
        {
            RtlSecureZeroMemory(fake_buf, PAGE_SIZE);
            ExFreePoolWithTag(fake_buf, 'kjnI');
            KeUnstackDetachProcess(&apc_state);
            ObDereferenceObject(proc);
            st = STATUS_UNSUCCESSFUL;
            HYPERPLATFORM_LOG_ERROR("[td] inject: PIC shellcode build failed");
            break;
        }
        // gap mode: original page untouched 鈥?DLL code + zero padding stays

        UINT64 base_phys = MmGetPhysicalAddress(base).QuadPart;
        HYPERPLATFORM_LOG_INFO("[td] inject: PA=%llx entry=%p", base_phys, entry_va);

        if (!base_phys)
        {
            RtlSecureZeroMemory(fake_buf, PAGE_SIZE);
            ExFreePoolWithTag(fake_buf, 'kjnI');
            KeUnstackDetachProcess(&apc_state);
            ObDereferenceObject(proc);
            st = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        // --- step 4: build trampoline + patch VMCALL in fake_buf ---
        //
        // VMCALL at shellcode entry (gap_offset in shadow page).
        // trampoline at shadow offset 0xF00.
        // HV intercepts VMCALL 鈫?set RIP = base+0xF00 鈫?trampoline 鈫?jmp back.
        //
        UINT32 hook_size = 4;  // sub rsp, 28h = 48 83 EC 28

        // trampoline at 0xF00: [saved shellcode entry bytes] + [abs jmp entry+4]
        RtlCopyMemory((PUINT8)fake_buf + 0xF00, (PUINT8)fake_buf + gap_offset, hook_size);
        {
            PUINT8 t = (PUINT8)fake_buf + 0xF00 + hook_size;
            UINT64 dst = (UINT64)entry_va + hook_size;
            t[0] = 0x68;
            *(PUINT32)(t + 1) = (UINT32)dst;
            t[5] = 0xC7; t[6] = 0x44; t[7] = 0x24; t[8] = 0x04;
            *(PUINT32)(t + 9) = (UINT32)(dst >> 32);
            t[13] = 0xC3;
        }

        // patch VMCALL at shellcode entry in shadow
        ((PUINT8)fake_buf)[gap_offset + 0] = 0x0F;
        ((PUINT8)fake_buf)[gap_offset + 1] = 0x01;
        ((PUINT8)fake_buf)[gap_offset + 2] = 0xC1;

        HYPERPLATFORM_LOG_INFO("[td] inject: trampoline at shadow+0xF00, entry at +0x%X", gap_offset);

        // --- step 5b: pre-compute PT page info for fake PT / NX hiding ---
        //
        // walk guest page tables AFTER zeroing (COW may have changed PTE/PA).
        // NEVER clear NX in real PTE 鈥?Windows' MiAgeWorkingSet restores it.
        // instead: copy PT page to kernel buffer, force NX=0 in the COPY.
        // VMX-root builds exec PT from this copy (NX=0), fake PT gets NX=1.
        //
        UINT64 pt_pfn = 0;
        UINT32 pt_idx = 0;
        PVOID  pt_page_buf = NULL;

        PVOID pt_real_va = NULL;  // system VA of real PT page (for VMX-root resync)

        //
        // DISABLED fake PT for gap mode 鈥?the #PF + MTF single-step conflicts
        // with the VMCALL at shellcode entry (MTF fires before VMCALL executes,
        // restoring fake PT NX=1, causing infinite #PF loop).
        //
        // gap mode uses EPT X=0 path instead: EPT violation 鈫?shadow 鈫?VMCALL.
        // PTE NX bit is already 0 (PAGE_EXECUTE_READ .text section), no fake PT needed.
        //
        // TODO: fix #PF handler to not arm MTF for inject hook pages, then re-enable.
        //
        //
        // fake PT disabled for gap mode 鈥?the #PF + MTF single-step conflicts
        // with the VMCALL at shellcode entry. gap mode uses EPT X=0 path instead.
        // PTE NX bit is already 0 (PAGE_EXECUTE_READ .text section), no fake PT needed.
        //

        // --- step 6: VMCALL to set up EPT (kernel buffers only, no user VA in VMX-root) ---
        TD_HOOK_INJECT_PARAM inj_req = {};
        inj_req.target_va        = (UINT64)entry_va;
        inj_req.target_phys      = base_phys;
        inj_req.handler_va       = (UINT64)base + 0xF00;  // trampoline in shadow page
        inj_req.fake_page_buffer = fake_buf;
        inj_req.hook_size        = hook_size;
        inj_req.force_read_access = FALSE;  // execute-only: reads 鈫?original page (zeros)
        inj_req.pt_page_pfn      = pt_pfn;
        inj_req.pt_pte_index     = pt_idx;
        inj_req.pt_page_copy     = pt_page_buf;
        inj_req.pt_page_va       = pt_real_va;

        KeGenericCallDpc([](PKDPC, PVOID Ctx, PVOID A1, PVOID A2) {
            hv_vmcall_simple(VMCALL_EPT_HOOK_INJECT, (UINT64)Ctx, 0, 0);
            KeSignalCallDpcSynchronize(A2);
            KeSignalCallDpcDone(A1);
        }, &inj_req);

        RtlSecureZeroMemory(fake_buf, PAGE_SIZE);
        ExFreePoolWithTag(fake_buf, 'kjnI');
        if (pt_page_buf) { RtlSecureZeroMemory(pt_page_buf, PAGE_SIZE); ExFreePoolWithTag(pt_page_buf, 'kjnI'); }

        if (inj_req.result)
        {
            // original page already zeroed (step 3, before PA read + EPT install).
            // EPT binds to the zeroed page's PA. reads 鈫?zeros. execute 鈫?fake page.

            HYPERPLATFORM_LOG_INFO("[td] inject: EPT hook OK, fake_pt=%s",
                       inj_req.fake_pt_ok ? "YES" : "NO");

            // track for cleanup (no MDL 鈥?page is one-shot inject, not persistent)
            R3_HOOK_ENTRY * he = R3HookFindFree();
            if (he)
            {
                he->active          = TRUE;
                he->target_pid      = p->target_pid;
                he->target_va       = base;
                he->trampoline_va   = NULL;
                he->trampoline_size = 0;
                he->target_mdl      = NULL;
                he->target_cr3      = caller_cr3;
            }

            p->shellcode_va = (UINT64)entry_va;
            p->actual_size  = PAGE_SIZE;
            irp->IoStatus.Information = sizeof(TD_INJECT_PARAMS);
            HYPERPLATFORM_LOG_INFO("[td] inject: EPT hook OK");
        }
        else
        {
            HYPERPLATFORM_LOG_ERROR("[td] inject: EPT hook FAILED");
            st = STATUS_UNSUCCESSFUL;
        }

        //
        // --- step 7: resolve trigger function (valid CFG target) ---
        //
        // gap address is NOT in CFG bitmap 鈥?can't create thread there directly.
        // instead: EPT hook a legit function 鈫?redirect to entry_va (gap shellcode).
        // thread entry = trigger function (in CFG bitmap) 鈫?EPT hook 鈫?shellcode.
        //
        // NtYieldExecution: cold function, rarely monitored by anti-cheat.
        // takes no params, returns immediately 鈥?perfect as thread entry stub.
        // (NtTestAlert is a well-known injection vector and heavily monitored.)
        //
        PVOID trigger_fn = (PVOID)p->trigger_va;

        // resolve trigger from target process's ntdll via PEB walk
        if (!trigger_fn && NT_SUCCESS(st))
        {
            // try NtYieldExecution first, fall back to RtlSetCurrentTransaction
            static const char * trigger_candidates[] = {
                "NtYieldExecution",
                "RtlSetCurrentTransaction",
                "NtTestAlert",
                NULL
            };

            PPEB peb = PsGetProcessPeb(proc);
            if (peb)
            {
                __try {
                    TD_PEB_LDR_DATA * ldr = *(TD_PEB_LDR_DATA **)((PUINT8)peb + 0x18);
                    if (ldr)
                    {
                        PLIST_ENTRY ldr_head = &ldr->InMemoryOrderModuleList;
                        PLIST_ENTRY ldr_cur = ldr_head->Flink;
                        while (ldr_cur != ldr_head)
                        {
                            TD_LDR_ENTRY * ldr_e = CONTAINING_RECORD(ldr_cur, TD_LDR_ENTRY, InMemoryOrderLinks);
                            if (ldr_e->BaseDllName.Buffer &&
                                TdMatchDllName(ldr_e->BaseDllName.Buffer, ldr_e->BaseDllName.Length,
                                               g_ntdll_name, 9))
                            {
                                PIMAGE_DOS_HEADER dos_h = (PIMAGE_DOS_HEADER)ldr_e->DllBase;
                                PIMAGE_NT_HEADERS64 nt_h = (PIMAGE_NT_HEADERS64)((PUINT8)ldr_e->DllBase + dos_h->e_lfanew);
                                ULONG exp_rva = nt_h->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                                PIMAGE_EXPORT_DIRECTORY exp_d = (PIMAGE_EXPORT_DIRECTORY)((PUINT8)ldr_e->DllBase + exp_rva);
                                PULONG names = (PULONG)((PUINT8)ldr_e->DllBase + exp_d->AddressOfNames);
                                PUSHORT ords = (PUSHORT)((PUINT8)ldr_e->DllBase + exp_d->AddressOfNameOrdinals);
                                PULONG funcs = (PULONG)((PUINT8)ldr_e->DllBase + exp_d->AddressOfFunctions);

                                for (const char ** cand = trigger_candidates; *cand && !trigger_fn; cand++)
                                {
                                    for (ULONG ei = 0; ei < exp_d->NumberOfNames; ei++)
                                    {
                                        const char * fn = (const char *)((PUINT8)ldr_e->DllBase + names[ei]);
                                        if (strcmp(fn, *cand) == 0)
                                        {
                                            trigger_fn = (PUINT8)ldr_e->DllBase + funcs[ords[ei]];
                                            HYPERPLATFORM_LOG_INFO("[td] inject: trigger=%s at %p", *cand, trigger_fn);
                                            break;
                                        }
                                    }
                                }
                                break;
                            }
                            ldr_cur = ldr_cur->Flink;
                        }
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    HYPERPLATFORM_LOG_WARN("[td] inject: trigger resolve exception");
                }
            }
        }

        if (!trigger_fn && NT_SUCCESS(st))
        {
            HYPERPLATFORM_LOG_ERROR("[td] inject: cannot resolve trigger function");
            st = STATUS_NOT_FOUND;
        }

        //
        // --- step 8: EPT hook trigger 鈫?entry_va (single VMCALL, CPU 0) ---
        //
        NTSTATUS hook_st = STATUS_UNSUCCESSFUL;
        if (NT_SUCCESS(st))
        {
            KAFFINITY old_aff = KeSetSystemAffinityThreadEx((KAFFINITY)1);  // CPU 0

            PVOID dummy_origin = NULL;
            hook_st = hv_vmcall_ex(
                VMCALL_EPT_HOOK,
                (UINT64)trigger_fn,         // target: NtYieldExecution
                (UINT64)entry_va,           // proxy: shellcode in gap
                (UINT64)&dummy_origin,      // origin (unused)
                caller_cr3,                 // caller CR3
                1,                          // hook_type = VMCALL (0F 01 C1)
                caller_cr3,                 // target_cr3 (per-process filter)
                0, 0, 2);                   // no user trampoline, flags bit1 = oneshot

            KeRevertToUserAffinityThreadEx(old_aff);

            HYPERPLATFORM_LOG_INFO("[td] inject: trigger hook %s (trigger=%p -> entry=%p st=0x%08X)",
                       NT_SUCCESS(hook_st) ? "OK" : "FAILED", trigger_fn, entry_va, hook_st);
        }

        if (!NT_SUCCESS(hook_st))
            st = hook_st;

        KeUnstackDetachProcess(&apc_state);

        //
        // --- step 9: create thread at trigger, pin to CPU 0 ---
        //
        // trigger hook only on CPU 0's EPT 鈫?thread MUST run on CPU 0.
        // SUSPENDED 鈫?set affinity 鈫?resume.
        // keep thread handle for async cleanup.
        //
        HANDLE cleanup_thr_h = NULL;
        if (NT_SUCCESS(st) && p->shellcode_va)
        {
            if (g_pZwCreateThreadEx)
            {
                HANDLE thr_proc_h = NULL;
                NTSTATUS oh_st = ObOpenObjectByPointer(
                    proc, OBJ_KERNEL_HANDLE, NULL,
                    PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &thr_proc_h);

                if (NT_SUCCESS(oh_st))
                {
                    HANDLE thr_h = NULL;
                    NTSTATUS thr_st = g_pZwCreateThreadEx(
                        &thr_h, THREAD_ALL_ACCESS, NULL, thr_proc_h,
                        trigger_fn, NULL,
                        THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
                        0, 0, 0, NULL);

                    if (NT_SUCCESS(thr_st) && thr_h)
                    {
                        KAFFINITY cpu0 = (KAFFINITY)1;
                        ZwSetInformationThread(thr_h, ThreadAffinityMask, &cpu0, sizeof(cpu0));

                        ULONG prev = 0;
                        NTSTATUS resume_st = TdResumeThreadHandle(thr_h, &prev);
                        if (NT_SUCCESS(resume_st))
                        {
                            HYPERPLATFORM_LOG_INFO("[td] inject: thread SUSPENDED+CPU0+RESUMED trigger=%p", trigger_fn);
                            cleanup_thr_h = thr_h;  // keep for async cleanup (don't close yet)
                        }
                        else
                        {
                            HYPERPLATFORM_LOG_ERROR("[td] inject: thread resume failed: 0x%08X", resume_st);
                            TdCloseCreatedThreadHandle(thr_h, FALSE);
                            TdUnhookTriggerAllCpus(trigger_fn, caller_cr3);
                            st = resume_st;
                        }
                    }
                    else
                        HYPERPLATFORM_LOG_ERROR("[td] inject: ZwCreateThreadEx failed: 0x%08X", thr_st);
                    ZwClose(thr_proc_h);
                }
            }
            else
            {
                // fallback: RtlCreateUserThread
                KAFFINITY old_aff = KeSetSystemAffinityThreadEx((KAFFINITY)1);
                KAPC_STATE thr_apc;
                KeStackAttachProcess(proc, &thr_apc);

                HANDLE thr_h = NULL;
                CLIENT_ID cid = {};
                NTSTATUS thr_st = RtlCreateUserThread(
                    ZwCurrentProcess(), NULL, FALSE, 0, 0, 0,
                    trigger_fn, NULL, &thr_h, &cid);

                if (NT_SUCCESS(thr_st) && thr_h)
                {
                    KAFFINITY cpu0 = (KAFFINITY)1;
                    ZwSetInformationThread(thr_h, ThreadAffinityMask, &cpu0, sizeof(cpu0));
                    cleanup_thr_h = thr_h;
                }

                KeUnstackDetachProcess(&thr_apc);
                KeRevertToUserAffinityThreadEx(old_aff);
                HYPERPLATFORM_LOG_INFO("[td] inject: fallback RtlCreateUserThread trigger=%p st=0x%08X", trigger_fn, thr_st);
            }
        }

        //
        // --- step 10: async cleanup 鈥?unhook trigger ASAP, inject stays resident ---
        //
        // trigger hook only needed for first thread creation 鈫?shellcode entry.
        // once thread is running, unhook trigger immediately to minimize
        // EPT violation exposure on NtYieldExecution.
        // inject page EPT stealth stays permanently 鈥?shellcode runs forever.
        //
        if (cleanup_thr_h && NT_SUCCESS(st))
        {
            // allocate cleanup context
            struct _INJECT_CLEANUP_CTX {
                HANDLE          thread_handle;
                PVOID           trigger_fn;
                PVOID           inject_entry;
                UINT64          target_cr3;
                UINT64          target_pid;
                PIO_WORKITEM    work_item;
            };

            PIO_WORKITEM wi = IoAllocateWorkItem(IoGetCurrentIrpStackLocation(irp)->DeviceObject);
            if (wi)
            {
                auto * ctx = (struct _INJECT_CLEANUP_CTX *)
                    ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(struct _INJECT_CLEANUP_CTX), 'nlcI');

                if (ctx)
                {
                    ctx->thread_handle = cleanup_thr_h;
                    ctx->trigger_fn    = trigger_fn;
                    ctx->inject_entry  = entry_va;
                    ctx->target_cr3    = caller_cr3;
                    ctx->target_pid    = p->target_pid;
                    ctx->work_item     = wi;

                    IoQueueWorkItem(wi, [](PDEVICE_OBJECT, PVOID context) {
                        auto * c = (struct _INJECT_CLEANUP_CTX *)context;

                        // short delay 鈥?let thread start executing (trigger fires once)
                        LARGE_INTEGER delay;
                        delay.QuadPart = -5LL * 10000000LL;  // 5 sec
                        KeDelayExecutionThread(KernelMode, FALSE, &delay);

                        // thread handle kept open but not waited on (thread runs forever)
                        TdCloseCreatedThreadHandle(c->thread_handle, TRUE);

                        HYPERPLATFORM_LOG_INFO("[td] cleanup: unhooking trigger, inject stays resident");

                        // unhook trigger only 鈥?inject page stays
                        PEPROCESS proc2 = NULL;
                        if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)c->target_pid, &proc2)))
                        {
                            KAPC_STATE apc2;
                            KeStackAttachProcess(proc2, &apc2);

                            KAFFINITY old = KeSetSystemAffinityThreadEx((KAFFINITY)1);

                            // unhook trigger (NtYieldExecution) 鈥?no longer needed
                            hv_vmcall_ex(VMCALL_EPT_UNHOOK,
                                (UINT64)c->trigger_fn, 0, 0,
                                c->target_cr3, 0, 0, 0, 0, 0);

                            // inject page EPT stealth KEPT 鈥?shellcode runs permanently
                            // read view  = original DLL code (anti-cheat sees clean page)
                            // exec view  = shadow page (shellcode loop)

                            KeRevertToUserAffinityThreadEx(old);
                            KeUnstackDetachProcess(&apc2);
                            ObDereferenceObject(proc2);

                            HYPERPLATFORM_LOG_INFO("[td] cleanup: trigger unhook=%p, inject RESIDENT=%p",
                                       c->trigger_fn, c->inject_entry);
                        }

                        IoFreeWorkItem(c->work_item);
                        ExFreePoolWithTag(c, 'nlcI');
                    }, DelayedWorkQueue, ctx);

                    cleanup_thr_h = NULL;  // ownership transferred to work item
                }
                else
                {
                    IoFreeWorkItem(wi);
                }
            }

            // if work item failed, close thread handle directly
            if (cleanup_thr_h)
            {
                TdCloseCreatedThreadHandle(cleanup_thr_h, TRUE);
                TdUnhookTriggerAllCpus(trigger_fn, caller_cr3);
            }
        }

        ObDereferenceObject(proc);
        break;
    }

    case IOCTL_EPT_HOOK:
    {
        st = TdEptHookNtCreateFile();
        break;
    }

    case IOCTL_EPT_UNHOOK:
    {
        st = TdEptUnhookNtCreateFile();
        break;
    }

    case IOCTL_EPT_HOOK_R3:
    {
        if (io->Parameters.DeviceIoControl.InputBufferLength < sizeof(TD_R3_HOOK_PARAMS) ||
            io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(TD_R3_HOOK_PARAMS))
        { st = STATUS_BUFFER_TOO_SMALL; break; }

        TD_R3_HOOK_PARAMS * p = (TD_R3_HOOK_PARAMS *)irp->AssociatedIrp.SystemBuffer;

        PVOID tramp = NULL;
        st = TdEptHookR3(
            p->target_pid,
            (PVOID)p->target_function_va,
            (PVOID)p->proxy_function_va,
            (UINT32)p->hook_type,
            &tramp);

        p->trampoline_va = (UINT64)tramp;
        p->status        = (UINT64)st;
        irp->IoStatus.Information = sizeof(TD_R3_HOOK_PARAMS);
        break;
    }

    case IOCTL_EPT_UNHOOK_R3:
    {
        if (io->Parameters.DeviceIoControl.InputBufferLength < sizeof(TD_R3_UNHOOK_PARAMS) ||
            io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(TD_R3_UNHOOK_PARAMS))
        { st = STATUS_BUFFER_TOO_SMALL; break; }

        TD_R3_UNHOOK_PARAMS * p = (TD_R3_UNHOOK_PARAMS *)irp->AssociatedIrp.SystemBuffer;

        st = TdEptUnhookR3(p->target_pid, (PVOID)p->target_function_va);
        p->status = (UINT64)st;
        irp->IoStatus.Information = sizeof(TD_R3_UNHOOK_PARAMS);
        break;
    }

    case IOCTL_INJECT_DLL:
    {
        //
        // manual-map DLL injection 鈥?zero R3 API calls.
        // buffer layout: [TD_INJECT_DLL_PARAMS header] [raw DLL bytes]
        //
        ULONG in_len  = io->Parameters.DeviceIoControl.InputBufferLength;
        ULONG out_len = io->Parameters.DeviceIoControl.OutputBufferLength;

        if (in_len < sizeof(TD_INJECT_DLL_PARAMS) || out_len < sizeof(TD_INJECT_DLL_PARAMS))
        { st = STATUS_BUFFER_TOO_SMALL; break; }

        TD_INJECT_DLL_PARAMS * p = (TD_INJECT_DLL_PARAMS *)irp->AssociatedIrp.SystemBuffer;

        if (p->dll_offset < sizeof(TD_INJECT_DLL_PARAMS) ||
            p->dll_size == 0 ||
            (UINT64)p->dll_offset + p->dll_size > in_len)
        {
            HYPERPLATFORM_LOG_ERROR("[td-map] invalid DLL params: offset=%u size=%u in_len=%u",
                       p->dll_offset, p->dll_size, in_len);
            st = STATUS_INVALID_PARAMETER;
            break;
        }

        PUINT8 raw_dll = (PUINT8)p + p->dll_offset;

        HYPERPLATFORM_LOG_INFO("[td-map] IOCTL_INJECT_DLL: pid=%llu dll_size=%u",
                   p->target_pid, p->dll_size);

        // look up target process
        PEPROCESS proc = NULL;
        st = PsLookupProcessByProcessId((HANDLE)p->target_pid, &proc);
        if (!NT_SUCCESS(st))
        {
            HYPERPLATFORM_LOG_ERROR("[td-map] PsLookupProcessByProcessId failed: 0x%08X", st);
            break;
        }

        KAPC_STATE apc_state;
        KeStackAttachProcess(proc, &apc_state);

        PVOID image_base  = NULL;
        PVOID image_entry = NULL;

        st = TdManualMapInProcess(proc, raw_dll, (SIZE_T)p->dll_size, &image_base, &image_entry);

        if (NT_SUCCESS(st) && image_entry)
        {
            HYPERPLATFORM_LOG_INFO("[td-map] mapped OK: base=%p entry=%p", image_base, image_entry);

            // fill output
            PIMAGE_DOS_HEADER raw_dos = (PIMAGE_DOS_HEADER)raw_dll;
            PIMAGE_NT_HEADERS64 raw_nt = (PIMAGE_NT_HEADERS64)(raw_dll + raw_dos->e_lfanew);
            p->out_base  = (UINT64)image_base;
            p->out_entry = (UINT64)image_entry;
            p->out_size  = raw_nt->OptionalHeader.SizeOfImage;
            irp->IoStatus.Information = sizeof(TD_INJECT_DLL_PARAMS);

            //
            // resolve trigger from ntdll (prefer cold functions that are not hot scheduler paths)
            //
            PVOID trigger_fn = NULL;
            {
                static const char * trigger_candidates[] = {
                    "NtTestAlert", "RtlSetCurrentTransaction", NULL
                };
                PPEB peb = PsGetProcessPeb(proc);
                if (peb)
                {
                    __try {
                        TD_PEB_LDR_DATA * ldr = *(TD_PEB_LDR_DATA **)((PUINT8)peb + 0x18);
                        if (ldr)
                        {
                            PLIST_ENTRY ldr_head = &ldr->InMemoryOrderModuleList;
                            PLIST_ENTRY ldr_cur = ldr_head->Flink;
                            while (ldr_cur != ldr_head)
                            {
                                TD_LDR_ENTRY * ldr_e = CONTAINING_RECORD(ldr_cur, TD_LDR_ENTRY, InMemoryOrderLinks);
                                if (ldr_e->BaseDllName.Buffer &&
                                    TdMatchDllName(ldr_e->BaseDllName.Buffer, ldr_e->BaseDllName.Length,
                                                   g_ntdll_name, 9))
                                {
                                    for (const char ** c = trigger_candidates; *c && !trigger_fn; c++)
                                    {
                                        trigger_fn = TdFindExportByName(ldr_e->DllBase, *c);
                                        if (trigger_fn)
                                            HYPERPLATFORM_LOG_INFO("[td-map] trigger=%s at %p", *c, trigger_fn);
                                    }
                                    break;
                                }
                                ldr_cur = ldr_cur->Flink;
                            }
                        }
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        HYPERPLATFORM_LOG_WARN("[td-map] exception resolving trigger");
                    }
                }
            }

            if (!trigger_fn)
            {
                HYPERPLATFORM_LOG_ERROR("[td-map] cannot resolve trigger function");
                st = STATUS_NOT_FOUND;
            }

            //
            // EPT hook trigger 鈫?stub (oneshot, per-process CR3 filter)
            //
            UINT64 caller_cr3 = __readcr3();
            NTSTATUS hook_st = STATUS_UNSUCCESSFUL;

            if (NT_SUCCESS(st))
            {
                KAFFINITY old_aff = KeSetSystemAffinityThreadEx((KAFFINITY)1);  // CPU 0

                PVOID dummy_origin = NULL;
                hook_st = hv_vmcall_ex(
                    VMCALL_EPT_HOOK,
                    (UINT64)trigger_fn,          // target: trigger function
                    (UINT64)image_entry,         // proxy: DllMain stub
                    (UINT64)&dummy_origin,       // origin (unused)
                    caller_cr3,                  // caller CR3
                    1,                           // hook_type = VMCALL (0F 01 C1)
                    caller_cr3,                  // target_cr3 (per-process filter)
                    0, 0, 2);                    // no user trampoline, flags bit1 = oneshot

                KeRevertToUserAffinityThreadEx(old_aff);

                HYPERPLATFORM_LOG_INFO("[td-map] trigger hook %s (trigger=%p -> entry=%p st=0x%08X)",
                           NT_SUCCESS(hook_st) ? "OK" : "FAILED", trigger_fn, image_entry, hook_st);

                if (!NT_SUCCESS(hook_st))
                    st = hook_st;
            }

            KeUnstackDetachProcess(&apc_state);

            //
            // create thread at trigger 鈫?EPT hook 鈫?DllMain stub
            //
            if (NT_SUCCESS(st))
            {
                if (g_pZwCreateThreadEx)
                {
                    HANDLE thr_proc_h = NULL;
                    NTSTATUS oh_st = ObOpenObjectByPointer(
                        proc, OBJ_KERNEL_HANDLE, NULL,
                        PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &thr_proc_h);

                    if (NT_SUCCESS(oh_st))
                    {
                        HANDLE thr_h = NULL;
                        NTSTATUS thr_st = g_pZwCreateThreadEx(
                            &thr_h, THREAD_ALL_ACCESS, NULL, thr_proc_h,
                            trigger_fn, NULL,
                            THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
                            0, 0, 0, NULL);

                        if (NT_SUCCESS(thr_st) && thr_h)
                        {
                            KAFFINITY cpu0 = (KAFFINITY)1;
                            ZwSetInformationThread(thr_h, ThreadAffinityMask, &cpu0, sizeof(cpu0));

                            ULONG prev = 0;
                            NTSTATUS resume_st = TdResumeThreadHandle(thr_h, &prev);
                            if (NT_SUCCESS(resume_st))
                            {
                                HYPERPLATFORM_LOG_INFO("[td-map] thread SUSPENDED+CPU0+RESUMED trigger=%p", trigger_fn);
                                TdCloseCreatedThreadHandle(thr_h, TRUE);
                            }
                            else
                            {
                                HYPERPLATFORM_LOG_ERROR("[td-map] thread resume failed: 0x%08X", resume_st);
                                TdCloseCreatedThreadHandle(thr_h, FALSE);
                                TdUnhookTriggerAllCpus(trigger_fn, caller_cr3);
                                st = resume_st;
                            }
                        }
                        else
                            HYPERPLATFORM_LOG_ERROR("[td-map] ZwCreateThreadEx failed: 0x%08X", thr_st);
                        ZwClose(thr_proc_h);
                    }
                }
                else
                {
                    // fallback: RtlCreateUserThread
                    KAFFINITY old_aff = KeSetSystemAffinityThreadEx((KAFFINITY)1);
                    KAPC_STATE thr_apc;
                    KeStackAttachProcess(proc, &thr_apc);

                    HANDLE thr_h = NULL;
                    CLIENT_ID cid = {};
                    NTSTATUS thr_st = RtlCreateUserThread(
                        ZwCurrentProcess(), NULL, FALSE, 0, 0, 0,
                        trigger_fn, NULL, &thr_h, &cid);

                    if (NT_SUCCESS(thr_st) && thr_h)
                    {
                        KAFFINITY cpu0 = (KAFFINITY)1;
                        ZwSetInformationThread(thr_h, ThreadAffinityMask, &cpu0, sizeof(cpu0));
                        ZwClose(thr_h);
                    }

                    KeUnstackDetachProcess(&thr_apc);
                    KeRevertToUserAffinityThreadEx(old_aff);
                    HYPERPLATFORM_LOG_INFO("[td-map] fallback RtlCreateUserThread trigger=%p st=0x%08X",
                               trigger_fn, thr_st);
                }
            }
        }
        else
        {
            HYPERPLATFORM_LOG_ERROR("[td-map] TdManualMapInProcess failed: 0x%08X", st);
            KeUnstackDetachProcess(&apc_state);
        }

        ObDereferenceObject(proc);
        break;
    }

    case IOCTL_INJECT_RW:
    case IOCTL_INJECT_RW_SHADOW:
    {
        //
        // RW-alloc + EPT stealth + trigger hook injection.
        //
        // flow:
        //   1. attach to target process
        //   2. ZwAllocateVirtualMemory(PAGE_READWRITE) 鈥?own VAD, NX=1 in PTE
        //   3. build PIC shellcode into the page
        //   4. EPT stealth: shadow page = shellcode (execute view),
        //      original page zeroed (read view = clean for anti-cheat)
        //      NX handled by HV #PF cycle (no PTE/fake PT manipulation)
        //   5. EPT hook trigger function 鈫?redirect to shellcode VA
        //   6. create thread at trigger 鈫?EPT hook fires 鈫?#PF 鈫?NX cycle 鈫?executes
        //   7. async cleanup: unhook trigger after delay, inject stays resident
        //
        if (io->Parameters.DeviceIoControl.InputBufferLength < sizeof(TD_INJECT_RW_PARAMS) ||
            io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(TD_INJECT_RW_PARAMS))
        { st = STATUS_BUFFER_TOO_SMALL; break; }

        TD_INJECT_RW_PARAMS * p = (TD_INJECT_RW_PARAMS *)irp->AssociatedIrp.SystemBuffer;
        BOOLEAN shadow_only = (io->Parameters.DeviceIoControl.IoControlCode == IOCTL_INJECT_RW_SHADOW);
        UINT64 r3_shellcode_size64 = p->shellcode_size;
        UINT32 r3_shellcode_size = (UINT32)r3_shellcode_size64;
        PUINT8 r3_shellcode = (PUINT8)(p + 1);
        ULONG alloc_protect = (ULONG)(p->alloc_protect ? p->alloc_protect : PAGE_READWRITE);

        if (shadow_only && !g_process_notify_registered)
        {
            HYPERPLATFORM_LOG_ERROR("[td-rw-shadow] process notify unavailable; refusing persistent shadow injection");
            st = STATUS_DEVICE_NOT_READY;
            break;
        }

        if (!r3_shellcode_size64 ||
            r3_shellcode_size64 > TD_MAX_INJECT_RW_SIZE ||
            r3_shellcode_size64 > 0xFFFFFFFFULL ||
            r3_shellcode_size64 > (0xFFFFFFFFULL - sizeof(TD_INJECT_RW_PARAMS)) ||
            io->Parameters.DeviceIoControl.InputBufferLength < sizeof(TD_INJECT_RW_PARAMS) + (ULONG)r3_shellcode_size64)
        {
            HYPERPLATFORM_LOG_ERROR("[td-rw] invalid R3 shellcode size=%llu input=%u",
                       r3_shellcode_size64, io->Parameters.DeviceIoControl.InputBufferLength);
            st = STATUS_INVALID_PARAMETER;
            break;
        }

        if (alloc_protect != PAGE_READWRITE && alloc_protect != PAGE_WRITECOPY)
        {
            HYPERPLATFORM_LOG_ERROR("[td-rw] invalid allocation protect=0x%X", alloc_protect);
            st = STATUS_INVALID_PARAMETER;
            break;
        }

        PEPROCESS proc = NULL;
        st = PsLookupProcessByProcessId((HANDLE)p->target_pid, &proc);
        if (!NT_SUCCESS(st)) break;

        KAPC_STATE apc_state;
        KeStackAttachProcess(proc, &apc_state);

        //
        // step 1: allocate PAGE_READWRITE in target process
        //
        SIZE_T alloc_size = (r3_shellcode_size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
        PVOID  alloc_base = NULL;
        BOOLEAN stealth_tracked = FALSE;
        BOOLEAN thread_started = FALSE;
        BOOLEAN trigger_hooked = FALSE;
        SIZE_T pages_installed = 0;

        st = ZwAllocateVirtualMemory(
            ZwCurrentProcess(), &alloc_base, 0, &alloc_size,
            MEM_COMMIT | MEM_RESERVE, alloc_protect);

        if (!NT_SUCCESS(st) || !alloc_base)
        {
            HYPERPLATFORM_LOG_ERROR("[td-rw] ZwAllocateVirtualMemory failed: 0x%08X", st);
            KeUnstackDetachProcess(&apc_state);
            ObDereferenceObject(proc);
            break;
        }

        HYPERPLATFORM_LOG_INFO("[td-rw%s] allocated RW page: VA=%p size=0x%llX pid=%llu",
                   shadow_only ? "-shadow" : "", alloc_base, (UINT64)alloc_size, p->target_pid);

        //
        // step 2: copy R3-provided shellcode directly into the allocated page
        //
        RtlZeroMemory(alloc_base, alloc_size);
        RtlCopyMemory(alloc_base, r3_shellcode, r3_shellcode_size);
        HYPERPLATFORM_LOG_INFO("[td-rw%s] copied R3 shellcode: VA=%p sc_size=0x%X alloc=0x%llX",
                   shadow_only ? "-shadow" : "", alloc_base, r3_shellcode_size, (UINT64)alloc_size);

        //
        // NO PTE NX clear needed here 鈥?HV handles NX via #PF cycle:
        //   #PF (NX=1) 鈫?VMX-root clears NX 鈫?MTF restores NX 鈫?TLB keeps NX=0
        //   PTE always shows NX=1 to scanners. TLB eviction 鈫?#PF 鈫?repeat.
        //

        //
        // step 4: EPT stealth 鈥?shadow page gets shellcode, original page zeroed
        //
        // use resident mode: shellcode_buffer = NULL 鈫?HV copies from
        // target_page_copy (kernel NonPaged buffer, safe on any CPU).
        // the shellcode is already written in the page, so target_page_copy
        // contains the shellcode content 鈫?shadow page gets it.
        // EPT: execute 鈫?shadow (shellcode), read/write 鈫?original (zeros).
        //
        UINT64 caller_cr3 = __readcr3();

        // build shadow CR3: copies page tables with NX=0 for shellcode page.
        // never modifies real PTEs 鈥?no conflict with MiAgeWorkingSet.
        UINT64 existing = TdStealthFindShadowCr3ForPid(p->target_pid);
        UINT64 shadow_cr3 = existing ? TdExtendShadowCR3(existing, caller_cr3, (UINT64)alloc_base, alloc_size)
                                      : TdBuildShadowCR3(caller_cr3, (UINT64)alloc_base, alloc_size);
        if (!shadow_cr3)
        {
            HYPERPLATFORM_LOG_ERROR("[td-rw] shadow CR3 build failed");
            ZwFreeVirtualMemory(ZwCurrentProcess(), &alloc_base, &alloc_size, MEM_RELEASE);
            KeUnstackDetachProcess(&apc_state);
            ObDereferenceObject(proc);
            st = STATUS_UNSUCCESSFUL;
            break;
        }

        NTSTATUS stealth_st = STATUS_SUCCESS;
        for (SIZE_T off = 0; off < alloc_size; off += PAGE_SIZE)
        {
            PVOID page_va = (PUINT8)alloc_base + off;
            UINT64 page_phys = MmGetPhysicalAddress(page_va).QuadPart;
            UINT64 pt_pfn = 0;
            UINT32 pt_idx = 0;

            if (!page_phys || !TdResolveGuestPT(caller_cr3, (UINT64)page_va, &pt_pfn, &pt_idx))
            {
                HYPERPLATFORM_LOG_ERROR("[td-rw%s] PT/PA resolve failed VA=%p PA=0x%llX",
                    shadow_only ? "-shadow" : "", page_va, page_phys);
                stealth_st = STATUS_UNSUCCESSFUL;
                break;
            }

            stealth_st = TdStealthAllocPage(
                caller_cr3,
                page_va,
                page_phys,
                NULL,
                0,
                TRUE,
                pt_pfn,
                pt_idx,
                FALSE,
                shadow_cr3,
                shadow_only,
                FALSE);

            if (!NT_SUCCESS(stealth_st))
            {
                HYPERPLATFORM_LOG_ERROR("[td-rw%s] stealth setup failed VA=%p st=0x%08X",
                    shadow_only ? "-shadow" : "", page_va, stealth_st);
                break;
            }

            pages_installed++;
        }

        if (!NT_SUCCESS(stealth_st))
        {
            if (stealth_st != STATUS_IO_TIMEOUT)
            {
                for (SIZE_T i = 0; i < pages_installed; i++)
                    TdStealthFreePage((PUINT8)alloc_base + (i * PAGE_SIZE));
                if (!existing)
                    TdShadowFreeCr3(shadow_cr3);
                ZwFreeVirtualMemory(ZwCurrentProcess(), &alloc_base, &alloc_size, MEM_RELEASE);
            }
            KeUnstackDetachProcess(&apc_state);
            ObDereferenceObject(proc);
            st = stealth_st;
            break;
        }

        HYPERPLATFORM_LOG_INFO("[td-rw%s] stealth setup OK pages=%llu shadow_cr3=0x%llX",
            shadow_only ? "-shadow" : "", (UINT64)pages_installed, shadow_cr3);

        //
        // step 5: zero the original page 鈥?read view is now clean
        // EPT stealth is already active, so execute view (shadow) is untouched.
        //
        if (!shadow_only)
        {
            RtlZeroMemory(alloc_base, alloc_size);
            HYPERPLATFORM_LOG_INFO("[td-rw] EPT stealth OK, original page zeroed");
        }
        else
        {
            HYPERPLATFORM_LOG_INFO("[td-rw-shadow] shadow CR3 NX bypass OK, target EPT unchanged");
        }

        // track for process exit cleanup (fake PT removal)
        if (!TdStealthTrackAdd(p->target_pid, alloc_base, alloc_size, shadow_cr3))
        {
            HYPERPLATFORM_LOG_ERROR("[td-rw] stealth track table full");
            for (SIZE_T i = 0; i < pages_installed; i++)
                TdStealthFreePage((PUINT8)alloc_base + (i * PAGE_SIZE));
            if (!existing)
                TdShadowFreeCr3(shadow_cr3);
            ZwFreeVirtualMemory(ZwCurrentProcess(), &alloc_base, &alloc_size, MEM_RELEASE);
            KeUnstackDetachProcess(&apc_state);
            ObDereferenceObject(proc);
            st = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        stealth_tracked = TRUE;

        //
        // step 7: resolve trigger function from ntdll
        //
        PVOID trigger_fn = (PVOID)p->trigger_va;
        if (!trigger_fn)
        {
            static const char * trigger_candidates[] = {
                "NtTestAlert", "RtlSetCurrentTransaction", NULL
            };
            PPEB peb = PsGetProcessPeb(proc);
            if (peb)
            {
                __try {
                    TD_PEB_LDR_DATA * ldr = *(TD_PEB_LDR_DATA **)((PUINT8)peb + 0x18);
                    if (ldr)
                    {
                        PLIST_ENTRY ldr_head = &ldr->InMemoryOrderModuleList;
                        PLIST_ENTRY ldr_cur = ldr_head->Flink;
                        while (ldr_cur != ldr_head)
                        {
                            TD_LDR_ENTRY * ldr_e = CONTAINING_RECORD(ldr_cur, TD_LDR_ENTRY, InMemoryOrderLinks);
                            if (ldr_e->BaseDllName.Buffer &&
                                TdMatchDllName(ldr_e->BaseDllName.Buffer, ldr_e->BaseDllName.Length,
                                               g_ntdll_name, 9))
                            {
                                for (const char ** c = trigger_candidates; *c && !trigger_fn; c++)
                                {
                                    trigger_fn = TdFindExportByName(ldr_e->DllBase, *c);
                                    if (trigger_fn)
                                        HYPERPLATFORM_LOG_INFO("[td-rw] trigger=%s at %p", *c, trigger_fn);
                                }
                                break;
                            }
                            ldr_cur = ldr_cur->Flink;
                        }
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    HYPERPLATFORM_LOG_WARN("[td-rw] exception resolving trigger");
                }
            }
        }

        if (!trigger_fn)
        {
            HYPERPLATFORM_LOG_ERROR("[td-rw] cannot resolve trigger function");
            st = STATUS_NOT_FOUND;
        }

        //
        // step 8: create thread at trigger (SUSPENDED) 鈥?before hook, no race
        //
        HANDLE cleanup_thr_h = NULL;
        UINT64 expected_tid = 0;
        if (NT_SUCCESS(st))
        {
            if (g_pZwCreateThreadEx)
            {
                HANDLE thr_proc_h = NULL;
                NTSTATUS oh_st = ObOpenObjectByPointer(
                    proc, OBJ_KERNEL_HANDLE, NULL,
                    PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &thr_proc_h);

                if (NT_SUCCESS(oh_st))
                {
                    HANDLE thr_h = NULL;
                    NTSTATUS thr_st = g_pZwCreateThreadEx(
                        &thr_h, THREAD_ALL_ACCESS, NULL, thr_proc_h,
                        trigger_fn, NULL,
                        THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
                        0, 0, 0, NULL);

                    if (NT_SUCCESS(thr_st) && thr_h)
                    {
                        HANDLE kernel_thr_h = NULL;
                        NTSTATUS kh_st = TdMakeKernelThreadHandle(thr_h, &kernel_thr_h, &expected_tid);
                        ZwClose(thr_h);

                        if (!NT_SUCCESS(kh_st) || !kernel_thr_h || !expected_tid)
                        {
                            HYPERPLATFORM_LOG_ERROR("[td-rw] cannot convert created thread handle: st=0x%08X tid=%llu",
                                kh_st, expected_tid);
                            if (kernel_thr_h)
                                ZwClose(kernel_thr_h);
                            st = NT_SUCCESS(kh_st) ? STATUS_UNSUCCESSFUL : kh_st;
                        }
                        else
                        {
                            cleanup_thr_h = kernel_thr_h;
                            HYPERPLATFORM_LOG_INFO("[td-rw] thread SUSPENDED trigger=%p tid=%llu", trigger_fn, expected_tid);
                        }
                    }
                    else
                    {
                        HYPERPLATFORM_LOG_ERROR("[td-rw] ZwCreateThreadEx failed: 0x%08X", thr_st);
                        st = thr_st;
                    }
                    ZwClose(thr_proc_h);
                }
                else
                {
                    HYPERPLATFORM_LOG_ERROR("[td-rw] ObOpenObjectByPointer failed: 0x%08X", oh_st);
                    st = oh_st;
                }
            }
            else
            {
                // fallback: RtlCreateUserThread (suspended)
                KAPC_STATE thr_apc;
                KeStackAttachProcess(proc, &thr_apc);

                HANDLE thr_h = NULL;
                CLIENT_ID cid = {};
                NTSTATUS thr_st = RtlCreateUserThread(
                    ZwCurrentProcess(), NULL, TRUE, 0, 0, 0,
                    trigger_fn, NULL, &thr_h, &cid);

                if (NT_SUCCESS(thr_st) && thr_h)
                {
                    expected_tid = (UINT64)(ULONG_PTR)cid.UniqueThread;

                    HANDLE kernel_thr_h = NULL;
                    UINT64 resolved_tid = expected_tid;
                    NTSTATUS kh_st = TdMakeKernelThreadHandle(thr_h, &kernel_thr_h, &resolved_tid);
                    ZwClose(thr_h);
                    if (!expected_tid)
                        expected_tid = resolved_tid;

                    if (!NT_SUCCESS(kh_st) || !kernel_thr_h || !expected_tid)
                    {
                        HYPERPLATFORM_LOG_ERROR("[td-rw] cannot convert fallback thread handle: st=0x%08X tid=%llu",
                            kh_st, expected_tid);
                        if (kernel_thr_h)
                            ZwClose(kernel_thr_h);
                        st = !expected_tid ? STATUS_UNSUCCESSFUL : kh_st;
                    }
                    else
                    {
                        cleanup_thr_h = kernel_thr_h;
                    }
                }
                else
                {
                    st = thr_st;
                }

                KeUnstackDetachProcess(&thr_apc);
                HYPERPLATFORM_LOG_INFO("[td-rw] fallback RtlCreateUserThread trigger=%p tid=%llu st=0x%08X",
                           trigger_fn, expected_tid, thr_st);
            }
        }

        //
        // step 9: prepare cleanup ctx before resume so we can signal immediate unhook
        //
        struct _RW_CLEANUP_CTX {
            HANDLE          thread_handle;
            PVOID           trigger_fn;
            PVOID           shellcode_va;
            UINT64          target_cr3;
            UINT64          target_pid;
            PIO_WORKITEM    work_item;
            volatile LONG   fired_signal;
        };

        PIO_WORKITEM wi = NULL;
        struct _RW_CLEANUP_CTX * cleanup_ctx = NULL;

        if (cleanup_thr_h && NT_SUCCESS(st))
        {
            wi = IoAllocateWorkItem(IoGetCurrentIrpStackLocation(irp)->DeviceObject);
            if (wi)
            {
                cleanup_ctx = (struct _RW_CLEANUP_CTX *)
                    ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(struct _RW_CLEANUP_CTX), 'wRcI');
            }
        }

        if (cleanup_ctx)
        {
            cleanup_ctx->thread_handle = cleanup_thr_h;
            cleanup_ctx->trigger_fn    = trigger_fn;
            cleanup_ctx->shellcode_va  = alloc_base;
            cleanup_ctx->target_cr3    = caller_cr3;
            cleanup_ctx->target_pid    = p->target_pid;
            cleanup_ctx->work_item     = wi;
            cleanup_ctx->fired_signal  = 0;
        }
        else if (cleanup_thr_h && NT_SUCCESS(st))
        {
            st = STATUS_INSUFFICIENT_RESOURCES;
            TdCloseCreatedThreadHandle(cleanup_thr_h, FALSE);
            cleanup_thr_h = NULL;
            if (wi)
            {
                IoFreeWorkItem(wi);
                wi = NULL;
            }
        }

        //
        // step 10: EPT hook trigger 鈫?shellcode VA (TID-filtered, oneshot)
        //
        if (NT_SUCCESS(st) && expected_tid)
        {
            PVOID dummy_origin = NULL;
            volatile LONG * fired_ptr = cleanup_ctx ? &cleanup_ctx->fired_signal : NULL;
            NTSTATUS hook_st = TdInstallTriggerHookAllCpus(
                trigger_fn, alloc_base, caller_cr3, 2, expected_tid, &dummy_origin, fired_ptr);

            HYPERPLATFORM_LOG_INFO("[td-rw] trigger hook %s trigger=%p sc=%p tid=%llu st=0x%08X",
                       NT_SUCCESS(hook_st) ? "OK" : "FAILED", trigger_fn, alloc_base, expected_tid, hook_st);

            if (!NT_SUCCESS(hook_st))
                st = hook_st;
            else
                trigger_hooked = TRUE;
        }

        KeUnstackDetachProcess(&apc_state);

        //
        // step 11: resume thread (now hook is active with correct TID)
        //
        if (NT_SUCCESS(st) && cleanup_thr_h)
        {
            ULONG prev_count = 0;
            NTSTATUS resume_st = TdResumeThreadHandle(cleanup_thr_h, &prev_count);
            if (NT_SUCCESS(resume_st))
            {
                HYPERPLATFORM_LOG_INFO("[td-rw] thread RESUMED trigger=%p tid=%llu prev=%u",
                    trigger_fn, expected_tid, prev_count);
                thread_started = TRUE;
            }
            else
            {
                HYPERPLATFORM_LOG_ERROR("[td-rw] thread resume failed: 0x%08X", resume_st);
                st = resume_st;
                TdCloseCreatedThreadHandle(cleanup_thr_h, FALSE);
                cleanup_thr_h = NULL;
                if (cleanup_ctx)
                {
                    cleanup_ctx->fired_signal = 1;
                    cleanup_ctx->thread_handle = NULL;
                }
            }
        }

        //
        // step 12: async cleanup 鈥?unhook trigger immediately after first hit
        //
        if (cleanup_ctx && NT_SUCCESS(st) && thread_started)
        {
            IoQueueWorkItem(wi, [](PDEVICE_OBJECT, PVOID context) {
                auto * c = (struct _RW_CLEANUP_CTX *)context;

                LARGE_INTEGER poll_interval;
                poll_interval.QuadPart = -1LL * 10000LL;

                for (ULONG i = 0; i < 10000 && c->fired_signal == 0; i++)
                {
                    if (KeDelayExecutionThread(KernelMode, FALSE, &poll_interval) != STATUS_SUCCESS)
                        break;
                }

                if (c->thread_handle)
                    TdCloseCreatedThreadHandle(c->thread_handle, TRUE);

                HYPERPLATFORM_LOG_INFO("[td-rw] cleanup: unhooking trigger (fired=%ld), inject stays resident",
                    c->fired_signal);

                PEPROCESS proc2 = NULL;
                if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)c->target_pid, &proc2)))
                {
                    KAPC_STATE apc2;
                    KeStackAttachProcess(proc2, &apc2);

                    TdUnhookTriggerAllCpus(c->trigger_fn, c->target_cr3);
                    KeUnstackDetachProcess(&apc2);
                    ObDereferenceObject(proc2);

                    HYPERPLATFORM_LOG_INFO("[td-rw] cleanup: trigger unhook=%p, inject RESIDENT=%p",
                        c->trigger_fn, c->shellcode_va);
                }

                IoFreeWorkItem(c->work_item);
                ExFreePoolWithTag(c, 'wRcI');
            }, DelayedWorkQueue, cleanup_ctx);

            cleanup_thr_h = NULL;
        }
        else
        {
            if (cleanup_ctx)
            {
                if (cleanup_ctx->thread_handle)
                    TdCloseCreatedThreadHandle(cleanup_ctx->thread_handle, thread_started ? TRUE : FALSE);
                ExFreePoolWithTag(cleanup_ctx, 'wRcI');
                cleanup_ctx = NULL;
                cleanup_thr_h = NULL;
            }
            if (wi)
            {
                IoFreeWorkItem(wi);
                wi = NULL;
            }
        }

        if (cleanup_thr_h)
            TdCloseCreatedThreadHandle(cleanup_thr_h, thread_started ? TRUE : FALSE);

        if (NT_SUCCESS(st) && !thread_started)
            st = STATUS_UNSUCCESSFUL;

        if (!NT_SUCCESS(st) && stealth_tracked && !thread_started)
        {
            KAPC_STATE cleanup_apc;
            KeStackAttachProcess(proc, &cleanup_apc);
            if (trigger_hooked)
                TdUnhookTriggerAllCpus(trigger_fn, caller_cr3);
            UINT64 cleanup_shadow_cr3 = TdStealthTrackRemove(p->target_pid, alloc_base);
            for (SIZE_T i = 0; i < pages_installed; i++)
                TdStealthFreePage((PUINT8)alloc_base + (i * PAGE_SIZE));
            if (cleanup_shadow_cr3)
                TdShadowFreeCr3(cleanup_shadow_cr3);
            ZwFreeVirtualMemory(ZwCurrentProcess(), &alloc_base, &alloc_size, MEM_RELEASE);
            KeUnstackDetachProcess(&cleanup_apc);
            stealth_tracked = FALSE;
        }

        if (NT_SUCCESS(st))
        {
            p->shellcode_va = (UINT64)alloc_base;
            p->alloc_size   = alloc_size;
            irp->IoStatus.Information = sizeof(TD_INJECT_RW_PARAMS);
        }

        ObDereferenceObject(proc);
        break;
    }

    case IOCTL_ALLOC_SHADOW_MEMORY:
    {
        if (io->Parameters.DeviceIoControl.InputBufferLength < sizeof(TD_ALLOC_SHADOW_MEMORY_PARAMS) ||
            io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(TD_ALLOC_SHADOW_MEMORY_PARAMS))
        { st = STATUS_BUFFER_TOO_SMALL; break; }

        TD_ALLOC_SHADOW_MEMORY_PARAMS * p =
            (TD_ALLOC_SHADOW_MEMORY_PARAMS *)irp->AssociatedIrp.SystemBuffer;

        HYPERPLATFORM_LOG_INFO("[td-alloc] ENTER: pid=%llu size=%llu exec=%u prot=0x%llX",
            p->target_pid, p->size, p->need_execute, p->alloc_protect);

        p->base_va = 0;
        p->shadow_cr3 = 0;

        if (!p->target_pid || !p->size)
        {
            st = STATUS_INVALID_PARAMETER;
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_ALLOC_SHADOW_MEMORY_PARAMS);
            break;
        }

        if (p->size > (MAXSIZE_T - (PAGE_SIZE - 1)))
        {
            st = STATUS_INTEGER_OVERFLOW;
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_ALLOC_SHADOW_MEMORY_PARAMS);
            break;
        }

        SIZE_T alloc_size = (SIZE_T)((p->size + PAGE_SIZE - 1) & ~(UINT64)(PAGE_SIZE - 1));
        BOOLEAN need_execute = (p->need_execute != 0);
        ULONG alloc_protect = (ULONG)(p->alloc_protect ? p->alloc_protect : PAGE_READWRITE);
        PEPROCESS proc = NULL;

        if (need_execute && !g_process_notify_registered)
        {
            HYPERPLATFORM_LOG_ERROR("[td-alloc] process notify unavailable; refusing persistent shadow allocation");
            st = STATUS_DEVICE_NOT_READY;
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_ALLOC_SHADOW_MEMORY_PARAMS);
            break;
        }

        if (alloc_protect != PAGE_READWRITE && alloc_protect != PAGE_WRITECOPY)
        {
            HYPERPLATFORM_LOG_ERROR("[td-alloc] invalid allocation protect=0x%X", alloc_protect);
            st = STATUS_INVALID_PARAMETER;
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_ALLOC_SHADOW_MEMORY_PARAMS);
            break;
        }

        st = PsLookupProcessByProcessId((HANDLE)p->target_pid, &proc);
        if (!NT_SUCCESS(st))
        {
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_ALLOC_SHADOW_MEMORY_PARAMS);
            break;
        }

        KAPC_STATE apc_state;
        KeStackAttachProcess(proc, &apc_state);

        PVOID alloc_base = NULL;
        UINT64 shadow_cr3 = 0;
        SIZE_T pages_installed = 0;
        BOOLEAN timeout_seen = FALSE;

        st = ZwAllocateVirtualMemory(
            ZwCurrentProcess(), &alloc_base, 0, &alloc_size,
            MEM_COMMIT | MEM_RESERVE, alloc_protect);

        if (NT_SUCCESS(st) && alloc_base)
        {
            RtlZeroMemory(alloc_base, alloc_size);
            HYPERPLATFORM_LOG_INFO("[td-alloc] allocation: pid=%llu VA=%p size=0x%llX exec=%u protect=0x%X",
                       p->target_pid, alloc_base, (UINT64)alloc_size, need_execute, alloc_protect);
        }

        UINT64 existing = 0;
        if (NT_SUCCESS(st) && need_execute)
        {
            UINT64 caller_cr3 = __readcr3();
            existing = TdStealthFindShadowCr3ForPid(p->target_pid);
            if (existing)
                shadow_cr3 = TdExtendShadowCR3(existing, caller_cr3, (UINT64)alloc_base, alloc_size);
            else
                shadow_cr3 = TdBuildShadowCR3(caller_cr3, (UINT64)alloc_base, alloc_size);
            if (!shadow_cr3)
            {
                HYPERPLATFORM_LOG_ERROR("[td-alloc] shadow CR3 build failed VA=%p size=0x%llX",
                           alloc_base, (UINT64)alloc_size);
                st = STATUS_UNSUCCESSFUL;
            }

            for (SIZE_T off = 0; NT_SUCCESS(st) && off < alloc_size; off += PAGE_SIZE)
            {
                PVOID page_va = (PUINT8)alloc_base + off;
                UINT64 page_phys = MmGetPhysicalAddress(page_va).QuadPart;
                UINT64 pt_pfn = 0;
                UINT32 pt_idx = 0;

                if (!page_phys || !TdResolveGuestPT(caller_cr3, (UINT64)page_va, &pt_pfn, &pt_idx))
                {
                    HYPERPLATFORM_LOG_ERROR("[td-alloc] PT/PA resolve failed VA=%p PA=0x%llX",
                               page_va, page_phys);
                    st = STATUS_UNSUCCESSFUL;
                    break;
                }

                NTSTATUS stealth_st = TdStealthAllocPage(
                    caller_cr3,
                    page_va,
                    page_phys,
                    NULL,
                    0,
                    TRUE,
                    pt_pfn,
                    pt_idx,
                    FALSE,
                    shadow_cr3,
                    TRUE,
                    FALSE);

                if (!NT_SUCCESS(stealth_st))
                {
                    HYPERPLATFORM_LOG_ERROR("[td-alloc] shadow-only stealth failed VA=%p st=0x%08X",
                               page_va, stealth_st);
                    st = stealth_st;
                    if (stealth_st == STATUS_IO_TIMEOUT)
                        timeout_seen = TRUE;
                    break;
                }

                pages_installed++;
            }

            if (NT_SUCCESS(st))
            {
                if (!TdStealthTrackAdd(p->target_pid, alloc_base, alloc_size, shadow_cr3))
                {
                    HYPERPLATFORM_LOG_ERROR("[td-alloc] stealth track table full");
                    st = STATUS_INSUFFICIENT_RESOURCES;
                }
            }
        }

        if (!NT_SUCCESS(st) && alloc_base && !timeout_seen)
        {
            for (SIZE_T i = 0; i < pages_installed; i++)
                TdStealthFreePage((PUINT8)alloc_base + (i * PAGE_SIZE));
            if (shadow_cr3 && !existing)
                TdShadowFreeCr3(shadow_cr3);
            ZwFreeVirtualMemory(ZwCurrentProcess(), &alloc_base, &alloc_size, MEM_RELEASE);
            alloc_base = NULL;
            shadow_cr3 = 0;
        }

        p->base_va = (UINT64)alloc_base;
        p->size = (UINT64)alloc_size;
        p->alloc_protect = alloc_protect;
        p->shadow_cr3 = shadow_cr3;
        p->status = (UINT64)(ULONG)st;
        irp->IoStatus.Information = sizeof(TD_ALLOC_SHADOW_MEMORY_PARAMS);

        KeUnstackDetachProcess(&apc_state);
        ObDereferenceObject(proc);
        break;
    }

    case IOCTL_FREE_SHADOW_MEMORY:
    {
        if (io->Parameters.DeviceIoControl.InputBufferLength < sizeof(TD_ALLOC_SHADOW_MEMORY_PARAMS) ||
            io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(TD_ALLOC_SHADOW_MEMORY_PARAMS))
        { st = STATUS_BUFFER_TOO_SMALL; break; }

        TD_ALLOC_SHADOW_MEMORY_PARAMS * p =
            (TD_ALLOC_SHADOW_MEMORY_PARAMS *)irp->AssociatedIrp.SystemBuffer;

        if (!p->target_pid || !p->base_va || !p->size)
        {
            st = STATUS_INVALID_PARAMETER;
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_ALLOC_SHADOW_MEMORY_PARAMS);
            break;
        }

        if (p->size > (MAXSIZE_T - (PAGE_SIZE - 1)))
        {
            st = STATUS_INTEGER_OVERFLOW;
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_ALLOC_SHADOW_MEMORY_PARAMS);
            break;
        }

        SIZE_T free_size = (SIZE_T)((p->size + PAGE_SIZE - 1) & ~(UINT64)(PAGE_SIZE - 1));
        PVOID free_base = (PVOID)p->base_va;
        if (!free_size || (UINT64)free_base > (~0ULL - free_size))
        {
            st = STATUS_INTEGER_OVERFLOW;
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_ALLOC_SHADOW_MEMORY_PARAMS);
            break;
        }

        PEPROCESS proc = NULL;
        st = PsLookupProcessByProcessId((HANDLE)p->target_pid, &proc);
        if (!NT_SUCCESS(st))
        {
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_ALLOC_SHADOW_MEMORY_PARAMS);
            break;
        }

        KAPC_STATE apc_state;
        KeStackAttachProcess(proc, &apc_state);

        UINT64 freed_shadow_cr3 = 0;
        if (TdStealthTrackHasPartialOverlap(p->target_pid, free_base, free_size))
        {
            st = STATUS_CONFLICTING_ADDRESSES;
        }

        for (;;)
        {
            if (!NT_SUCCESS(st))
                break;

            PVOID tracked_base = NULL;
            SIZE_T tracked_size = 0;
            UINT64 shadow_cr3 = 0;
            if (!TdStealthTrackFindOverlap(
                p->target_pid, free_base, free_size, &tracked_base, &tracked_size, &shadow_cr3))
                break;

            UINT64 tracked_start = (UINT64)tracked_base;
            UINT64 tracked_end = tracked_start + tracked_size;

            for (UINT64 page = tracked_start; page < tracked_end; page += PAGE_SIZE)
                TdStealthFreePage((PVOID)page);

            {
                UINT64 to_free = TdStealthTrackRemove(p->target_pid, tracked_base);
                if (to_free)
                    TdShadowFreeCr3(to_free);
            }
            freed_shadow_cr3 = shadow_cr3;
        }

        SIZE_T release_size = 0;
        if (NT_SUCCESS(st))
            st = ZwFreeVirtualMemory(ZwCurrentProcess(), &free_base, &release_size, MEM_RELEASE);
        if (NT_SUCCESS(st))
        {
            HYPERPLATFORM_LOG_INFO("[td-free] freed memory: pid=%llu VA=%p size=0x%llX shadow_cr3=0x%llX",
                       p->target_pid, (PVOID)p->base_va, (UINT64)free_size, freed_shadow_cr3);
            p->base_va = 0;
            p->shadow_cr3 = 0;
        }
        else
        {
            HYPERPLATFORM_LOG_ERROR("[td-free] ZwFreeVirtualMemory failed: pid=%llu VA=%p st=0x%08X",
                       p->target_pid, (PVOID)p->base_va, st);
        }

        p->size = (UINT64)free_size;
        p->status = (UINT64)(ULONG)st;
        irp->IoStatus.Information = sizeof(TD_ALLOC_SHADOW_MEMORY_PARAMS);

        KeUnstackDetachProcess(&apc_state);
        ObDereferenceObject(proc);
        break;
    }

    case IOCTL_SHADOW_PROTECT_MEMORY:
    {
        if (io->Parameters.DeviceIoControl.InputBufferLength < sizeof(TD_SHADOW_PROTECT_PARAMS) ||
            io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(TD_SHADOW_PROTECT_PARAMS))
        { st = STATUS_BUFFER_TOO_SMALL; HYPERPLATFORM_LOG_ERROR("[td-protect] EXIT: buffer too small in=%u out=%u",
            io->Parameters.DeviceIoControl.InputBufferLength,
            io->Parameters.DeviceIoControl.OutputBufferLength); break; }

        TD_SHADOW_PROTECT_PARAMS * p =
            (TD_SHADOW_PROTECT_PARAMS *)irp->AssociatedIrp.SystemBuffer;

        HYPERPLATFORM_LOG_INFO("[td-protect] ENTER: pid=%llu base=0x%llX size=%llu newProt=0x%llX",
            p->target_pid, p->base_va, p->size, p->new_protect);

        if (!p->target_pid || !p->base_va || !p->size)
        {
            st = STATUS_INVALID_PARAMETER;
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_SHADOW_PROTECT_PARAMS);
            break;
        }

        if (p->size > (MAXSIZE_T - (PAGE_SIZE - 1)))
        {
            st = STATUS_INTEGER_OVERFLOW;
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_SHADOW_PROTECT_PARAMS);
            break;
        }

        ULONG new_protect = 0;
        if (!TdNormalizeShadowProtect((ULONG)p->new_protect, &new_protect))
        {
            st = STATUS_INVALID_PARAMETER;
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_SHADOW_PROTECT_PARAMS);
            break;
        }

        UINT64 start = p->base_va & ~0xFFFULL;
        SIZE_T protect_size = (SIZE_T)((p->size + (p->base_va - start) + PAGE_SIZE - 1) & ~(UINT64)(PAGE_SIZE - 1));
        if (!protect_size || start > (~0ULL - protect_size))
        {
            st = STATUS_INTEGER_OVERFLOW;
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_SHADOW_PROTECT_PARAMS);
            break;
        }
        UINT64 end = start + protect_size;

        PEPROCESS proc = NULL;
        st = PsLookupProcessByProcessId((HANDLE)p->target_pid, &proc);
        if (!NT_SUCCESS(st))
        {
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_SHADOW_PROTECT_PARAMS);
            break;
        }

        KAPC_STATE apc_state;
        KeStackAttachProcess(proc, &apc_state);

        UINT64 caller_cr3 = __readcr3();
        PVOID tracked_base = NULL;
        SIZE_T tracked_size = 0;
        UINT64 shadow_cr3 = 0;
        UINT64 flush_shadow_cr3 = 0;
        BOOLEAN tracked = TdStealthTrackFindOverlap(
            p->target_pid, (PVOID)start, protect_size, &tracked_base, &tracked_size, &shadow_cr3);
        flush_shadow_cr3 = shadow_cr3;

        if (tracked)
        {
            UINT64 tracked_start = (UINT64)tracked_base;
            UINT64 tracked_end = (UINT64)tracked_base + tracked_size;
            if (start < tracked_start || end > tracked_end)
            {
                st = STATUS_CONFLICTING_ADDRESSES;
                goto ShadowProtectExit;
            }
        }

        PUINT64 old_view_pte = tracked ?
            TdResolveShadowPte(shadow_cr3, start) :
            TdResolveGuestPte(caller_cr3, start);
        if (!old_view_pte || !(*old_view_pte & 1))
        {
            // Shadow PTE not present - the real PTE may have been lazy-allocated
            // after TdExtendShadowCR3 copied it.  Re-sync from the real PTE.
            if (tracked && old_view_pte)
            {
                PUINT64 real_pte = TdResolveGuestPte(caller_cr3, start);
                if (real_pte && (*real_pte & 1))
                {
                    *old_view_pte = *real_pte;
                    HYPERPLATFORM_LOG_INFO("[td-protect] re-synced shadow PTE from real: pid=%llu va=%p real=0x%llX shadow_pte=%p",
                        p->target_pid, (PVOID)start, *real_pte, old_view_pte);
                    p->old_protect = TdProtectFromPte(*old_view_pte);
                }
                else
                {
                    HYPERPLATFORM_LOG_ERROR("[td-protect] re-sync FAILED: pid=%llu va=%p tracked=%u cr3=0x%llX shadow=0x%llX real_pte=%p",
                        p->target_pid, (PVOID)start, tracked, caller_cr3, shadow_cr3, real_pte);
                    st = STATUS_NOT_FOUND;
                    goto ShadowProtectExit;
                }
            }
            else
            {
                HYPERPLATFORM_LOG_ERROR("[td-protect] old view PTE not found: pid=%llu va=%p tracked=%u cr3=0x%llX shadow=0x%llX pte=%p",
                    p->target_pid, (PVOID)start, tracked, caller_cr3, shadow_cr3, old_view_pte);
                if (old_view_pte)
                    HYPERPLATFORM_LOG_ERROR("[td-protect] old view PTE present but !Present bit: *pte=0x%llX", *old_view_pte);
                else
                {
                    if (tracked)
                    {
                        HYPERPLATFORM_LOG_ERROR("[td-protect] tracked=true but TdResolveShadowPte returned NULL: shadow_cr3=0x%llX start=%p",
                            shadow_cr3, (PVOID)start);
                        UINT64 cr3_va = (UINT64)(ULONG_PTR)TdShadowVaFromPhys(shadow_cr3);
                        HYPERPLATFORM_LOG_ERROR("[td-protect] shadow_cr3_phys=0x%llX -> kernelVA=%p", shadow_cr3, (PVOID)cr3_va);
                        if (cr3_va)
                        {
                            UINT64 pml4e = *(PUINT64)cr3_va;
                            HYPERPLATFORM_LOG_ERROR("[td-protect] shadow PML4E[0]=0x%llX", pml4e);
                        }
                    }
                    else
                    {
                        HYPERPLATFORM_LOG_ERROR("[td-protect] tracked=false but TdResolveGuestPte returned NULL: caller_cr3=0x%llX start=%p",
                            caller_cr3, (PVOID)start);
                    }
                }
                st = STATUS_NOT_FOUND;
                goto ShadowProtectExit;
            }
        }

        BOOLEAN all_same_as_real = TRUE;
        for (UINT64 page = start; page < end; page += PAGE_SIZE)
        {
            PUINT64 real_pte = TdResolveGuestPte(caller_cr3, page);
            if (!real_pte || !(*real_pte & 1))
            {
                HYPERPLATFORM_LOG_ERROR("[td-protect] real PTE not found while scanning: pid=%llu va=%p cr3=0x%llX pte=%p",
                    p->target_pid, (PVOID)page, caller_cr3, real_pte);
                st = STATUS_NOT_FOUND;
                goto ShadowProtectExit;
            }

            UINT64 wanted = *real_pte;
            TdApplyProtectToPte(&wanted, new_protect);
            if (wanted != *real_pte)
                all_same_as_real = FALSE;
        }

        if (!tracked && !all_same_as_real)
        {
            if (!g_process_notify_registered)
            {
                HYPERPLATFORM_LOG_ERROR("[td-protect] process notify unavailable; refusing persistent shadow protect");
                st = STATUS_DEVICE_NOT_READY;
                goto ShadowProtectExit;
            }

            UINT64 existing = TdStealthFindShadowCr3ForPid(p->target_pid);
            if (existing)
                shadow_cr3 = TdExtendShadowCR3(existing, caller_cr3, start, protect_size);
            else
                shadow_cr3 = TdBuildShadowCR3(caller_cr3, start, protect_size);
            flush_shadow_cr3 = shadow_cr3;
            if (!shadow_cr3)
            {
                st = STATUS_UNSUCCESSFUL;
                goto ShadowProtectExit;
            }

            SIZE_T pages_installed = 0;
            for (UINT64 page = start; page < end; page += PAGE_SIZE)
            {
                UINT64 page_phys = MmGetPhysicalAddress((PVOID)page).QuadPart;
                UINT64 pt_pfn = 0;
                UINT32 pt_idx = 0;

                if (!page_phys || !TdResolveGuestPT(caller_cr3, page, &pt_pfn, &pt_idx))
                {
                    st = STATUS_UNSUCCESSFUL;
                    break;
                }

                NTSTATUS stealth_st = TdStealthAllocPage(
                    caller_cr3,
                    (PVOID)page,
                    page_phys,
                    NULL,
                    0,
                    TRUE,
                    pt_pfn,
                    pt_idx,
                    FALSE,
                    shadow_cr3,
                    TRUE,
                    TRUE);

                if (!NT_SUCCESS(stealth_st))
                {
                    st = stealth_st;
                    break;
                }

                pages_installed++;
            }

            if (!NT_SUCCESS(st))
            {
                for (SIZE_T i = 0; i < pages_installed; i++)
                    TdStealthFreePage((PVOID)(start + (i * PAGE_SIZE)));
                if (!existing)
                    TdShadowFreeCr3(shadow_cr3);
                shadow_cr3 = 0;
                goto ShadowProtectExit;
            }

            if (!TdStealthTrackAdd(p->target_pid, (PVOID)start, protect_size, shadow_cr3))
            {
                for (UINT64 page = start; page < end; page += PAGE_SIZE)
                    TdStealthFreePage((PVOID)page);
                if (!existing)
                    TdShadowFreeCr3(shadow_cr3);
                shadow_cr3 = 0;
                st = STATUS_INSUFFICIENT_RESOURCES;
                goto ShadowProtectExit;
            }

            tracked = TRUE;
            tracked_base = (PVOID)start;
            tracked_size = protect_size;
            flush_shadow_cr3 = shadow_cr3;
        }

        if (tracked)
        {
            for (UINT64 page = start; page < end; page += PAGE_SIZE)
            {
                PUINT64 real_pte = TdResolveGuestPte(caller_cr3, page);
                PUINT64 shadow_pte = TdResolveShadowPte(shadow_cr3, page);
                if (!real_pte || !(*real_pte & 1))
                {
                    HYPERPLATFORM_LOG_ERROR("[td-protect] real PTE gone while applying: pid=%llu va=%p real=%p realv=0x%llX",
                        p->target_pid, (PVOID)page, real_pte, real_pte ? *real_pte : 0);
                    st = STATUS_NOT_FOUND;
                    goto ShadowProtectExit;
                }
                // Re-sync shadow PTE on the fly if it's not present (lazy PTE).
                if (!shadow_pte || !(*shadow_pte & 1))
                {
                    if (shadow_pte)
                    {
                        *shadow_pte = *real_pte;
                        HYPERPLATFORM_LOG_INFO("[td-protect] re-synced shadow PTE on-the-fly: pid=%llu va=%p real=0x%llX",
                            p->target_pid, (PVOID)page, *real_pte);
                    }
                    else
                    {
                        HYPERPLATFORM_LOG_ERROR("[td-protect] shadow PTE NULL while applying: pid=%llu va=%p shadow_cr3=0x%llX",
                            p->target_pid, (PVOID)page, shadow_cr3);
                        st = STATUS_NOT_FOUND;
                        goto ShadowProtectExit;
                    }
                }

                UINT64 wanted = *real_pte;
                TdApplyProtectToPte(&wanted, new_protect);
                if (wanted == *real_pte)
                    *shadow_pte = *real_pte;
                else
                    *shadow_pte = wanted;

                // Data pages (non-executable): also write the REAL PTE. renderdoc
                // often runs the write instruction on the REAL CR3 (its instruction
                // fetch is cached from a prior shadow-CR3 window -> no fetch #PF ->
                // no shadow swap), so the write lands on the REAL PTE. Without this
                // the IAT write AVs on real RO despite the shadow PTE being W=1.
                // Code pages (PAGE_EXECUTE_*) keep the real PTE (NX) for stealth.
                if (new_protect == PAGE_READWRITE || new_protect == PAGE_READONLY)
                    *real_pte = wanted;

                if (page == start)
                {
                    HYPERPLATFORM_LOG_INFO("[td-protect] applied: pid=%llu va=%p real=0x%llX shadow=0x%llX new=0x%X spte=%p",
                        p->target_pid, (PVOID)page, *real_pte, *shadow_pte, new_protect, shadow_pte);
                }
            }

            BOOLEAN tracked_has_diff = FALSE;
            if (tracked_base && tracked_size)
            {
                UINT64 tracked_end = (UINT64)tracked_base + tracked_size;
                for (UINT64 page = (UINT64)tracked_base; page < tracked_end; page += PAGE_SIZE)
                {
                    PUINT64 real_pte = TdResolveGuestPte(caller_cr3, page);
                    PUINT64 shadow_pte = TdResolveShadowPte(shadow_cr3, page);
                    if (!real_pte || !(*real_pte & 1))
                    {
                        HYPERPLATFORM_LOG_ERROR("[td-protect] real PTE gone while checking diff: pid=%llu va=%p real=%p realv=0x%llX",
                            p->target_pid, (PVOID)page, real_pte, real_pte ? *real_pte : 0);
                        st = STATUS_NOT_FOUND;
                        goto ShadowProtectExit;
                    }
                    if (!shadow_pte || !(*shadow_pte & 1))
                    {
                        if (shadow_pte)
                        {
                            *shadow_pte = *real_pte;
                            HYPERPLATFORM_LOG_INFO("[td-protect] re-synced shadow PTE in diff: pid=%llu va=%p real=0x%llX",
                                p->target_pid, (PVOID)page, *real_pte);
                        }
                        else
                        {
                            HYPERPLATFORM_LOG_ERROR("[td-protect] shadow PTE NULL while checking diff: pid=%llu va=%p shadow_cr3=0x%llX",
                                p->target_pid, (PVOID)page, shadow_cr3);
                            st = STATUS_NOT_FOUND;
                            goto ShadowProtectExit;
                        }
                    }

                    if (TdProtectFromPte(*shadow_pte) != TdProtectFromPte(*real_pte))
                    {
                        tracked_has_diff = TRUE;
                        break;
                    }
                }
            }

            if (!tracked_has_diff && tracked_base && tracked_size)
            {
                TdFlushAddressRange((UINT64)tracked_base, tracked_size, caller_cr3, shadow_cr3);
                for (UINT64 page = (UINT64)tracked_base;
                     page < (UINT64)tracked_base + tracked_size;
                     page += PAGE_SIZE)
                    TdStealthFreePage((PVOID)page);

                {
                    // Refcount-aware: free the shared CR3 only if this was the
                    // last tracked range for the process.
                    UINT64 to_free = TdStealthTrackRemove(p->target_pid, tracked_base);
                    if (to_free)
                        TdShadowFreeCr3(to_free);
                }
                shadow_cr3 = 0;
                flush_shadow_cr3 = 0;
            }
        }

        TdFlushAddressRange(start, protect_size, caller_cr3, flush_shadow_cr3);
        st = STATUS_SUCCESS;

    ShadowProtectExit:
        p->base_va = start;
        p->size = (UINT64)protect_size;
        p->new_protect = new_protect;
        p->shadow_cr3 = shadow_cr3;
        if (p->status == 0)
            p->status = (UINT64)(ULONG)st;
        irp->IoStatus.Information = sizeof(TD_SHADOW_PROTECT_PARAMS);

        KeUnstackDetachProcess(&apc_state);
        ObDereferenceObject(proc);
        break;
    }

    case IOCTL_RESOLVE_EXPORT:
    {
        if (io->Parameters.DeviceIoControl.InputBufferLength < sizeof(TD_RESOLVE_EXPORT_PARAMS) ||
            io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(TD_RESOLVE_EXPORT_PARAMS))
        { st = STATUS_BUFFER_TOO_SMALL; break; }

        TD_RESOLVE_EXPORT_PARAMS * p = (TD_RESOLVE_EXPORT_PARAMS *)irp->AssociatedIrp.SystemBuffer;
        p->messageboxa_va = 0;
        p->sleepex_va = 0;

        if (!p->target_pid)
        {
            st = STATUS_INVALID_PARAMETER;
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_RESOLVE_EXPORT_PARAMS);
            break;
        }

        PEPROCESS proc = NULL;
        st = PsLookupProcessByProcessId((HANDLE)p->target_pid, &proc);
        if (!NT_SUCCESS(st))
        {
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_RESOLVE_EXPORT_PARAMS);
            break;
        }

        KAPC_STATE apc_state;
        KeStackAttachProcess(proc, &apc_state);

        UINT64 pMsgBox = 0;
        UINT64 pSleepEx = 0;
        PVOID user32_base = NULL;
        PVOID kernel32_base = NULL;

        __try {
            user32_base = TdFindModuleBaseA("user32.dll", NULL);
            kernel32_base = TdFindModuleBaseA("kernel32.dll", NULL);

            if (user32_base)
                pMsgBox = (UINT64)TdFindExportByName(user32_base, "MessageBoxA");

            if (kernel32_base)
                pSleepEx = (UINT64)TdFindExportByName(kernel32_base, "SleepEx");
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            HYPERPLATFORM_LOG_ERROR("[td] resolve export: exception walking PEB/exports");
            st = STATUS_UNSUCCESSFUL;
        }

        if (!pMsgBox)
            HYPERPLATFORM_LOG_WARN("[td] resolve export: MessageBoxA not found in user32");
        if (!pSleepEx)
            HYPERPLATFORM_LOG_WARN("[td] resolve export: SleepEx not found in kernel32");

        if (NT_SUCCESS(st) && (!pMsgBox || !pSleepEx))
            st = STATUS_NOT_FOUND;

        p->messageboxa_va = pMsgBox;
        p->sleepex_va = pSleepEx;
        p->status = (UINT64)(ULONG)st;
        irp->IoStatus.Information = sizeof(TD_RESOLVE_EXPORT_PARAMS);

        HYPERPLATFORM_LOG_INFO("[td] resolve export: pid=%llu MessageBoxA=0x%llX SleepEx=0x%llX",
                   p->target_pid, pMsgBox, pSleepEx);

        KeUnstackDetachProcess(&apc_state);
        ObDereferenceObject(proc);
        break;
    }

    case IOCTL_INSTALL_TRIGGER_JUMP:
    {
        if (io->Parameters.DeviceIoControl.InputBufferLength < sizeof(TD_TRIGGER_JUMP_PARAMS) ||
            io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(TD_TRIGGER_JUMP_PARAMS))
        { st = STATUS_BUFFER_TOO_SMALL; break; }

        TD_TRIGGER_JUMP_PARAMS * p =
            (TD_TRIGGER_JUMP_PARAMS *)irp->AssociatedIrp.SystemBuffer;

        if (!p->target_pid || !p->jump_to_va)
        {
            st = STATUS_INVALID_PARAMETER;
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_TRIGGER_JUMP_PARAMS);
            break;
        }

        PEPROCESS proc = NULL;
        st = PsLookupProcessByProcessId((HANDLE)p->target_pid, &proc);
        if (!NT_SUCCESS(st))
        {
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_TRIGGER_JUMP_PARAMS);
            break;
        }

        KAPC_STATE apc_state;
        KeStackAttachProcess(proc, &apc_state);

        PVOID trigger_fn = (PVOID)p->trigger_va;
        if (!trigger_fn)
            trigger_fn = TdResolveDefaultTrigger(proc, "td-trigger");

        if (!trigger_fn)
        {
            HYPERPLATFORM_LOG_ERROR("[td-trigger] cannot resolve trigger function");
            st = STATUS_NOT_FOUND;
        }
        else
        {
            UINT64 caller_cr3 = __readcr3();
            PVOID dummy_origin = NULL;
            UINT64 flags = p->flags ? p->flags : 2;

            st = TdInstallTriggerHookAllCpus(
                trigger_fn, (PVOID)p->jump_to_va, caller_cr3, flags, p->target_tid, &dummy_origin, NULL);

            HYPERPLATFORM_LOG_INFO("[td-trigger] hook %s trigger=%p jump=%p flags=0x%llX st=0x%08X",
                       NT_SUCCESS(st) ? "OK" : "FAILED",
                       trigger_fn, (PVOID)p->jump_to_va, flags, st);

            p->trigger_va = (UINT64)trigger_fn;
        }

        p->status = (UINT64)(ULONG)st;
        irp->IoStatus.Information = sizeof(TD_TRIGGER_JUMP_PARAMS);

        KeUnstackDetachProcess(&apc_state);
        ObDereferenceObject(proc);
        break;
    }

    case IOCTL_GET_MODULE_BASE:
    {
        if (io->Parameters.DeviceIoControl.InputBufferLength < sizeof(TD_GET_MODULE_BASE_PARAMS) ||
            io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(TD_GET_MODULE_BASE_PARAMS))
        { st = STATUS_BUFFER_TOO_SMALL; break; }

        TD_GET_MODULE_BASE_PARAMS * p = (TD_GET_MODULE_BASE_PARAMS *)irp->AssociatedIrp.SystemBuffer;
        p->module_base = 0;
        p->module_size = 0;

        // ensure null-termination
        p->module_name[sizeof(p->module_name) - 1] = '\0';

        if (!p->target_pid || !p->module_name[0])
        {
            st = STATUS_INVALID_PARAMETER;
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_GET_MODULE_BASE_PARAMS);
            break;
        }

        PEPROCESS proc = NULL;
        st = PsLookupProcessByProcessId((HANDLE)p->target_pid, &proc);
        if (!NT_SUCCESS(st))
        {
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_GET_MODULE_BASE_PARAMS);
            break;
        }

        KAPC_STATE apc_state;
        KeStackAttachProcess(proc, &apc_state);

        __try {
            ULONG img_size = 0;
            PVOID base = TdFindModuleBaseA(p->module_name, &img_size);
            if (base)
            {
                p->module_base = (UINT64)base;
                p->module_size = img_size;
            }
            else
            {
                st = STATUS_NOT_FOUND;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            HYPERPLATFORM_LOG_ERROR("[td] get module base: exception walking PEB");
            st = STATUS_UNSUCCESSFUL;
        }

        p->status = (UINT64)(ULONG)st;
        irp->IoStatus.Information = sizeof(TD_GET_MODULE_BASE_PARAMS);

        HYPERPLATFORM_LOG_INFO("[td] get module base: pid=%llu name=%s base=0x%llX size=0x%llX",
                   p->target_pid, p->module_name, p->module_base, p->module_size);

        KeUnstackDetachProcess(&apc_state);
        ObDereferenceObject(proc);
        break;
    }

    case IOCTL_GET_SELF_PE_INFO:
    {
        if (io->Parameters.DeviceIoControl.InputBufferLength < sizeof(TD_GET_SELF_PE_INFO_PARAMS) ||
            io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(TD_GET_SELF_PE_INFO_PARAMS))
        { st = STATUS_BUFFER_TOO_SMALL; break; }

        TD_GET_SELF_PE_INFO_PARAMS * p = (TD_GET_SELF_PE_INFO_PARAMS *)irp->AssociatedIrp.SystemBuffer;
        p->rsrc_rva = 0;
        p->rsrc_size = 0;
        p->export_dir_rva = 0;
        p->export_dir_size = 0;
        p->size_of_image = 0;
        p->status = (UINT64)(ULONG)STATUS_INVALID_PARAMETER;

        // No attach needed: the cache is global driver state keyed by (pid, base).
        if (p->target_pid && p->module_base)
        {
            TD_SELF_PE_INFO_ENTRY entry;
            if (TdLookupSelfPeInfo(p->target_pid, p->module_base, &entry))
            {
                p->rsrc_rva = entry.rsrc_rva;
                p->rsrc_size = entry.rsrc_size;
                p->export_dir_rva = entry.export_dir_rva;
                p->export_dir_size = entry.export_dir_size;
                p->size_of_image = entry.size_of_image;
                p->status = 0;
            }
            else
            {
                p->status = (UINT64)(ULONG)STATUS_NOT_FOUND;
            }
        }

        HYPERPLATFORM_LOG_INFO("[td] get self pe info: pid=%llu base=0x%llX rsrc=0x%llX exp=0x%llX st=%llu",
                   p->target_pid, p->module_base, p->rsrc_rva, p->export_dir_rva, p->status);

        irp->IoStatus.Information = sizeof(TD_GET_SELF_PE_INFO_PARAMS);
        break;
    }

    case IOCTL_HIDE_DEVICE:
    {
        //
        // Hides the device & symlink from user-mode enumeration.
        // Called by version.dll after all init is done - the device is no longer
        // needed (EPT hooks are already installed). TdUnload checks g_device_hidden
        // and skips IoDeleteSymbolicLink / IoDeleteDevice when already torn down.
        //
        g_device_hidden = TRUE;

        UNICODE_STRING sym;
        RtlInitUnicodeString(&sym, TD_SYMLINK_NAME);
        // Best-effort: delete symlink first so namespace enumeration stops seeing
        // it, then delete the device object. Either failure is non-fatal.
        NTSTATUS st1 = IoDeleteSymbolicLink(&sym);
        if (!NT_SUCCESS(st1))
        {
            HYPERPLATFORM_LOG_WARN("[td] hide device: symlink delete failed 0x%08X (may already be removed)", st1);
        }

        if (g_dev_obj)
        {
            IoDeleteDevice(g_dev_obj);
            HYPERPLATFORM_LOG_INFO("[td] device + symlink hidden. IOCTL_HIDE_DEVICE done.");
        }
        else
        {
            HYPERPLATFORM_LOG_WARN("[td] hide device: g_dev_obj is NULL (already hidden?)");
        }

        st = STATUS_SUCCESS;
        break;
    }

    default:
        st = STATUS_INVALID_DEVICE_REQUEST;
        HYPERPLATFORM_LOG_ERROR("[td-ioctl] unhandled IOCTL code=0x%08X", io->Parameters.DeviceIoControl.IoControlCode);
        break;
    }

    HYPERPLATFORM_LOG_INFO("[td-ioctl] exit: code=0x%08X st=0x%08lX info=%llu",
        io->Parameters.DeviceIoControl.IoControlCode,
        (ULONG)st, (ULONGLONG)irp->IoStatus.Information);

    irp->IoStatus.Status = st;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return st;
}

// =========================================================================
//  stealth inject tracking + process exit cleanup
// =========================================================================

//
// free param struct 鈥?must match Ophion's EPT_STEALTH_FREE_PARAM
//
#pragma pack(push, 8)
typedef struct _TD_STEALTH_FREE_PARAM {
    UINT64  caller_cr3;
    PVOID   target_va;
    UINT64  target_phys;
    volatile LONG freed;
    BOOLEAN result;
} TD_STEALTH_FREE_PARAM;
#pragma pack(pop)

//
// track stealth inject allocations for process exit cleanup
//
#define MAX_STEALTH_TRACKS 64
typedef struct _STEALTH_TRACK_ENTRY {
    BOOLEAN active;
    UINT64  target_pid;
    PVOID   target_va;
    SIZE_T  alloc_size;
    UINT64  shadow_cr3_phys;
} STEALTH_TRACK_ENTRY;

static STEALTH_TRACK_ENTRY g_stealth_tracks[MAX_STEALTH_TRACKS] = {};
static KSPIN_LOCK g_stealth_track_lock;

static BOOLEAN
TdStealthTrackAdd(UINT64 pid, PVOID va, SIZE_T size, UINT64 shadow_cr3)
{
    BOOLEAN added = FALSE;
    KIRQL old_irql;
    KeAcquireSpinLock(&g_stealth_track_lock, &old_irql);

    for (int i = 0; i < MAX_STEALTH_TRACKS; i++)
    {
        if (!g_stealth_tracks[i].active)
        {
            g_stealth_tracks[i].target_pid  = pid;
            g_stealth_tracks[i].target_va   = va;
            g_stealth_tracks[i].alloc_size  = size;
            g_stealth_tracks[i].shadow_cr3_phys = shadow_cr3;
            g_stealth_tracks[i].active      = TRUE;
            added = TRUE;
            break;
        }
    }

    // AddRef the shared CR3 while still holding the track lock (matches Remove's
    // Release-under-lock) so a concurrent Remove on another range cannot drop the
    // refcount to 0 and free the CR3 before this range's ref is recorded.
    if (added)
        TdShadowCr3AddRef(shadow_cr3);

    KeReleaseSpinLock(&g_stealth_track_lock, old_irql);
    return added;
}

static UINT64
TdStealthTrackRemove(UINT64 pid, PVOID va)
{
    UINT64 shadow_cr3 = 0;
    UINT64 to_free = 0;
    KIRQL old_irql;
    KeAcquireSpinLock(&g_stealth_track_lock, &old_irql);

    for (int i = 0; i < MAX_STEALTH_TRACKS; i++)
    {
        if (g_stealth_tracks[i].active &&
            g_stealth_tracks[i].target_pid == pid &&
            g_stealth_tracks[i].target_va == va)
        {
            shadow_cr3 = g_stealth_tracks[i].shadow_cr3_phys;
            RtlZeroMemory(&g_stealth_tracks[i], sizeof(g_stealth_tracks[i]));
            break;
        }
    }

    // Release the shared CR3's refcount under the track lock. If this was the
    // last range, to_free is set and the caller frees via TdShadowFreeCr3
    // OUTSIDE the lock (it does PASSIVE page/MDL freeing).
    if (shadow_cr3)
        TdShadowCr3Release(shadow_cr3, &to_free);

    KeReleaseSpinLock(&g_stealth_track_lock, old_irql);
    return to_free;
}

// Find the (shared) shadow CR3 for a process, if any range is already tracked.
// All ranges of a process share one shadow CR3 (multi-range per process).
// NOTE: returns the cr3 without AddRef'ing; callers must not race a concurrent
// remove on the same pid (renderdoc's protect/restore is single-threaded per
// process). Hardening for concurrent multi-threaded range ops is a follow-up.
static UINT64
TdStealthFindShadowCr3ForPid(UINT64 pid)
{
    UINT64 shadow_cr3 = 0;
    KIRQL old_irql;
    KeAcquireSpinLock(&g_stealth_track_lock, &old_irql);
    for (int i = 0; i < MAX_STEALTH_TRACKS; i++)
    {
        if (g_stealth_tracks[i].active && g_stealth_tracks[i].target_pid == pid)
        {
            shadow_cr3 = g_stealth_tracks[i].shadow_cr3_phys;
            break;
        }
    }
    KeReleaseSpinLock(&g_stealth_track_lock, old_irql);
    return shadow_cr3;
}

static BOOLEAN
TdStealthTrackFindOverlap(UINT64 pid, PVOID base_va, SIZE_T size, PVOID * out_base, SIZE_T * out_size, UINT64 * out_shadow_cr3)
{
    if (!size)
        return FALSE;

    BOOLEAN found = FALSE;
    UINT64 req_base = (UINT64)base_va;
    if (req_base > (~0ULL - size))
        return FALSE;
    UINT64 req_end = req_base + size;

    KIRQL old_irql;
    KeAcquireSpinLock(&g_stealth_track_lock, &old_irql);

    for (int i = 0; i < MAX_STEALTH_TRACKS; i++)
    {
        STEALTH_TRACK_ENTRY * entry = &g_stealth_tracks[i];
        if (!entry->active || entry->target_pid != pid)
            continue;

        UINT64 base = (UINT64)entry->target_va;
        UINT64 end = base + entry->alloc_size;
        if (req_base < end && req_end > base)
        {
            if (out_base) *out_base = entry->target_va;
            if (out_size) *out_size = entry->alloc_size;
            if (out_shadow_cr3) *out_shadow_cr3 = entry->shadow_cr3_phys;
            found = TRUE;
            break;
        }
    }

    KeReleaseSpinLock(&g_stealth_track_lock, old_irql);
    return found;
}

static BOOLEAN
TdStealthTrackHasPartialOverlap(UINT64 pid, PVOID base_va, SIZE_T size)
{
    if (!size)
        return FALSE;

    UINT64 req_base = (UINT64)base_va;
    if (req_base > (~0ULL - size))
        return TRUE;
    UINT64 req_end = req_base + size;
    BOOLEAN partial = FALSE;

    KIRQL old_irql;
    KeAcquireSpinLock(&g_stealth_track_lock, &old_irql);

    for (int i = 0; i < MAX_STEALTH_TRACKS; i++)
    {
        STEALTH_TRACK_ENTRY * entry = &g_stealth_tracks[i];
        if (!entry->active || entry->target_pid != pid)
            continue;

        UINT64 base = (UINT64)entry->target_va;
        UINT64 end = base + entry->alloc_size;
        if (req_base < end && req_end > base &&
            (base < req_base || end > req_end))
        {
            partial = TRUE;
            break;
        }
    }

    KeReleaseSpinLock(&g_stealth_track_lock, old_irql);
    return partial;
}

//
// free one stealth page via DPC broadcast 鈫?VMCALL_STEALTH_FREE
// must be called while attached to the target process.
//
static BOOLEAN
TdStealthFreePage(PVOID target_va)
{
    if (!target_va) return FALSE;
    UINT64 phys = MmGetPhysicalAddress(target_va).QuadPart;
    // phys may be 0 if page already freed/paged 鈥?still try VMCALL with VA match
    TD_STEALTH_FREE_PARAM req = {};
    req.caller_cr3  = __readcr3();
    req.target_va   = target_va;
    req.target_phys = phys;

    KeGenericCallDpc([](PKDPC, PVOID Ctx, PVOID A1, PVOID A2) {
        hv_vmcall_simple(VMCALL_STEALTH_FREE, (UINT64)Ctx, 0, 0);
        KeSignalCallDpcSynchronize(A2);
        KeSignalCallDpcDone(A1);
    }, &req);
    return req.result;
}

//
// process exit callback 鈥?clean up stealth pages + fake PT before
// MiDeleteFinalPageTables destroys the address space.
//
static VOID
TdCleanupStealthForProcess(PEPROCESS Process, UINT64 pid)
{
    //
    // 0. retire (passthrough) this process's EPT hooks on the shared d3d12/dxgi
    //    pages. Without this, the hooks (and their proxy pointers) survive exit
    //    and the NEXT Box process gets dispatched to THIS process's freed proxy
    //    during its own hook re-install window -> 0xC0000005 (confirmed: the
    //    crash RIP was the prior run's CreateDXGIFactory2 proxy). VMCALL_EPT_UNHOOK
    //    can't be used here (it loads the dying CR3 on every CPU and deadlocks
    //    in the exit callback), so use the CR3-free VMCALL_EPT_UNHOOK_BY_CR3.
    //    The VMCALL does not switch CR3, so it is safe to issue from here.
    //
    {
        KAPC_STATE apc;
        KeStackAttachProcess(Process, &apc);
        UINT64 dying_cr3 = __readcr3();
        KeUnstackDetachProcess(&apc);

        struct { UINT64 target_cr3; } rctx;
        rctx.target_cr3 = dying_cr3;
        KeGenericCallDpc(DpcEptUnhookByCr3, &rctx);
    }

    //
    // 1. clean up R3 EPT hooks for this process (unlock MDL pages, free trampoline)
    //
    for (int i = 0; i < MAX_R3_HOOKS; i++)
    {
        if (!g_r3_hooks[i].active || g_r3_hooks[i].target_pid != pid)
            continue;

        HYPERPLATFORM_LOG_INFO("[td-rw] process exit cleanup R3 hook: pid=%llu target=%p",
                   pid, g_r3_hooks[i].target_va);

        // snapshot before teardown (ZwFreeVirtualMemory zeroes trampoline_va).
        PVOID   trampoline_va = g_r3_hooks[i].trampoline_va;
        SIZE_T  trampoline_sz = g_r3_hooks[i].trampoline_size;
        PMDL    target_mdl    = g_r3_hooks[i].target_mdl;

        // The hypervisor-side EPT hook on the shared d3d12/dxgi page is NOT
        // unhooked here. VMCALL_EPT_UNHOOK switches CR3 to the (dying) process
        // on every CPU via KeGenericCallDpc, which deadlocks when issued from
        // the process-exit notify callback (one CPU never reaches
        // KeSignalCallDpcDone -> caller blocks forever). The hook is CR3-filtered
        // (ept_hook.cpp target_cr3 check), so it is inert for every other
        // process, and the next Box process repoints it (existing-entry update
        // path) on re-install. Full unhook happens on driver unload
        // (TdEptUnhookAllR3 -> ept_unhook_all).

        // attach: trampoline stealth-page free + trampoline free need the
        // process address space, still valid at exit-notify time.
        KAPC_STATE apc;
        KeStackAttachProcess(Process, &apc);

        // free the trampoline stealth page (registered in TdEptHookR3 via
        // TdStealthAllocPage with target_pid=0, so NOT in g_stealth_tracks and
        // never freed before). Without this the sp leaks in g_ept->stealth_pages
        // referencing this process's soon-freed shadow CR3. VMCALL_STEALTH_FREE
        // does not switch CR3, so it is safe from the exit callback. Must run
        // while the trampoline page is still mapped (before ZwFreeVirtualMemory).
        if (trampoline_va)
            TdStealthFreePage((PVOID)((UINT64)trampoline_va & ~0xFFFULL));

        // free trampoline memory
        if (trampoline_va != NULL && trampoline_sz > 0)
            ZwFreeVirtualMemory(ZwCurrentProcess(), &trampoline_va, &trampoline_sz, MEM_RELEASE);

        KeUnstackDetachProcess(&apc);

        // unlock target page MDL
        if (target_mdl != NULL)
        {
            MmUnlockPages(target_mdl);
            IoFreeMdl(target_mdl);
        }

        RtlZeroMemory(&g_r3_hooks[i], sizeof(g_r3_hooks[i]));
    }

    //
    // 2. clean up stealth tracks (shadow memory)
    //
    for (int i = 0; i < MAX_STEALTH_TRACKS; i++)
    {
        PVOID va = NULL;
        SIZE_T sz = 0;

        KIRQL old_irql;
        KeAcquireSpinLock(&g_stealth_track_lock, &old_irql);

        if (g_stealth_tracks[i].active && g_stealth_tracks[i].target_pid == pid)
        {
            va = g_stealth_tracks[i].target_va;
            sz  = g_stealth_tracks[i].alloc_size;
        }

        KeReleaseSpinLock(&g_stealth_track_lock, old_irql);

        if (!va || !sz)
            continue;

        HYPERPLATFORM_LOG_INFO("[td-rw] process exit cleanup: pid=%llu va=%p size=0x%llX",
                   pid, va, (UINT64)sz);

        // Remove the tracked range. TdStealthTrackRemove decrements the shared
        // CR3's refcount and returns the CR3 only if this was the last range for
        // the process, so the shared shadow CR3 is freed once per process.
        UINT64 to_free = TdStealthTrackRemove(pid, va);

        // attach to the exiting process to free stealth pages
        KAPC_STATE apc;
        KeStackAttachProcess(Process, &apc);

        UINT64 base = (UINT64)va & ~0xFFFULL;
        UINT64 end  = ((UINT64)va + sz + PAGE_SIZE - 1) & ~0xFFFULL;
        for (UINT64 page = base; page < end; page += PAGE_SIZE)
            TdStealthFreePage((PVOID)page);

        if (to_free)
            TdShadowFreeCr3(to_free);

        KeUnstackDetachProcess(&apc);

        HYPERPLATFORM_LOG_INFO("[td-rw] process exit cleanup done: pid=%llu", pid);
    }
}

// =========================================================================
//  TdLoadImageNotify 鈥?fires when a DLL is loaded in any process
// =========================================================================
//
// When user32.dll loads in a recorded target (Box.exe), we inject renderdoc.dll
// directly using the NtTestAlert EPT trigger + shadow CR3 mechanism.
//
static VOID
TdLoadImageNotify(PUNICODE_STRING ImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
    UNREFERENCED_PARAMETER(ImageInfo);

    if (!ImageName || !ImageName->Buffer || !g_loadimage_registered || !g_inject_target_lock_init)
        return;

    // extract basename
    const WCHAR * buf = ImageName->Buffer;
    USHORT len = ImageName->Length / sizeof(WCHAR);
    USHORT base_off = 0;
    for (USHORT i = 0; i < len; i++)
        if (buf[i] == L'\\') base_off = (USHORT)(i + 1);
    USHORT base_len = (USHORT)(len - base_off);

    // check if it's "d3d12.dll" (late enough that renderdoc's imports
    // user32/gdi32/ole32/dxgi/d3d11/dbghelp/etc. are all already in the PEB
    // LDR, so TdPeResolveImports can fill the whole IAT before DllMain runs)
    static const WCHAR kD3d12[] = L"d3d12.dll";
    static const USHORT kD3d12Len = (USHORT)((sizeof(kD3d12) / sizeof(WCHAR)) - 1);
    if (base_len != kD3d12Len) return;
    for (USHORT i = 0; i < kD3d12Len; i++)
    {
        WCHAR ca = buf[base_off + i], cb = kD3d12[i];
        if (ca >= L'a' && ca <= L'z') ca -= 32;
        if (cb >= L'a' && cb <= L'z') cb -= 32;
        if (ca != cb) return;
    }

    // claim target and get stored exe path
    WCHAR exe_path_buf[MAX_PATH];
    if (!TdInjectTargetClaim(ProcessId, exe_path_buf, MAX_PATH))
        return;

    // build renderdoc path from the exe path:
    //   "\??\C:\dir\Box.exe" -> "\??\C:\dir\renderdoc.dll"
    WCHAR renderdoc_path_buf[MAX_PATH];
    USHORT last_slash = 0;
    USHORT src_chars = 0;
    for (; src_chars < MAX_PATH && exe_path_buf[src_chars]; src_chars++)
    {
        renderdoc_path_buf[src_chars] = exe_path_buf[src_chars];
        if (exe_path_buf[src_chars] == L'\\') last_slash = (USHORT)(src_chars + 1);
    }
    static const WCHAR kRenderdoc[] = L"renderdoc.dll";
    USHORT rd_chars = (USHORT)((sizeof(kRenderdoc) / sizeof(WCHAR)) - 1);
    if ((ULONG)last_slash + rd_chars + 1 > MAX_PATH) return;
    for (USHORT i = 0; i < rd_chars; i++)
        renderdoc_path_buf[last_slash + i] = kRenderdoc[i];
    renderdoc_path_buf[last_slash + rd_chars] = L'\0';

    UNICODE_STRING renderdoc_nt;
    RtlInitUnicodeString(&renderdoc_nt, renderdoc_path_buf);

    HYPERPLATFORM_LOG_INFO("[td-inj] d3d12 loaded in target pid=%llu -- injecting renderdoc directly (shadow CR3)",
        (UINT64)ProcessId);

    // lookup process
    PEPROCESS proc = NULL;
    NTSTATUS st = PsLookupProcessByProcessId(ProcessId, &proc);
    if (!NT_SUCCESS(st) || !proc)
    {
        HYPERPLATFORM_LOG_ERROR("[td-inj] PsLookupProcessByProcessId failed: 0x%08X", st);
        return;
    }

    // inject
    st = TdInjectRenderdocShadow(proc, &renderdoc_nt, "td-inj-shadow", FALSE);
    if (!NT_SUCCESS(st))
    {
        HYPERPLATFORM_LOG_ERROR("[td-inj] TdInjectRenderdocShadow failed: 0x%08X", st);
    }

    ObDereferenceObject(proc);
}

static VOID
TdProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    if (CreateInfo != NULL)
    {
        // process creation -- record target for later injection
        if (g_inject_target_lock_init && CreateInfo->ImageFileName)
        {
            if (TdInjectMatchBasename(CreateInfo->ImageFileName, L"Box.exe", 7))
                TdInjectTargetAdd(ProcessId, CreateInfo->ImageFileName);
        }
        return;
    }
    // process exit -- cleanup stealth
    NTSTATUS exit_st = PsGetProcessExitStatus(Process);
    HYPERPLATFORM_LOG_INFO("[td-rw] process exit: pid=%llu exit_status=0x%08X",
        (UINT64)ProcessId, (UINT32)exit_st);
    TdCleanupStealthForProcess(Process, (UINT64)ProcessId);
    TdCleanupSelfPeInfo((UINT64)ProcessId);

    // re-arm CreateFile("test") injection: if this is the Box.exe we injected,
    // clear the recorded pid so the next Box.exe (even one reusing this pid)
    // injects again. Idempotent - no-op if this pid wasn't the injected one.
    _InterlockedCompareExchange64(&g_test_injected_pid, 0, (LONG64)ProcessId);
}

static VOID
TdProcessNotifyLegacy(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
{
    UNREFERENCED_PARAMETER(ParentId);

    if (Create) return;

    PEPROCESS proc = NULL;
    NTSTATUS st = PsLookupProcessByProcessId(ProcessId, &proc);
    if (!NT_SUCCESS(st))
    {
        HYPERPLATFORM_LOG_WARN("[td-rw] legacy process exit cleanup lookup failed: pid=%llu st=0x%08X",
            (UINT64)ProcessId, st);
        return;
    }

    NTSTATUS exit_st = PsGetProcessExitStatus(proc);
    HYPERPLATFORM_LOG_INFO("[td-rw] legacy process exit: pid=%llu exit_status=0x%08X",
        (UINT64)ProcessId, (UINT32)exit_st);

    TdCleanupStealthForProcess(proc, (UINT64)ProcessId);
    TdCleanupSelfPeInfo((UINT64)ProcessId);

    // re-arm CreateFile("test") injection for the next Box.exe (see TdProcessNotify).
    _InterlockedCompareExchange64(&g_test_injected_pid, 0, (LONG64)ProcessId);
    ObDereferenceObject(proc);
}

// =========================================================================
//  driver entry / unload
// =========================================================================

PDEVICE_OBJECT g_dev_obj = NULL;
BOOLEAN g_device_hidden = FALSE;

static VOID TdUnload(PDRIVER_OBJECT drv)
{
    if (g_process_notify_registered)
    {
        if (g_process_notify_ex_registered)
            PsSetCreateProcessNotifyRoutineEx(TdProcessNotify, TRUE);
        else
            PsSetCreateProcessNotifyRoutine(TdProcessNotifyLegacy, TRUE);
        g_process_notify_registered = FALSE;
        g_process_notify_ex_registered = FALSE;
    }

    // [已禁用] 不再通过 LoadImage 回调注入 renderdoc，改为 NtCreateFile hook 触发
    //if (g_loadimage_registered)
    //{
    //    PsRemoveLoadImageNotifyRoutine(TdLoadImageNotify);
    //    g_loadimage_registered = FALSE;
    //}

    if (g_hooked_target)
    {
        HYPERPLATFORM_LOG_INFO("[td] Unhooking R0 hook before unload...");
        TdEptUnhookNtCreateFile();
    }

    TdEptUnhookAllR3();

    if (!g_device_hidden)
    {
        UNICODE_STRING sym;
        RtlInitUnicodeString(&sym, TD_SYMLINK_NAME);
        IoDeleteSymbolicLink(&sym);
        if (drv->DeviceObject) IoDeleteDevice(drv->DeviceObject);
    }

    HYPERPLATFORM_LOG_INFO("[td] Unloaded (device_hidden=%u).", g_device_hidden);
    LogTermination();
}

extern "C"
// DKOM: unlink this driver from PsLoadedModuleList so EnumDeviceDrivers /
// NtQuerySystemInformation(SystemModuleInformation) can't enumerate it.
// DriverObject->DriverSection points to the kernel LDR_DATA_TABLE_ENTRY.
// Links are set to self after unlinking so RemoveEntryList on unload is a
// no-op (safe). Must be called AFTER all init (MmGetSystemRoutineAddress,
// IoCreateDevice, etc.) so those APIs find the driver while it's set up.
#ifndef TD_HIDE_DRIVER
#define TD_HIDE_DRIVER 1
#endif
#if TD_HIDE_DRIVER
static VOID TdHideFromPsLoadedModuleList(PDRIVER_OBJECT drv)
{
    PTD_LDR_ENTRY ldr = (PTD_LDR_ENTRY)drv->DriverSection;
    if (!ldr) return;
    // PsLoadedModuleList links kernel modules ONLY via InLoadOrderLinks.
    // InMemoryOrderLinks / InInitializationOrderLinks are NOT initialized by
    // MiLoadSystemImage for kernel modules - they hold stale pool data, so
    // unlinking them dereferences garbage and BSODs. Only unlink
    // InLoadOrderLinks, then self-link so RemoveEntryList on unload is a no-op.
    PLIST_ENTRY e = &ldr->InLoadOrderLinks;          // PsLoadedModuleList
    e->Blink->Flink = e->Flink; e->Flink->Blink = e->Blink;
    e->Flink = e; e->Blink = e;
}
#endif

NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg)
{
    UNREFERENCED_PARAMETER(reg);
    KeInitializeSpinLock(&g_shadow_alloc_lock);
    KeInitializeSpinLock(&g_stealth_track_lock);
    KeInitializeSpinLock(&g_inject_target_lock);
    g_inject_target_lock_init = TRUE;
    KeInitializeSpinLock(&g_SelfPeInfoLock);
    g_SelfPeInfoLockInit = TRUE;

    //
    // init log system 鈥?file output, truncate on load
    //
    static const wchar_t kLogFilePath[] = L"\\SystemRoot\\T.log";
    auto log_status = LogInitialization(kLogPutLevelDebug, kLogFilePath);
    if (log_status == STATUS_REINITIALIZATION_NEEDED)
        LogRegisterReinitialization(drv);

    UNICODE_STRING fn;
    // try NtCreateThreadEx first (more likely exported), then ZwCreateThreadEx
    RtlInitUnicodeString(&fn, L"NtCreateThreadEx");
    g_pZwCreateThreadEx = (fn_ZwCreateThreadEx)MmGetSystemRoutineAddress(&fn);
    if (!g_pZwCreateThreadEx)
    {
        RtlInitUnicodeString(&fn, L"ZwCreateThreadEx");
        g_pZwCreateThreadEx = (fn_ZwCreateThreadEx)MmGetSystemRoutineAddress(&fn);
    }
    // resolve ZwResumeThread via MmGetSystemRoutineAddress (exported)
    RtlInitUnicodeString(&fn, L"NtResumeThread");
    g_pZwResumeThread = (fn_ZwResumeThread)MmGetSystemRoutineAddress(&fn);
    if (!g_pZwResumeThread)
    {
        RtlInitUnicodeString(&fn, L"ZwResumeThread");
        g_pZwResumeThread = (fn_ZwResumeThread)MmGetSystemRoutineAddress(&fn);
    }
    if (!g_pZwResumeThread)
        g_pZwResumeThread = (fn_ZwResumeThread)TdResolveNtoskrnlExport("NtResumeThread");
    if (!g_pZwResumeThread)
        g_pZwResumeThread = (fn_ZwResumeThread)TdResolveNtoskrnlExport("ZwResumeThread");

    // resolve PsResumeThread and KeResumeThread via ntoskrnl export table walk
    // (Blackbone-style 鈥?these are not in MmGetSystemRoutineAddress's table)
    g_pPsResumeThread = (fn_PsResumeThread)TdResolveNtoskrnlExport("PsResumeThread");
    g_pKeResumeThread = (fn_KeResumeThread)TdResolveNtoskrnlExport("KeResumeThread");

    HYPERPLATFORM_LOG_INFO("[td] thread APIs: create=%p zw_resume=%p ps_resume=%p ke_resume=%p",
        g_pZwCreateThreadEx, g_pZwResumeThread, g_pPsResumeThread, g_pKeResumeThread);

    UNICODE_STRING dev_name, sym_name;
    RtlInitUnicodeString(&dev_name, TD_DEVICE_NAME);
    RtlInitUnicodeString(&sym_name, TD_SYMLINK_NAME);

    PDEVICE_OBJECT dev = NULL;
    NTSTATUS st = IoCreateDevice(drv, 0, &dev_name,
        FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &dev);
    if (!NT_SUCCESS(st)) return st;
    g_dev_obj = dev;

    st = IoCreateSymbolicLink(&sym_name, &dev_name);
    if (!NT_SUCCESS(st)) { IoDeleteDevice(dev); return st; }

    drv->DriverUnload = TdUnload;
    drv->MajorFunction[IRP_MJ_CREATE] = TdCreateClose;
    drv->MajorFunction[IRP_MJ_CLOSE]  = TdCreateClose;
    drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = TdIoControl;

    //
    // register process exit notification for stealth page cleanup.
    // prevents BSOD in MiDeleteFinalPageTables when fake PT is active.
    //
    NTSTATUS notify_st = PsSetCreateProcessNotifyRoutineEx(TdProcessNotify, FALSE);
    if (NT_SUCCESS(notify_st))
    {
        g_process_notify_registered = TRUE;
        g_process_notify_ex_registered = TRUE;
        HYPERPLATFORM_LOG_INFO("[td] Process notify callback registered (Ex).");
    }
    else
    {
        HYPERPLATFORM_LOG_WARN("[td] PsSetCreateProcessNotifyRoutineEx failed: 0x%08X", notify_st);
        NTSTATUS legacy_st = PsSetCreateProcessNotifyRoutine(TdProcessNotifyLegacy, FALSE);
        if (NT_SUCCESS(legacy_st))
        {
            g_process_notify_registered = TRUE;
            g_process_notify_ex_registered = FALSE;
            HYPERPLATFORM_LOG_INFO("[td] Process notify callback registered (legacy).");
        }
        else
        {
            HYPERPLATFORM_LOG_ERROR("[td] PsSetCreateProcessNotifyRoutine legacy failed: 0x%08X", legacy_st);
        }
    }

    // [已注释] 不再使用 LoadImage 通知注入 renderdoc，改为 HookedNtCreateFile 触发
    //if (g_process_notify_registered)
    //{
    //    NTSTATUS li_st = PsSetLoadImageNotifyRoutine(TdLoadImageNotify);
    //    if (NT_SUCCESS(li_st))
    //    {
    //        g_loadimage_registered = TRUE;
    //        HYPERPLATFORM_LOG_INFO("[td] LoadImage notify registered (driver-side injection armed).");
    //    }
    //}

    // 自动安装 NtCreateFile EPT hook（不再依赖 Injector 发 IOCTL）
    {
        NTSTATUS hook_st = TdEptHookNtCreateFile();
        if (NT_SUCCESS(hook_st))
            HYPERPLATFORM_LOG_INFO("[td] NtCreateFile EPT hook installed (CreateFile(\"test\") triggers renderdoc inject).");
        else
            HYPERPLATFORM_LOG_WARN("[td] NtCreateFile EPT hook failed: 0x%08X (manual IOCTL may be needed)", hook_st);
    }
    //    NTSTATUS li_st = PsSetLoadImageNotifyRoutine(TdLoadImageNotify);
    //    if (NT_SUCCESS(li_st))
    //    {
    //        g_loadimage_registered = TRUE;
    //        HYPERPLATFORM_LOG_INFO("[td] LoadImage notify registered (driver-side injection armed).");
    //    }
    //}


#if TD_HIDE_DRIVER
    // DKOM: hide this driver from PsLoadedModuleList (after all init).
    TdHideFromPsLoadedModuleList(drv);
#endif

    HYPERPLATFORM_LOG_INFO("[td] Loaded. Device: %wZ", &sym_name);
    return STATUS_SUCCESS;
}

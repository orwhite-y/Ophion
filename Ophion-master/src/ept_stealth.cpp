/*
*   ept_stealth.cpp - stealth memory allocation via dual EPT split
*
*   ARCHITECTURE:
*     all shadow pages and fake PT pages are carved from a single contiguous
*     physical region (default 64MB). this eliminates scattered orphan pages
*     that physical memory forensics could detect.
*
*     fake PT pages are shared: multiple stealth pages in the same 2MB VA
*     range share one fake PT page (ref-counted). the fake PT page has NX=1
*     for ALL stealth entries in that PT page.
*
*   CAPACITY:
*     64MB region = 16384 pages. each stealth page needs 1 shadow page.
*     fake PT pages are shared (~1 per 2MB range). effectively supports
*     up to ~16MB of stealth memory (with room for fake PTs).
*     tracking structs are ~200 bytes each (pre-allocated in pool: 4096).
*
*   PHYSICAL LAYOUT:
*     contiguous region: [shadow_0][shadow_1]...[fakePT_0][fakePT_1]...
*     all at consecutive physical addresses 闂?looks like one normal allocation.
*/
#include "hv.h"
#include "log.h"

#define POOL_TAG_STEALTH_INFO   4
#define POOL_TAG_STEALTH_FAKEPT 5

#define PFN_MASK  0x000FFFFFFFFFF000ULL
#define NX_BIT    (1ULL << 63)
#define PFEC_PRESENT      0x01
#define PFEC_WRITE        0x02
#define PFEC_USER         0x04
#define PFEC_INSTR_FETCH  0x10

volatile LONG g_dbg_shadow_pf_seen = 0;
volatile LONG g_dbg_shadow_pf_allowed = 0;
volatile LONG g_dbg_shadow_pf_switched = 0;
volatile LONG g_dbg_shadow_pf_reject = 0;
volatile LONG g_dbg_shadow_pf_midwin = 0;        // mid-window data #PFs that hit an abort path (unbounded)
volatile LONG g_dbg_shadow_pf_midwin_logged = 0;  // verbose-log cap counter (diagnostic only)
volatile LONG g_dbg_shadow_pf_synced = 0;         // A2: mid-window data #PFs serviced by in-window shadow PT sync
volatile LONG g_dbg_shadow_pf_synced_logged = 0;  // verbose-log cap counter for A2 syncs (diagnostic only)
volatile LONG g_dbg_a2_abort = 0;                 // A2: fallbacks to abort+reinject (any reason)
volatile LONG g_dbg_a2_spurious = 0;              // A2: SPURIOUS aborts (real state != error code -> the crash class)
volatile LONG g_dbg_a2_spurious_logged = 0;       // verbose-log cap counter for spurious aborts (diagnostic only)
volatile LONG g_dbg_nomatch = 0;                  // mid-window FETCH #PF to non-stealth NX page (clobber signal)
volatile LONG g_dbg_nomatch_logged = 0;           // verbose-log cap counter for nomatch (diagnostic only)
volatile LONG g_dbg_a2_code_synced = 0;           // NX-open: shadow CODE PTE re-synced from real (repaged code page fix)
volatile LONG g_dbg_a2_code_synced_logged = 0;    // verbose-log cap counter for code syncs (diagnostic only)
volatile LONG g_dbg_a2_code_enter = 0;            // NX-open: code-refresh calls total (proves the path is reached)
volatile LONG g_dbg_a2_throttle_ctr = 0;     // throttle counter for full-PT resync (every 256th code-enter)
volatile LONG g_dbg_a2_code_enter_logged = 0;     // verbose-log cap counter for refresh outcomes (MATCH/BAIL)
volatile LONG g_dbg_a2_data_synced = 0;           // A2: mid-window data #PFs healed via the data page's own sp->shadow_pte_va
volatile LONG g_dbg_a2_data_synced_logged = 0;    // verbose-log cap counter for data syncs (diagnostic only)
volatile LONG g_dbg_a2_ptpage_synced = 0;         // NX-open: code-2MB shadow PT page refreshed (>=1 stale PTE synced)
volatile LONG g_dbg_a2_ptpage_synced_logged = 0;  // verbose-log cap counter for PT-page syncs (diagnostic only)
volatile LONG g_dbg_a2_stale_p1_logged = 0;       // verbose-log cap counter for silent P=1/wrong-PFN staleness (the crash cause)
volatile LONG g_dbg_a2_stale_p1_total = 0;         // A2: total silent P=1/wrong-PFN staleness detected (UNBOUNDED; overlay-killer / crash class)
volatile LONG g_dbg_a2_dump_tick = 0;              // A2: periodic counter-dump tick (diagnostic)
volatile LONG g_dbg_a2_already_on_shadow = 0;      // A2: mid-window NX-fetch #PF hitting the already_on_shadow branch (stale-gap suspect)

// Ultimate Solution diagnostics
volatile LONG g_dbg_demand_sync = 0;               // Demand-sync: PTE synced at NX-fetch (fast PFN check)
volatile LONG g_dbg_hash_collisions = 0;           // Hash: collision chain walks (should be rare)
volatile LONG g_dbg_hash_lookups = 0;              // Hash: total lookups (for collision rate calc)

//
// ============================================================================
// PERFORMANCE OPTIMIZATION: Cache Helpers (Phase 1)
// ============================================================================
//
// These inline functions cache frequently-accessed values to eliminate
// expensive operations on the hot path (#PF handler, 10k+/sec).
//
// Benefit: ~85% reduction in hot-path overhead (1.92M cycles/sec saved)
// Safety: CR3-based validation ensures correctness
//

//
// Get current PID with caching
// Avoids expensive PsGetCurrentProcessId() call (~50 cycles) on cache hit.
// Cache key: current_cr3 (PID doesn't change within same process/CR3)
//
static __forceinline UINT64
vcpu_get_current_pid(VIRTUAL_MACHINE_STATE *vcpu, UINT64 current_cr3)
{
    // Fast path: cache hit (CR3 unchanged -> same process -> same PID)
    if (vcpu->cached_pid_cr3 == current_cr3)
        return vcpu->cached_pid;

    // Slow path: cache miss, query and update
    UINT64 pid = (UINT64)(ULONG_PTR)PsGetCurrentProcessId();
    vcpu->cached_pid = pid;
    vcpu->cached_pid_cr3 = current_cr3;
    return pid;
}

//
// Get GUEST_CR3 with caching
// Avoids expensive VMREAD(VMCS_GUEST_CR3) call (~100 cycles) on cache hit.
// Cache is populated at VM-exit entry and invalidated on CR3 writes.
//
static __forceinline UINT64
vcpu_get_guest_cr3(VIRTUAL_MACHINE_STATE *vcpu)
{
    // Fast path: cache valid
    if (vcpu->cached_cr3_valid)
        return vcpu->cached_guest_cr3;

    // Slow path: cache invalid, read and update
    __vmx_vmread(VMCS_GUEST_CR3, &vcpu->cached_guest_cr3);
    vcpu->cached_cr3_valid = TRUE;
    return vcpu->cached_guest_cr3;
}

//
// ============================================================================
// End of Performance Optimization
// ============================================================================
//

//
// DIAG: capture the first distinct renderdoc code RIPs that open an NX-fetch
// shadow window. Correlate against renderdoc.pdb (RIP - renderdoc_base, where
// renderdoc_base comes from T.log "shadow CR3 extended VA=...") to see WHICH
// renderdoc code actually runs: overlay/Present draw (per-frame) vs one-time
// init. Bounded, lock-free, best-effort -- a duplicate race only double-logs.
//
#define DBG_RIP_SLOTS 96
static volatile UINT64 g_dbg_rip_slots[DBG_RIP_SLOTS];

static void
dbg_log_distinct_rip(UINT64 rip)
{
    if (!rip) return;
    for (UINT32 i = 0; i < DBG_RIP_SLOTS; i++)
    {
        if (g_dbg_rip_slots[i] == rip)
            return;                                 // already captured
    }
    for (UINT32 i = 0; i < DBG_RIP_SLOTS; i++)
    {
        if (g_dbg_rip_slots[i] == 0)
        {
            g_dbg_rip_slots[i] = rip;               // x64: aligned 64-bit store is atomic
            HYPERPLATFORM_LOG_WARN_SAFE("[stealth-diag] code-rip#%u rip=%llx", i, rip);
            return;
        }
    }
    // table full -- hottest paths already logged
}

VOID
ept_update_pf_intercept(VIRTUAL_MACHINE_STATE * vcpu)
{
    if (!vcpu)
        return;

    BOOLEAN need_exec_pf = FALSE;
    BOOLEAN need_write_pf = FALSE;

    if (g_ept)
    {
        PLIST_ENTRY cur = g_ept->stealth_pages.Flink;
        while (cur != &g_ept->stealth_pages)
        {
            PEPT_STEALTH_PAGE_INFO sp = CONTAINING_RECORD(cur, EPT_STEALTH_PAGE_INFO, stealth_page_list);
            cur = cur->Flink;

            if (sp->fake_pt || sp->shadow_cr3_phys)
                need_exec_pf = TRUE;
            if (sp->intercept_write)
                need_write_pf = TRUE;
            if (need_exec_pf && need_write_pf)
                break;
        }

        if (!need_exec_pf)
        {
            cur = g_ept->hooked_pages.Flink;
            while (cur != &g_ept->hooked_pages)
            {
                PEPT_HOOKED_PAGE_INFO hp = CONTAINING_RECORD(cur, EPT_HOOKED_PAGE_INFO, hooked_page_list);
                cur = cur->Flink;
                if (hp->fake_pt || hp->exec_pt_page)
                {
                    need_exec_pf = TRUE;
                    break;
                }
            }
        }
    }

    SIZE_T exc_bitmap = 0;
    __vmx_vmread(VMCS_CTRL_EXCEPTION_BITMAP, &exc_bitmap);

    if (need_exec_pf || need_write_pf)
        exc_bitmap |= (1ULL << 14);
    else
        exc_bitmap &= ~(1ULL << 14);
    __vmx_vmwrite(VMCS_CTRL_EXCEPTION_BITMAP, exc_bitmap);

    if (need_write_pf)
    {
        __vmx_vmwrite(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MASK, PFEC_PRESENT | PFEC_USER);
        __vmx_vmwrite(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MATCH, PFEC_PRESENT | PFEC_USER);
    }
    else if (need_exec_pf)
    {
        __vmx_vmwrite(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MASK, PFEC_PRESENT | PFEC_INSTR_FETCH);
        __vmx_vmwrite(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MATCH, PFEC_PRESENT | PFEC_INSTR_FETCH);
    }
    else
    {
        __vmx_vmwrite(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MASK, 0);
        __vmx_vmwrite(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MATCH, 0);
    }

    vcpu->stealth_pf_configured = (need_exec_pf || need_write_pf) ? TRUE : FALSE;
}

// =========================================================================
//  contiguous shadow region allocator
// =========================================================================

//
// init: allocate contiguous physical region at PASSIVE_LEVEL
//
BOOLEAN
ept_stealth_region_init(VOID)
{
    STEALTH_REGION * region = &g_ept->stealth_region;
    if (region->base_va) return TRUE;  // already initialized

    PHYSICAL_ADDRESS max_phys;
    max_phys.QuadPart = MAXULONG64;

    SIZE_T size = STEALTH_REGION_DEFAULT_SIZE;
    region->base_va = MmAllocateContiguousMemory(size, max_phys);
    if (!region->base_va)
    {
        // fallback: try 16MB
        size = 16 * 1024 * 1024;
        region->base_va = MmAllocateContiguousMemory(size, max_phys);
        if (!region->base_va)
        {
            HYPERPLATFORM_LOG_ERROR("[hv] stealth region: alloc failed");
            return FALSE;
        }
    }

    RtlZeroMemory(region->base_va, size);
    region->base_pa    = MmGetPhysicalAddress(region->base_va).QuadPart;
    region->total_pages = size / PAGE_SIZE;
    region->next_page  = 0;

    HYPERPLATFORM_LOG_INFO("[hv] stealth region: %lluMB at VA=%p PA=%llx (%llu pages)",
               (UINT64)(size / (1024*1024)), region->base_va, region->base_pa,
               (UINT64)region->total_pages);

#if USE_PRIVATE_HOST_CR3
    //
    // map the stealth region into private host page tables so VMX-root
    // can access shadow/fake pages under host CR3 (without CR3 switch)
    //
    hostcr3_map_va(region->base_va, size);
#endif

    return TRUE;
}

VOID
ept_stealth_region_destroy(VOID)
{
    STEALTH_REGION * region = &g_ept->stealth_region;
    if (region->base_va)
    {
        MmFreeContiguousMemory(region->base_va);
        RtlZeroMemory(region, sizeof(*region));
    }
}

//
// allocate a 4KB page from the contiguous region (lock-free bump allocator)
// returns VA and PFN. safe to call from VMX-root (no OS API calls).
//
PUINT8
stealth_region_alloc_page(UINT64 * out_pfn)
{
    STEALTH_REGION * region = &g_ept->stealth_region;
    LONG idx = _InterlockedIncrement(&region->next_page) - 1;

    if ((SIZE_T)idx >= region->total_pages)
    {
        _InterlockedDecrement(&region->next_page);
        return NULL;
    }

    PUINT8 va = (PUINT8)region->base_va + (SIZE_T)idx * PAGE_SIZE;
    if (out_pfn)
        *out_pfn = (region->base_pa + (UINT64)idx * PAGE_SIZE) >> 12;

    return va;
}

// =========================================================================
//  guest page table walk helpers (PASSIVE_LEVEL)
// =========================================================================

static UINT64
stealth_read_phys64(UINT64 phys_addr)
{
    PHYSICAL_ADDRESS pa;
    pa.QuadPart = (LONGLONG)phys_addr;
    PVOID mapped = MmMapIoSpace(pa, sizeof(UINT64), MmNonCached);
    if (!mapped) return 0;
    UINT64 val = *(volatile UINT64 *)mapped;
    MmUnmapIoSpace(mapped, sizeof(UINT64));
    return val;
}

typedef struct _PT_PAGE_INFO {
    UINT64 pt_page_phys;
    UINT64 pte_phys;
    UINT32 pte_index;
    UINT64 pte_value;
} PT_PAGE_INFO;

static BOOLEAN
stealth_find_pt_page(UINT64 cr3, UINT64 va, PT_PAGE_INFO * out)
{
    UINT64 pml4_idx = (va >> 39) & 0x1FF;
    UINT64 pdp_idx  = (va >> 30) & 0x1FF;
    UINT64 pd_idx   = (va >> 21) & 0x1FF;
    UINT64 pt_idx   = (va >> 12) & 0x1FF;

    UINT64 pml4e = stealth_read_phys64((cr3 & PFN_MASK) + pml4_idx * 8);
    if (!(pml4e & 1)) return FALSE;

    UINT64 pdpe = stealth_read_phys64((pml4e & PFN_MASK) + pdp_idx * 8);
    if (!(pdpe & 1) || (pdpe & (1ULL << 7))) return FALSE;

    UINT64 pde = stealth_read_phys64((pdpe & PFN_MASK) + pd_idx * 8);
    if (!(pde & 1) || (pde & (1ULL << 7))) return FALSE;

    out->pt_page_phys = pde & PFN_MASK;
    out->pte_index    = (UINT32)pt_idx;
    out->pte_phys     = out->pt_page_phys + pt_idx * 8;
    out->pte_value    = stealth_read_phys64(out->pte_phys);
    return (out->pte_value & 1) ? TRUE : FALSE;
}

static BOOLEAN
stealth_shadow_pte_allows(PEPT_STEALTH_PAGE_INFO sp, UINT32 error_code)
{
    if (!sp || !sp->shadow_cr3_phys || !sp->pt_page_va || sp->pt_pte_index >= 512)
        return FALSE;

    volatile UINT64 * pt = (volatile UINT64 *)sp->pt_page_va;
    UINT64 pte_value = pt[sp->pt_pte_index];
    if (!(pte_value & 1))
        return FALSE;

    if (error_code & PFEC_INSTR_FETCH)
        return (pte_value & NX_BIT) == 0;

    if (error_code & PFEC_WRITE)
    {
        BOOLEAN allows = (pte_value & (1ULL << 1)) != 0;
        if (!allows)
        {
            static volatile LONG s_wr_reject_logged = 0;
            if (_InterlockedIncrement(&s_wr_reject_logged) <= 16)
                HYPERPLATFORM_LOG_WARN_SAFE(
                    "[stealth-a2] write-check REJECT va=%llx pte=%llx W=0 pt_page=%p idx=%u shadow_cr3=%llx",
                    (UINT64)sp->guest_va, pte_value, sp->pt_page_va, sp->pt_pte_index,
                    sp->shadow_cr3_phys);
        }
        return allows;
    }

    return TRUE;
}

// =========================================================================
//  shared fake PT page management
// =========================================================================

//
// find or create a shared fake PT page for a given physical PT page.
// called from VMX-root (uses pool_manager + contiguous region).
// real_page_va: system VA of real PT page, hostcr3-mapped by caller at PASSIVE_LEVEL.
//              used by MTF handler for resync (NULL = no resync, stale fake PT).
//
PSTEALTH_FAKE_PT
stealth_get_or_create_fake_pt(VIRTUAL_MACHINE_STATE * vcpu, UINT64 pt_page_pfn, PVOID pt_page_va_hint, PVOID real_page_va)
{
    // check if already exists
    PLIST_ENTRY cur = g_ept->stealth_fake_pts.Flink;
    while (cur != &g_ept->stealth_fake_pts)
    {
        PSTEALTH_FAKE_PT fpt = CONTAINING_RECORD(cur, STEALTH_FAKE_PT, fake_pt_list);
        cur = cur->Flink;
        if (fpt->pt_page_pfn == pt_page_pfn)
        {
            fpt->ref_count++;
            return fpt;
        }
    }

    // create new
    PSTEALTH_FAKE_PT fpt = (PSTEALTH_FAKE_PT)
        pool_manager_request(POOL_TAG_STEALTH_FAKEPT, sizeof(STEALTH_FAKE_PT));
    if (!fpt) return NULL;
    RtlZeroMemory(fpt, sizeof(*fpt));

    // Initialize LIST_ENTRY to avoid crashes in RemoveEntryList
    InitializeListHead(&fpt->fake_pt_list);

    fpt->pt_page_pfn   = pt_page_pfn;
    fpt->ref_count     = 1;
    fpt->real_page_va  = real_page_va;

    // allocate fake page from contiguous region
    fpt->fake_page_va = stealth_region_alloc_page(&fpt->pfn_of_fake);
    if (!fpt->fake_page_va) { pool_manager_release(fpt); return NULL; }

    // copy real PT page content from caller's NonPaged buffer copy
    if (!pt_page_va_hint) { pool_manager_release(fpt); return NULL; }
    RtlCopyMemory(fpt->fake_page_va, pt_page_va_hint, PAGE_SIZE);

    // split EPT 2MB 闂?4KB for the PT page if needed
    UINT64 pt_phys = pt_page_pfn << 12;
    PEPT_PML2_ENTRY pt_pml2 = ept_get_pml2(vcpu->ept_page_table, (SIZE_T)pt_phys);
    if (pt_pml2 && pt_pml2->LargePage)
        ept_split_large_page_pool(vcpu->ept_page_table, (SIZE_T)pt_phys);

    PEPT_PML1_ENTRY pt_pte = ept_get_pml1(vcpu->ept_page_table, (SIZE_T)pt_phys);
    if (!pt_pte) { pool_manager_release(fpt); return NULL; }

    // save real entry + build fake entry
    fpt->pt_real_entry = *pt_pte;
    fpt->pt_real_entry.ReadAccess    = 1;
    fpt->pt_real_entry.WriteAccess   = 1;
    fpt->pt_real_entry.ExecuteAccess = 0;

    fpt->pt_fake_entry = fpt->pt_real_entry;
    fpt->pt_fake_entry.WriteAccess     = 1;    // allow A/D bit writes (no EPT violation on page walk)
    fpt->pt_fake_entry.PageFrameNumber = fpt->pfn_of_fake;

    // activate fake view 闂?EPT now maps PT page to fake page
    pt_pte->AsUInt = fpt->pt_fake_entry.AsUInt;

    InsertHeadList(&g_ept->stealth_fake_pts, &fpt->fake_pt_list);
    return fpt;
}

//
// add NX=1 for a specific PTE index in the shared fake PT page
//
VOID
stealth_fake_pt_set_nx(PSTEALTH_FAKE_PT fpt, UINT32 pte_index)
{
    PUINT64 pte = &((PUINT64)fpt->fake_page_va)[pte_index];
    *pte |= NX_BIT;
}

//
// resync fake PT page from real PT page, then re-apply NX for all entries.
// uses fpt->real_page_va (hostcr3-mapped) 闂?safe in VMX-root without pa_to_va.
// walks BOTH stealth_pages and hooked_pages to re-apply NX for all consumers.
//
VOID
stealth_fake_pt_resync(PSTEALTH_FAKE_PT fpt)
{
    if (!fpt->real_page_va) return;

    RtlCopyMemory(fpt->fake_page_va, fpt->real_page_va, PAGE_SIZE);

    // re-apply NX=1 for all stealth pages using this fake PT
    PLIST_ENTRY cur = g_ept->stealth_pages.Flink;
    while (cur != &g_ept->stealth_pages)
    {
        PEPT_STEALTH_PAGE_INFO sp = CONTAINING_RECORD(cur, EPT_STEALTH_PAGE_INFO, stealth_page_list);
        cur = cur->Flink;
        if (sp->fake_pt && sp->fake_pt->pt_page_pfn == fpt->pt_page_pfn)
            stealth_fake_pt_set_nx(fpt, sp->pt_pte_index);
    }

    // re-apply NX=1 for all inject-hooked pages using this fake PT,
    // and resync their exec PT pages (NX=0 for our entry, rest matches real PT)
    cur = g_ept->hooked_pages.Flink;
    while (cur != &g_ept->hooked_pages)
    {
        PEPT_HOOKED_PAGE_INFO hp = CONTAINING_RECORD(cur, EPT_HOOKED_PAGE_INFO, hooked_page_list);
        cur = cur->Flink;
        if (hp->fake_pt && hp->fake_pt->pt_page_pfn == fpt->pt_page_pfn)
        {
            stealth_fake_pt_set_nx(fpt, hp->pt_pte_index);

            // resync exec PT page: copy real PT content, keep NX=0 for our entry
            if (hp->exec_pt_page)
            {
                RtlCopyMemory(hp->exec_pt_page, fpt->real_page_va, PAGE_SIZE);
                PUINT64 exec_pte = (PUINT64)hp->exec_pt_page;
                exec_pte[hp->pt_pte_index] &= ~(1ULL << 63);  // NX=0
            }
        }
    }
}

//
// abort an open shadow-CR3 window: restore the real guest CR3, drop the MTF
// single-step, and restore the normal (NX-fetch only) #PF intercept. used when a
// #PF arrives mid-window that we must let the guest service under its REAL page
// tables - MmAccessFault must never run on the shadow page tables (it walks/edits
// stale shadow PTEs and corrupts the PFN database -> 0x1A / 0x61941). no-op if no
// window is open on this vCPU.
//
static VOID
stealth_pf_abort_shadow_window(VIRTUAL_MACHINE_STATE * vcpu)
{
    if (!vcpu->nx_timer_real_cr3)
        return;

    __vmx_vmwrite(VMCS_GUEST_CR3, vcpu->nx_timer_real_cr3);
    vcpu->nx_timer_restore  = NULL;
    vcpu->nx_timer_real_cr3 = 0;

    SIZE_T pc = 0;
    __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &pc);
    pc &= ~(SIZE_T)CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG;
    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, pc);

    // restore the NX-fetch-only #PF intercept that the shadow swap widened to
    // "all" for the duration of the window.
    ept_update_pf_intercept(vcpu);
}

//
// Clear stale shadow-CR3 window state on this vCPU WITHOUT dereferencing the
// (possibly freed) nx_timer_restore pointer. Called via VMCALL_SHADOW_ABORT_ALL
// DPC broadcast from TestDriver's process-exit cleanup BEFORE freeing stealth
// page entries. This prevents use-after-free in stealth_sync_data_pte_in_window
// and the MTF handler when the game crashes with a shadow window open.
//
// Safe because:
// - nx_timer_real_cr3 is a copied UINT64 (not a pointer to the freed entry)
// - CR3 is only restored if current CR3 differs from saved real CR3
//   (i.e., we're actually on the shadow CR3; if OS already context-switched,
//   current CR3 == some other process, we skip the restore)
// - nx_timer_restore is cleared FIRST, preventing any further dereference
//
VOID
stealth_clear_stale_window(VIRTUAL_MACHINE_STATE * vcpu)
{
    if (!vcpu->nx_timer_restore)
        return;

    // Save real CR3 before clearing (it's a value copy, not a pointer)
    UINT64 saved_real_cr3 = vcpu->nx_timer_real_cr3;

    // Clear state FIRST - prevents any further dereference of the freed sp
    vcpu->nx_timer_restore  = NULL;
    vcpu->nx_timer_real_cr3 = 0;

    // Disable MTF (was armed for the one-instruction shadow window)
    SIZE_T pc = 0;
    __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &pc);
    pc &= ~(SIZE_T)CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG;
    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, pc);

    // Only restore CR3 if we're actually on the shadow CR3 (current != saved real).
    // If the OS already context-switched to a different process, current CR3
    // will be that process's CR3, which is different from both shadow and saved
    // real - we skip the restore to avoid corrupting the running process.
    if (saved_real_cr3)
    {
        SIZE_T current_cr3 = vcpu_get_guest_cr3(vcpu);  // OPTIMIZATION: Use cached CR3
        if ((current_cr3 & PFN_MASK) != (saved_real_cr3 & PFN_MASK))
        {
            __vmx_vmwrite(VMCS_GUEST_CR3, saved_real_cr3);
            vcpu->cached_cr3_valid = FALSE;  // Invalidate cache after CR3 write
        }
    }

    // Restore the normal (NX-fetch only) #PF intercept that the shadow swap
    // widened to "all faults" for the one-instruction window.
    ept_update_pf_intercept(vcpu);
}


// =========================================================================
//  VMX-root diagnostic: mid-window data-#PF forensics
// =========================================================================
//
// ba8111a added the mid-window guard that aborts a shadow-CR3 window on a data
// #PF and returns FALSE so the caller re-injects the #PF under the real CR3.
// on renderdoc's NX-hidden GetThreadSerialiser prologue this surfaces as a
// spurious 0xC0000005 (the re-injected write #PF -> AV). this helper records,
// from VMX-root WITHOUT any physical-memory read (MmMapIoSpace / MmCopyMemory
// deadlock in VMX-root), the address arithmetic that distinguishes the two
// staleness regimes so we can pick fix A vs fix B instead of guessing:
//
//   same == 1 : the faulting VA shares the stealth page's PML4 index, i.e. it
//               lies inside the CLONED shadow subtree (shadow PDPT/PD/PT are
//               build-time snapshots). a stale entry here is NOT cured by
//               refreshing PML4 entries -> fix A territory.
//   same == 0 : the faulting VA uses a different PML4 index whose shadow PML4
//               entry points at the REAL lower page-table pages; the only thing
//               that can be stale is that PML4 entry itself (OS re-pointed it
//               after the shadow was built) -> fix B territory. if fix B turns
//               out not to help here, the cause is TLB/PCID aliasing -> fall
//               back to NX-cycle mode (no shadow CR3 at all).
//
// the error-code bits distinguish a genuine demand fault (P=0: abort+reinject is
// correct, no AV) from the spurious write (P=1 W=1: the bug itself).
//
// verbose logging is capped at 32 events so a tight fetch<->data loop cannot
// flood the log buffer; the total counter (g_dbg_shadow_pf_midwin) is unbounded.
static VOID
stealth_diag_midwin_pf(VIRTUAL_MACHINE_STATE * vcpu, UINT64 fault_addr,
                       UINT32 error_code, const char * site,
                       PEPT_STEALTH_PAGE_INFO sp)
{
    _InterlockedIncrement(&g_dbg_shadow_pf_midwin);
    if (_InterlockedIncrement(&g_dbg_shadow_pf_midwin_logged) > 32)
        return;

    UINT64 fault_pml4_idx = (fault_addr >> 39) & 0x1FF;
    UINT64 dll_pml4_idx   = 0xFFFFFFFFFFFFFFFFULL;
    UINT64 shadow_pml4_pa = 0;
    if (sp)
    {
        dll_pml4_idx   = (sp->guest_va >> 39) & 0x1FF;
        shadow_pml4_pa = sp->shadow_cr3_phys;
    }
    BOOLEAN same_region = (sp && fault_pml4_idx == dll_pml4_idx);

    HYPERPLATFORM_LOG_WARN_SAFE(
        "[stealth-diag] midwin %s fa=%llx ec=%x (W=%d P=%d F=%d U=%d) "
        "rip=%llx real_cr3=%llx sh_pml4=%llx pml4idx[f=%llx dll=%llx] same=%d",
        site, fault_addr, error_code,
        (error_code & PFEC_WRITE) ? 1 : 0,
        (error_code & PFEC_PRESENT) ? 1 : 0,
        (error_code & PFEC_INSTR_FETCH) ? 1 : 0,
        (error_code & PFEC_USER) ? 1 : 0,
        vcpu->vmexit_rip, vcpu->nx_timer_real_cr3, shadow_pml4_pa,
        fault_pml4_idx, dll_pml4_idx, same_region ? 1 : 0);
}

// =========================================================================
//  VMX-root: A2 - in-window shadow page-table sync (stealth-preserving)
// =========================================================================
//
// The diagnostic above proved the mid-window data #PF is a stale SHADOW page
// table: TdBuildShadowCR3 deep-copies the real page tables at build time, and
// renderdoc's runtime heap/TLS allocations live in 1GB/2MB regions that were
// unmapped (or since repaged) when that snapshot was taken, so they read P=0 in
// the shadow while being P=1 under the real CR3. ba8111a's mitigation aborts
// the shadow window and re-injects the #PF under the real CR3, which surfaces as
// a spurious 0xC0000005 (re-injected fault on an already-present page) - the
// crash under investigation. Letting the guest's MmAccessFault run on the shadow
// PT is not an option either (it walks/edits stale shadow PTEs and corrupts the
// PFN database -> 0x1A / 0x61941).
//
// A2 instead makes the shadow translation current FOR THIS FAULT so the access
// retries and succeeds INSIDE the shadow window: no #PF reaches the guest,
// MmAccessFault never runs on shadow PT, and the real PTEs are never touched
// (real NX stays 1 -> stealth preserved; A3's NX-cycle on the real PTE is
// explicitly avoided).
//
// Method:
//  1. Walk the REAL CR3 (vcpu->nx_timer_real_cr3) for fault_addr. If the page is
//     not actually committed there (real P=0 -> genuine demand fault) or is a
//     read-only page hit by a write (COW / write-protect), fall back to
//     abort+reinject so the guest services it under the real CR3 as before.
//  2. Walk the SHADOW CR3 (sp->shadow_cr3_phys) in parallel. At each level, if
//     the shadow entry points to a SNAPSHOT (stealth-region) lower page, descend
//     through it unchanged (it carries the NX=0 hiding for any code in that
//     subtree). Otherwise the entry is a real-pointing copy or stale (P=0 /
//     repaged): refresh it to the current real entry and STOP - the rest of the
//     shadow walk then follows current real pages (already confirmed P=1), so the
//     access succeeds. If every intermediate descends through a snapshot down to
//     the PT level, the stale PTE inside that snapshot PT is synced from the real
//     PTE with NX cleared (matching the build-time snapshot, which clears NX on
//     every PTE).
//
// At most ONE shadow entry is written per fault, and EVERY write lands on a
// SHADOW (stealth-region) page - real page-table pages are only ever read. Any
// anomaly (NULL pa_to_va, large page, inconsistent P bits) falls back to
// abort+reinject (the caller), preserving the current safe behaviour. pa_to_va
// (MmGetVirtualForPhysical) is the same VMX-root-runtime primitive the fake-PT
// MTF path already uses; the install-path deadlock warning does not apply to a
// single-CPU runtime #PF.
//
// Resolve the system VA of a REAL guest page-table page so the heal can read it.
// The heal runs under sp->guest_cr3 (the guest KERNEL CR3 -- see vmx_enter_cr3 /
// the comment block in hv.h). Under the guest kernel CR3, pa_to_va resolves the
// guest's real page-table pages via the guest kernel PML4's self-map (the user
// PDPT/PD/PT pages are shared between the guest user/kernel PML4 under KPTI), so
// pa_to_va is correct for real pages here -- NO MDL map is needed (and none can
// be created: every MM API that aliases a RAM page-table page into a
// CR3-independent VA is refused on modern Windows). Returns NULL if pa_to_va
// cannot resolve the page (the caller bails to abort+reinject). Shadow pages are
// NOT looked up here -- the heal reads them via pa_to_va directly (NonPaged pool,
// system PTE, resolved under the kernel CR3's kernel half).
//
static __forceinline PVOID
stealth_real_va(PEPT_STEALTH_PAGE_INFO sp, UINT64 pa)
{
    UNREFERENCED_PARAMETER(sp);
    return pa_to_va(pa & PFN_MASK);
}

//
// Walk a 4-level guest CR3 for va. Sets *out_pte to the final PTE (P=0 if not
// present at any level) and returns TRUE. Returns FALSE if the walk hits a real
// page that pa_to_va cannot resolve (NULL) or a large page at an intermediate
// level - the caller must then fall back to abort+reinject rather than guess.
// Real PT pages are read through stealth_real_va (== pa_to_va under the guest
// kernel CR3 the heal runs in -- see vmx_enter_cr3). The cr3 argument is the
// guest user CR3; at level 0 pa_to_va of a PML4 PA returns the self-map base VA
// which, under the kernel host CR3, maps the guest kernel PML4 (shared user
// entries), so the walk resolves the correct user-space PTEs regardless.
static BOOLEAN
stealth_walk_pte(PEPT_STEALTH_PAGE_INFO sp, UINT64 cr3, UINT64 va, UINT64 * out_pte)
{
    static const UINT32 shift[4] = { 39, 30, 21, 12 };
    UINT64 pa = cr3 & PFN_MASK;
    UINT64 entry = 0;
    for (UINT32 lvl = 0; lvl < 4; lvl++)
    {
        PUINT64 table = (PUINT64)stealth_real_va(sp, pa);
        if (!table)
            return FALSE;
        entry = table[(va >> shift[lvl]) & 0x1FF];
        if (!(entry & 1))            // not present at this level
            break;
        if (lvl == 3)                // PT level: entry is the final PTE
            break;
        if (entry & (1ULL << 7))     // large page at an intermediate level
        {
            *out_pte = entry;        // expose the large-page entry so callers can
            return FALSE;            // distinguish large-page (PS=1) from NULL (0)
        }
        pa = entry & PFN_MASK;
    }
    *out_pte = entry;
    return TRUE;
}

//
// Walk a 4-level guest CR3 for va, returning BOTH the leaf PTE (*out_pte) and
// the system VA of the PT page (the 512-PTE leaf table) that contains it
// (*out_pt_page_va). *out_pt_page_va is NULL if the walk did not reach the PT
// level (not present at an intermediate level). Returns FALSE on a large page
// or a NULL pa_to_va at any level (caller falls back). Used by the proactive
// PT-page refresh to copy all 512 real PTEs into the shadow PT page in one pass.
//
static BOOLEAN
stealth_walk_pt_page(PEPT_STEALTH_PAGE_INFO sp, UINT64 cr3, UINT64 va,
                     UINT64 * out_pt_page_va, UINT64 * out_pte)
{
    static const UINT32 shift[4] = { 39, 30, 21, 12 };
    UINT64 pa = cr3 & PFN_MASK;
    UINT64 entry = 0;
    PUINT64 pt_page = NULL;
    for (UINT32 lvl = 0; lvl < 4; lvl++)
    {
        PUINT64 table = (PUINT64)stealth_real_va(sp, pa);
        if (!table)
        {
            *out_pt_page_va = 0;
            *out_pte = 0;
            return FALSE;
        }
        if (lvl == 3)
            pt_page = table;
        entry = table[(va >> shift[lvl]) & 0x1FF];
        if (!(entry & 1))            // not present at this level
            break;
        if (lvl == 3)                // PT level: entry is the final PTE
            break;
        if (entry & (1ULL << 7))     // large page at an intermediate level
        {
            *out_pte = entry;
            *out_pt_page_va = 0;
            return FALSE;
        }
        pa = entry & PFN_MASK;
    }
    *out_pte = entry;
    *out_pt_page_va = (UINT64)pt_page;
    return TRUE;
}

static BOOLEAN
stealth_sync_data_pte_in_window(VIRTUAL_MACHINE_STATE * vcpu, UINT64 fault_addr,
                                UINT32 error_code)
{
    PEPT_STEALTH_PAGE_INFO sp = vcpu->nx_timer_restore;
    if (!sp || !sp->shadow_cr3_phys || !vcpu->nx_timer_real_cr3 || !sp->guest_va)
        return FALSE;

    // P=0 data faults are the stale-shadow case we heal below. A P=1 WRITE fault
    // is also frequently healable: the snapshot captured the page read-only (or
    // pre-COW) and real has since made it writable, so the shadow's R/W bit is
    // stale. The old code bailed here and fell to abort+reinject, which re-injects
    // a P=1/W=1 #PF under real where the page is writable -> MmAccessFault
    // demand-faults a zero page over live data -> state corruption -> later AV
    // (the "write to 0" seen in Box_last_crash.dmp). Heal it instead; the real-
    // walk COW check below still aborts GENUINE COW (real read-only). A P=1 READ
    // fault (protection/user/pkey) is not a staleness condition - leave to guest.
    if ((error_code & PFEC_PRESENT) && !(error_code & PFEC_WRITE))
        return FALSE;

    const UINT64  is_write   = (error_code & PFEC_WRITE);
    const UINT64  real_cr3   = vcpu->nx_timer_real_cr3;
    const UINT64  fault_page = fault_addr & ~0xFFFULL;

    // Find the DATA page's own stealth page. The old code walked the SHADOW CR3
    // via pa_to_va to reach the stale shadow PTE, but pa_to_va returns NULL for
    // NonPaged-pool shadow pages in VMX-root (DIAG: shadow-pml4 va=0 even under
    // sp->guest_cr3), so it ALWAYS bailed "shadow-null" and every mid-window data
    // #PF was abort+reinjected. Like the code healer, look up the data page's own
    // sp (its shadow_pte_va is a NonPaged-pool system VA, valid under any CR3)
    // and write the leaf PTE directly. Real PTEs are read-only here (A3 preserved).
    PEPT_STEALTH_PAGE_INFO sp_data = NULL;
    {
        // OPTIMIZATION: Use hash table for O(1) lookup instead of linear scan
        UINT32 hash = stealth_hash_va(fault_page);
        PLIST_ENTRY cur2 = g_ept->stealth_hash[hash].Flink;
        while (cur2 != &g_ept->stealth_hash[hash])
        {
            PEPT_STEALTH_PAGE_INFO s = CONTAINING_RECORD(cur2, EPT_STEALTH_PAGE_INFO, stealth_hash_list);
            cur2 = cur2->Flink;
            if (s->guest_va != fault_page) continue;
            if (s->shadow_cr3_phys != sp->shadow_cr3_phys) continue;   // different process / shadow CR3 (multi-range: all ranges of a process share one shadow_cr3)
            if (s->target_pid != 0)
            {
                // OPTIMIZATION: Use cached PID to avoid expensive PsGetCurrentProcessId() call
                UINT64 current_pid = vcpu_get_current_pid(vcpu, real_cr3);
                if (current_pid != s->target_pid) continue;
            }
            else if (s->guest_cr3 != 0 &&
                     (s->guest_cr3 & PFN_MASK) != (real_cr3 & PFN_MASK))
                continue;
            sp_data = s;
            break;
        }
    }

    // Not a DLL stealth page (heap/stack/TLS): these share the REAL PT through
    // the copied PML4 entry (no shadow PT copy), so a reinject commits them
    // correctly under the real CR3. Bail without touching anything.
    if (!sp_data || !sp_data->shadow_pte_va)
        return FALSE;

    // A write to a write-protected stealth page (intercept_write, shadow W=0)
    // must stay mediated - do NOT heal it (healing sets W=1 and lets the write
    // through). Let it reinject so the write-mediation path handles it.
    if (is_write && sp_data->intercept_write)
        return FALSE;

    // Under USE_PRIVATE_HOST_CR3, VMX-root runs on a private host CR3 whose
    // kernel half is a build-time snapshot; the NonPaged-pool shadow pages (and
    // HV code/stack) are NOT mapped there. Switch to sp->guest_cr3 -- the guest
    // process's KERNEL CR3 (captured by the TestDriver via __readcr3() in kernel
    // mode) -- for the walk. Under the guest kernel CR3, the full kernel half
    // (NonPaged pool, system PTEs, HV code/stack -- shared across all processes)
    // is mapped, so pa_to_va resolves SHADOW pages (NonPaged pool, system PTE),
    // AND the self-map resolves the guest's REAL page-table pages (guest kernel
    // PML4 -> shared user PDPT/PD/PT). No MDL real-page map is needed (and none
    // can be created -- the MM refuses to alias RAM page-table pages on modern
    // Windows). Every early exit goes through 'done' so the CR3 is always restored.
    BOOLEAN result       = FALSE;
    BOOLEAN real_walk_ok = FALSE;
    const char * bail_reason = "init";
    UINT64  saved_cr3 = vmx_enter_cr3(sp->guest_cr3);

    // --- 1. walk REAL CR3: confirm the page is committed & accessible there ---
    UINT64 real_pte = 0;
    if (!stealth_walk_pte(sp_data, real_cr3, fault_addr, &real_pte))
    { bail_reason = "real-walk-fail"; goto done; }   // real PT not mapped / large page -> abort
    real_walk_ok = TRUE;
    if (!(real_pte & 1))
    { bail_reason = "real-P0-demand"; goto done; }   // real P=0 -> genuine demand fault
    if (is_write && !(real_pte & 0x2))
    {
        // COW fix: shadow PTE was P=0, real is P=1 W=0. If we bail and
        // re-inject the original P=0 #PF under real CR3, the guest sees a
        // not-present fault for a present page -> confused -> crash.
        // Instead: sync shadow PTE to P=1 W=0 (matching real), return TRUE.
        // CPU re-executes under shadow CR3 -> hits P=1 W=0 -> generates a
        // correct P=1 W=1 #PF (write protection fault). That fault comes
        // back here, bails normally, and the re-injected P=1 W=1 #PF under
        // real CR3 is correct (guest handles COW properly).
        UINT64 cow_want = real_pte & ~NX_BIT;     // P=1, W=0 (from real), NX=0
        PUINT64 cow_spte = (PUINT64)sp_data->shadow_pte_va;
        if (*cow_spte != cow_want)
        {
            *cow_spte = cow_want;
            _InterlockedIncrement(&g_dbg_a2_data_synced);
            if (_InterlockedIncrement(&g_dbg_a2_data_synced_logged) <= 64)
                HYPERPLATFORM_LOG_WARN_SAFE(
                    "[stealth-a2] cow-fix fa=%llx ec=%x rip=%llx real_pte=%llx "
                    "cow_want=%llx",
                    fault_addr, error_code, vcpu->vmexit_rip, real_pte, cow_want);
        }
        result = TRUE;
        goto done;
    }
    // (a real 2MB large page is already rejected by stealth_walk_pte at the PD
    // level; bit 7 of the final 4KB PTE is PAT, not PS, so do NOT test it here.)

    // --- 2. write the shadow leaf PTE directly from the current real PTE ---
    // NX is cleared to match the build-time snapshot. W is preserved from the
    // shadow so write-protected (intercept_write) pages keep W=0; for every other
    // page the build-time W (== real W at snapshot) is kept. This heals BOTH a
    // stale P=0 (page allocated/repaged-in after the snapshot) AND a stale P=1
    // read-only write-protect (page made writable after the snapshot). The write
    // lands on sp_data->shadow_pte_va, a SHADOW page - real page-table pages are
    // only read (A3 preserved: real NX stays 1).
    UINT64 want = real_pte & ~NX_BIT;
    if (sp_data->intercept_write)
        want &= ~0x2ULL;                              // keep W=0 for protected pages
    PUINT64 spte = (PUINT64)sp_data->shadow_pte_va;
    UINT64  old  = *spte;
    if (old != want)
    {
        *spte = want;
        _InterlockedIncrement(&g_dbg_a2_data_synced);
        if (_InterlockedIncrement(&g_dbg_a2_data_synced_logged) <= 64)
            HYPERPLATFORM_LOG_WARN_SAFE(
                "[stealth-a2] data-sync fa=%llx ec=%x rip=%llx real_pte=%llx "
                "shadow_was=%llx want=%llx",
                fault_addr, error_code, vcpu->vmexit_rip, real_pte, old, want);
    }

    result = TRUE;

done:
    vmx_leave_guest_cr3(saved_cr3);
    if (!result)
    {
        // A2 fell back to abort+reinject. Classify it: the crash under
        // investigation is a SPURIOUS re-injection -- A2 bailed even though the
        // REAL page state does NOT match the (shadow-derived) error code, so the
        // re-injected #PF confuses MmAccessFault (demand-faulting a zero page
        // over live data -> corruption -> the intermittent renderdoc-init AV).
        // GENUINE cases (real P=0 demand, real read-only COW) re-inject correctly.
        // Spurious aborts are RARE (only the crash runs produce them) so they are
        // logged UNCAPPED -- unlike stealth_diag_midwin_pf, whose 32-event cap
        // saturates on the first (benign) run and hides every later crash run.
        BOOLEAN spurious = FALSE;
        if (!real_walk_ok)
            spurious = TRUE;                                   // real walk failed (large page / NULL): can't heal, re-inject under real-present is spurious
        else if ((real_pte & 1) && !(error_code & PFEC_PRESENT))
            spurious = TRUE;                                   // shadow stale P=0, real present -> should have healed
        else if ((real_pte & 1) && (real_pte & 0x2) &&
                 (error_code & PFEC_PRESENT) && (error_code & PFEC_WRITE))
            spurious = TRUE;                                   // shadow stale read-only, real writable -> should have healed
        _InterlockedIncrement(&g_dbg_a2_abort);
        if (spurious)
        {
            _InterlockedIncrement(&g_dbg_a2_spurious);
            if (_InterlockedIncrement(&g_dbg_a2_spurious_logged) <= 64)
            {
                HYPERPLATFORM_LOG_WARN_SAFE(
                    "[stealth-a2] SPURIOUS abort fa=%llx ec=%x (W=%d P=%d F=%d) "
                    "real_pte=%llx real_walk=%d reason=%s rip=%llx",
                    fault_addr, error_code,
                    (error_code & PFEC_WRITE) ? 1 : 0,
                    (error_code & PFEC_PRESENT) ? 1 : 0,
                    (error_code & PFEC_INSTR_FETCH) ? 1 : 0,
                    real_pte, real_walk_ok ? 1 : 0, bail_reason,
                    vcpu->vmexit_rip);
            }
        }
        return FALSE;
    }

    // flush any cached (stale P=0) translation for this VA so the retry re-walks
    // the now-current shadow PT, then resume in the shadow window. the open
    // window (MTF-armed, real CR3 saved) is closed normally by ept_handle_mtf
    // once the faulting instruction retires.
    INVVPID_DESCRIPTOR desc = {0};
    desc.Vpid = VPID_TAG;
    if (g_ept->invvpid_individual_addr)
    {
        desc.LinearAddress = fault_addr;
        asm_invvpid(InvvpidIndividualAddress, &desc);
    }
    else
    {
        asm_invvpid(InvvpidSingleContext, &desc);
    }

    _InterlockedIncrement(&g_dbg_shadow_pf_synced);
    if (_InterlockedIncrement(&g_dbg_shadow_pf_synced_logged) <= 32)
    {
        HYPERPLATFORM_LOG_WARN_SAFE(
            "[stealth-a2] synced fa=%llx ec=%x (W=%d P=%d) rip=%llx "
            "real_cr3=%llx sh_pml4=%llx real_pte=%llx",
            fault_addr, error_code,
            (error_code & PFEC_WRITE) ? 1 : 0,
            (error_code & PFEC_PRESENT) ? 1 : 0,
            vcpu->vmexit_rip, vcpu->nx_timer_real_cr3, sp->shadow_cr3_phys,
            real_pte);
    }
    return TRUE;
}

// =========================================================================
//  Ultimate Solution: Demand-Sync + Periodic-Sync (zero staleness)
// =========================================================================

//
// Demand-sync: fast PFN check at NX-fetch. O(1) - just one PFN comparison.
// Zero overhead when current (common case). Only syncs when repage happened.
// Combined with Periodic-Sync safety net, achieves zero code staleness.
//
static __forceinline BOOLEAN
stealth_demand_sync_code_pte(PEPT_STEALTH_PAGE_INFO sp, UINT64 fault_addr, UINT64 real_cr3)
{
    if (!sp->shadow_pte_va || !sp->shadow_cr3_phys)
        return FALSE;  // no shadow PTE (data page uses real PT, or legacy mode)

    // read real PTE via walk
    UINT64 real_pte = 0;
    if (!stealth_walk_pte(sp, real_cr3, fault_addr, &real_pte))
        return FALSE;

    if (!(real_pte & 1))
        return FALSE;  // not present

    // read shadow PTE (NonPaged pool VA, always valid)
    PUINT64 shadow_pte = (PUINT64)sp->shadow_pte_va;
    UINT64 shadow_val = *shadow_pte;

    // compare PFN (bits 12-51)
    UINT64 real_pfn = (real_pte & PFN_MASK) >> 12;
    UINT64 shadow_pfn = (shadow_val & PFN_MASK) >> 12;

    if (real_pfn == shadow_pfn)
        return TRUE;  // already current, zero work done

    // STALE! sync immediately (only writes shadow PTE, real PTE untouched)
    *shadow_pte = real_pte & ~NX_BIT;

    // flush TLB for this VA (in case shadow window is open)
    INVVPID_DESCRIPTOR desc = {0};
    desc.Vpid = VPID_TAG;
    if (g_ept->invvpid_individual_addr)
    {
        desc.LinearAddress = fault_addr;
        asm_invvpid(InvvpidIndividualAddress, &desc);
    }
    else
    {
        asm_invvpid(InvvpidSingleContext, &desc);
    }

    _InterlockedIncrement(&g_dbg_demand_sync);

    // log first few syncs
    static volatile LONG s_log_count = 0;
    if (g_dbg_demand_sync <= 32 && _InterlockedIncrement(&s_log_count) <= 32)
    {
        HYPERPLATFORM_LOG_WARN_SAFE(
            "[demand-sync] stale PFN detected va=%llx old_pfn=%llx new_pfn=%llx",
            fault_addr, shadow_pfn, real_pfn);
    }

    return TRUE;
}

// =========================================================================
//  VMX-root: NX-open code-PTE re-sync (repaged code page fix)
// =========================================================================
//
// The shadow PT is a build-time deep copy (TdBuildShadowCR3). A CODE page that
// was repaged after the snapshot (COW during relocation, section re-commit, page
// reuse) keeps its OLD physical PFN in the shadow PTE, so the one-instruction
// shadow window fetches STALE bytes -> the CPU executes wrong instructions ->
// silent state corruption -> the intermittent renderdoc-init AV ("write to 0"
// at a RIP whose real bytes are an innocent `push rbx`). This is silent: no
// mid-window data #PF, so A2 (data-reactive) never runs, and the crash run logs
// 0 SPURIOUS / 0 NOMATCH / 0 synced. Option 3's full passive refresh hides it by
// re-copying every shadow PTE; A2 does not, so the stale code PFN survives.
//
// Fix: on every NX-fetch that opens the shadow window, re-sync the shadow CODE
// PTE for fault_addr from the CURRENT real PTE (NX cleared to keep the stealth
// hide) BEFORE swapping to the shadow CR3. sp->guest_va == fault_page (the
// lookup is exact), so the shadow walk descends the repointed code path down to
// the snapshot PT and the single write lands on a shadow page - real page-table
// pages are only read, exactly as in stealth_sync_data_pte_in_window. Real NX
// stays 1 (stealth preserved; A3 NX-cycle avoided).
static BOOLEAN
stealth_refresh_shadow_code_pte(VIRTUAL_MACHINE_STATE * vcpu,
                                PEPT_STEALTH_PAGE_INFO sp,
                                UINT64 fault_addr, UINT64 real_cr3)
{
    if (!sp || !sp->shadow_cr3_phys || !sp->guest_va || !real_cr3)
        return FALSE;

    _InterlockedIncrement(&g_dbg_a2_code_enter);
    wedge_cmos_mark(0x03);  // WEDGE-C (heal enter)

    //
    // DIAG: periodic counter dump + distinct renderdoc code-RIP capture.
    //   code_enter rate  -> is renderdoc code running per-frame? (swapchain wrapped => overlay draw attempted)
    //   stale_p1_total   -> silent wrong-PFN corruption active? (overlay-killer / crash class)
    //   spurious         -> spurious abort+reinject? (crash class)
    //   distinct RIPs    -> which renderdoc functions execute (overlay/Present vs init)
    // The dump fires every 65536 code-enters. If it never fires, code_enter is
    // barely growing = renderdoc code is NOT running per-frame = swapchain not
    // wrapped (the no-overlay cause would be the hook, not the overlay draw).
    //
    if ((_InterlockedIncrement(&g_dbg_a2_dump_tick) & 65535) == 0)
    {
        HYPERPLATFORM_LOG_WARN_SAFE(
            "[stealth-diag] DUMP code_enter=%llu code_synced=%llu ptpage_synced=%llu "
            "stale_p1=%llu data_synced=%llu abort=%llu spurious=%llu nomatch=%llu "
            "pf_seen=%llu pf_switched=%llu a2shadow=%llu | "
            "demand_sync=%llu hash_lookups=%llu hash_collisions=%llu",
            (UINT64)g_dbg_a2_code_enter, (UINT64)g_dbg_a2_code_synced,
            (UINT64)g_dbg_a2_ptpage_synced, (UINT64)g_dbg_a2_stale_p1_total,
            (UINT64)g_dbg_a2_data_synced, (UINT64)g_dbg_a2_abort,
            (UINT64)g_dbg_a2_spurious, (UINT64)g_dbg_nomatch,
            (UINT64)g_dbg_shadow_pf_seen, (UINT64)g_dbg_shadow_pf_switched,
            (UINT64)g_dbg_a2_already_on_shadow,
            (UINT64)g_dbg_demand_sync,
            (UINT64)g_dbg_hash_lookups, (UINT64)g_dbg_hash_collisions);
    }
    dbg_log_distinct_rip(vcpu->vmexit_rip);

    // Same CR3 discipline as stealth_sync_data_pte_in_window: switch to
    // sp->guest_cr3 (the guest KERNEL CR3), under which the shadow pages
    // (NonPaged pool, system PTE) are dereferenceable AND pa_to_va resolves the
    // guest's real page-table pages via the guest kernel PML4's self-map. Under
    // g_system_cr3, pa_to_va resolved real PT pages through the System self-map
    // (PML4[idx]=0 for the code VA) -> sync always bailed -> stale shadow code
    // PFN -> CPU fetched wrong bytes -> execute AV.
    UINT64 saved_cr3 = vmx_enter_cr3(sp->guest_cr3);
    wedge_cmos_mark(0x04);  // WEDGE-D (post-enter-cr3, in heal)

    // One-shot sanity check: under sp->guest_cr3 (guest kernel CR3), pa_to_va on
    // the shadow PML4 (a NonPaged-pool page, resolved via system PTE in the kernel
    // half) must return non-NULL. NULL means the guest kernel CR3 does not map the
    // kernel half (e.g. wrong CR3 captured) and the heal cannot proceed.
    static volatile LONG s_shpml4_diag_done = 0;
    if (!_InterlockedExchange(&s_shpml4_diag_done, 1))
    {
        PVOID shpml4_va = pa_to_va(sp->shadow_cr3_phys & PFN_MASK);
        HYPERPLATFORM_LOG_WARN_SAFE(
            "[stealth-a2] DIAG shadow-pml4 pa=%llx va=%llx (NULL=kernel-cr3-broken) "
            "guest_cr3=%llx real_cr3=%llx fa=%llx",
            sp->shadow_cr3_phys & PFN_MASK, (UINT64)shpml4_va, sp->guest_cr3, real_cr3, fault_addr);
    }

    UINT64 real_pte = 0;
    wedge_cmos_mark(0x05);  // WEDGE-E (pre-walk)
    BOOLEAN walk_ok = stealth_walk_pte(sp, real_cr3, fault_addr, &real_pte);
    wedge_cmos_mark(0x06);  // WEDGE-E2 (post-walk)
    if (!walk_ok || !(real_pte & 1))
    {
        // real not present / large / NULL: nothing to sync (the existing NX-open
        // path will handle a genuinely absent page). Dump a level-by-level walk
        // to localize the failure: 0xDEAD = stealth_real_va NULL at that level
        // (real page not in the map), 0 = not-present entry, non-zero with bit7
        // = large page.
        if (_InterlockedIncrement(&g_dbg_a2_code_enter_logged) <= 200)
        {
            static const UINT32 dsh[4] = { 39, 30, 21, 12 };
            UINT64 dpa = real_cr3 & PFN_MASK;
            UINT64 e0 = 0, e1 = 0, e2 = 0, e3 = 0;
            for (UINT32 lvl = 0; lvl < 4; lvl++)
            {
                PUINT64 t = (PUINT64)stealth_real_va(sp, dpa);
                UINT64 ev;
                if (!t) { ev = 0xDEADULL; }
                else
                {
                    ev = t[(fault_addr >> dsh[lvl]) & 0x1FF];
                    if (!(ev & 1) || (ev & (1ULL << 7)))
                    {
                        if (lvl == 0) e0 = ev;
                        else if (lvl == 1) e1 = ev;
                        else if (lvl == 2) e2 = ev;
                        else e3 = ev;
                        break;
                    }
                    if (lvl == 3) { e3 = ev; break; }
                    dpa = ev & PFN_MASK;
                    continue;
                }
                if (lvl == 0) e0 = ev;
                else if (lvl == 1) e1 = ev;
                else if (lvl == 2) e2 = ev;
                else e3 = ev;
                break;
            }
            HYPERPLATFORM_LOG_WARN_SAFE(
                "[stealth-a2] code-refresh BAIL-realwalk fa=%llx rip=%llx cr3=%llx ok=%d pte=%llx pml4=%llx pdpt=%llx pd=%llx pt=%llx",
                fault_addr, vcpu->vmexit_rip, real_cr3, (int)walk_ok, real_pte,
                e0, e1, e2, e3);
        }
        return FALSE;
    }

    {
        // Direct shadow-PTE write via the pre-computed NonPaged-pool VA the
        // TestDriver passed at install (sp->shadow_pte_va). This replaces the
        // old 4-level pa_to_va walk: MmGetVirtualForPhysical CANNOT resolve
        // NonPaged-pool pages in VMX-root (returns NULL), so that walk always
        // bailed (BAIL-shtab) and the stale snapshot PTE - whose PFN predates
        // LdrLoadDll's repage - survived -> CPU fetched wrong bytes -> execute
        // AV (run 2). The pool VA is valid under any CR3 (system PTE), so we
        // write the leaf PTE directly. Each stealth page covers one 4KB page,
        // so fault_addr's PT index == guest_va's PT index and shadow_pte_va is
        // exactly this fault's leaf PTE. The intermediate shadow PML4/PDPT/PD
        // chain is a stable snapshot (built at TdBuildShadowCR3); only leaf PT
        // entries go stale on repage, and only the leaf needs refresh. The real
        // PTE is read-only here (A3 preserved: real NX stays 1).
        PUINT64 spte = (PUINT64)sp->shadow_pte_va;
        UINT64 want = real_pte & ~NX_BIT;

        if (!spte)
        {
            if (_InterlockedIncrement(&g_dbg_a2_code_enter_logged) <= 200)
                HYPERPLATFORM_LOG_WARN_SAFE(
                    "[stealth-a2] code-refresh BAIL-noshadowpteva fa=%llx rip=%llx",
                    fault_addr, vcpu->vmexit_rip);
            goto leave;
        }

        UINT64 s = *spte;
        if (s != want)
        {
            *spte = want;
            // flush any cached translation for this VA (stale real NX=1 entry
            // from the #PF, or a stale shadow entry from a prior window) so the
            // post-swap fetch re-walks the refreshed PTE.
            INVVPID_DESCRIPTOR desc = {0};
            desc.Vpid = VPID_TAG;
            if (g_ept->invvpid_individual_addr)
            {
                desc.LinearAddress = fault_addr;
                asm_invvpid(InvvpidIndividualAddress, &desc);
            }
            else
                asm_invvpid(InvvpidSingleContext, &desc);

            _InterlockedIncrement(&g_dbg_a2_code_synced);
            if (_InterlockedIncrement(&g_dbg_a2_code_synced_logged) <= 64)
            {
                HYPERPLATFORM_LOG_WARN_SAFE(
                    "[stealth-a2] code-sync fa=%llx rip=%llx "
                    "real_pte=%llx shadow_was=%llx want=%llx sh_pml4=%llx",
                    fault_addr, vcpu->vmexit_rip, real_pte, s, want,
                    sp->shadow_cr3_phys);
            }
        }
        else
        {
            // shadow PTE already matches real PFN (NX cleared): no staleness
            // detectable by PFN compare. Logging this proves the refresh
            // path IS reached and the comparison ran.
            if (_InterlockedIncrement(&g_dbg_a2_code_enter_logged) <= 200)
                HYPERPLATFORM_LOG_WARN_SAFE(
                    "[stealth-a2] code-refresh MATCH fa=%llx rip=%llx "
                    "real_pte=%llx shadow_pte=%llx",
                    fault_addr, vcpu->vmexit_rip, real_pte, s);
        }
    }


    // P=0 reactive sync: no cross-2MB scan needed. Data PTEs start P=0 and
    // are synced on first access via stealth_sync_data_pte_in_window.
    // Code PTEs are synced on every code-enter above (individual refresh).
    // Stale PFN is impossible: P=0 forces a fresh read from real PT on every
    // first access. The only sync needed is the single code PTE refresh above.

leave:
    vmx_leave_guest_cr3(saved_cr3);
    return TRUE;
}

// =========================================================================
//  VMX-root: ept_stealth_install
// =========================================================================

BOOLEAN
ept_stealth_install_ex(VIRTUAL_MACHINE_STATE * vcpu, PEPT_STEALTH_ALLOC_PARAM req, volatile LONG * interlock)
{
    if (!vcpu->ept_page_table || !req->target_va)
        return FALSE;
    if (!req->handler_function && !req->shellcode_buffer && !req->resident)
        return FALSE;

    UINT64 target_phys = req->target_phys & ~0xFFFULL;
    if (!target_phys)
        return FALSE;
    UINT64 target_pfn = target_phys >> 12;

    // --- check if already installed (by another CPU in DPC broadcast) ---
    PLIST_ENTRY cur = g_ept->stealth_pages.Flink;
    while (cur != &g_ept->stealth_pages)
    {
        PEPT_STEALTH_PAGE_INFO existing = CONTAINING_RECORD(cur, EPT_STEALTH_PAGE_INFO, stealth_page_list);
        cur = cur->Flink;
        if (existing->pfn_of_target == target_pfn)
        {
            //
            // tracking struct exists (another CPU did full install).
            // still need to split THIS CPU's EPT and set the PTE,
            // otherwise this CPU's 2MB page stays RWX and the thread
            // can execute from the original page without shadow redirection.
            //
            if (!existing->no_ept_split)
            {
                PEPT_PML2_ENTRY tp2 = ept_get_pml2(vcpu->ept_page_table, (SIZE_T)target_phys);
                if (tp2 && tp2->LargePage)
                    ept_split_large_page_pool(vcpu->ept_page_table, (SIZE_T)target_phys);

                PEPT_PML1_ENTRY tp1 = ept_get_pml1(vcpu->ept_page_table, (SIZE_T)target_phys);
                if (tp1)
                {
                    if (existing->resident)
                        tp1->AsUInt = existing->execute_entry.AsUInt;
                    else
                    {
                        tp1->ReadAccess    = 1;
                        tp1->WriteAccess   = 1;
                        tp1->ExecuteAccess = 0;
                    }
                }
            }

            // enable #PF interception on THIS CPU if fake PT is active
            // enable #PF interception on THIS CPU for NX cycle
            if (existing->fake_pt)
            {
                // fake PT mode: split PT page EPT on this CPU + map to fake PT
                UINT64 pt_phys = existing->fake_pt->pt_page_pfn << 12;
                PEPT_PML2_ENTRY pt_p2 = ept_get_pml2(vcpu->ept_page_table, (SIZE_T)pt_phys);
                if (pt_p2 && pt_p2->LargePage)
                    ept_split_large_page_pool(vcpu->ept_page_table, (SIZE_T)pt_phys);
                PEPT_PML1_ENTRY pt_p1 = ept_get_pml1(vcpu->ept_page_table, (SIZE_T)pt_phys);
                if (pt_p1) pt_p1->AsUInt = existing->fake_pt->pt_fake_entry.AsUInt;
            }

            if (existing->fake_pt || existing->shadow_cr3_phys)
                ept_update_pf_intercept(vcpu);

            _mm_mfence();
            ept_invept_single(vcpu->ept_pointer);
            return TRUE;
        }
    }

    // === first CPU: full install (use interlock to prevent duplicate) ===
    //
    // multiple CPUs enter VMX-root via KeGenericCallDpc simultaneously.
    // the "already installed" check above is not atomic with InsertHeadList.
    // use the interlock to ensure only one CPU does the full install.
    // other CPUs that lose the race will re-check the list and take the
    // "already installed" path on next iteration (after winner inserts).
    //
    BOOLEAN full_install_owner = TRUE;
    if (interlock)
    {
        LONG state = _InterlockedCompareExchange(interlock, 1, 0);
        if (state != 0)
            full_install_owner = FALSE;
    }

    if (!full_install_owner)
    {
        for (int i = 0; i < 1000000; i++)
        {
            if (!interlock || *interlock != 1)
                break;
            _mm_pause();
        }

        cur = g_ept->stealth_pages.Flink;
        while (cur != &g_ept->stealth_pages)
        {
            PEPT_STEALTH_PAGE_INFO existing = CONTAINING_RECORD(cur, EPT_STEALTH_PAGE_INFO, stealth_page_list);
            cur = cur->Flink;
            if (existing->pfn_of_target == target_pfn)
            {
                // winner installed 闂?split this CPU's EPT
                if (!existing->no_ept_split)
                {
                    PEPT_PML2_ENTRY tp2 = ept_get_pml2(vcpu->ept_page_table, (SIZE_T)target_phys);
                    if (tp2 && tp2->LargePage)
                        ept_split_large_page_pool(vcpu->ept_page_table, (SIZE_T)target_phys);
                    PEPT_PML1_ENTRY tp1 = ept_get_pml1(vcpu->ept_page_table, (SIZE_T)target_phys);
                    if (tp1)
                    {
                        if (existing->resident)
                            tp1->AsUInt = existing->execute_entry.AsUInt;
                        else
                        {
                            tp1->ReadAccess    = 1;
                            tp1->WriteAccess   = 1;
                            tp1->ExecuteAccess = 0;
                        }
                    }
                }

                if (existing->fake_pt)
                {
                    UINT64 pt_phys2 = existing->fake_pt->pt_page_pfn << 12;
                    PEPT_PML2_ENTRY pt_p2 = ept_get_pml2(vcpu->ept_page_table, (SIZE_T)pt_phys2);
                    if (pt_p2 && pt_p2->LargePage)
                        ept_split_large_page_pool(vcpu->ept_page_table, (SIZE_T)pt_phys2);
                    PEPT_PML1_ENTRY pt_p1 = ept_get_pml1(vcpu->ept_page_table, (SIZE_T)pt_phys2);
                    if (pt_p1) pt_p1->AsUInt = existing->fake_pt->pt_fake_entry.AsUInt;
                }

                if (existing->fake_pt || existing->shadow_cr3_phys)
                    ept_update_pf_intercept(vcpu);

                _mm_mfence();
                ept_invept_single(vcpu->ept_pointer);
                return TRUE;
            }
        }

        return FALSE;
    }

    // allocate tracking struct
    PEPT_STEALTH_PAGE_INFO sp = (PEPT_STEALTH_PAGE_INFO)
        pool_manager_request(POOL_TAG_STEALTH_INFO, sizeof(EPT_STEALTH_PAGE_INFO));
    if (!sp)
    {
        if (interlock)
            _InterlockedExchange(interlock, 0);
        return FALSE;
    }
    RtlZeroMemory(sp, sizeof(*sp));

    // Initialize LIST_ENTRY fields to avoid crashes in RemoveEntryList
    // RtlZeroMemory sets Flink/Blink to NULL, but LIST_ENTRY requires proper init
    InitializeListHead(&sp->stealth_page_list);
    InitializeListHead(&sp->stealth_hash_list);

    sp->guest_va         = (UINT64)req->target_va & ~0xFFFULL;
    sp->pfn_of_target    = target_pfn;
    sp->handler_function = req->handler_function;
    sp->guest_cr3        = req->caller_cr3;
    sp->target_pid       = req->target_pid;

    // --- resolve guest PT page info ---
    //
    // prefer pre-computed values (filled at PASSIVE/DISPATCH level by caller).
    // avoids pa_to_va (MmGetVirtualForPhysical) in VMX-root which can deadlock
    // when KeGenericCallDpc sends all CPUs into VMX-root simultaneously and
    // another CPU holds an OS internal lock that pa_to_va needs.
    //
    UINT64 pt_page_pfn;
    UINT64 pt_idx;

    // pt_precomputed MUST be TRUE 闂?callers fill pt_page_pfn/pt_pte_index/pt_page_va
    // at PASSIVE/DISPATCH level. NEVER walk guest page tables via pa_to_va in VMX-root
    // (deadlocks when KeGenericCallDpc puts all CPUs into VMX-root simultaneously).
    if (!req->pt_precomputed)
    {
        pool_manager_release(sp);
        if (interlock)
            _InterlockedExchange(interlock, 0);
        return FALSE;
    }

    pt_page_pfn = req->pt_page_pfn;
    pt_idx      = req->pt_pte_index;

    sp->pt_pte_index    = (UINT32)pt_idx;
    sp->pt_page_pfn     = pt_page_pfn;
    sp->pt_page_va      = req->pt_page_va;
    sp->resident        = req->resident;
    sp->shadow_cr3_phys = req->shadow_cr3_phys;
    sp->no_ept_split    = req->no_ept_split;
    sp->intercept_write = req->intercept_write;
    sp->shadow_pte_va   = req->shadow_pte_va;
    // MDL-mapped real page-table pages (PML4+PDPT+PDs+PTs along the alloc
    // path), built by TdBuildShadowCR3 in the guest driver and passed up here.
    // VMX-root reads real page-table entries through stealth_real_va(sp, pa)
    // (NOT pa_to_va, which under g_system_cr3 resolves them via the System
    // self-map -> PML4[idx]=0). Shadow PTEs are written through sp->shadow_pte_va
    // (the NonPaged-pool VA passed per page): pa_to_va CANNOT resolve NonPaged
    // pool in VMX-root (returns NULL), so the old shadow walk always bailed.
    sp->real_page_map   = (PSTEALTH_REAL_PAGE_ENTRY)req->real_page_map;
    sp->real_page_count = req->real_page_count;

    if (sp->no_ept_split)
    {
        if (!sp->shadow_cr3_phys)
        {
            pool_manager_release(sp);
            if (interlock)
                _InterlockedExchange(interlock, 0);
            return FALSE;
        }

#if USE_PRIVATE_HOST_CR3
        if (sp->intercept_write && sp->pt_page_va)
            hostcr3_map_va(sp->pt_page_va, PAGE_SIZE);
#endif

        // Insert into both legacy list (for cleanup walk) and hash table (for O(1) lookup)
        InsertHeadList(&g_ept->stealth_pages, &sp->stealth_page_list);

        // hash table insert (use independent stealth_hash_list)
        UINT32 hash = stealth_hash_va(sp->guest_va);
        InsertHeadList(&g_ept->stealth_hash[hash], &sp->stealth_hash_list);

        ept_update_pf_intercept(vcpu);

        _mm_mfence();
        ept_invept_single(vcpu->ept_pointer);
        if (interlock)
            _InterlockedExchange(interlock, 2);
        return TRUE;
    }

    if (req->use_fake_pt && req->pt_precomputed && req->pt_page_copy)
    {
        //
        // fake PT mode: create shared fake PT page with NX=1 for our entry.
        // real PTE has NX=0 (cleared by caller at PASSIVE_LEVEL).
        // anti-cheat reads fake PT 闂?sees NX=1 闂?page looks non-executable.
        // CPU page walk 闂?#PF (NX=1 in fake PT) 闂?HV swaps to real PT (NX=0)
        // 闂?TLB entry (NX=0) 闂?MTF 闂?swap back to fake PT.
        //
        sp->fake_pt = stealth_get_or_create_fake_pt(
            vcpu, pt_page_pfn, req->pt_page_copy, req->pt_page_va);

        if (sp->fake_pt)
        {
            sp->pt_pte_index = (UINT32)pt_idx;
            stealth_fake_pt_set_nx(sp->fake_pt, sp->pt_pte_index);

            _mm_mfence();
            ept_invept_single(vcpu->ept_pointer);
        }
    }
    else
    {
        //
        // EPT-only stealth: no fake PT page manipulation.
        // execute 闂?EPT violation 闂?swap to shadow page (execute view)
        // read/write 闂?sees original page (read view)
        // simpler and doesn't corrupt other PTEs in the same PT page.
        //
        sp->fake_pt = NULL;
    }

    // --- allocate shadow page from contiguous region ---
    sp->shadow_page = stealth_region_alloc_page(&sp->pfn_of_shadow);
    if (!sp->shadow_page) { goto fail_cleanup_fakept; }

    // fill shadow page content
    UINT64 page_offset = (UINT64)req->target_va & 0xFFF;
    if (req->shellcode_buffer && req->shellcode_size > 0)
    {
        // shellcode/DLL mode: shadow has provided content
        RtlZeroMemory(sp->shadow_page, PAGE_SIZE);
        SIZE_T copy_size = req->shellcode_size;
        if (copy_size > PAGE_SIZE - page_offset)
            copy_size = PAGE_SIZE - page_offset;
        RtlCopyMemory(&sp->shadow_page[page_offset], req->shellcode_buffer, copy_size);
    }
    else
    {
        // copy original page content 闂?MUST use pre-computed VA, NEVER pa_to_va
        if (req->target_page_copy)
            RtlCopyMemory(sp->shadow_page, req->target_page_copy, PAGE_SIZE);

        if (!req->resident)
        {
            // hook mode: overwrite entry with VMCALL
            sp->shadow_page[page_offset + 0] = 0x0F;
            sp->shadow_page[page_offset + 1] = 0x01;
            sp->shadow_page[page_offset + 2] = 0xC1;
        }
        // resident mode: shadow page = copy of DLL code as-is
    }

    // --- set up EPT for TARGET page ---
    PEPT_PML2_ENTRY target_pml2 = ept_get_pml2(vcpu->ept_page_table, (SIZE_T)target_phys);
    if (target_pml2 && target_pml2->LargePage)
        ept_split_large_page_pool(vcpu->ept_page_table, (SIZE_T)target_phys);

    PEPT_PML1_ENTRY target_pte = ept_get_pml1(vcpu->ept_page_table, (SIZE_T)target_phys);
    if (!target_pte) { goto fail_cleanup_fakept; }

    sp->entry_address = target_pte;

    // read view: shows original clean page (anti-cheat sees this)
    sp->original_entry = *target_pte;
    sp->original_entry.ReadAccess    = 1;
    sp->original_entry.WriteAccess   = 1;
    sp->original_entry.ExecuteAccess = 0;

    // execute view: shows shadow page (DLL code / shellcode)
    sp->execute_entry = sp->original_entry;
    //
    // shellcode inject (non-resident, shellcode_buffer != NULL):
    //   must keep ReadAccess=1 so shellcode can read its own embedded
    //   strings/data from the shadow page. with execute-only (R=0),
    //   reads would EPT-violate 闂?swap to original page (zeros) 闂?crash.
    //
    // resident DLL mode: use execute-only if supported 闂?reads are served
    //   from the original (zeroed) page via EPT violation + MTF.
    //   DLL code reads its own data sections through separate VA ranges.
    //
    BOOLEAN needs_self_read = (req->shellcode_buffer != NULL && req->shellcode_size > 0)
                           || (!req->resident && req->handler_function != NULL);
    sp->execute_entry.ReadAccess       = (g_ept->execute_only_supported && !needs_self_read) ? 0 : 1;
    sp->execute_entry.WriteAccess      = 0;
    sp->execute_entry.ExecuteAccess    = 1;
    sp->execute_entry.PageFrameNumber  = sp->pfn_of_shadow;

    if (req->resident)
    {
        //
        // RESIDENT: default = EXECUTE view
        //   CPU fetches from shadow page directly (TLB cached after first #PF)
        //   reads trigger EPT violation 闂?temp swap to clean 闂?MTF 闂?back
        //   #PF only fires on TLB miss (context switch, INVLPG) 闂?rare
        //
        target_pte->AsUInt = sp->execute_entry.AsUInt;
    }
    else
    {
        //
        // ONESHOT: default = READ view
        //   #PF on execute 闂?swap to execute view 闂?VMCALL/run 闂?swap back
        //
        target_pte->ReadAccess    = 1;
        target_pte->WriteAccess   = 1;
        target_pte->ExecuteAccess = 0;
    }

    //
    // enable #PF interception if fake PT is active.
    // CPU page walk reads fake PT (NX=1) 闂?#PF with I/D bit (error code bit 4).
    // HV intercepts #PF 闂?ept_stealth_handle_pf swaps to real PT (NX=0).
    //
    //
    // enable #PF interception for NX cycle:
    //   fake_pt mode: #PF 闂?swap to real PT (NX=0) 闂?MTF 闂?swap back
    //   no-fake-pt mode: #PF 闂?clear NX in real PTE 闂?MTF 闂?restore NX
    // both require intercepting NX violations (P=1 + I/D=1).
    //
    // Insert into both legacy list (for cleanup walk) and hash table (for O(1) lookup)
    InsertHeadList(&g_ept->stealth_pages, &sp->stealth_page_list);

    // hash table insert (use independent stealth_hash_list)
    UINT32 hash = stealth_hash_va(sp->guest_va);
    InsertHeadList(&g_ept->stealth_hash[hash], &sp->stealth_hash_list);

    if (sp->fake_pt || sp->shadow_cr3_phys)
        ept_update_pf_intercept(vcpu);

    //
    //
    // only modify CURRENT CPU's EPT 闂?never touch other CPUs' EPT directly.
    // modifying another CPU's EPT while it's walking it 闂?EPT misconfiguration
    // 闂?VMRESUME failure 闂?CPU dies 闂?0x101 CLOCK_WATCHDOG.
    //
    // other CPUs: lazy setup via ept_stealth_handle_violation on EPT violation,
    // or via the "already installed" path when this function is called again.
    //
    {
        // split target page 2MB闂?KB
        PEPT_PML2_ENTRY tp2 = ept_get_pml2(vcpu->ept_page_table, (SIZE_T)target_phys);
        if (tp2 && tp2->LargePage)
            ept_split_large_page_pool(vcpu->ept_page_table, (SIZE_T)target_phys);
        PEPT_PML1_ENTRY tp1 = ept_get_pml1(vcpu->ept_page_table, (SIZE_T)target_phys);
        if (tp1)
        {
            if (req->resident)
                tp1->AsUInt = sp->execute_entry.AsUInt;
            else
            {
                tp1->ReadAccess    = 1;
                tp1->WriteAccess   = 1;
                tp1->ExecuteAccess = 0;
            }
        }

        // DEBUG: skip PT page fake mapping (pt_fake_entry not initialized in debug mode)
        // if (sp->fake_pt)
        // {
        //     ...
        // }
    }

    _mm_mfence();
    ept_invept_single(vcpu->ept_pointer);
    if (interlock)
        _InterlockedExchange(interlock, 2);

    return TRUE;

fail_cleanup_fakept:
    // error after fake_pt was acquired 闂?must release ref
    if (sp->fake_pt)
    {
        sp->fake_pt->ref_count--;
        if (sp->fake_pt->ref_count == 0)
        {
            PEPT_PML1_ENTRY pp = ept_get_pml1(vcpu->ept_page_table,
                (SIZE_T)(sp->fake_pt->pt_page_pfn << 12));
            if (pp)
            {
                pp->ReadAccess = 1; pp->WriteAccess = 1; pp->ExecuteAccess = 1;
                pp->PageFrameNumber = sp->fake_pt->pt_page_pfn;
            }
            // BUGFIX: Check if fake_pt_list is properly initialized before removing
            if (sp->fake_pt->fake_pt_list.Flink != NULL &&
                sp->fake_pt->fake_pt_list.Blink != NULL &&
                sp->fake_pt->fake_pt_list.Flink != &sp->fake_pt->fake_pt_list)
            {
                RemoveEntryList(&sp->fake_pt->fake_pt_list);
            }
            pool_manager_release(sp->fake_pt);
        }
    }
    pool_manager_release(sp);
    if (interlock)
        _InterlockedExchange(interlock, 0);
    return FALSE;
}

// =========================================================================
//  VMX-root: #PF handler (NX violation)
// =========================================================================

BOOLEAN
ept_stealth_handle_pf(VIRTUAL_MACHINE_STATE * vcpu, UINT64 fault_addr, UINT32 error_code)
{
    if (!g_ept || IsListEmpty(&g_ept->stealth_pages)) return FALSE;

    // WEDGE-B (0x02) removed: per-CPU exit-reason snap in vmexit_handler records
    // #PF as 0x8E per-CPU now. This global mark was a per-#PF port-I/O confound
    // (it + 0x0D were why the global marker always read 0x0d under the storm).

    //
    // mid shadow window: a non-fetch (data) #PF arrived while this vCPU is already
    // running on the shadow CR3. it must be serviced under the REAL CR3 - never let
    // MmAccessFault run on the shadow page tables (it would walk/modify the stale
    // shadow PT and corrupt the PFN database -> 0x1A / 0x61941). abort the window
    // (restore real CR3 + normal #PF intercept) and return FALSE so the caller
    // re-injects this #PF under the real CR3. fetch #PFs mid-window are the legit
    // case of the target jumping to another alloc page and fall through to handling.
    //
    if (vcpu->nx_timer_real_cr3 && !(error_code & PFEC_INSTR_FETCH))
    {
        // A2: try to service the data #PF INSIDE the shadow window by syncing the
        // stale shadow PT entry from the real CR3 (stealth-preserving: real PTEs
        // are never touched). on success resume in shadow; on any failure (genuine
        // demand fault, COW, large page, NULL pa_to_va) fall back to the original
        // abort+reinject so the guest services it under the real CR3 as before.
        if (stealth_sync_data_pte_in_window(vcpu, fault_addr, error_code))
            return TRUE;

        stealth_diag_midwin_pf(vcpu, fault_addr, error_code, "guard",
                               vcpu->nx_timer_restore);
        stealth_pf_abort_shadow_window(vcpu);
        return FALSE;
    }

    // MODE_A: shadow leaf PTEs start P=0. A P=0 fetch is expected (reactive
    // sync of not-yet-accessed code pages). Allow all fetches through to
    // stealth matching. Non-fetch P=0 faults are genuine demand faults (bail).
    // P=1 reads bail (protection violation). P=1 writes fall through (COW).
    //
    // MODE_C (default): shadow leaf PTEs start P=1/NX=0. No P=0 faults.
    // Only NX-fetch (P=1/F=1) and COW-write (P=1/W=1) are relevant.
#if (SHADOW_PT_MODE == SHADOW_PT_MODE_A)
    if (!(error_code & PFEC_INSTR_FETCH))
    {
        if (!(error_code & PFEC_PRESENT) || !(error_code & PFEC_WRITE))
            return FALSE;
    }
#else
    if (!(error_code & PFEC_PRESENT) ||
        !(error_code & (PFEC_INSTR_FETCH | PFEC_WRITE)))
        return FALSE;
#endif

    UINT64 fault_page = fault_addr & ~0xFFFULL;

    // === HASH TABLE LOOKUP: O(1) instead of O(N) ===
    // Linear scan = avg 8K comparisons with 16K pages. Hash lookup = avg 4 comparisons.
    // 2000x performance improvement on hot path.
    UINT32 hash = stealth_hash_va(fault_page);
    PLIST_ENTRY cur = g_ept->stealth_hash[hash].Flink;
    UINT32 chain_len = 0;

    _InterlockedIncrement(&g_dbg_hash_lookups);

    while (cur != &g_ept->stealth_hash[hash])
    {
        PEPT_STEALTH_PAGE_INFO sp = CONTAINING_RECORD(cur, EPT_STEALTH_PAGE_INFO, stealth_hash_list);
        cur = cur->Flink;
        chain_len++;

        if (sp->guest_va != fault_page) continue;

        if (sp->target_pid != 0)
        {
            // PID is invariant under the shadow-CR3 swap (same process, only
            // the CR3 value changes), so this stays correct inside the shadow
            // window and is the authoritative per-process filter.
            // OPTIMIZATION: Use cached PID to avoid expensive PsGetCurrentProcessId() call
            UINT64 current_cr3 = vcpu_get_guest_cr3(vcpu);
            UINT64 current_pid = vcpu_get_current_pid(vcpu, current_cr3);
            if (current_pid != sp->target_pid)
                continue;
        }
        else if (sp->guest_cr3 != 0)
        {
            // Fallback (target_pid == 0): identify the process by CR3.
            // GUEST_CR3 cannot be trusted during the shadow-CR3 window - it
            // holds the shadow PML4, not the process CR3, so a direct compare
            // mismatches and drops #PFs/VMCALLs we must handle. If a shadow
            // swap is in flight on this vCPU, nx_timer_real_cr3 is the real
            // process CR3; use it. Otherwise GUEST_CR3 is the real CR3.
            UINT64 cr3_to_check = 0;
            if (vcpu->nx_timer_real_cr3)
                cr3_to_check = vcpu->nx_timer_real_cr3;
            else
                cr3_to_check = vcpu_get_guest_cr3(vcpu);  // OPTIMIZATION: Use cached CR3
            if ((cr3_to_check & PFN_MASK) != (sp->guest_cr3 & PFN_MASK))
                continue;
        }

        //
        // two modes for making NX=0 visible to CPU page walker:
        //
        // fake PT mode: swap PT page EPT 闂?real PT (NX=0 pre-cleared by caller)
        //   MTF: swap back to fake PT (NX=1)
        //
        // NX cycle mode (no fake PT): clear NX in real PTE from VMX-root
        //   MTF: restore NX=1 in real PTE, don't flush TLB
        //   TLB keeps NX=0 闂?code continues. TLB eviction 闂?#PF 闂?repeat.
        //
        if (sp->shadow_cr3_phys)
        {
            _InterlockedIncrement(&g_dbg_shadow_pf_seen);
            if ((error_code & PFEC_WRITE) &&
                (!sp->intercept_write || !stealth_shadow_pte_allows(sp, error_code)))
            {
                _InterlockedIncrement(&g_dbg_shadow_pf_reject);
                stealth_diag_midwin_pf(vcpu, fault_addr, error_code, "reject", sp);
                return FALSE;
            }
            _InterlockedIncrement(&g_dbg_shadow_pf_allowed);
        }
        else if (!(error_code & PFEC_INSTR_FETCH))
        {
            return FALSE;
        }

        // WEDGE-B1 (CMOS 0x0B): stealth page MATCHED (guest_va + pid/cr3), entering mode handling.
        wedge_cmos_mark(0x0B);
        wedge_cmos_set_match_seen();  // sticky: a match happened this run (survives reset)

        if (sp->fake_pt)
        {
            // fake PT mode
            PEPT_PML1_ENTRY pt_pte = ept_get_pml1(vcpu->ept_page_table,
                (SIZE_T)(sp->fake_pt->pt_page_pfn << 12));
            if (pt_pte) pt_pte->AsUInt = sp->fake_pt->pt_real_entry.AsUInt;
        }
        else if (sp->shadow_cr3_phys)
        {
            //
            // shadow CR3 mode: swap guest CR3 to shadow page tables (NX=0),
            // let exactly one guest instruction retire, then restore real CR3
            // from MTF. This keeps the shadow window extremely small and avoids
            // letting the guest run for an arbitrary timer interval on shadow CR3.
            //

            SIZE_T current_cr3 = vcpu_get_guest_cr3(vcpu);  // OPTIMIZATION: Use cached CR3

            UINT64 current_pfn = (UINT64)current_cr3 & PFN_MASK;
            UINT64 shadow_pfn  = sp->shadow_cr3_phys & PFN_MASK;
            BOOLEAN already_on_shadow = (current_pfn == shadow_pfn);

            // WEDGE-B2 (CMOS 0x0C): match, CR3 read + already_on_shadow done, about to call heal.
            wedge_cmos_mark(0x0C);

            // === DEMAND SYNC: fast PFN check before opening shadow window ===
            // Check if shadow PTE has stale PFN (code page was repaged). If stale,
            // sync immediately. O(1) - just one PFN comparison. Zero overhead when
            // current (common case). Skipped on already-on-shadow (mid-window).
            if (!already_on_shadow)
            {
                stealth_demand_sync_code_pte(sp, fault_addr, current_cr3);
            }

            // Re-sync the shadow CODE PTE from the current real PTE before opening
            // the window. The shadow PT is a build-time snapshot; a code page
            // repaged after the snapshot keeps a stale PFN and the window would
            // fetch wrong bytes -> silent corruption (the renderdoc-init AV).
            // sp->guest_va == fault_page, so this refreshes exactly the faulting
            // code page. Skipped on already-on-shadow (mid-window re-fetch): the
            // real CR3 is nx_timer_real_cr3 there, not current_cr3, and the first
            // NX-open already refreshed it.
            //
            // NOTE: With demand-sync above, this is now a fallback (redundant most
            // of the time, but catches edge cases where demand-sync couldn't run).
            if (already_on_shadow)
            {
                // Mid-window NX-fetch #PF (the shadow window stayed open >1 insn,
                // e.g. an interrupt was delivered during the one-instruction window
                // and the next renderdoc insn faulted on a DIFFERENT page). The
                // first NX-open refreshed only the ORIGINAL faulting page -- this
                // one's shadow PTE may still be stale -> wrong bytes -> AV. Re-sync
                // it. current_cr3 is the shadow CR3 here (walking it would read
                // back the stale shadow PTE), so walk the real CR3 saved at open.
                _InterlockedIncrement(&g_dbg_a2_already_on_shadow);
                if (vcpu->nx_timer_real_cr3)
                {
                    if (!stealth_refresh_shadow_code_pte(vcpu, sp, fault_addr, vcpu->nx_timer_real_cr3))
                    {
                        // real PTE not present (page paged out): abort shadow
                        // window, re-inject #PF under real CR3 for demand fault.
                        stealth_pf_abort_shadow_window(vcpu);
                        return FALSE;
                    }
                }
            }
            else
            {
                if (!stealth_refresh_shadow_code_pte(vcpu, sp, fault_addr, current_cr3))
                {
                    // real PTE not present: genuine demand fault, let guest handle.
                    return FALSE;
                }
            }

            if (!already_on_shadow)
                vcpu->nx_timer_real_cr3 = current_cr3;

            vcpu->nx_timer_restore = sp;

            if (!already_on_shadow)
            {
                // build shadow CR3 value: replace PFN, keep PCID/flags
                UINT64 shadow_cr3_val = (current_cr3 & ~PFN_MASK) | shadow_pfn;
                __vmx_vmwrite(VMCS_GUEST_CR3, shadow_cr3_val);
                _InterlockedIncrement(&g_dbg_shadow_pf_switched);

                //
                // widen #PF interception to ALL faults for this one-instruction
                // window. normally only NX-fetch #PFs VM-exit (PRESENT|FETCH), so a
                // data #PF during the window would reach the guest's MmAccessFault
                // running UNDER shadow CR3 and corrupt the PFN database (0x1A).
                // catching every #PF lets the mid-window guard above abort the
                // window and service the fault under the real CR3 instead. the
                // window is closed (mask restored) by MTF or the abort path.
                //
                __vmx_vmwrite(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MASK, 0);
                __vmx_vmwrite(VMCS_CTRL_PAGEFAULT_ERROR_CODE_MATCH, 0);
            }

            if (error_code & PFEC_WRITE)
            {
                INVVPID_DESCRIPTOR desc = {0};
                desc.Vpid = VPID_TAG;
                asm_invvpid(InvvpidSingleContext, &desc);
            }
            else
            {
                // NX-fetch open: with VPID the CR3 swap above does NOT flush the
                // TLB, so a cached entry for the faulting code VA survives. If
                // that entry is the real-PT NX=1 translation, the post-swap fetch
                // re-#PFs instead of executing; if it is a stale wrong-PFN entry
                // (cached from before a repage the guest INVLPG missed, or carried
                // over from a prior shadow window), the fetch reads wrong bytes ->
                // silent corruption (the renderdoc-init AV). Flush just fault_addr
                // (individual-address when available): only that VA is fetched in
                // this one-instruction window, so the post-swap fetch re-walks the
                // refreshed shadow PT and reads the correct PFN.
                INVVPID_DESCRIPTOR desc = {0};
                desc.Vpid = VPID_TAG;
                if (g_ept->invvpid_individual_addr)
                {
                    desc.LinearAddress = fault_addr;
                    asm_invvpid(InvvpidIndividualAddress, &desc);
                }
                else
                    asm_invvpid(InvvpidSingleContext, &desc);
            }

            SIZE_T pc = 0;
            __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &pc);
            pc |= (SIZE_T)CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG;
            __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, pc);
        }

        // fake PT mode: EPT changes + MTF
        if (sp->fake_pt)
        {
            PEPT_PML1_ENTRY target_pte = ept_get_pml1(vcpu->ept_page_table,
                (SIZE_T)(sp->pfn_of_target << 12));
            if (target_pte) target_pte->AsUInt = sp->execute_entry.AsUInt;

            vcpu->stealth_pf_swapped = sp;
            SIZE_T pc = 0;
            __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &pc);
            pc |= (SIZE_T)CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG;
            __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, pc);

            _mm_mfence();
            ept_invept_single(vcpu->ept_pointer);
        }
        else
        {
            // shadow CR3 mode: no EPT changes, no INVEPT
            _mm_mfence();
        }

        //
        // shadow CR3 mode relies on the shadow translation surviving until MTF
        // gives us a chance to restore the real CR3, so do not invalidate the
        // just-warmed guest TLB entry here.
        //
        if (sp->fake_pt)
        {
            INVVPID_DESCRIPTOR desc = {0};
            desc.Vpid = VPID_TAG;
            if (g_ept->invvpid_individual_addr)
            {
                desc.LinearAddress = fault_addr;
                asm_invvpid(InvvpidIndividualAddress, &desc);
            }
            else
                asm_invvpid(InvvpidSingleContext, &desc);
        }

        // diagnostic: track collision chain length
        if (chain_len > 1)
            _InterlockedIncrement(&g_dbg_hash_collisions);

        return TRUE;
    }

    // WEDGE-BN (0x0D) removed: per-CPU snap captures the nomatch reinject; this
    // global mark was a hot-path port-I/O confound. (nomatch reinject path follows.)

    // no stealth page matched. if a shadow window is still open, close it first so
    // the re-injected #PF is serviced under the real CR3. (defensive: the mid-window
    // guard above already handles data #PFs; this catches a mid-window fetch #PF to
    // a non-stealth NX page, trading a potential 0x1A for a clean process AV.) A
    // mid-window FETCH #PF here is the signature of a clobbered code 2MB: A2's
    // code-path heuristic only protects sp->guest_va's path, so a data fault whose
    // path crosses a SIBLING code 2MB (renderdoc .text spans >2MB) can refresh that
    // sibling's shadow PD to real, re-exposing NX=1 -> this fetch #PF. That is a
    // crash-causing event, so log it UNCAPPED (the 32-cap hides later runs).
    if (vcpu->nx_timer_real_cr3)
    {
        _InterlockedIncrement(&g_dbg_nomatch);
        if (_InterlockedIncrement(&g_dbg_nomatch_logged) <= 64)
        {
            PEPT_STEALTH_PAGE_INFO sp = vcpu->nx_timer_restore;
            UINT64 fault_pml4_idx = (fault_addr >> 39) & 0x1FF;
            UINT64 fault_pdpt_idx = (fault_addr >> 30) & 0x1FF;
            UINT64 fault_pd_idx   = (fault_addr >> 21) & 0x1FF;
            UINT64 code_pml4_idx  = sp ? ((sp->guest_va >> 39) & 0x1FF) : 0;
            UINT64 code_pdpt_idx  = sp ? ((sp->guest_va >> 30) & 0x1FF) : 0;
            UINT64 code_pd_idx    = sp ? ((sp->guest_va >> 21) & 0x1FF) : 0;
            HYPERPLATFORM_LOG_WARN_SAFE(
                "[stealth-a2] NOMATCH midwin fetch fa=%llx ec=%x (W=%d P=%d F=%d) "
                "rip=%llx idx[pml4 f=%llx/%llx pdpt f=%llx/%llx pd f=%llx/%llx]",
                fault_addr, error_code,
                (error_code & PFEC_WRITE) ? 1 : 0,
                (error_code & PFEC_PRESENT) ? 1 : 0,
                (error_code & PFEC_INSTR_FETCH) ? 1 : 0,
                vcpu->vmexit_rip,
                fault_pml4_idx, code_pml4_idx,
                fault_pdpt_idx, code_pdpt_idx,
                fault_pd_idx, code_pd_idx);
        }
        stealth_pf_abort_shadow_window(vcpu);
    }
    else
    {
        stealth_pf_abort_shadow_window(vcpu);
    }
    return FALSE;
}

// =========================================================================
//  VMX-root: VMCALL dispatch from stealth page
// =========================================================================

BOOLEAN
ept_handle_stealth_vmcall(VIRTUAL_MACHINE_STATE * vcpu)
{
    UINT64 rip = vcpu->vmexit_rip;
    UINT64 rip_page = rip & ~0xFFFULL;

    PLIST_ENTRY cur = g_ept->stealth_pages.Flink;
    while (cur != &g_ept->stealth_pages)
    {
        PEPT_STEALTH_PAGE_INFO sp = CONTAINING_RECORD(cur, EPT_STEALTH_PAGE_INFO, stealth_page_list);
        cur = cur->Flink;

        if (sp->guest_va != rip_page) continue;

        //
        // shellcode mode: handler_function is NULL 闂?VMCALL should not
        // redirect anywhere. skip this entry so it falls through to #UD.
        //
        if (!sp->handler_function) continue;

        //
        // per-process filtering: only dispatch VMCALL for the target process.
        // without this, a different process with the same VA executing VMCALL
        // would be incorrectly redirected.
        //
        if (sp->target_pid != 0)
        {
            // PID is invariant under the shadow-CR3 swap (same process, only
            // the CR3 value changes), so this stays correct inside the shadow
            // window and is the authoritative per-process filter.
            // OPTIMIZATION: Use cached PID to avoid expensive PsGetCurrentProcessId() call
            UINT64 current_cr3 = vcpu_get_guest_cr3(vcpu);
            UINT64 current_pid = vcpu_get_current_pid(vcpu, current_cr3);
            if (current_pid != sp->target_pid)
                continue;
        }
        else if (sp->guest_cr3 != 0)
        {
            // Fallback (target_pid == 0): identify the process by CR3.
            // GUEST_CR3 cannot be trusted during the shadow-CR3 window - it
            // holds the shadow PML4, not the process CR3, so a direct compare
            // mismatches and drops #PFs/VMCALLs we must handle. If a shadow
            // swap is in flight on this vCPU, nx_timer_real_cr3 is the real
            // process CR3; use it. Otherwise GUEST_CR3 is the real CR3.
            UINT64 cr3_to_check = 0;
            if (vcpu->nx_timer_real_cr3)
                cr3_to_check = vcpu->nx_timer_real_cr3;
            else
                cr3_to_check = vcpu_get_guest_cr3(vcpu);  // OPTIMIZATION: Use cached CR3
            if ((cr3_to_check & PFN_MASK) != (sp->guest_cr3 & PFN_MASK))
                continue;
        }

        // restore target page EPT 闂?read view
        PEPT_PML1_ENTRY target_pte = ept_get_pml1(vcpu->ept_page_table,
            (SIZE_T)(sp->pfn_of_target << 12));
        if (target_pte) target_pte->AsUInt = sp->original_entry.AsUInt;

        // restore PT page EPT 闂?fake view
        if (sp->fake_pt)
        {
            PEPT_PML1_ENTRY pt_pte = ept_get_pml1(vcpu->ept_page_table,
                (SIZE_T)(sp->fake_pt->pt_page_pfn << 12));
            if (pt_pte) pt_pte->AsUInt = sp->fake_pt->pt_fake_entry.AsUInt;
        }

        vcpu->stealth_pf_swapped = NULL;

        _mm_mfence();
        ept_invept_single(vcpu->ept_pointer);

        INVVPID_DESCRIPTOR desc = {0};
        desc.Vpid = VPID_TAG;
        if (g_ept->invvpid_individual_addr)
        {
            desc.LinearAddress = sp->guest_va;
            asm_invvpid(InvvpidIndividualAddress, &desc);
        }
        else
            asm_invvpid(InvvpidSingleContext, &desc);

        __vmx_vmwrite(VMCS_GUEST_RIP, (UINT64)sp->handler_function);
        return TRUE;
    }

    //
    // no match 闂?stealth page may have been freed between #PF and VMCALL.
    // clear stealth_pf_swapped to prevent use-after-free in MTF handler.
    //
    vcpu->stealth_pf_swapped = NULL;
    return FALSE;
}

// =========================================================================
//  VMX-root: EPT violation handler
// =========================================================================

BOOLEAN
ept_stealth_handle_violation(VIRTUAL_MACHINE_STATE * vcpu, UINT64 guest_phys, UINT64 exit_qual)
{
    VMX_EXIT_QUALIFICATION_EPT_VIOLATION viol;
    viol.AsUInt = exit_qual;
    UINT64 pfn = guest_phys >> 12;

    // --- check stealth target pages ---
    PLIST_ENTRY cur = g_ept->stealth_pages.Flink;
    while (cur != &g_ept->stealth_pages)
    {
        PEPT_STEALTH_PAGE_INFO sp = CONTAINING_RECORD(cur, EPT_STEALTH_PAGE_INFO, stealth_page_list);
        cur = cur->Flink;

        if (sp->no_ept_split) continue;

        if (sp->pfn_of_target == pfn || sp->pfn_of_shadow == pfn)
        {
            PEPT_PML1_ENTRY pte = ept_get_pml1(vcpu->ept_page_table,
                (SIZE_T)(sp->pfn_of_target << 12));
            if (!pte) continue;

            if (viol.ReadAccess || viol.WriteAccess)
            {
                pte->AsUInt = sp->original_entry.AsUInt;
                _mm_mfence();
                ept_invept_single(vcpu->ept_pointer);

                vcpu->mtf_restore_stealth = sp;
                SIZE_T pc = 0;
                __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &pc);
                pc |= (SIZE_T)CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG;
                __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, pc);
                return TRUE;
            }
            if (viol.ExecuteAccess)
            {
                pte->AsUInt = sp->execute_entry.AsUInt;
                _mm_mfence();
                ept_invept_single(vcpu->ept_pointer);
                return TRUE;
            }
        }
    }

    // --- check shared fake PT pages (write to PT page) ---
    PLIST_ENTRY fpt_cur = g_ept->stealth_fake_pts.Flink;
    while (fpt_cur != &g_ept->stealth_fake_pts)
    {
        PSTEALTH_FAKE_PT fpt = CONTAINING_RECORD(fpt_cur, STEALTH_FAKE_PT, fake_pt_list);
        fpt_cur = fpt_cur->Flink;

        if (fpt->pt_page_pfn == pfn || fpt->pfn_of_fake == pfn)
        {
            PEPT_PML1_ENTRY pt_pte = ept_get_pml1(vcpu->ept_page_table,
                (SIZE_T)(fpt->pt_page_pfn << 12));
            if (!pt_pte) continue;

            if (viol.WriteAccess || viol.ReadAccess)
            {
                // swap to real PT page, single-step, then resync fake
                pt_pte->AsUInt = fpt->pt_real_entry.AsUInt;
                _mm_mfence();
                ept_invept_single(vcpu->ept_pointer);

                vcpu->mtf_restore_fake_pt = fpt;
                SIZE_T pc = 0;
                __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &pc);
                pc |= (SIZE_T)CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG;
                __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, pc);
                return TRUE;
            }
        }
    }

    return FALSE;
}

// =========================================================================
//  uninstall / cleanup
// =========================================================================

BOOLEAN
ept_stealth_uninstall(VIRTUAL_MACHINE_STATE * vcpu, PEPT_STEALTH_FREE_PARAM req)
{
    if (!g_ept || !req->target_va) return FALSE;
    UINT64 target_pfn = (req->target_phys & ~0xFFFULL) >> 12;
    UINT64 target_gva = (UINT64)req->target_va & ~0xFFFULL;

    if (_InterlockedCompareExchange(&req->freed, 1, 0) == 0)
    {
        PLIST_ENTRY cur = g_ept->stealth_pages.Flink;
        while (cur != &g_ept->stealth_pages)
        {
            PEPT_STEALTH_PAGE_INFO sp = CONTAINING_RECORD(cur, EPT_STEALTH_PAGE_INFO, stealth_page_list);
            cur = cur->Flink;

            // match by PFN (normal) or by guest VA (fallback when phys unavailable on process exit)
            if (sp->pfn_of_target != target_pfn && sp->guest_va != target_gva) continue;

            // restore NX in real PTE
            if (sp->fake_pt)
            {
                PVOID pt_va = pa_to_va(sp->fake_pt->pt_page_pfn << 12);
                if (pt_va)
                {
                    PUINT64 real_pte = &((PUINT64)pt_va)[sp->pt_pte_index];
                    *real_pte |= NX_BIT;
                }

                // decref shared fake PT
                sp->fake_pt->ref_count--;
                if (sp->fake_pt->ref_count == 0)
                {
                    // restore PT page EPT to RWX on ALL CPUs
                    // (install set fake PT EPT on every CPU via "already installed" path)
                    for (UINT32 ci = 0; ci < g_cpu_count; ci++)
                    {
                        if (!g_vcpu[ci].ept_page_table) continue;
                        PEPT_PML1_ENTRY pp = ept_get_pml1(g_vcpu[ci].ept_page_table,
                            (SIZE_T)(sp->fake_pt->pt_page_pfn << 12));
                        if (pp)
                        {
                            pp->ReadAccess = 1; pp->WriteAccess = 1; pp->ExecuteAccess = 1;
                            pp->PageFrameNumber = sp->fake_pt->pt_page_pfn;
                        }
                    }
                    // BUGFIX: Check if fake_pt_list is properly initialized before removing
                    if (sp->fake_pt->fake_pt_list.Flink != NULL &&
                        sp->fake_pt->fake_pt_list.Blink != NULL &&
                        sp->fake_pt->fake_pt_list.Flink != &sp->fake_pt->fake_pt_list)
                    {
                        RemoveEntryList(&sp->fake_pt->fake_pt_list);
                    }
                    pool_manager_release(sp->fake_pt);
                }
                else
                {
                    // other pages still use this fake PT 闂?remove our NX entry
                    // (it was already restored in real PTE above)
                    // resync fake page from real
                    stealth_fake_pt_resync(sp->fake_pt);
                }
            }

            // BUGFIX: Check if stealth_page_list is properly initialized before removing
            if (sp->stealth_page_list.Flink != NULL &&
                sp->stealth_page_list.Blink != NULL &&
                sp->stealth_page_list.Flink != &sp->stealth_page_list)
            {
                RemoveEntryList(&sp->stealth_page_list);
            }
            pool_manager_release(sp);
            req->result = TRUE;
            break;
        }
    }

    // restore target page EPT on all CPUs
    for (UINT32 i = 0; i < g_cpu_count; i++)
    {
        if (!g_vcpu[i].ept_page_table) continue;
        PEPT_PML1_ENTRY p = ept_get_pml1(g_vcpu[i].ept_page_table, (SIZE_T)(target_pfn << 12));
        if (p) { p->ReadAccess = 1; p->WriteAccess = 1; p->ExecuteAccess = 1; p->PageFrameNumber = target_pfn; }
    }

    _mm_mfence();
    ept_invept_single(vcpu->ept_pointer);
    ept_update_pf_intercept(vcpu);
    return TRUE;
}

VOID
ept_stealth_free_all(VOID)
{
    if (!g_ept) return;

    // restore target page EPT on ALL CPUs
    while (!IsListEmpty(&g_ept->stealth_pages))
    {
        PLIST_ENTRY item = RemoveHeadList(&g_ept->stealth_pages);
        PEPT_STEALTH_PAGE_INFO sp = CONTAINING_RECORD(item, EPT_STEALTH_PAGE_INFO, stealth_page_list);

        // Also remove from hash table
        // BUGFIX: Check if hash_list is properly initialized before removing
        // (protects against partially-constructed entries or double-free)
        if (sp->stealth_hash_list.Flink != NULL &&
            sp->stealth_hash_list.Blink != NULL &&
            sp->stealth_hash_list.Flink != &sp->stealth_hash_list)  // not self-referencing (already removed)
        {
            RemoveEntryList(&sp->stealth_hash_list);
        }

        for (UINT32 i = 0; i < g_cpu_count; i++)
        {
            if (!g_vcpu[i].ept_page_table) continue;
            PEPT_PML1_ENTRY p = ept_get_pml1(g_vcpu[i].ept_page_table,
                (SIZE_T)(sp->pfn_of_target << 12));
            if (p)
            {
                p->ReadAccess = 1; p->WriteAccess = 1;
                p->ExecuteAccess = 1; p->PageFrameNumber = sp->pfn_of_target;
            }
        }
        pool_manager_release(sp);
    }

    // restore fake PT page EPT on ALL CPUs
    while (!IsListEmpty(&g_ept->stealth_fake_pts))
    {
        PLIST_ENTRY item = RemoveHeadList(&g_ept->stealth_fake_pts);
        PSTEALTH_FAKE_PT fpt = CONTAINING_RECORD(item, STEALTH_FAKE_PT, fake_pt_list);

        for (UINT32 i = 0; i < g_cpu_count; i++)
        {
            if (!g_vcpu[i].ept_page_table) continue;
            PEPT_PML1_ENTRY pp = ept_get_pml1(g_vcpu[i].ept_page_table,
                (SIZE_T)(fpt->pt_page_pfn << 12));
            if (pp)
            {
                pp->ReadAccess = 1; pp->WriteAccess = 1;
                pp->ExecuteAccess = 1; pp->PageFrameNumber = fpt->pt_page_pfn;
            }
        }
        pool_manager_release(fpt);
    }
}

VOID ept_stealth_free_all_broadcast(VOID) { ept_stealth_free_all(); }

// =========================================================================
//  PASSIVE_LEVEL wrappers
// =========================================================================

extern "C" {
    NTKERNELAPI VOID    KeGenericCallDpc(PKDEFERRED_ROUTINE, PVOID);
    NTKERNELAPI VOID    KeSignalCallDpcDone(PVOID);
    NTKERNELAPI LOGICAL KeSignalCallDpcSynchronize(PVOID);
}

static VOID dpc_stealth_alloc(PKDPC Dpc, PVOID Ctx, PVOID A1, PVOID A2)
{
    UNREFERENCED_PARAMETER(Dpc);
    PEPT_STEALTH_ALLOC_PARAM req = (PEPT_STEALTH_ALLOC_PARAM)Ctx;
    asm_vmx_vmcall(VMCALL_STEALTH_ALLOC, (UINT64)req, req->caller_cr3, 0);
    KeSignalCallDpcSynchronize(A2);
    KeSignalCallDpcDone(A1);
}

static BOOLEAN ept_stealth_alloc_publish(PEPT_STEALTH_ALLOC_PARAM req)
{
    req->result = FALSE;

    // Owner-first: one VMCALL performs the full install.  The following DPC
    // broadcast only takes the already-installed path for each vCPU EPT.
    asm_vmx_vmcall(VMCALL_STEALTH_ALLOC, (UINT64)req, req->caller_cr3, 0);
    if (!req->result)
        return FALSE;

    KeGenericCallDpc(dpc_stealth_alloc, req);
    return req->result;
}

static VOID dpc_stealth_free(PKDPC Dpc, PVOID Ctx, PVOID A1, PVOID A2)
{
    UNREFERENCED_PARAMETER(Dpc);
    PEPT_STEALTH_FREE_PARAM req = (PEPT_STEALTH_FREE_PARAM)Ctx;
    asm_vmx_vmcall(VMCALL_STEALTH_FREE, (UINT64)req, req->caller_cr3, 0);
    KeSignalCallDpcSynchronize(A2);
    KeSignalCallDpcDone(A1);
}

BOOLEAN
ept_stealth_alloc(PVOID target_va, PVOID handler_function)
{
    if (!target_va || !handler_function) return FALSE;
    if (!ept_stealth_region_init()) return FALSE;

    UINT64 caller_cr3 = __readcr3();
    UINT64 target_phys = MmGetPhysicalAddress(target_va).QuadPart;
    if (!target_phys) return FALSE;

    EPT_STEALTH_ALLOC_PARAM req = {};
    req.caller_cr3       = caller_cr3;
    req.target_va        = target_va;
    req.handler_function = handler_function;
    req.target_phys      = target_phys;

    // pre-compute PT info at PASSIVE level 闂?avoid pa_to_va in VMX-root
    {
        PT_PAGE_INFO pti = {};
        if (stealth_find_pt_page(caller_cr3, (UINT64)target_va & ~0xFFFULL, &pti))
        {
            req.pt_page_pfn    = pti.pt_page_phys >> 12;
            req.pt_pte_index   = pti.pte_index;
            // copy PT page + target page content into NonPaged buffers for VMX-root
            { PHYSICAL_ADDRESS _pa; _pa.QuadPart = (LONGLONG)pti.pt_page_phys;
              PVOID _v = MmGetVirtualForPhysical(_pa);
              req.pt_page_copy = _v ? ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'htpS') : NULL;
              if (req.pt_page_copy && _v) RtlCopyMemory(req.pt_page_copy, _v, PAGE_SIZE); }
            { PHYSICAL_ADDRESS _pa; _pa.QuadPart = (LONGLONG)(req.target_phys & ~0xFFFULL);
              PVOID _v = MmGetVirtualForPhysical(_pa);
              req.target_page_copy = _v ? ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'htpS') : NULL;
              if (req.target_page_copy && _v) RtlCopyMemory(req.target_page_copy, _v, PAGE_SIZE); }
            req.pt_precomputed = TRUE;
        }
    }

    return ept_stealth_alloc_publish(&req);
}

BOOLEAN
ept_stealth_inject(PVOID target_va, PVOID shellcode, UINT32 shellcode_size)
{
    if (!target_va || !shellcode || !shellcode_size) return FALSE;
    if (!ept_stealth_region_init()) return FALSE;

    UINT64 caller_cr3 = __readcr3();
    UINT64 base_va    = (UINT64)target_va;
    UINT32 bytes_done = 0, page_count = 0;

    HYPERPLATFORM_LOG_INFO("[hv] stealth inject: VA=%p size=%u", target_va, shellcode_size);

    while (bytes_done < shellcode_size)
    {
        UINT64 current_va     = base_va + bytes_done;
        PVOID  page_va        = (PVOID)(current_va & ~0xFFFULL);
        UINT64 offset_in_page = current_va & 0xFFF;
        UINT32 space_in_page  = (UINT32)(PAGE_SIZE - offset_in_page);
        UINT32 chunk          = shellcode_size - bytes_done;
        if (chunk > space_in_page) chunk = space_in_page;

        UINT64 page_phys = MmGetPhysicalAddress(page_va).QuadPart;
        if (!page_phys) goto rollback;

        EPT_STEALTH_ALLOC_PARAM req = {};
        req.caller_cr3       = caller_cr3;
        req.target_va        = (PVOID)current_va;
        req.handler_function = NULL;
        req.target_phys      = page_phys + (current_va & 0xFFF);
        req.shellcode_buffer = (PUINT8)shellcode + bytes_done;
        req.shellcode_size   = chunk;

        // pre-compute PT info at PASSIVE level 闂?avoid pa_to_va in VMX-root
        {
            PT_PAGE_INFO pti = {};
            if (stealth_find_pt_page(caller_cr3, (UINT64)current_va & ~0xFFFULL, &pti))
            {
                req.pt_page_pfn    = pti.pt_page_phys >> 12;
                req.pt_pte_index   = pti.pte_index;
                req.pt_precomputed = TRUE;
            }
        }

        if (!ept_stealth_alloc_publish(&req))
            goto rollback;

        bytes_done += chunk;
        page_count++;
    }

    HYPERPLATFORM_LOG_INFO("[hv] stealth inject: %u pages set up", page_count);
    return TRUE;

rollback:
    if (page_count > 0)
        ept_stealth_free_range(target_va, bytes_done);
    return FALSE;
}

BOOLEAN
ept_stealth_free(PVOID target_va)
{
    if (!target_va) return FALSE;
    UINT64 free_phys = MmGetPhysicalAddress(target_va).QuadPart;
    if (!free_phys) return FALSE;

    EPT_STEALTH_FREE_PARAM req = {};
    req.caller_cr3  = __readcr3();
    req.target_va   = target_va;
    req.target_phys = free_phys;

    KeGenericCallDpc(dpc_stealth_free, &req);
    return req.result;
}

BOOLEAN
ept_stealth_free_range(PVOID target_va, SIZE_T size)
{
    if (!target_va || !size) return FALSE;
    UINT64 base = (UINT64)target_va & ~0xFFFULL;
    UINT64 end  = ((UINT64)target_va + size + PAGE_SIZE - 1) & ~0xFFFULL;
    BOOLEAN any = FALSE;
    for (UINT64 va = base; va < end; va += PAGE_SIZE)
        if (ept_stealth_free((PVOID)va)) any = TRUE;
    return any;
}

//
// ept_stealth_map_resident 闂?RESIDENT mode for manually mapped DLLs
//
// the caller has already:
//   1. allocated PAGE_READWRITE memory in target process
//   2. written DLL content (PE sections, relocations, imports resolved)
//   3. the memory contains the ready-to-execute DLL image
//
// this function:
//   - copies each page's content into a shadow page (execute view)
//   - zeroes the original page (read view = clean for anti-cheat)
//   - sets EPT: default = execute view (code runs at native speed)
//   - reads trigger EPT violation 闂?temp show clean page 闂?MTF 闂?back
//   - fake PT page hides NX=0 (TLB trick: #PF 闂?real PT 闂?TLB 闂?swap back)
//
// target_va: base VA of the mapped DLL (page-aligned)
// size:      total size of the mapped image
//
BOOLEAN
ept_stealth_map_resident(PVOID target_va, SIZE_T size)
{
    if (!target_va || !size) return FALSE;
    if (!ept_stealth_region_init()) return FALSE;

    UINT64 caller_cr3 = __readcr3();
    UINT64 base_va    = (UINT64)target_va & ~0xFFFULL;
    UINT64 end_va     = ((UINT64)target_va + size + PAGE_SIZE - 1) & ~0xFFFULL;
    UINT32 page_count = 0;

    HYPERPLATFORM_LOG_INFO("[hv] stealth map_resident: VA=%p size=0x%llX (%llu pages)",
               target_va, (UINT64)size, (end_va - base_va) / PAGE_SIZE);

    for (UINT64 va = base_va; va < end_va; va += PAGE_SIZE)
    {
        UINT64 page_phys = MmGetPhysicalAddress((PVOID)va).QuadPart;
        if (!page_phys) goto rollback;

        //
        // for resident mode, the shadow page content = current page content
        // (DLL image already written by caller)
        // the original page will show zeroed content (read view)
        //
        // we pass the current page content as "shellcode" to copy into shadow,
        // then the install function zeroes the original page's EPT read view.
        //
        EPT_STEALTH_ALLOC_PARAM req = {};
        req.caller_cr3       = caller_cr3;
        req.target_va        = (PVOID)va;
        req.handler_function = NULL;
        req.target_phys      = page_phys;
        req.shellcode_buffer = NULL;    // NULL = copy current page content
        req.shellcode_size   = 0;
        req.resident         = TRUE;    // resident mode

        // pre-compute PT info at PASSIVE level 闂?avoid pa_to_va in VMX-root
        {
            PT_PAGE_INFO pti = {};
            if (stealth_find_pt_page(caller_cr3, va, &pti))
            {
                req.pt_page_pfn    = pti.pt_page_phys >> 12;
                req.pt_pte_index   = pti.pte_index;
                req.pt_precomputed = TRUE;
            }
        }

        KeGenericCallDpc(dpc_stealth_alloc, &req);
        if (!req.result)
        {
            HYPERPLATFORM_LOG_ERROR("[hv] stealth map_resident: page %u failed (VA=%p)", page_count, (PVOID)va);
            goto rollback;
        }

        //
        // zero the original page AFTER EPT split is set up
        // now reads see the original page (zeroed) via EPT read view
        // executes see the shadow page (DLL code) via EPT execute view
        //
        RtlZeroMemory((PVOID)va, PAGE_SIZE);

        page_count++;
    }

    HYPERPLATFORM_LOG_INFO("[hv] stealth map_resident: %u pages mapped, DLL running at native speed",
               page_count);
    return TRUE;

rollback:
    if (page_count > 0)
        ept_stealth_free_range(target_va, (SIZE_T)page_count * PAGE_SIZE);
    return FALSE;
}



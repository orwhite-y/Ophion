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
*     all at consecutive physical addresses → looks like one normal allocation.
*/
#include "hv.h"
#include "log.h"

#define POOL_TAG_STEALTH_INFO   4
#define POOL_TAG_STEALTH_FAKEPT 5

#define PFN_MASK  0x000FFFFFFFFFF000ULL
#define NX_BIT    (1ULL << 63)

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
static PUINT8
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

// =========================================================================
//  shared fake PT page management
// =========================================================================

//
// find or create a shared fake PT page for a given physical PT page.
// called from VMX-root (uses pool_manager + contiguous region).
//
static PSTEALTH_FAKE_PT
stealth_get_or_create_fake_pt(VIRTUAL_MACHINE_STATE * vcpu, UINT64 pt_page_pfn, PVOID pt_page_va_hint)
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

    fpt->pt_page_pfn = pt_page_pfn;
    fpt->ref_count   = 1;

    // allocate fake page from contiguous region
    fpt->fake_page_va = stealth_region_alloc_page(&fpt->pfn_of_fake);
    if (!fpt->fake_page_va) { pool_manager_release(fpt); return NULL; }

    // copy real PT page content from caller's NonPaged buffer copy
    if (!pt_page_va_hint) { pool_manager_release(fpt); return NULL; }
    RtlCopyMemory(fpt->fake_page_va, pt_page_va_hint, PAGE_SIZE);

    // split EPT 2MB → 4KB for the PT page if needed
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
    fpt->pt_fake_entry.WriteAccess     = 0;    // write-protect for sync
    fpt->pt_fake_entry.PageFrameNumber = fpt->pfn_of_fake;

    // activate fake view — EPT now maps PT page to fake page
    pt_pte->AsUInt = fpt->pt_fake_entry.AsUInt;

    InsertHeadList(&g_ept->stealth_fake_pts, &fpt->fake_pt_list);
    return fpt;
}

//
// add NX=1 for a specific PTE index in the shared fake PT page
//
static VOID
stealth_fake_pt_set_nx(PSTEALTH_FAKE_PT fpt, UINT32 pte_index)
{
    PUINT64 pte = &((PUINT64)fpt->fake_page_va)[pte_index];
    *pte |= NX_BIT;
}

//
// resync fake PT page from real PT page, then re-apply NX for all stealth entries
//
static VOID
stealth_fake_pt_resync(PSTEALTH_FAKE_PT fpt)
{
    PVOID real_pt_va = pa_to_va(fpt->pt_page_pfn << 12);
    if (!real_pt_va) return;

    RtlCopyMemory(fpt->fake_page_va, real_pt_va, PAGE_SIZE);

    // re-apply NX=1 for all stealth pages using this fake PT
    PLIST_ENTRY cur = g_ept->stealth_pages.Flink;
    while (cur != &g_ept->stealth_pages)
    {
        PEPT_STEALTH_PAGE_INFO sp = CONTAINING_RECORD(cur, EPT_STEALTH_PAGE_INFO, stealth_page_list);
        cur = cur->Flink;
        if (sp->fake_pt && sp->fake_pt->pt_page_pfn == fpt->pt_page_pfn)
            stealth_fake_pt_set_nx(fpt, sp->pt_pte_index);
    }
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
    if (interlock && _InterlockedCompareExchange(interlock, 1, 0) != 0)
    {
        //
        // another CPU is doing or has done the full install.
        // spin briefly then re-check the list — winner should have inserted by now.
        //
        for (int i = 0; i < 1000; i++) _mm_pause();

        cur = g_ept->stealth_pages.Flink;
        while (cur != &g_ept->stealth_pages)
        {
            PEPT_STEALTH_PAGE_INFO existing = CONTAINING_RECORD(cur, EPT_STEALTH_PAGE_INFO, stealth_page_list);
            cur = cur->Flink;
            if (existing->pfn_of_target == target_pfn)
            {
                // winner installed — split this CPU's EPT
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
                _mm_mfence();
                ept_invept_single(vcpu->ept_pointer);
                return TRUE;
            }
        }

        // winner failed or hasn't inserted yet — fall through to try full install
        // (interlock is already 1, but that's fine — only one CPU reaches here)
    }

    // allocate tracking struct
    PEPT_STEALTH_PAGE_INFO sp = (PEPT_STEALTH_PAGE_INFO)
        pool_manager_request(POOL_TAG_STEALTH_INFO, sizeof(EPT_STEALTH_PAGE_INFO));
    if (!sp) return FALSE;
    RtlZeroMemory(sp, sizeof(*sp));

    sp->guest_va         = (UINT64)req->target_va & ~0xFFFULL;
    sp->pfn_of_target    = target_pfn;
    sp->handler_function = req->handler_function;
    sp->guest_cr3        = req->caller_cr3;

    // --- resolve guest PT page info ---
    //
    // prefer pre-computed values (filled at PASSIVE/DISPATCH level by caller).
    // avoids pa_to_va (MmGetVirtualForPhysical) in VMX-root which can deadlock
    // when KeGenericCallDpc sends all CPUs into VMX-root simultaneously and
    // another CPU holds an OS internal lock that pa_to_va needs.
    //
    UINT64 pt_page_pfn;
    UINT64 pt_idx;

    // pt_precomputed MUST be TRUE — callers fill pt_page_pfn/pt_pte_index/pt_page_va
    // at PASSIVE/DISPATCH level. NEVER walk guest page tables via pa_to_va in VMX-root
    // (deadlocks when KeGenericCallDpc puts all CPUs into VMX-root simultaneously).
    if (!req->pt_precomputed) { pool_manager_release(sp); return FALSE; }

    pt_page_pfn = req->pt_page_pfn;
    pt_idx      = req->pt_pte_index;

    sp->pt_pte_index = (UINT32)pt_idx;
    sp->resident     = req->resident;

    //
    // NX clear is done by caller at PASSIVE_LEVEL (TestDriver side).

    //
    // EPT-only stealth: no fake PT page manipulation.
    // execute → EPT violation → swap to shadow page (execute view)
    // read/write → sees original page (read view)
    // simpler and doesn't corrupt other PTEs in the same PT page.
    //
    sp->fake_pt = NULL;  // no fake PT

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
        // copy original page content — MUST use pre-computed VA, NEVER pa_to_va
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
    //   reads would EPT-violate → swap to original page (zeros) → crash.
    //
    // resident DLL mode: use execute-only if supported — reads are served
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
        //   reads trigger EPT violation → temp swap to clean → MTF → back
        //   #PF only fires on TLB miss (context switch, INVLPG) — rare
        //
        target_pte->AsUInt = sp->execute_entry.AsUInt;
    }
    else
    {
        //
        // ONESHOT: default = READ view
        //   #PF on execute → swap to execute view → VMCALL/run → swap back
        //
        target_pte->ReadAccess    = 1;
        target_pte->WriteAccess   = 1;
        target_pte->ExecuteAccess = 0;
    }

    // no #PF interception needed — pure EPT violation driven

    InsertHeadList(&g_ept->stealth_pages, &sp->stealth_page_list);

    //
    //
    // only modify CURRENT CPU's EPT — never touch other CPUs' EPT directly.
    // modifying another CPU's EPT while it's walking it → EPT misconfiguration
    // → VMRESUME failure → CPU dies → 0x101 CLOCK_WATCHDOG.
    //
    // other CPUs: lazy setup via ept_stealth_handle_violation on EPT violation,
    // or via the "already installed" path when this function is called again.
    //
    {
        // split target page 2MB→4KB
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

    return TRUE;

fail_cleanup_fakept:
    // error after fake_pt was acquired — must release ref
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
            RemoveEntryList(&sp->fake_pt->fake_pt_list);
            pool_manager_release(sp->fake_pt);
        }
    }
    pool_manager_release(sp);
    return FALSE;
}

// =========================================================================
//  VMX-root: #PF handler (NX violation)
// =========================================================================

BOOLEAN
ept_stealth_handle_pf(VIRTUAL_MACHINE_STATE * vcpu, UINT64 fault_addr, UINT32 error_code)
{
    UNREFERENCED_PARAMETER(error_code);
    if (!g_ept || IsListEmpty(&g_ept->stealth_pages)) return FALSE;

    UINT64 fault_page = fault_addr & ~0xFFFULL;

    PLIST_ENTRY cur = g_ept->stealth_pages.Flink;
    while (cur != &g_ept->stealth_pages)
    {
        PEPT_STEALTH_PAGE_INFO sp = CONTAINING_RECORD(cur, EPT_STEALTH_PAGE_INFO, stealth_page_list);
        cur = cur->Flink;

        if (sp->guest_va != fault_page) continue;

        // 1. swap PT page EPT → real view (NX=0 visible to page walker)
        if (sp->fake_pt)
        {
            PEPT_PML1_ENTRY pt_pte = ept_get_pml1(vcpu->ept_page_table,
                (SIZE_T)(sp->fake_pt->pt_page_pfn << 12));
            if (pt_pte) pt_pte->AsUInt = sp->fake_pt->pt_real_entry.AsUInt;
        }

        // 2. swap target page EPT → execute view (shadow page)
        PEPT_PML1_ENTRY target_pte = ept_get_pml1(vcpu->ept_page_table,
            (SIZE_T)(sp->pfn_of_target << 12));
        if (target_pte) target_pte->AsUInt = sp->execute_entry.AsUInt;

        // 3. record for MTF restore
        vcpu->stealth_pf_swapped = sp;

        //
        // 4. ARM MTF — after one instruction executes (TLB entry created),
        //    MTF fires and swaps PT page BACK to fake view (NX=1).
        //    BUT does NOT flush the stealth VA's TLB entry.
        //    result: CPU continues from TLB (NX=0 cached), anti-cheat sees NX=1.
        //
        {
            SIZE_T pc = 0;
            __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &pc);
            pc |= (SIZE_T)CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG;
            __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, pc);
        }

        _mm_mfence();
        ept_invept_single(vcpu->ept_pointer);

        // flush guest TLB for stealth VA so CPU re-walks page table
        // (needs to read real PT with NX=0 and build new TLB entry)
        INVVPID_DESCRIPTOR desc = {0};
        desc.Vpid = VPID_TAG;
        if (g_ept->invvpid_individual_addr)
        {
            desc.LinearAddress = fault_addr;
            asm_invvpid(InvvpidIndividualAddress, &desc);
        }
        else
            asm_invvpid(InvvpidSingleContext, &desc);

        return TRUE;
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
        // shellcode mode: handler_function is NULL — VMCALL should not
        // redirect anywhere. skip this entry so it falls through to #UD.
        //
        if (!sp->handler_function) continue;

        //
        // per-process filtering: only dispatch VMCALL for the target process.
        // without this, a different process with the same VA executing VMCALL
        // would be incorrectly redirected.
        //
        if (sp->guest_cr3 != 0)
        {
            UINT64 guest_cr3 = 0;
            __vmx_vmread(VMCS_GUEST_CR3, &guest_cr3);
            if ((guest_cr3 & 0x000FFFFFFFFFF000ULL) != (sp->guest_cr3 & 0x000FFFFFFFFFF000ULL))
                continue;
        }

        // restore target page EPT → read view
        PEPT_PML1_ENTRY target_pte = ept_get_pml1(vcpu->ept_page_table,
            (SIZE_T)(sp->pfn_of_target << 12));
        if (target_pte) target_pte->AsUInt = sp->original_entry.AsUInt;

        // restore PT page EPT → fake view
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
    // no match — stealth page may have been freed between #PF and VMCALL.
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

    if (_InterlockedCompareExchange(&req->freed, 1, 0) == 0)
    {
        PLIST_ENTRY cur = g_ept->stealth_pages.Flink;
        while (cur != &g_ept->stealth_pages)
        {
            PEPT_STEALTH_PAGE_INFO sp = CONTAINING_RECORD(cur, EPT_STEALTH_PAGE_INFO, stealth_page_list);
            cur = cur->Flink;

            if (sp->pfn_of_target != target_pfn) continue;

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
                    // restore PT page EPT to RWX
                    PEPT_PML1_ENTRY pp = ept_get_pml1(vcpu->ept_page_table,
                        (SIZE_T)(sp->fake_pt->pt_page_pfn << 12));
                    if (pp)
                    {
                        pp->ReadAccess = 1; pp->WriteAccess = 1; pp->ExecuteAccess = 1;
                        pp->PageFrameNumber = sp->fake_pt->pt_page_pfn;
                    }
                    RemoveEntryList(&sp->fake_pt->fake_pt_list);
                    pool_manager_release(sp->fake_pt);
                }
                else
                {
                    // other pages still use this fake PT — remove our NX entry
                    // (it was already restored in real PTE above)
                    // resync fake page from real
                    stealth_fake_pt_resync(sp->fake_pt);
                }
            }

            RemoveEntryList(&sp->stealth_page_list);
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

    // pre-compute PT info at PASSIVE level — avoid pa_to_va in VMX-root
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

    KeGenericCallDpc(dpc_stealth_alloc, &req);
    return req.result;
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

        // pre-compute PT info at PASSIVE level — avoid pa_to_va in VMX-root
        {
            PT_PAGE_INFO pti = {};
            if (stealth_find_pt_page(caller_cr3, (UINT64)current_va & ~0xFFFULL, &pti))
            {
                req.pt_page_pfn    = pti.pt_page_phys >> 12;
                req.pt_pte_index   = pti.pte_index;
                req.pt_precomputed = TRUE;
            }
        }

        KeGenericCallDpc(dpc_stealth_alloc, &req);
        if (!req.result) goto rollback;

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
// ept_stealth_map_resident — RESIDENT mode for manually mapped DLLs
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
//   - reads trigger EPT violation → temp show clean page → MTF → back
//   - fake PT page hides NX=0 (TLB trick: #PF → real PT → TLB → swap back)
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

        // pre-compute PT info at PASSIVE level — avoid pa_to_va in VMX-root
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

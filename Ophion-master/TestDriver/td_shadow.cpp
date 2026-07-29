#include "td_common.h"

// =========================================================================
//  shadow CR3: build shadow page tables with NX=0 for a VA range.
//  supports multi-megabyte ranges spanning multiple PT/PD pages.
//  only duplicates pages along the path 閳?all other entries share real pages.
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

#define MAX_REAL_PAGES_PER_SHADOW  64   // PML4 + PDPT + PDs + PTs along the range



KSPIN_LOCK g_shadow_alloc_lock;
TD_SHADOW_CR3_ALLOCATION g_shadow_allocs[MAX_SHADOW_CR3_ALLOCS] = {};

VOID
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

PVOID
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
VOID
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

BOOLEAN
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

BOOLEAN
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
VOID
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
BOOLEAN
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

PVOID
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

BOOLEAN
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

PUINT64
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

BOOLEAN
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
VOID
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

PUINT64
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
UINT64
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
BOOLEAN
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
UINT64
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
BOOLEAN
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

PUINT64
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

BOOLEAN
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

ULONG
TdProtectFromPte(UINT64 pte)
{
    BOOLEAN writable = (pte & (1ULL << 1)) != 0;
    BOOLEAN executable = (pte & NX_BIT_) == 0;

    if (executable)
        return writable ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
    return writable ? PAGE_READWRITE : PAGE_READONLY;
}

VOID
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

VOID
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

VOID
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


/*
*   hostcr3.c - private host page tables for vmx host mode
*
*   deep-copies kernel portion of system page tables to create an isolated
*   cr3 for vmx host mode. protects the hypervisor from guest-mode page
*   table modifications (eg. anti-cheat drivers that unmap/corrupt kernel ptes)
*
*   strategy:
*     1. read system process pml4 (stable kernel cr3)
*     2. allocate our own pml4 -> pdpt -> pd -> pt hierarchy
*     3. copy kernel-space entries (pml4[256..511]), deep-copying every level
*     4. leaf entries still point to same physical pages — isolation is
*        at the page table level only
*     5. set VMCS_HOST_CR3 to our private pml4 physical address
*/
#include "hv.h"
#include "log.h"

#define PTE_PRESENT     (1ULL << 0)
#define PTE_LARGE_PAGE  (1ULL << 7)
#define PTE_PFN_MASK    0x000FFFFFFFFFF000ULL

#define MAX_HOST_PT_PAGES 4096

static PVOID   g_host_pt_pages[MAX_HOST_PT_PAGES];
static UINT32  g_host_pt_count = 0;
static PUINT64 g_host_pml4_va  = NULL;
static UINT64  g_host_pml4_pa  = 0;

static PVOID
host_alloc_page(VOID)
{
    PVOID page = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, HV_POOL_TAG);
    if (!page)
        return NULL;

    RtlZeroMemory(page, PAGE_SIZE);

    if (g_host_pt_count < MAX_HOST_PT_PAGES)
        g_host_pt_pages[g_host_pt_count++] = page;

    return page;
}

//
// map a physical page via MmGetVirtualForPhysical
// returns existing kernel va for any pfn-tracked ram page
// unlike MmMapIoSpace, never fails for regular ram and needs no unmap
//
static PUINT64
host_map_phys(UINT64 pa)
{
    PHYSICAL_ADDRESS phys;
    phys.QuadPart = (LONGLONG)(pa & ~0xFFFULL);
    return (PUINT64)MmGetVirtualForPhysical(phys);
}

//
// deep-copy a single pt (level 1) — 512 leaf 4kb entries
// leaf entries copied as-is (same physical pages)
//
static PUINT64
host_clone_pt(PUINT64 orig_pt)
{
    PUINT64 our_pt = (PUINT64)host_alloc_page();
    if (!our_pt)
        return NULL;

    RtlCopyMemory(our_pt, orig_pt, PAGE_SIZE);
    return our_pt;
}

//
// deep-copy a pd (level 2) — 512 entries, each either a 2mb large page
// (copied as-is) or a pointer to a pt (deep-copied)
//
static PUINT64
host_clone_pd(PUINT64 orig_pd)
{
    PUINT64 our_pd = (PUINT64)host_alloc_page();
    if (!our_pd)
        return NULL;

    for (UINT32 k = 0; k < 512; k++)
    {
        if (!(orig_pd[k] & PTE_PRESENT))
        {
            our_pd[k] = 0;
            continue;
        }

        if (orig_pd[k] & PTE_LARGE_PAGE)
        {
            our_pd[k] = orig_pd[k];
            continue;
        }

        UINT64  orig_pt_pa = orig_pd[k] & PTE_PFN_MASK;
        PUINT64 orig_pt    = host_map_phys(orig_pt_pa);
        if (!orig_pt)
        {
            our_pd[k] = orig_pd[k];
            continue;
        }

        PUINT64 our_pt = host_clone_pt(orig_pt);
        if (!our_pt)
        {
            our_pd[k] = orig_pd[k];
            continue;
        }

        our_pd[k] = (orig_pd[k] & ~PTE_PFN_MASK) | va_to_pa(our_pt);
    }

    return our_pd;
}

//
// deep-copy a pdpt (level 3) — 512 entries, each either a 1gb large page
// (copied as-is) or a pointer to a pd (deep-copied)
//
static PUINT64
host_clone_pdpt(PUINT64 orig_pdpt)
{
    PUINT64 our_pdpt = (PUINT64)host_alloc_page();
    if (!our_pdpt)
        return NULL;

    for (UINT32 j = 0; j < 512; j++)
    {
        if (!(orig_pdpt[j] & PTE_PRESENT))
        {
            our_pdpt[j] = 0;
            continue;
        }

        if (orig_pdpt[j] & PTE_LARGE_PAGE)
        {
            our_pdpt[j] = orig_pdpt[j];
            continue;
        }

        UINT64  orig_pd_pa = orig_pdpt[j] & PTE_PFN_MASK;
        PUINT64 orig_pd    = host_map_phys(orig_pd_pa);
        if (!orig_pd)
        {
            our_pdpt[j] = orig_pdpt[j];
            continue;
        }

        PUINT64 our_pd = host_clone_pd(orig_pd);
        if (!our_pd)
        {
            our_pdpt[j] = orig_pdpt[j];
            continue;
        }

        our_pdpt[j] = (orig_pdpt[j] & ~PTE_PFN_MASK) | va_to_pa(our_pd);
    }

    return our_pdpt;
}

/*
*   build private host page tables by deep-copying kernel pml4 entries
*   must be called after all host-mode allocations (vmm stacks, bitmaps, etc)
*/
BOOLEAN
hostcr3_build(VOID)
{
    UINT64 sys_cr3 = get_system_cr3();
    UINT64 pml4_pa = sys_cr3 & PTE_PFN_MASK;

    PUINT64 orig_pml4 = host_map_phys(pml4_pa);
    if (!orig_pml4)
    {
        HYPERPLATFORM_LOG_ERROR("[hv] hostcr3: failed to map PML4 at PA 0x%llx", pml4_pa);
        return FALSE;
    }

    PUINT64 our_pml4 = (PUINT64)host_alloc_page();
    if (!our_pml4)
        return FALSE;

    //
    // zero user-space entries (never run user code in host mode)
    //
    for (UINT32 i = 0; i < 256; i++)
        our_pml4[i] = 0;

    for (UINT32 i = 256; i < 512; i++)
    {
        if (!(orig_pml4[i] & PTE_PRESENT))
        {
            our_pml4[i] = 0;
            continue;
        }

        //
        // skip self-referencing entry — windows uses one pml4 entry that
        // points back to the pml4 itself for page table self-mapping.
        // fix it up after building our pml4
        //
        if ((orig_pml4[i] & PTE_PFN_MASK) == pml4_pa)
        {
            our_pml4[i] = orig_pml4[i];
            continue;
        }

        UINT64  orig_pdpt_pa = orig_pml4[i] & PTE_PFN_MASK;
        PUINT64 orig_pdpt    = host_map_phys(orig_pdpt_pa);
        if (!orig_pdpt)
        {
            our_pml4[i] = orig_pml4[i];
            continue;
        }

        PUINT64 our_pdpt = host_clone_pdpt(orig_pdpt);
        if (!our_pdpt)
        {
            our_pml4[i] = orig_pml4[i];
            continue;
        }

        our_pml4[i] = (orig_pml4[i] & ~PTE_PFN_MASK) | va_to_pa(our_pdpt);
    }

    g_host_pml4_va = our_pml4;
    g_host_pml4_pa = va_to_pa(our_pml4);

    //
    // fix self-referencing pml4 entry to point to our pml4
    //
    for (UINT32 i = 256; i < 512; i++)
    {
        if ((our_pml4[i] & PTE_PRESENT) &&
            ((our_pml4[i] & PTE_PFN_MASK) == pml4_pa))
        {
            our_pml4[i] = (our_pml4[i] & ~PTE_PFN_MASK) | g_host_pml4_pa;
            break;
        }
    }

    HYPERPLATFORM_LOG_INFO("[hv] Private host CR3 built: PA=0x%llx (%u pages allocated)",
               g_host_pml4_pa, g_host_pt_count);

    return TRUE;
}

UINT64
hostcr3_get(VOID)
{
    return g_host_pml4_pa;
}

/*
*   map a virtual address range into the private host page tables.
*   called at PASSIVE_LEVEL for memory allocated after hostcr3_build()
*   (e.g., stealth contiguous region).
*
*   walks system page tables to find current mappings, then ensures our
*   private page tables have matching entries. creates missing intermediate
*   page table levels as needed.
*/
BOOLEAN
hostcr3_map_va(PVOID va, SIZE_T size)
{
    if (!g_host_pml4_va || !size)
        return FALSE;

    UINT64 sys_cr3    = get_system_cr3();
    UINT64 sys_pml4_pa = sys_cr3 & PTE_PFN_MASK;
    PUINT64 sys_pml4   = host_map_phys(sys_pml4_pa);
    if (!sys_pml4)
        return FALSE;

    UINT64 start = (UINT64)va & ~0xFFFULL;
    UINT64 end   = ((UINT64)va + size + 0xFFF) & ~0xFFFULL;
    UINT32 pages_mapped = 0;

    for (UINT64 addr = start; addr < end; addr += PAGE_SIZE)
    {
        UINT32 pml4_idx = (UINT32)((addr >> 39) & 0x1FF);
        UINT32 pdpt_idx = (UINT32)((addr >> 30) & 0x1FF);
        UINT32 pd_idx   = (UINT32)((addr >> 21) & 0x1FF);
        UINT32 pt_idx   = (UINT32)((addr >> 12) & 0x1FF);

        // only kernel space
        if (pml4_idx < 256)
            continue;

        //
        // walk system page tables to find the leaf
        //
        if (!(sys_pml4[pml4_idx] & PTE_PRESENT))
            continue;

        // skip self-referencing entry
        if ((sys_pml4[pml4_idx] & PTE_PFN_MASK) == sys_pml4_pa)
            continue;

        PUINT64 sys_pdpt = host_map_phys(sys_pml4[pml4_idx] & PTE_PFN_MASK);
        if (!sys_pdpt || !(sys_pdpt[pdpt_idx] & PTE_PRESENT))
            continue;

        if (sys_pdpt[pdpt_idx] & PTE_LARGE_PAGE)
        {
            //
            // 1GB large page — sync to our PDPT if stale.
            // MmAllocateContiguousMemory may cause Windows to create new large
            // pages after hostcr3_build(). Must update our copy to match.
            //
            if (!(g_host_pml4_va[pml4_idx] & PTE_PRESENT))
            {
                addr += (1ULL << 30) - PAGE_SIZE;
                continue;
            }
            PUINT64 our_pdpt_lp = host_map_phys(g_host_pml4_va[pml4_idx] & PTE_PFN_MASK);
            if (our_pdpt_lp && our_pdpt_lp[pdpt_idx] != sys_pdpt[pdpt_idx])
            {
                our_pdpt_lp[pdpt_idx] = sys_pdpt[pdpt_idx];
                pages_mapped++;
            }
            addr += (1ULL << 30) - PAGE_SIZE;
            continue;
        }

        PUINT64 sys_pd = host_map_phys(sys_pdpt[pdpt_idx] & PTE_PFN_MASK);
        if (!sys_pd || !(sys_pd[pd_idx] & PTE_PRESENT))
            continue;

        if (sys_pd[pd_idx] & PTE_LARGE_PAGE)
        {
            //
            // 2MB large page — sync to our PD if stale.
            // common for large contiguous allocations (stealth 64MB region).
            //
            if (!(g_host_pml4_va[pml4_idx] & PTE_PRESENT))
            {
                addr += (1ULL << 21) - PAGE_SIZE;
                continue;
            }
            PUINT64 _our_pdpt = host_map_phys(g_host_pml4_va[pml4_idx] & PTE_PFN_MASK);
            if (!_our_pdpt || !(_our_pdpt[pdpt_idx] & PTE_PRESENT) || (_our_pdpt[pdpt_idx] & PTE_LARGE_PAGE))
            {
                addr += (1ULL << 21) - PAGE_SIZE;
                continue;
            }
            PUINT64 _our_pd = host_map_phys(_our_pdpt[pdpt_idx] & PTE_PFN_MASK);
            if (_our_pd && _our_pd[pd_idx] != sys_pd[pd_idx])
            {
                _our_pd[pd_idx] = sys_pd[pd_idx];
                pages_mapped++;
            }
            addr += (1ULL << 21) - PAGE_SIZE;
            continue;
        }

        PUINT64 sys_pt = host_map_phys(sys_pd[pd_idx] & PTE_PFN_MASK);
        if (!sys_pt || !(sys_pt[pt_idx] & PTE_PRESENT))
            continue;

        //
        // walk our private page tables, creating missing levels
        //

        // PML4 — kernel entries deep-copied at build time, should exist
        if (!(g_host_pml4_va[pml4_idx] & PTE_PRESENT))
        {
            PUINT64 our_pdpt = (PUINT64)host_alloc_page();
            if (!our_pdpt)
                return FALSE;
            g_host_pml4_va[pml4_idx] = (sys_pml4[pml4_idx] & ~PTE_PFN_MASK) | va_to_pa(our_pdpt);
        }

        PUINT64 our_pdpt = host_map_phys(g_host_pml4_va[pml4_idx] & PTE_PFN_MASK);
        if (!our_pdpt)
            continue;

        // PDPT
        if (our_pdpt[pdpt_idx] & PTE_LARGE_PAGE)
        {
            addr += (1ULL << 30) - PAGE_SIZE;
            continue;
        }
        if (!(our_pdpt[pdpt_idx] & PTE_PRESENT))
        {
            //
            // clone the entire PD from system (gets all sibling 2MB entries + PTs)
            //
            PUINT64 cloned_pd = host_clone_pd(sys_pd);
            if (!cloned_pd)
                continue;
            our_pdpt[pdpt_idx] = (sys_pdpt[pdpt_idx] & ~PTE_PFN_MASK) | va_to_pa(cloned_pd);
            // cloned PD includes all PT entries for this 1GB range — skip ahead
            addr += (1ULL << 30) - PAGE_SIZE;
            continue;
        }

        PUINT64 our_pd = host_map_phys(our_pdpt[pdpt_idx] & PTE_PFN_MASK);
        if (!our_pd)
            continue;

        // PD
        if (our_pd[pd_idx] & PTE_LARGE_PAGE)
        {
            addr += (1ULL << 21) - PAGE_SIZE;
            continue;
        }
        if (!(our_pd[pd_idx] & PTE_PRESENT))
        {
            //
            // clone the entire PT from system (gets all sibling 4KB entries)
            //
            PUINT64 cloned_pt = host_clone_pt(sys_pt);
            if (!cloned_pt)
                continue;
            our_pd[pd_idx] = (sys_pd[pd_idx] & ~PTE_PFN_MASK) | va_to_pa(cloned_pt);
            addr += (1ULL << 21) - PAGE_SIZE;
            continue;
        }

        PUINT64 our_pt = host_map_phys(our_pd[pd_idx] & PTE_PFN_MASK);
        if (!our_pt)
            continue;

        //
        // leaf PTE — copy from system if ours is stale/missing
        //
        if (our_pt[pt_idx] != sys_pt[pt_idx])
        {
            our_pt[pt_idx] = sys_pt[pt_idx];
            pages_mapped++;
        }
    }

    if (pages_mapped)
    {
        HYPERPLATFORM_LOG_INFO("[hv] hostcr3_map_va: mapped %u pages for VA %p (size 0x%llx)",
                   pages_mapped, va, (UINT64)size);
    }

    return TRUE;
}

VOID
hostcr3_destroy(VOID)
{
    for (UINT32 i = 0; i < g_host_pt_count; i++)
    {
        if (g_host_pt_pages[i])
            ExFreePoolWithTag(g_host_pt_pages[i], HV_POOL_TAG);
    }

    g_host_pt_count = 0;
    g_host_pml4_va  = NULL;
    g_host_pml4_pa  = 0;
}

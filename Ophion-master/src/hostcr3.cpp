/*
*   hostcr3.c - private host page tables for vmx host mode
*/
#include "hv.h"
#include "log.h"

#define PTE_PRESENT     (1ULL << 0)
#define PTE_LARGE_PAGE  (1ULL << 7)
#define PTE_PFN_MASK    0x000FFFFFFFFFF000ULL

#define MAX_HOST_PT_PAGES 4096
#define HOST_TEMP_TAG 'tCrH'

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

static PUINT64
host_private_va_from_pa(UINT64 pa)
{
    UINT64 page_pa = pa & ~0xFFFULL;

    for (UINT32 i = 0; i < g_host_pt_count; i++)
    {
        if (!g_host_pt_pages[i])
            continue;

        if ((MmGetPhysicalAddress(g_host_pt_pages[i]).QuadPart & ~0xFFFULL) == page_pa)
            return (PUINT64)g_host_pt_pages[i];
    }

    return NULL;
}

static PUINT64
host_read_phys_page(UINT64 pa)
{
    PUINT64 page = (PUINT64)ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, HOST_TEMP_TAG);
    if (!page)
        return NULL;

    PHYSICAL_ADDRESS phys = {};
    phys.QuadPart = (LONGLONG)(pa & ~0xFFFULL);

    MM_COPY_ADDRESS src = {};
    src.PhysicalAddress = phys;

    SIZE_T bytes = 0;
    NTSTATUS st = MmCopyMemory(page, src, PAGE_SIZE, MM_COPY_MEMORY_PHYSICAL, &bytes);
    if (!NT_SUCCESS(st) || bytes != PAGE_SIZE)
    {
        ExFreePoolWithTag(page, HOST_TEMP_TAG);
        return NULL;
    }

    return page;
}

static VOID
host_free_temp_page(PUINT64 page)
{
    if (page)
        ExFreePoolWithTag(page, HOST_TEMP_TAG);
}

static PUINT64
host_clone_pt(PUINT64 orig_pt)
{
    PUINT64 our_pt = (PUINT64)host_alloc_page();
    if (!our_pt)
        return NULL;

    RtlCopyMemory(our_pt, orig_pt, PAGE_SIZE);
    return our_pt;
}

static PUINT64
host_clone_pd(PUINT64 orig_pd)
{
    PUINT64 our_pd = (PUINT64)host_alloc_page();
    if (!our_pd)
        return NULL;

    for (UINT32 k = 0; k < 512; k++)
    {
        UINT64 entry = orig_pd[k];
        if (!(entry & PTE_PRESENT))
        {
            our_pd[k] = 0;
            continue;
        }

        if (entry & PTE_LARGE_PAGE)
        {
            our_pd[k] = entry;
            continue;
        }

        PUINT64 orig_pt = host_read_phys_page(entry & PTE_PFN_MASK);
        if (!orig_pt)
        {
            our_pd[k] = entry;
            continue;
        }

        PUINT64 our_pt = host_clone_pt(orig_pt);
        host_free_temp_page(orig_pt);
        if (!our_pt)
        {
            our_pd[k] = entry;
            continue;
        }

        our_pd[k] = (entry & ~PTE_PFN_MASK) | va_to_pa(our_pt);
    }

    return our_pd;
}

static PUINT64
host_clone_pdpt(PUINT64 orig_pdpt)
{
    PUINT64 our_pdpt = (PUINT64)host_alloc_page();
    if (!our_pdpt)
        return NULL;

    for (UINT32 j = 0; j < 512; j++)
    {
        UINT64 entry = orig_pdpt[j];
        if (!(entry & PTE_PRESENT))
        {
            our_pdpt[j] = 0;
            continue;
        }

        if (entry & PTE_LARGE_PAGE)
        {
            our_pdpt[j] = entry;
            continue;
        }

        PUINT64 orig_pd = host_read_phys_page(entry & PTE_PFN_MASK);
        if (!orig_pd)
        {
            our_pdpt[j] = entry;
            continue;
        }

        PUINT64 our_pd = host_clone_pd(orig_pd);
        host_free_temp_page(orig_pd);
        if (!our_pd)
        {
            our_pdpt[j] = entry;
            continue;
        }

        our_pdpt[j] = (entry & ~PTE_PFN_MASK) | va_to_pa(our_pd);
    }

    return our_pdpt;
}

BOOLEAN
hostcr3_build(VOID)
{
    UINT64 sys_cr3 = get_system_cr3();
    UINT64 pml4_pa = sys_cr3 & PTE_PFN_MASK;

    PUINT64 orig_pml4 = host_read_phys_page(pml4_pa);
    if (!orig_pml4)
    {
        HYPERPLATFORM_LOG_ERROR("[hv] hostcr3: failed to read PML4 at PA 0x%llx", pml4_pa);
        return FALSE;
    }

    PUINT64 our_pml4 = (PUINT64)host_alloc_page();
    if (!our_pml4)
    {
        host_free_temp_page(orig_pml4);
        return FALSE;
    }

    for (UINT32 i = 0; i < 256; i++)
        our_pml4[i] = 0;

    for (UINT32 i = 256; i < 512; i++)
    {
        UINT64 entry = orig_pml4[i];
        if (!(entry & PTE_PRESENT))
        {
            our_pml4[i] = 0;
            continue;
        }

        if ((entry & PTE_PFN_MASK) == pml4_pa)
        {
            our_pml4[i] = entry;
            continue;
        }

        PUINT64 orig_pdpt = host_read_phys_page(entry & PTE_PFN_MASK);
        if (!orig_pdpt)
        {
            our_pml4[i] = entry;
            continue;
        }

        PUINT64 our_pdpt = host_clone_pdpt(orig_pdpt);
        host_free_temp_page(orig_pdpt);
        if (!our_pdpt)
        {
            our_pml4[i] = entry;
            continue;
        }

        our_pml4[i] = (entry & ~PTE_PFN_MASK) | va_to_pa(our_pdpt);
    }

    g_host_pml4_va = our_pml4;
    g_host_pml4_pa = va_to_pa(our_pml4);

    for (UINT32 i = 256; i < 512; i++)
    {
        if ((our_pml4[i] & PTE_PRESENT) &&
            ((our_pml4[i] & PTE_PFN_MASK) == pml4_pa))
        {
            our_pml4[i] = (our_pml4[i] & ~PTE_PFN_MASK) | g_host_pml4_pa;
            break;
        }
    }

    host_free_temp_page(orig_pml4);

    HYPERPLATFORM_LOG_INFO("[hv] Private host CR3 built: PA=0x%llx (%u pages allocated)",
               g_host_pml4_pa, g_host_pt_count);
    return TRUE;
}

UINT64
hostcr3_get(VOID)
{
    return g_host_pml4_pa;
}

BOOLEAN
hostcr3_map_va(PVOID va, SIZE_T size)
{
    if (!g_host_pml4_va || !size)
        return FALSE;

    PUINT64 sys_pml4 = host_read_phys_page(get_system_cr3() & PTE_PFN_MASK);
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

        if (pml4_idx < 256)
            continue;

        UINT64 sys_pml4e = sys_pml4[pml4_idx];
        if (!(sys_pml4e & PTE_PRESENT))
            continue;

        PUINT64 sys_pdpt = host_read_phys_page(sys_pml4e & PTE_PFN_MASK);
        if (!sys_pdpt)
            continue;

        UINT64 sys_pdpte = sys_pdpt[pdpt_idx];
        if (!(sys_pdpte & PTE_PRESENT))
        {
            host_free_temp_page(sys_pdpt);
            continue;
        }

        PUINT64 our_pdpt = host_private_va_from_pa(g_host_pml4_va[pml4_idx] & PTE_PFN_MASK);
        if (!our_pdpt)
        {
            host_free_temp_page(sys_pdpt);
            continue;
        }

        if (sys_pdpte & PTE_LARGE_PAGE)
        {
            if (our_pdpt[pdpt_idx] != sys_pdpte)
            {
                our_pdpt[pdpt_idx] = sys_pdpte;
                pages_mapped++;
            }
            host_free_temp_page(sys_pdpt);
            addr += (1ULL << 30) - PAGE_SIZE;
            continue;
        }

        PUINT64 sys_pd = host_read_phys_page(sys_pdpte & PTE_PFN_MASK);
        if (!sys_pd)
        {
            host_free_temp_page(sys_pdpt);
            continue;
        }

        UINT64 sys_pde = sys_pd[pd_idx];
        if (!(sys_pde & PTE_PRESENT))
        {
            host_free_temp_page(sys_pd);
            host_free_temp_page(sys_pdpt);
            continue;
        }

        if (!(our_pdpt[pdpt_idx] & PTE_PRESENT))
        {
            PUINT64 cloned_pd = host_clone_pd(sys_pd);
            if (cloned_pd)
            {
                our_pdpt[pdpt_idx] = (sys_pdpte & ~PTE_PFN_MASK) | va_to_pa(cloned_pd);
                pages_mapped++;
            }
            host_free_temp_page(sys_pd);
            host_free_temp_page(sys_pdpt);
            addr += (1ULL << 30) - PAGE_SIZE;
            continue;
        }

        PUINT64 our_pd = host_private_va_from_pa(our_pdpt[pdpt_idx] & PTE_PFN_MASK);
        if (!our_pd)
        {
            host_free_temp_page(sys_pd);
            host_free_temp_page(sys_pdpt);
            continue;
        }

        if (sys_pde & PTE_LARGE_PAGE)
        {
            if (our_pd[pd_idx] != sys_pde)
            {
                our_pd[pd_idx] = sys_pde;
                pages_mapped++;
            }
            host_free_temp_page(sys_pd);
            host_free_temp_page(sys_pdpt);
            addr += (1ULL << 21) - PAGE_SIZE;
            continue;
        }

        PUINT64 sys_pt = host_read_phys_page(sys_pde & PTE_PFN_MASK);
        if (!sys_pt)
        {
            host_free_temp_page(sys_pd);
            host_free_temp_page(sys_pdpt);
            continue;
        }

        if (!(sys_pt[pt_idx] & PTE_PRESENT))
        {
            host_free_temp_page(sys_pt);
            host_free_temp_page(sys_pd);
            host_free_temp_page(sys_pdpt);
            continue;
        }

        if (!(our_pd[pd_idx] & PTE_PRESENT))
        {
            PUINT64 cloned_pt = host_clone_pt(sys_pt);
            if (cloned_pt)
            {
                our_pd[pd_idx] = (sys_pde & ~PTE_PFN_MASK) | va_to_pa(cloned_pt);
                pages_mapped++;
            }
            host_free_temp_page(sys_pt);
            host_free_temp_page(sys_pd);
            host_free_temp_page(sys_pdpt);
            addr += (1ULL << 21) - PAGE_SIZE;
            continue;
        }

        PUINT64 our_pt = host_private_va_from_pa(our_pd[pd_idx] & PTE_PFN_MASK);
        if (our_pt && our_pt[pt_idx] != sys_pt[pt_idx])
        {
            our_pt[pt_idx] = sys_pt[pt_idx];
            pages_mapped++;
        }

        host_free_temp_page(sys_pt);
        host_free_temp_page(sys_pd);
        host_free_temp_page(sys_pdpt);
    }

    host_free_temp_page(sys_pml4);

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

    RtlZeroMemory(g_host_pt_pages, sizeof(g_host_pt_pages));
    g_host_pt_count = 0;
    g_host_pml4_va  = NULL;
    g_host_pml4_pa  = 0;
}

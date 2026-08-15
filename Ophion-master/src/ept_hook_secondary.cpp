/*
*   ept_hook_secondary.cpp - Secondary CPU EPT hook installation
*
*   In Per-CPU EPT architecture, each CPU must modify its own EPT.
*   This module handles secondary CPU hook installation (EPT-only, no resource allocation).
*
*   Primary CPU (is_primary_cpu=TRUE):
*     - Allocates all resources (fake page, trampoline, metadata)
*     - Modifies EPT
*     - Adds to global hook list
*
*   Secondary CPUs (is_primary_cpu=FALSE):
*     - Lookup existing hook info from global list
*     - Split large pages if needed
*     - Modify EPT PTEs only
*     - No resource allocation (avoids race conditions)
*/
#include "hv.h"
#include "log.h"
#include "ept.h"

extern volatile UINT64 g_ept_hook_diag;
extern volatile UINT64 g_ept_hook_diag2;

// Diagnostic codes (from ept_hook.cpp)
#define HOOK_DIAG_SECONDARY_NO_PAGE  16  // Secondary CPU: HOOKED_PAGE_INFO not found
#define HOOK_DIAG_SECONDARY_SPLIT    17  // Secondary CPU: split large page failed
#define HOOK_DIAG_SECONDARY_NO_PML1  18  // Secondary CPU: PML1 entry not found

//
// Secondary CPU hook installation
// Only modifies EPT, assumes primary CPU already allocated resources
//
BOOLEAN
ept_hook_install_secondary_cpu(
    VIRTUAL_MACHINE_STATE * vcpu,
    PEPT_HOOK_VMCALL_PARAM req,
    UINT64 target_pfn,
    UINT64 phys_addr)
{
    //
    // 1. Find existing HOOKED_PAGE_INFO (primary CPU already created it)
    //
    PEPT_HOOKED_PAGE_INFO hp = NULL;

    for (struct _LIST_ENTRY * cur = g_ept->hooked_pages.Flink;
         cur != &g_ept->hooked_pages;
         cur = cur->Flink)
    {
        PEPT_HOOKED_PAGE_INFO existing = CONTAINING_RECORD(cur, EPT_HOOKED_PAGE_INFO, hooked_page_list);
        if (existing->pfn_of_hooked_page == target_pfn)
        {
            hp = existing;
            break;
        }
    }

    if (!hp)
    {
        // Primary CPU failed or hasn't completed yet
        g_ept_hook_diag = HOOK_DIAG_SECONDARY_NO_PAGE;
        g_ept_hook_diag2 = target_pfn;
        return FALSE;
    }

    //
    // 2. Split large page if needed (each CPU has independent EPT)
    //
    PEPT_PML2_ENTRY p2 = ept_get_pml2(vcpu->ept_page_table, (SIZE_T)phys_addr);
    if (p2 && p2->LargePage)
    {
        if (!ept_split_large_page_pool(vcpu->ept_page_table, (SIZE_T)phys_addr))
        {
            g_ept_hook_diag = HOOK_DIAG_SECONDARY_SPLIT;
            g_ept_hook_diag2 = phys_addr;
            return FALSE;
        }
    }

    //
    // 3. Modify target page EPT: X=0 (trigger EPT violation)
    //
    PEPT_PML1_ENTRY target_pte = ept_get_pml1(vcpu->ept_page_table, (SIZE_T)phys_addr);
    if (!target_pte)
    {
        g_ept_hook_diag = HOOK_DIAG_SECONDARY_NO_PML1;
        g_ept_hook_diag2 = phys_addr;
        return FALSE;
    }

    target_pte->ExecuteAccess = 0;  // Trigger EPT violation on execute

    //
    // 4. Modify fake page EPT: R=0, W=0, X=1 (execute-only)
    //
    UINT64 fake_phys = (UINT64)(hp->pfn_of_fake_page_contents << 12);

    // Split fake page's 2MB if needed
    PEPT_PML2_ENTRY fake_p2 = ept_get_pml2(vcpu->ept_page_table, (SIZE_T)fake_phys);
    if (fake_p2 && fake_p2->LargePage)
    {
        ept_split_large_page_pool(vcpu->ept_page_table, (SIZE_T)fake_phys);
    }

    PEPT_PML1_ENTRY fake_pte = ept_get_pml1(vcpu->ept_page_table, (SIZE_T)fake_phys);
    if (fake_pte)
    {
        fake_pte->ReadAccess = (req->force_read_access) ? 1 : 0;
        fake_pte->WriteAccess = 0;
        fake_pte->ExecuteAccess = 1;  // Execute-only (or R+X if force_read_access)
    }

    //
    // 5. INVEPT (single-context is sufficient)
    //
    ept_invept_single_context(vcpu->ept_pointer);

    return TRUE;
}

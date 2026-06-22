/*
*   ept_diag.cpp - read-only EPT diagnostics helpers
*
*   This module intentionally does not alter EPT permissions, replace PFNs,
*   install hooks, or redirect guest execution. It only snapshots already-built
*   EPT state for diagnostics and defensive verification.
*/
#include "hv.h"

BOOLEAN
ept_diag_query_snapshot(_Out_ PEPT_DIAGNOSTICS_SNAPSHOT snapshot)
{
    if (snapshot == NULL)
        return FALSE;

    RtlZeroMemory(snapshot, sizeof(*snapshot));

    snapshot->processor_count = g_cpu_count;

    if (g_ept != NULL)
    {
        snapshot->mtrr_range_count                  = g_ept->num_ranges;
        snapshot->default_memory_type               = g_ept->default_type;
        snapshot->ad_supported                      = g_ept->ad_supported;
        snapshot->invvpid_supported                 = g_ept->invvpid_supported;
        snapshot->invvpid_individual_addr           = g_ept->invvpid_individual_addr;
        snapshot->invvpid_single_context            = g_ept->invvpid_single_context;
        snapshot->invvpid_all_contexts              = g_ept->invvpid_all_contexts;
        snapshot->invvpid_single_retaining_globals  = g_ept->invvpid_single_retaining_globals;
    }

    if (g_vcpu != NULL)
    {
        for (UINT32 i = 0; i < g_cpu_count; i++)
        {
            if (g_vcpu[i].ept_page_table != NULL && g_vcpu[i].ept_pointer.AsUInt != 0)
                snapshot->initialized_processors++;
        }
    }

    return TRUE;
}

BOOLEAN
ept_diag_query_pml2(
    _In_  UINT32          processor_index,
    _In_  SIZE_T          phys_addr,
    _Out_ PEPT_PML2_ENTRY entry_out)
{
    PEPT_PML2_ENTRY entry;

    if (entry_out == NULL || g_vcpu == NULL || processor_index >= g_cpu_count)
        return FALSE;

    if (g_vcpu[processor_index].ept_page_table == NULL)
        return FALSE;

    entry = ept_get_pml2(g_vcpu[processor_index].ept_page_table, phys_addr);
    if (entry == NULL)
        return FALSE;

    RtlCopyMemory(entry_out, entry, sizeof(*entry_out));
    return TRUE;
}

BOOLEAN
ept_diag_query_pml1(
    _In_  UINT32          processor_index,
    _In_  SIZE_T          phys_addr,
    _Out_ PEPT_PML1_ENTRY entry_out)
{
    PEPT_PML1_ENTRY entry;

    if (entry_out == NULL || g_vcpu == NULL || processor_index >= g_cpu_count)
        return FALSE;

    if (g_vcpu[processor_index].ept_page_table == NULL)
        return FALSE;

    entry = ept_get_pml1(g_vcpu[processor_index].ept_page_table, phys_addr);
    if (entry == NULL)
        return FALSE;

    RtlCopyMemory(entry_out, entry, sizeof(*entry_out));
    return TRUE;
}
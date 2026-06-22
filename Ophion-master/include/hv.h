/*
*   hv.h - master hypervisor header — includes everything needed
*/
#pragma once

//
// windows kernel headers (used only at PASSIVE/DPC level in non-root)
//
#include <ntddk.h>
#include <intrin.h>

#include "ia32.h"
#include "hv_types.h"
#include "asm_prototypes.h"
#include "stealth.h"

#ifdef __cplusplus
extern "C" {
#endif

UINT64 va_to_pa(PVOID va);
PVOID  pa_to_va(UINT64 pa);
UINT64 get_system_cr3(VOID);

//
// private host page tables (hostcr3.c)
//
BOOLEAN hostcr3_build(VOID);
UINT64  hostcr3_get(VOID);
VOID    hostcr3_destroy(VOID);

//
// private host IDT (hostidt.c)
//
BOOLEAN hostidt_build(VOID);
UINT64  hostidt_get_base(VOID);
VOID    hostidt_destroy(VOID);

//
// per-core private host GDT (hostgdt.c)
//
BOOLEAN hostgdt_build_for_vcpu(VIRTUAL_MACHINE_STATE * vcpu);
VOID    hostgdt_destroy_for_vcpu(VIRTUAL_MACHINE_STATE * vcpu);

//
// segment helpers (segment.c)
//
VOID segment_get_descriptor(PUCHAR gdt_base, UINT16 selector, VMX_SEGMENT_SELECTOR * result);
VOID segment_fill_vmcs(PVOID gdt_base, UINT32 seg_reg, UINT16 selector);

BOOLEAN vmx_check_support(VOID);
BOOLEAN vmx_init(VOID);
VOID    vmx_terminate(VOID);

BOOLEAN vmx_virtualize_cpu(PVOID guest_stack);
BOOLEAN vmx_setup_vmcs(VIRTUAL_MACHINE_STATE * vcpu, PVOID guest_stack);

BOOLEAN vmx_alloc_vmxon(VIRTUAL_MACHINE_STATE * vcpu);
BOOLEAN vmx_alloc_vmcs(VIRTUAL_MACHINE_STATE * vcpu);
BOOLEAN vmx_clear_vmcs(VIRTUAL_MACHINE_STATE * vcpu);
BOOLEAN vmx_load_vmcs(VIRTUAL_MACHINE_STATE * vcpu);

UINT32  vmx_adjust_controls(UINT32 requested, UINT32 capability_msr);
VOID    vmx_set_fixed_bits(VOID);
VOID    vmx_vmresume(VOID);
UINT64  vmx_return_rsp_for_vmxoff(VOID);
UINT64  vmx_return_rip_for_vmxoff(VOID);

BOOLEAN ept_check_features(VOID);
BOOLEAN ept_build_mtrr_map(VOID);
BOOLEAN ept_init(VOID);
PVMM_EPT_PAGE_TABLE ept_alloc_identity_map(VOID);
UINT8   ept_get_memory_type(SIZE_T pfn, BOOLEAN is_large_page);
BOOLEAN ept_valid_for_large_page(SIZE_T pfn);
BOOLEAN ept_setup_pml2(PVMM_EPT_PAGE_TABLE page_table, PEPT_PML2_ENTRY new_entry, SIZE_T pfn);

PEPT_PML1_ENTRY ept_get_pml1(PVMM_EPT_PAGE_TABLE page_table, SIZE_T phys_addr);
PEPT_PML2_ENTRY ept_get_pml2(PVMM_EPT_PAGE_TABLE page_table, SIZE_T phys_addr);
BOOLEAN ept_split_large_page(PVMM_EPT_PAGE_TABLE page_table, SIZE_T phys_addr);

BOOLEAN ept_diag_query_snapshot(PEPT_DIAGNOSTICS_SNAPSHOT snapshot);
BOOLEAN ept_diag_query_pml2(UINT32 processor_index, SIZE_T phys_addr, PEPT_PML2_ENTRY entry_out);
BOOLEAN ept_diag_query_pml1(UINT32 processor_index, SIZE_T phys_addr, PEPT_PML1_ENTRY entry_out);

VOID ept_invept_single(EPT_POINTER ept_ptr);
VOID ept_invept_all(VOID);
VOID vpid_invvpid_single(UINT16 vpid);

//
// EPT hook engine (ept_hook.cpp)
//   hook_type: 0 = absolute jump (14B), 1 = VMCALL (3B), 2 = INT3 (1B)
//

// public API — PASSIVE_LEVEL, issues VMCALL to all CPUs via DPC broadcast
BOOLEAN ept_hook_function(PVOID target, PVOID proxy, PVOID * original, UINT32 hook_type);
BOOLEAN ept_unhook_function(PVOID target);
VOID    ept_unhook_all_broadcast(VOID);

// VMX-root internal — called from VMCALL handler (guest CR3 must be active)
BOOLEAN ept_hook_install(VIRTUAL_MACHINE_STATE * vcpu, PEPT_HOOK_VMCALL_PARAM req);
BOOLEAN ept_unhook_install(VIRTUAL_MACHINE_STATE * vcpu, PEPT_UNHOOK_VMCALL_PARAM req);
VOID    ept_unhook_all(VOID);

// VMX-root handlers — called from vmexit dispatch
BOOLEAN ept_handle_violation(VIRTUAL_MACHINE_STATE * vcpu, UINT64 guest_phys, UINT64 exit_qual);
VOID    ept_handle_mtf(VIRTUAL_MACHINE_STATE * vcpu);
BOOLEAN ept_handle_vmcall_hook(VIRTUAL_MACHINE_STATE * vcpu);

//
// pool manager (pool_manager.cpp)
//
BOOLEAN pool_manager_init(VOID);
PVOID   pool_manager_request(UINT32 type, SIZE_T size);
UINT64  pool_manager_get_physical(PVOID address);  // safe in VMX-root
VOID    pool_manager_release(PVOID address);
VOID    pool_manager_destroy(VOID);

BOOLEAN vmexit_handler(PGUEST_REGS regs, VIRTUAL_MACHINE_STATE * vcpu);

//
// exit sub-handlers
//
VOID vmexit_handle_cpuid(VIRTUAL_MACHINE_STATE * vcpu);
VOID vmexit_handle_msr_read(VIRTUAL_MACHINE_STATE * vcpu);
VOID vmexit_handle_msr_write(VIRTUAL_MACHINE_STATE * vcpu);
VOID vmexit_handle_mov_cr(VIRTUAL_MACHINE_STATE * vcpu);
VOID vmexit_handle_mov_dr(VIRTUAL_MACHINE_STATE * vcpu);
VOID vmexit_handle_ept_violation(VIRTUAL_MACHINE_STATE * vcpu);
VOID vmexit_handle_vmcall(VIRTUAL_MACHINE_STATE * vcpu);
VOID vmexit_handle_triple_fault(VIRTUAL_MACHINE_STATE * vcpu);

//
// event injection helpers (events.c)
//
VOID vmexit_inject_gp(VOID);
VOID vmexit_inject_ud(VOID);
VOID vmexit_inject_df(VOID);
VOID vmexit_inject_interrupt(UINT32 vector);
VOID vmexit_inject_bp(VOID);
VOID vmexit_inject_pf(UINT32 error_code, UINT64 fault_addr);

VOID broadcast_virtualize_all(VOID);
VOID broadcast_terminate_all(VOID);

NTSTATUS DriverEntry(PDRIVER_OBJECT driver_obj, PUNICODE_STRING registry_path);
VOID     DriverUnload(PDRIVER_OBJECT driver_obj);

#ifdef __cplusplus
}
#endif

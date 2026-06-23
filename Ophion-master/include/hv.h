/*
*   hv.h - master hypervisor header — includes everything needed
*/
#pragma once

//
// windows kernel headers (used only at PASSIVE/DPC level in non-root)
// ntifs.h includes ntddk.h + wdm.h + APC types + ObOpenObjectByPointer
//
#include <ntifs.h>
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
// CR3 switch helpers for private host CR3 compatibility.
//
// in VMX-root with USE_PRIVATE_HOST_CR3, the host CR3 is a static snapshot
// that doesn't map memory allocated after init (DPC stacks, other drivers, etc.)
//
// before accessing guest/system memory in VMX-root, switch to system CR3.
// after done, switch back. the VMM stack is always accessible under both
// (allocated before hostcr3_build, mapped in both private and system CR3).
//
// IMPORTANT: read all values from VMM stack (regs->xxx) BEFORE switching CR3.
// the compiler may reorder reads across __writecr3 — use _mm_mfence if needed.
//
static __forceinline UINT64
vmx_enter_guest_cr3(VOID)
{
#if USE_PRIVATE_HOST_CR3
    UINT64 saved = __readcr3();
    __writecr3(g_system_cr3);
    _mm_mfence();
    return saved;
#else
    return 0;
#endif
}

static __forceinline VOID
vmx_leave_guest_cr3(UINT64 saved)
{
#if USE_PRIVATE_HOST_CR3
    _mm_mfence();
    __writecr3(saved);
#else
    UNREFERENCED_PARAMETER(saved);
#endif
}

//
// private host page tables (hostcr3.c)
//
BOOLEAN hostcr3_build(VOID);
UINT64  hostcr3_get(VOID);
VOID    hostcr3_destroy(VOID);
BOOLEAN hostcr3_map_va(PVOID va, SIZE_T size);

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

// VMX-root internal — called from VMCALL handler (guest CR3 must be active)
BOOLEAN ept_hook_install(VIRTUAL_MACHINE_STATE * vcpu, PEPT_HOOK_VMCALL_PARAM req);
BOOLEAN ept_unhook_install(VIRTUAL_MACHINE_STATE * vcpu, PEPT_UNHOOK_VMCALL_PARAM req);
VOID    ept_unhook_all(VOID);

// VMX-root safe EPT 2MB→4KB split (uses pre-allocated pool, NOT ExAllocatePool2)
PVMM_EPT_DYNAMIC_SPLIT ept_split_large_page_pool(PVMM_EPT_PAGE_TABLE page_table, SIZE_T phys_addr);

// VMX-root handlers — called from vmexit dispatch
BOOLEAN ept_handle_violation(VIRTUAL_MACHINE_STATE * vcpu, UINT64 guest_phys, UINT64 exit_qual);
VOID    ept_handle_mtf(VIRTUAL_MACHINE_STATE * vcpu);
BOOLEAN ept_handle_vmcall_hook(VIRTUAL_MACHINE_STATE * vcpu);

//
// stealth memory allocation (ept_stealth.cpp)
//   allocates PAGE_READWRITE memory with hidden execute capability via EPT split
//   read → clean data (no exec attr), execute → VMCALL → handler dispatch
//

// stealth region — contiguous physical memory for shadow/fake pages
BOOLEAN ept_stealth_region_init(VOID);
VOID    ept_stealth_region_destroy(VOID);

// public API — PASSIVE_LEVEL
BOOLEAN ept_stealth_alloc(PVOID target_va, PVOID handler_function);
BOOLEAN ept_stealth_inject(PVOID target_va, PVOID shellcode, UINT32 shellcode_size);
BOOLEAN ept_stealth_map_resident(PVOID target_va, SIZE_T size);
BOOLEAN ept_stealth_free(PVOID target_va);
BOOLEAN ept_stealth_free_range(PVOID target_va, SIZE_T size);
VOID    ept_stealth_free_all_broadcast(VOID);

// VMX-root internal
BOOLEAN ept_stealth_install_ex(VIRTUAL_MACHINE_STATE * vcpu, PEPT_STEALTH_ALLOC_PARAM req, volatile LONG * interlock);

// convenience wrapper: uses &req->installed as interlock (for Ophion internal DPC path)
static __forceinline BOOLEAN
ept_stealth_install(VIRTUAL_MACHINE_STATE * vcpu, PEPT_STEALTH_ALLOC_PARAM req)
{ return ept_stealth_install_ex(vcpu, req, &req->installed); }
BOOLEAN ept_stealth_uninstall(VIRTUAL_MACHINE_STATE * vcpu, PEPT_STEALTH_FREE_PARAM req);
VOID    ept_stealth_free_all(VOID);

// VMX-root handler — check if VMCALL came from a stealth page
BOOLEAN ept_handle_stealth_vmcall(VIRTUAL_MACHINE_STATE * vcpu);

// EPT violation handler for stealth pages (target page + PT page writes)
BOOLEAN ept_stealth_handle_violation(VIRTUAL_MACHINE_STATE * vcpu, UINT64 guest_phys, UINT64 exit_qual);

// #PF handler — intercepts instruction-fetch page faults (NX violations)
// temporarily swaps PT page EPT to real view so CPU page walk sees NX=0
BOOLEAN ept_stealth_handle_pf(VIRTUAL_MACHINE_STATE * vcpu, UINT64 fault_addr, UINT32 error_code);

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

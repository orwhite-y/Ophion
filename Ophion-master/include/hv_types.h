/*
*   hv_types.h - core hypervisor type definitions — per-vcpu state, ept structures, configs
*   zero windows api dependency in vmx-root mode by design
*/
#pragma once

#include "ia32.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MAXULONG64
#define MAXULONG64              ((ULONG64)~((ULONG64)0))
#endif

#define VMM_STACK_SIZE          0x8000      // 32 KB per-VCPU VMM stack
#define VMM_STACK_VCPU_OFFSET   8           // vcpu ptr stored at top-8 of stack
#define VMXON_SIZE              0x1000
#define VMCS_SIZE               0x1000
#define MAX_PROCESSORS          256
#define MAX_MTRR_RANGES         256

#define HV_POOL_TAG             'nhpO'

typedef struct _GUEST_REGS {
    UINT64 rax;
    UINT64 rcx;
    UINT64 rdx;
    UINT64 rbx;
    UINT64 rsp;    // placeholder — real RSP read from VMCS
    UINT64 rbp;
    UINT64 rsi;
    UINT64 rdi;
    UINT64 r8;
    UINT64 r9;
    UINT64 r10;
    UINT64 r11;
    UINT64 r12;
    UINT64 r13;
    UINT64 r14;
    UINT64 r15;
} GUEST_REGS, *PGUEST_REGS;

typedef struct _VMX_VMXOFF_STATE {
    BOOLEAN executed;
    UINT64  guest_rip;
    UINT64  guest_rsp;
    UINT64  guest_cr3;
} VMX_VMXOFF_STATE;

typedef struct _MTRR_RANGE_DESCRIPTOR {
    UINT64  phys_base;
    UINT64  phys_end;
    UINT8   mem_type;
    BOOLEAN fixed;
} MTRR_RANGE_DESCRIPTOR;

typedef struct _VMM_EPT_PAGE_TABLE {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML4_ENTRY   PML4[VMM_EPT_PML4E_COUNT];
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML3_POINTER PML3[VMM_EPT_PML3E_COUNT];
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML2_ENTRY   PML2[VMM_EPT_PML3E_COUNT][VMM_EPT_PML2E_COUNT];
} VMM_EPT_PAGE_TABLE, *PVMM_EPT_PAGE_TABLE;

//
// dynamic split: when we split a 2MB page into 512 4KB pages
//
typedef struct _VMM_EPT_DYNAMIC_SPLIT {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_PML1_ENTRY PML1[VMM_EPT_PML1E_COUNT];
    union {
        PEPT_PML2_ENTRY   Entry;
        PEPT_PML2_POINTER Pointer;
    } u;
    LIST_ENTRY SplitList;
} VMM_EPT_DYNAMIC_SPLIT, *PVMM_EPT_DYNAMIC_SPLIT;

//
// EPT hook option flags
//
#define EPTO_HOOK_FUNCTION       2
#define EPTO_VIRTUAL_BREAKPOINT  1

//
// per-function hook tracking — one for each function hooked within a page
//
typedef struct _EPT_HOOKED_FUNCTION_INFO {
    LIST_ENTRY  hooked_function_list;
    PVOID       virtual_address;          // original function VA
    PVOID       handler_function;         // proxy/hook function
    PUINT8      first_trampoline_address; // trampoline for calling original
    PUINT8      fake_page_contents;       // pointer to parent page's fake page
    UINT64      hook_size;                // bytes overwritten
} EPT_HOOKED_FUNCTION_INFO, *PEPT_HOOKED_FUNCTION_INFO;

//
// per-page hook tracking — one for each 4KB page with hooks
//
typedef struct _EPT_HOOKED_PAGE_INFO {
    LIST_ENTRY       hooked_page_list;
    LIST_ENTRY       hooked_functions_list;
    DECLSPEC_ALIGN(PAGE_SIZE) UINT8 fake_page_contents[PAGE_SIZE];
    UINT64           pfn_of_hooked_page;
    UINT64           pfn_of_fake_page_contents;
    PEPT_PML1_ENTRY  entry_address;       // pointer to EPT PTE being manipulated
    EPT_PML1_ENTRY   original_entry;      // saved original PTE (RW, no X)
    EPT_PML1_ENTRY   changed_entry;       // fake page PTE (X only, no RW)
    UINT32           Options;             // EPTO_HOOK_FUNCTION or EPTO_VIRTUAL_BREAKPOINT
} EPT_HOOKED_PAGE_INFO, *PEPT_HOOKED_PAGE_INFO;

typedef struct _EPT_STATE {
    MTRR_RANGE_DESCRIPTOR mem_ranges[MAX_MTRR_RANGES];
    UINT32                num_ranges;
    UINT8                 default_type;
    BOOLEAN               ad_supported;
    BOOLEAN               execute_only_supported;  // CPU supports X-only EPT pages (R=0,W=0,X=1)
    LIST_ENTRY            hooked_pages;    // list of EPT_HOOKED_PAGE_INFO

    //
    // INVVPID capability bits (cached from IA32_VMX_EPT_VPID_CAP)
    //
    BOOLEAN               invvpid_supported;
    BOOLEAN               invvpid_individual_addr;
    BOOLEAN               invvpid_single_context;
    BOOLEAN               invvpid_all_contexts;
    BOOLEAN               invvpid_single_retaining_globals;
} EPT_STATE, *PEPT_STATE;

typedef struct _EPT_DIAGNOSTICS_SNAPSHOT {
    UINT32  processor_count;
    UINT32  initialized_processors;
    UINT32  mtrr_range_count;
    UINT8   default_memory_type;
    BOOLEAN ad_supported;
    BOOLEAN invvpid_supported;
    BOOLEAN invvpid_individual_addr;
    BOOLEAN invvpid_single_context;
    BOOLEAN invvpid_all_contexts;
    BOOLEAN invvpid_single_retaining_globals;
} EPT_DIAGNOSTICS_SNAPSHOT, *PEPT_DIAGNOSTICS_SNAPSHOT;

typedef struct _VIRTUAL_MACHINE_STATE {

    UINT64 vmxon_va;
    UINT64 vmxon_pa;
    UINT64 vmcs_va;
    UINT64 vmcs_pa;

    //
    // VMM stack (HOST_RSP points near top of this)
    //
    UINT64 vmm_stack;

    UINT64 msr_bitmap_va;
    UINT64 msr_bitmap_pa;
    UINT64 io_bitmap_va_a;
    UINT64 io_bitmap_pa_a;
    UINT64 io_bitmap_va_b;
    UINT64 io_bitmap_pa_b;

    PVMM_EPT_PAGE_TABLE ept_page_table;
    EPT_POINTER         ept_pointer;

    PGUEST_REGS regs;
    UINT32      core_id;
    UINT32      exit_reason;
    UINT64      exit_qual;
    UINT64      vmexit_rip;
    BOOLEAN     in_root;
    BOOLEAN     launched;
    BOOLEAN     advance_rip;

    VMX_VMXOFF_STATE vmxoff;

    //
    // stealth: per-VCPU TSC compensation state for "trap next RDTSC" approach.
    // after CPUID exit, RDTSC exiting is armed for one instruction.
    // the trapped RDTSC returns a compensated value hiding VM-exit overhead.
    // TSC_OFFSET is never modified — zero drift, zero monotonicity issues.
    //
    UINT64  tsc_cpuid_entry;        // TSC recorded at start of CPUID VM-exit handler
    BOOLEAN tsc_rdtsc_armed;        // TRUE = next RDTSC/RDTSCP should be compensated

    //
    // pending external interrupt for deferred re-injection
    // used when external-interrupt exiting is active but the guest
    // can't accept an interrupt right now (IF=0 or STI/MOV-SS blocking)
    //
    UINT8   pending_ext_vector;
    BOOLEAN has_pending_ext_interrupt;

    //
    // pending NMI for deferred delivery via NMI-window exiting
    // set when an NMI VM-exit interrupts IDT delivery of another event
    //
    BOOLEAN has_pending_nmi;

    // guest DR0-DR3/DR6 saved on vm-exit, restored before vmresume
    UINT64  guest_dr0;
    UINT64  guest_dr1;
    UINT64  guest_dr2;
    UINT64  guest_dr3;
    UINT64  guest_dr6;
    BOOLEAN mov_dr_exiting;

    // shadowed guest CR8 (TPR) for interrupt priority checks
    UINT8   guest_cr8;

    //
    // EPT hook: page to restore after MTF single-step
    //
    PEPT_HOOKED_PAGE_INFO mtf_restore_page;

    // per-core private host GDT for VMXOFF restore
    PVOID   host_gdt;
    UINT64  original_gdt_base;
    UINT16  original_gdt_limit;
    UINT16  original_tr_selector;

} VIRTUAL_MACHINE_STATE, *PVIRTUAL_MACHINE_STATE;

#define VMCALL_TEST             0x00000001
#define VMCALL_VMXOFF           0x00000002
#define VMCALL_EPT_HOOK         0x00000003
#define VMCALL_EPT_UNHOOK       0x00000004
#define VMCALL_EPT_UNHOOK_ALL   0x00000005

//
// VMCALL identifier in rax — like UnrealVTDbg's VMCALL_IDENTIFIER
// checked BEFORE the r10/r11/r12 signature. if rax matches this,
// parameters are in rcx/rdx/r8/r9/r10-r15 (no signature registers).
//
#define OPHION_VMCALL_ID        0x4F5048494F4E4558ULL   // 'OPHIONEX'

//
// EPT hook VMCALL request — caller fills at PASSIVE_LEVEL, VMX-root processes.
// VMX-root temporarily switches to guest CR3 to access guest memory safely.
// param1 (rdx) = pointer to this struct
//
typedef struct _EPT_HOOK_VMCALL_PARAM {
    UINT64  caller_cr3;           // [in] for guest memory access inside ept_hook_install
    PVOID   target_function;      // [in] VA of function to hook
    PVOID   proxy_function;       // [in] VA of hook proxy
    PVOID * origin_function;      // [in/out] receives trampoline address (or NULL)
    UINT32  hook_type;            // [in] 0=abs jmp, 1=VMCALL, 2=INT3
    volatile LONG installed;      // [internal] 0→1 by first CPU, others just split+PTE
    BOOLEAN result;               // [out]
    UINT32  error_code;           // [out] debug: 0=ok, 1=no_pa, 2=split_fail, 3=pml1_null,
                                  //   4=pool_page, 5=pool_func, 6=pool_tramp, 7=pa_fake
} EPT_HOOK_VMCALL_PARAM, *PEPT_HOOK_VMCALL_PARAM;

typedef struct _EPT_UNHOOK_VMCALL_PARAM {
    UINT64  caller_cr3;           // [in] caller's CR3
    PVOID   target_function;      // [in] VA to unhook
    volatile LONG unhooked;       // [internal] 0→1 by first CPU
    BOOLEAN result;               // [out]
} EPT_UNHOOK_VMCALL_PARAM, *PEPT_UNHOOK_VMCALL_PARAM;

// per-cpu NMI pending flag for host IDT NMI handler
extern volatile LONG g_host_nmi_pending[MAX_PROCESSORS];

typedef struct _HOST_IDT_STATE {
    DECLSPEC_ALIGN(16) IDT_GATE_DESCRIPTOR_64 idt[IDT_NUM_ENTRIES];
    UINT64  original_idt_base;
    BOOLEAN initialized;
} HOST_IDT_STATE, *PHOST_IDT_STATE;

extern VIRTUAL_MACHINE_STATE * g_vcpu;
extern EPT_STATE *             g_ept;
extern UINT32                  g_cpu_count;
extern UINT64                  g_system_cr3;
extern UINT64 *                g_msr_bitmap_invalid;
extern HOST_IDT_STATE          g_host_idt;

#ifdef __cplusplus
}
#endif

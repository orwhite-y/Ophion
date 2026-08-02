/*
*   hv_types.h - core hypervisor type definitions é”?per-vcpu state, ept structures, configs
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
    UINT64 rsp;    // placeholder é”?real RSP read from VMCS
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

// forward declaration é”?needed by EPT_HOOKED_PAGE_INFO before full definition
typedef struct _STEALTH_FAKE_PT *PSTEALTH_FAKE_PT;

//
// per-function hook tracking é”?one for each function hooked within a page
//
typedef struct _EPT_HOOKED_FUNCTION_INFO {
    LIST_ENTRY  hooked_function_list;
    PVOID       virtual_address;          // original function VA
    PVOID       handler_function;         // proxy/hook function
    PUINT8      first_trampoline_address; // trampoline for calling original
    PUINT8      fake_page_contents;       // pointer to parent page's fake page
    UINT64      hook_size;                // bytes overwritten
    UINT32      hook_type;                // 0=abs jmp, 1=VMCALL, 2=INT3
    BOOLEAN     user_trampoline;          // TRUE = trampoline is user-mode (don't pool_release)
    BOOLEAN     oneshot;                  // TRUE = redirect once, then pass through to original
    volatile LONG oneshot_fired;          // atomically set by handler after first trigger
    volatile LONG * external_fired;       // optional NonPaged signal set on first oneshot hit
    UINT64      expected_tid;             // 0 = any thread, non-0 = only this TID may redirect
    BOOLEAN     retiring;                 // TRUE = unhook requested; per-vCPU paths restore lazily
} EPT_HOOKED_FUNCTION_INFO, *PEPT_HOOKED_FUNCTION_INFO;

//
// per-page hook tracking é”?one for each 4KB page with hooks
//
typedef struct _EPT_HOOKED_PAGE_INFO {
    LIST_ENTRY       hooked_page_list;
    LIST_ENTRY       hooked_functions_list;
    PUINT8           fake_page_va;            // shellcode page in stealth region (EPT X-only)
    UINT64           pfn_of_hooked_page;
    UINT64           pfn_of_fake_page_contents;
    PEPT_PML1_ENTRY  entry_address;       // pointer to EPT PTE being manipulated
    EPT_PML1_ENTRY   original_entry;      // saved original PTE (RW, no X)
    EPT_PML1_ENTRY   changed_entry;       // fake page PTE (X only, no RW)
    UINT32           Options;             // EPTO_HOOK_FUNCTION or EPTO_VIRTUAL_BREAKPOINT
    //
    // R3 hook: per-process filtering via CR3.
    //   0 = R0 hook (all processes see the hook)
    //   non-0 = R3 hook (only the process with this CR3 PFN sees the hook,
    //           other processes execute original code transparently via MTF)
    //
    UINT64           target_cr3;
    //
    // fake PT page association (for inject hooks with NX hiding)
    //
    PSTEALTH_FAKE_PT fake_pt;           // shared fake PT page (NULL if not using fake PT)
    UINT32           pt_pte_index;      // our PTE index in the PT page
    //
    // exec PT page é”?separate page with NX=0 for #PF recovery.
    // used by ept_hook_handle_pf to swap EPT PFN (no content modification).
    //   fake PT page: NX=1 (anti-cheat reads)   é”?default EPT view
    //   exec PT page: NX=0 (CPU page walk)      é”?swapped in during #PF recovery
    //
    PUINT8           exec_pt_page;      // contiguous region page with NX=0
    UINT64           exec_pt_pfn;       // PFN of exec_pt_page
    EPT_PML1_ENTRY   pt_exec_entry;     // EPT entry pointing to exec_pt_page
    volatile LONG *  dbg_pf_counter;    // debug: #PF handler writes here (kernel NonPaged)
} EPT_HOOKED_PAGE_INFO, *PEPT_HOOKED_PAGE_INFO;

//
// contiguous shadow region é”?must be defined before EPT_STATE (embedded, not pointer)
//
#define STEALTH_REGION_DEFAULT_MB   64
#define STEALTH_REGION_DEFAULT_SIZE ((SIZE_T)STEALTH_REGION_DEFAULT_MB * 1024 * 1024)

typedef struct _STEALTH_REGION {
    PVOID           base_va;
    UINT64          base_pa;
    SIZE_T          total_pages;
    volatile LONG   next_page;
} STEALTH_REGION;

// forward declarations for pointer types used in VIRTUAL_MACHINE_STATE
typedef struct _EPT_STEALTH_PAGE_INFO *PEPT_STEALTH_PAGE_INFO;
// PSTEALTH_FAKE_PT already forward-declared above (before EPT_HOOKED_PAGE_INFO)

typedef struct _EPT_STATE {
    MTRR_RANGE_DESCRIPTOR mem_ranges[MAX_MTRR_RANGES];
    UINT32                num_ranges;
    UINT8                 default_type;
    BOOLEAN               ad_supported;
    BOOLEAN               execute_only_supported;
    LIST_ENTRY            hooked_pages;
    LIST_ENTRY            stealth_pages;
    LIST_ENTRY            stealth_fake_pts;
    STEALTH_REGION        stealth_region;

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
    // TSC_OFFSET is never modified é”?zero drift, zero monotonicity issues.
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

    //
    // stealth page: page to restore after MTF single-step
    //
    PEPT_STEALTH_PAGE_INFO mtf_restore_stealth;

    //
    // stealth PT page: restore fake PT after MTF (PTE write passthrough)
    //
    PSTEALTH_FAKE_PT mtf_restore_fake_pt;

    //
    // stealth #PF swap state: target + PT EPTs swapped for execution
    //
    PEPT_STEALTH_PAGE_INFO stealth_pf_swapped;

    //
    // Shadow-CR3 single-step restore state.
    // After a #PF on NX=1, VMX-root switches to shadow CR3, lets one guest
    // instruction retire, and restores the real CR3 from MTF.
    //
    PEPT_STEALTH_PAGE_INFO nx_timer_restore;
    UINT64      nx_timer_real_cr3;
    BOOLEAN     stealth_pf_configured;  // TRUE after this CPU's VMCS has #PF interception

    //
    // inject hook #PF recovery: EPT hook page with fake PT that was swapped for execution
    //
    PEPT_HOOKED_PAGE_INFO stealth_pf_swapped_hook;

    // per-core private host GDT for VMXOFF restore
    PVOID   host_gdt;
    UINT64  original_gdt_base;
    UINT16  original_gdt_limit;
    UINT16  original_tr_selector;


    // EPT violation livelock detection: track consecutive unhandled
    // EPT violations at the same RIP. After MAX_RETRIES, inject #GP
    // and advance RIP instead of infinite-looping (CLOCK_WATCHDOG_TIMEOUT).
    UINT64  ept_violation_rip;
    UINT32  ept_violation_count;
    UINT64  ept_violation_phys;

    // host #PF tracking (diagnostic, for private host CR3 #PF analysis)
    UINT64  host_pf_rip;
    UINT32  host_pf_count;
    UINT64  host_pf_cr2;
} VIRTUAL_MACHINE_STATE, *PVIRTUAL_MACHINE_STATE;

#define VMCALL_TEST             0x00000001
#define VMCALL_VMXOFF           0x00000002
#define VMCALL_EPT_HOOK         0x00000003
#define VMCALL_EPT_UNHOOK       0x00000004
#define VMCALL_EPT_UNHOOK_ALL   0x00000005
#define VMCALL_STEALTH_ALLOC    0x00000006
#define VMCALL_STEALTH_FREE     0x00000007
#define VMCALL_EPT_HOOK_INJECT  0x00000008
#define VMCALL_EPT_SET_EXTERNAL_FIRED 0x00000009
#define VMCALL_EPT_UNHOOK_BY_CR3 0x0000000A   // retire all R3 hooks for a CR3 (no CR3 switch - safe from process-exit callback)
#define VMCALL_READ_MEM         0x0000000B   // R3/R0: read target mem (rdx=&req, r8=caller_pid, r9=target_pid)
#define VMCALL_WRITE_MEM        0x0000000C   // R3/R0: write target mem (rdx=&req, r8=caller_pid, r9=target_pid)
#define VMCALL_QUERY_VA         0x0000000D   // R3/R0: query VA->PA (rdx=&req, r8=caller_pid, r9=target_pid)
#define VMCALL_QUERY_CR3        0x0000000E
#define VMCALL_SET_SELFMAP     0x0000000F
#define VMCALL_DIAG_WALK        0x00000010   // R3: rdx=target_pid -> rax=kernel CR3
#define VMCALL_READ_MEM_PTE     0x00000011   // R0: PTE-window read (rdx=pa_arr, r8=data, r9=size, r10=tva, r11=pa_cnt)
#define VMCALL_WRITE_MEM_PTE    0x00000012   // R0: PTE-window write (same layout)

#define HV_R3_MEM_MAX           262144        // max bytes per R3 read/write call (16 pages, prefetch batch)

//
// memory read/write VMCALL request (rdx = pointer to this struct).
//
// R3 path: caller_pid (r8) and target_pid (r9) are passed in registers so the
// handler can resolve both kernel CR3s from the PID->CR3 cache (kernel space,
// readable under the private host CR3 without a switch) BEFORE touching the
// struct (which lives in the caller`s user space, unreachable under the private
// host CR3). The handler then:
//   1. switches to caller`s kernel CR3, reads target_va/size (and for WRITE
//      copies data[] into the per-CPU kernel scratch buffer),
//   2. switches to target`s kernel CR3, copies between target_va and scratch,
//   3. switches back to caller`s kernel CR3, copies scratch into data[] (READ)
//      and writes status/result.
//
// R0 path (TestDriver): caller_pid=0, target_cr3 pre-filled. struct is kernel
// VA, readable under the private host CR3 directly.
//
typedef struct _VMCALL_MEM_REQUEST {
    UINT64  target_cr3;     // [in]  R0: pre-resolved kernel CR3; R3: 0 (looked up by r9=target_pid)
    UINT64  target_va;      // [in]  VA to read/write in target
    UINT32  size;           // [in]  bytes (max HV_R3_MEM_MAX)
    UINT32  status;         // [out] NTSTATUS of the operation
    UINT64  result;         // [out] bytes actually copied
    PUCHAR  data;               // [in write]/[out read] pointer to data buffer
} VMCALL_MEM_REQUEST, *PVMCALL_MEM_REQUEST;

//
// VMCALL identifier in rax é”?like UnrealVTDbg's VMCALL_IDENTIFIER
// checked BEFORE the r10/r11/r12 signature. if rax matches this,
// parameters are in rcx/rdx/r8/r9/r10-r15 (no signature registers).
//
#define OPHION_VMCALL_ID        0x4F5048494F4E4558ULL   // 'OPHIONEX'

//
// EPT hook VMCALL request é”?caller fills at PASSIVE_LEVEL, VMX-root processes.
// VMX-root temporarily switches to guest CR3 to access guest memory safely.
// param1 (rdx) = pointer to this struct
//
typedef struct _EPT_HOOK_VMCALL_PARAM {
    UINT64  caller_cr3;           // [in] for guest memory access inside ept_hook_install
    PVOID   target_function;      // [in] VA of function to hook
    PVOID   proxy_function;       // [in] VA of hook proxy
    PVOID * origin_function;      // [in/out] receives trampoline address (or NULL)
    UINT32  hook_type;            // [in] 0=abs jmp, 1=VMCALL, 2=INT3
    volatile LONG installed;      // [internal] 0é”? by first CPU, others just split+PTE
    BOOLEAN result;               // [out]
    UINT32  error_code;           // [out] debug: 0=ok, 1=no_pa, 2=split_fail, 3=pml1_null,
                                  //   4=pool_page, 5=pool_func, 6=pool_tramp, 7=pa_fake
    //
    // R3 hook extensions é”?set target_cr3 != 0 to enable per-process EPT hook.
    //   caller must:
    //     1. attach to target process (KeStackAttachProcess)
    //     2. lock target page (MmProbeAndLockPages) to pin physical page
    //     3. allocate user-mode PAGE_EXECUTE_READWRITE trampoline buffer
    //     4. pre-compute trampoline PA via MmGetPhysicalAddress
    //     5. pass caller_cr3 = target process CR3
    //
    UINT64  target_cr3;           // [in] 0 = R0 hook, non-0 = R3 per-process (CR3 PFN)
    PVOID   user_trampoline;      // [in] R3 executable buffer for trampoline (NULL = kernel pool)
    UINT64  user_trampoline_pa;   // [in] pre-computed PA of user_trampoline
    //
    // force changed_entry ReadAccess=1 even when execute-only EPT is supported.
    // needed for shellcode inject: code reads its own embedded data from the
    // fake page. without R=1, reads EPT-violate é”?original page (zeros) é”?crash.
    //
    BOOLEAN force_read_access;    // [in] TRUE = changed_entry R=1 (shellcode self-read)
    BOOLEAN oneshot;              // [in] TRUE = redirect to proxy once, then pass-through to trampoline
    UINT64  expected_tid;         // [in] 0 = any thread, non-0 = only this TID may redirect
    volatile LONG * external_fired; // [in] optional kernel NonPaged signal set to 1 on first oneshot hit
} EPT_HOOK_VMCALL_PARAM, *PEPT_HOOK_VMCALL_PARAM;

//
// EPT hook inject é”?pre-built at PASSIVE_LEVEL, no user VA access in VMX-root.
// all data passed via kernel NonPaged buffers. safe from SMAP / page faults.
// param passed as pointer via rdx (like VMCALL_STEALTH_ALLOC).
//
typedef struct _EPT_HOOK_INJECT_PARAM {
    UINT64  target_va;              // [in] user VA of shellcode entry (for tracking)
    UINT64  target_phys;            // [in] pre-computed PA of target page
    UINT64  handler_va;             // [in] trampoline VA (VMCALL redirects here)
    PVOID   fake_page_buffer;       // [in] kernel buffer: pre-built fake page (shellcode + VMCALL)
    UINT32  hook_size;              // [in] bytes overwritten by VMCALL (LDE result)
    BOOLEAN force_read_access;      // [in] changed_entry R=1 for shellcode self-read
    //
    // pre-computed guest PT page info (filled at PASSIVE_LEVEL by caller).
    // used to create fake PT page in VMX-root for NX hiding.
    //
    UINT64  pt_page_pfn;            // [in] PFN of guest PT page containing target PTE
    UINT32  pt_pte_index;           // [in] index within PT page (0-511)
    PVOID   pt_page_copy;           // [in] kernel buffer with PT page content (for fake PT init)
    PVOID   pt_page_va;             // [in] system VA of real PT page (hostcr3-mapped, for resync)
    volatile LONG installed;        // [internal] first CPU é”?1
    BOOLEAN result;                 // [out]
    BOOLEAN fake_pt_ok;             // [out] TRUE if fake PT was created successfully
    volatile LONG * dbg_pf_counter; // [in] pointer to counter (kernel NonPaged), handler increments
} EPT_HOOK_INJECT_PARAM, *PEPT_HOOK_INJECT_PARAM;

typedef struct _EPT_UNHOOK_VMCALL_PARAM {
    UINT64  caller_cr3;           // [in] caller's CR3
    PVOID   target_function;      // [in] VA to unhook
    volatile LONG unhooked;       // [internal] 0é”? by first CPU
    BOOLEAN result;               // [out]
} EPT_UNHOOK_VMCALL_PARAM, *PEPT_UNHOOK_VMCALL_PARAM;

//
// stealth memory allocation é”?EPT split page with hidden execute capability
//
// allocates memory as PAGE_READWRITE (non-executable in VAD/NtQueryVirtualMemory)
// hypervisor clears NX in guest PTE and sets up EPT split:
//   read  é”?original page (clean data, no suspicious code)
//   exec  é”?shadow page with VMCALL at entry é”?dispatch to handler
//
// anti-cheat sees: PAGE_READWRITE, no executable attribute, no PE/MZ headers
// CPU executes: VMCALL é”?VM exit é”?handler function
//

#define EPTO_STEALTH_PAGE       4

//
// shared fake PT page é”?one per physical PT page, ref-counted
// multiple stealth pages in the same 2MB VA range share this
//
typedef struct _STEALTH_FAKE_PT {
    LIST_ENTRY      fake_pt_list;
    UINT64          pt_page_pfn;        // PFN of the real guest PT page
    PUINT8          fake_page_va;       // VA of fake page in contiguous region
    UINT64          pfn_of_fake;        // PFN of fake page
    EPT_PML1_ENTRY  pt_fake_entry;      // EPT PTE: read é”?fake (NX=1)
    EPT_PML1_ENTRY  pt_real_entry;      // EPT PTE: real PT (for temp swap)
    PVOID           real_page_va;       // system VA of real PT page (hostcr3-mapped, for resync)
    UINT32          ref_count;          // number of stealth pages using this
} STEALTH_FAKE_PT, *PSTEALTH_FAKE_PT;

//
// per-page stealth allocation tracking (~200 bytes, no embedded PAGE_SIZE arrays)
//
// shadow page and fake PT page are in the contiguous region (not embedded).
// fake PT page is shared among stealth pages in the same physical PT page.
//

//
// Real page-table page map entry. The HV's reactive heal
// (stealth_refresh_shadow_code_pte / stealth_sync_data_pte_in_window) must walk
// the guest's REAL page tables in VMX-root. pa_to_va (MmGetVirtualForPhysical)
// resolves REGISTERED page-table pages through the current CR3's self-map, so
// under g_system_cr3 it reads the System process's tables (PML4[idx]=0) -- the
// real walk is broken. The TestDriver therefore maps each real PT page along the
// protected range's path (PML4/PDPT/PD/PT) at PASSIVE and passes the resulting
// system VAs here; they are valid under g_system_cr3 (system space, mapped in
// every address space). Mapping uses an MDL + MmMapLockedPagesSpecifyCache(MmCached)
// -- NOT MmMapIoSpace, which returns NULL for system-RAM page-table pages on
// modern Windows (MM refuses to double-map RAM as I/O space). MmCached matches
// the WB attribute of RAM, so a persistent mapping is safe (no cache conflict).
// Shadow pages are NonPaged pool (NOT registered page tables) so pa_to_va still
// resolves THEM under g_system_cr3 -- no map entry needed for shadow pages.
//
typedef struct _STEALTH_REAL_PAGE_ENTRY {
    UINT64  pa;     // physical address (page-aligned) of a real guest PT page
    PVOID   va;     // MmMapLockedPagesSpecifyCache system VA, valid under g_system_cr3
    PVOID   mdl;    // PMDL (opaque to the HV; TestDriver stores it for MmUnmapLockedPages)
} STEALTH_REAL_PAGE_ENTRY, *PSTEALTH_REAL_PAGE_ENTRY;

#define MAX_REAL_PAGES_PER_SHADOW  64   // PML4 + PDPT + PDs + PTs along the range

typedef struct _EPT_STEALTH_PAGE_INFO {
    LIST_ENTRY      stealth_page_list;

    // --- target page ---
    UINT64          guest_va;           // guest VA of stealth page (page-aligned)
    UINT64          pfn_of_target;      // original physical page PFN
    PUINT8          shadow_page;        // ptr into contiguous region (execute view)
    UINT64          pfn_of_shadow;      // PFN of shadow page
    PVOID           handler_function;   // VMCALL dispatch target (NULL for shellcode/resident)
    PEPT_PML1_ENTRY entry_address;      // EPT PTE for target page
    EPT_PML1_ENTRY  original_entry;     // read view PTE: R+W, no X
    EPT_PML1_ENTRY  execute_entry;      // execute view PTE: X only (or R+X for resident)
    UINT64          guest_cr3;
    UINT64          target_pid;         // optional process filter for KVA-shadow/user CR3 cases
    BOOLEAN         resident;           // TRUE = DLL mode (default exec view, reads swap)
    BOOLEAN         no_ept_split;       // TRUE = shadow CR3 only, no target EPT split/swap
    BOOLEAN         intercept_write;    // TRUE = this page needs write-side #PF mediation

    // --- PT page info ---
    PSTEALTH_FAKE_PT fake_pt;           // shared fake PT page info (NULL = use NX cycle instead)
    UINT64          pt_page_pfn;        // PFN of guest PT page containing our PTE
    PVOID           pt_page_va;         // shadow mode: shadow PT page VA; else real PT page VA (VMX-root reads only for write-intercept paths)
    UINT32          pt_pte_index;       // index (0-511) of our PTE in the PT page

    // --- shadow CR3 (NX bypass without touching real PTE) ---
    UINT64          shadow_cr3_phys;    // physical address of shadow PML4 (0 = not used)
    UINT64          real_cr3_value;     // saved real guest CR3 during shadow switch
    PVOID           shadow_pte_va;      // VA of this page's shadow PTE (NonPaged pool, valid under any CR3); HV writes *shadow_pte_va=(real_pte&~NX) on #PF. NULL = legacy pa_to_va walk (broken in VMX-root).

    // --- real page-table page map (MDL-mapped, valid under g_system_cr3) ---
    // shared across all stealth pages of the same shadow CR3 (same protected
    // range). NULL = no map (real walk via pa_to_va, broken under g_system_cr3).
    PSTEALTH_REAL_PAGE_ENTRY real_page_map;
    UINT32          real_page_count;

} EPT_STEALTH_PAGE_INFO, *PEPT_STEALTH_PAGE_INFO;

//
// VMCALL parameter for stealth allocation (register-based, like EPT hook)
//   rdx = target_va (already allocated as PAGE_READWRITE by caller)
//   r8  = handler_function (proxy to redirect VMCALL to)
//   r10 = caller_cr3
//
typedef struct _EPT_STEALTH_ALLOC_PARAM {
    UINT64  caller_cr3;           // [in] guest CR3
    UINT64  target_pid;            // [in] optional target PID, 0 = filter by caller_cr3 only
    PVOID   target_va;            // [in] PAGE_READWRITE memory in guest
    PVOID   handler_function;     // [in] function to dispatch VMCALL to (NULL for shellcode mode)
    UINT64  target_phys;          // [in] pre-computed physical address of target_va
    PVOID   shellcode_buffer;     // [in] if non-NULL: shellcode for THIS page's execute view
    UINT32  shellcode_size;       // [in] shellcode bytes for this page (max PAGE_SIZE)
    BOOLEAN resident;             // [in] TRUE = DLL mode: default execute view, no #PF overhead
    BOOLEAN intercept_write;      // [in] TRUE = keep write-side #PF interception enabled
    //
    // pre-computed guest PT info (filled by caller at PASSIVE/DISPATCH level).
    // avoids pa_to_va (MmGetVirtualForPhysical) in VMX-root which can deadlock
    // when KeGenericCallDpc puts all CPUs into VMX-root simultaneously.
    //
    UINT64  pt_page_pfn;          // [in] PFN of the guest PT page containing target PTE
    UINT32  pt_pte_index;         // [in] index of target PTE within PT page (0-511)
    PVOID   pt_page_copy;         // [in] NonPaged buffer with PT page content (4KB, caller-allocated)
    PVOID   pt_page_va;           // [in] shadow mode: shadow PT page VA; else real PT page VA (mapped only for write-intercept paths)
    PVOID   target_page_copy;     // [in] NonPaged buffer with target page content (4KB, for shadow copy)
    BOOLEAN pt_precomputed;       // [in] TRUE = caller filled above fields at PASSIVE_LEVEL
    BOOLEAN use_fake_pt;          // [in] TRUE = create fake PT page (NX=1 visible to scanners, NX=0 in real PTE)
    UINT64  shadow_cr3_phys;      // [in] physical address of shadow PML4 (0 = no shadow CR3)
    BOOLEAN no_ept_split;         // [in] TRUE = shadow CR3 only, keep target EPT mapping unchanged
    PVOID   shadow_pte_va;        // [in] VA of this page's shadow PTE (NonPaged pool, computed by caller via TdResolveShadowPte); HV writes *shadow_pte_va=(real_pte&~NX) on #PF without pa_to_va (NULL = legacy walk)
    PVOID   real_page_map;        // [in] ptr to STEALTH_REAL_PAGE_ENTRY[real_page_count]: MDL-mapped real PT pages (NULL = none)
    UINT32  real_page_count;      // [in] number of entries in real_page_map
    volatile LONG installed;      // [internal] 0é”? by first CPU
    BOOLEAN result;               // [out]
} EPT_STEALTH_ALLOC_PARAM, *PEPT_STEALTH_ALLOC_PARAM;

typedef struct _EPT_STEALTH_FREE_PARAM {
    UINT64  caller_cr3;
    PVOID   target_va;
    UINT64  target_phys;          // [in] pre-computed physical address of target_va
    volatile LONG freed;
    BOOLEAN result;
} EPT_STEALTH_FREE_PARAM, *PEPT_STEALTH_FREE_PARAM;

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

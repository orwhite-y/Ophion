/*
*   hv.h - master hypervisor header �?includes everything needed
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

// PML4 self-map index (found at PASSIVE_LEVEL by hv_selfmap_init).
// 0xFFFFFFFF = not initialized (hv_walk_va returns FALSE).
extern volatile UINT32 g_self_map_index;
UINT64 get_system_cr3(VOID);

// Per-CPU PTE window pages for VMX-root memory access.
// Allocates one 4KB stealth-region page per CPU for PTE-window remapping.
VOID hv_pte_window_init(ULONG cpu_count);

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
// the compiler may reorder reads across __writecr3 �?use _mm_mfence if needed.
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

//
// The reactive shadow-CR3 heal (stealth_refresh_shadow_code_pte /
// stealth_sync_data_pte_in_window) must walk the guest's REAL page tables and the
// NonPaged-pool SHADOW pages in VMX-root. pa_to_va (MmGetVirtualForPhysical)
// resolves REGISTERED page-table pages through the CURRENT CR3's self-map, so the
// CR3 the heal runs under determines whose tables pa_to_va sees.
//
// g_system_cr3 (System's kernel CR3) is WRONG: its self-map resolves the System
// process's tables (PML4[idx]=0 for any user VA), so the guest's real PT walk is
// broken. The guest's USER CR3 (captured at the user-mode #PF VM-exit) is also
// WRONG: under KVA-shadow/KPTI the user CR3 strips kernel space, so the
// NonPaged-pool shadow pages become inaccessible AND the self-map is stripped.
//
// The fix: run the heal under the guest process's KERNEL CR3 (sp->guest_cr3,
// captured by the TestDriver via __readcr3() in the IOCTL handler -- kernel mode
// = kernel CR3 under KPTI). The kernel CR3 has the FULL kernel half (NonPaged
// pool, HV code/stack, system PTEs -- shared across all processes) PLUS the
// process's user half. So under sp->guest_cr3, pa_to_va resolves BOTH the guest's
// real page-table pages (self-map -> guest kernel PML4 -> shared user PDPT/PD/PT)
// AND the shadow pages (NonPaged pool, system PTE). No real-page mapping is
// needed -- which is essential, because every MM API that could map a RAM
// page-table page into a CR3-independent VA is REFUSED on modern Windows
// (MmMapIoSpace MmCached/MmNonCached, manual-PFN MDL MmMapLockedPagesSpecifyCache
// with or without MDL_IO_SPACE -- all return NULL for the PML4 page; the MM
// protects page-table pages from aliasing). This also matches the original design
// request: do NOT map shadow/real page VAs.
//
// vmx_enter_cr3(cr3) saves the live CR3 and switches to `cr3` for the heal;
// vmx_leave_guest_cr3(saved) restores it. The walk's CR3 argument (the guest user
// CR3) is irrelevant at level 0: pa_to_va of a PML4 PA returns the self-map base
// VA, which under the kernel host CR3 maps the guest kernel PML4 (shared user
// entries) -- so the walk resolves the correct user-space PTEs regardless.
//
static __forceinline UINT64
vmx_enter_cr3(UINT64 cr3)
{
#if USE_PRIVATE_HOST_CR3
    UINT64 saved = __readcr3();
    __writecr3(cr3);
    _mm_mfence();
    return saved;
#else
    UNREFERENCED_PARAMETER(cr3);
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

// ---------------------------------------------------------------------------
// WEDGE CMOS diagnostic marker: writes a 1-byte progress marker to battery-backed
// RTC NVRAM (CMOS) so it survives a triple-fault reset (the RAM log buffer is lost
// on reset). Port 0x70 = index (bit7 = NMI disable), 0x71 = data. Offsets 0x50/0x51
// are in extended CMOS (usually free on modern 256-byte RTC). Host port IO in
// VMX-root is never intercepted, so __outbyte / __inbyte work directly. The trailing
// __outbyte(0x70, 0x0D) clears bit7 to re-enable NMI after each access.
//
#define WEDGE_CMOS_MAGIC_OFF  0x50
#define WEDGE_CMOS_VALUE_OFF  0x51
#define WEDGE_CMOS_MAGIC      0xA5
// Sticky "match seen" flag: set once (at WEDGE 0x0B) the first time a stealth page
// matches, never cleared during the run. Survives reset alongside the marker so the
// readback can tell "shellcode matched+healed then a later nomatch killed it" apart
// from "shellcode never matched at all". Cleared by wedge_cmos_clear on readback.
#define WEDGE_CMOS_MATCH_OFF  0x52
// Sticky "trigger seen" flag: set once (at WEDGE 0x01) the first time the injection
// trigger fires. Survives reset. Tells "shellcode ran but didn't match" (trig=1,
// match=0 -> target filter wrong for this process) apart from "shellcode never ran"
// (trig=0 -> the fetch #PFs are EAC/kernel NX code, not the shellcode).
#define WEDGE_CMOS_TRIG_OFF   0x53
// WEDGE reinject livelock probe (replaces the old per-#PF 0x0E mark, which did
// port I/O on EVERY fetch-#PF reinject -> hot path under EAC's #PF storm). A
// per-CPU consecutive same-address reinject streak is tracked in memory (no
// per-#PF port I/O); only when a CPU's streak hits 1024 (pathological = guest
// re-#PFs the same instruction, HV re-injects, tight loop = livelock) does that
// CPU snap to CMOS. Normal activity never reaches 1024 consecutive same-addr
// reinjects (each NX #PF is resolved by the guest handler -> next #PF is a
// different addr -> streak resets), so normal CPUs never write. On a 卡死 (freeze)
// boot: streak>=1024 + addr = #PF reinject livelock on addr; streak=0 = no
// livelock (deadlock, or normal activity). 4-byte streak @ 0x54, 8-byte VA @ 0x58.
#define WEDGE_CMOS_REINJ_CNT_OFF   0x54
#define WEDGE_CMOS_REINJ_ADDR_OFF  0x58

// per-CPU last-VM-exit byte (0x60..0x7F, up to 32 CPUs). Each CPU owns its byte so
// the #PF storm on other CPUs can't mask the handler a wedged/TFing CPU is actually
// in. Throttled (write only on value change): hot path costs ~1 write/CPU, not
// 1 write/#PF. Encoding: 0x80|vector for exceptions (0x8E=#PF,0x8D=#GP,0x86=#UD);
// else raw exit reason (<0x40). 0 = no VM-exit recorded on that CPU.
#define WEDGE_CMOS_PERCPU_BASE  0x60

static __forceinline VOID
wedge_cmos_mark(UCHAR v)
{
    UNREFERENCED_PARAMETER(v);
}

static __forceinline VOID
wedge_cmos_read(UCHAR *magic, UCHAR *val)
{
    if (magic) *magic = 0;
    if (val) *val = 0;
}

static __forceinline VOID
wedge_cmos_clear(VOID)
{
}

// Set the sticky "match seen" flag (idempotent). Called at WEDGE 0x0B.
static __forceinline VOID
wedge_cmos_set_match_seen(VOID)
{
}

// Read the sticky "match seen" flag (0 = no match this run, 1 = a stealth page
// matched at some point before the reset).
static __forceinline UCHAR
wedge_cmos_read_match_seen(VOID)
{
    return 0;
}

// Set the sticky "trigger seen" flag (idempotent). Called at WEDGE 0x01.
static __forceinline VOID
wedge_cmos_set_trig_seen(VOID)
{
}

// Read the sticky "trigger seen" flag (0 = trigger never fired this run, 1 = the
// injection trigger fired at some point before the reset).
static __forceinline UCHAR
wedge_cmos_read_trig_seen(VOID)
{
    // disabled: CMOS port I/O races across CPUs. Return 0 (not seen).
    return 0;
}

// Snap the reinject livelock probe (streak + fault addr) to CMOS. Called ONLY when
// a CPU's consecutive same-addr reinject streak hits a multiple of 1024 (i.e. only
// by a livelocked CPU), so this is NOT on the hot #PF path - no per-#PF port I/O.
static __forceinline VOID
wedge_cmos_snap_reinj(UINT32 streak, UINT64 addr)
{
    // disabled: CMOS port I/O races across CPUs under load (see vmexit.cpp).
    // livelock info is kept in-memory only; no port writes.
    UNREFERENCED_PARAMETER(streak);
    UNREFERENCED_PARAMETER(addr);
}

// Read back the reinject livelock probe. streak==0 (+ addr==0) = no livelock this
// run; streak>=1024 + addr = #PF reinject livelock on that fault VA.
static __forceinline VOID
wedge_cmos_read_reinj(UINT32 *streak, UINT64 *addr)
{
    if (streak) *streak = 0;
    if (addr) *addr = 0;
}

// Read one CPU's last-exit byte (0x60+cpu). Called from DriverEntry readback.
static __forceinline UCHAR
wedge_cmos_read_percpu(UINT32 cpu)
{
    UNREFERENCED_PARAMETER(cpu);
    return 0;
}

//
// private host page tables (hostcr3.c)
//
BOOLEAN hostcr3_build(VOID);
UINT64  hostcr3_get(VOID);
VOID    hostcr3_destroy(VOID);
BOOLEAN hostcr3_map_va(PVOID va, SIZE_T size);

//
// PID -> kernel CR3 cache + per-CPU scratch buffer (driver.c)
// lock-free lookup, callable from VMX-root.
//
UINT64  hv_pid_to_cr3(HANDLE pid);
PUCHAR  hv_get_scratch(VOID);

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

// VMX-root internal �?called from VMCALL handler (guest CR3 must be active)
BOOLEAN ept_hook_install(VIRTUAL_MACHINE_STATE * vcpu, PEPT_HOOK_VMCALL_PARAM req);
BOOLEAN ept_unhook_install(VIRTUAL_MACHINE_STATE * vcpu, PEPT_UNHOOK_VMCALL_PARAM req);
VOID    ept_unhook_all(VOID);
VOID    ept_unhook_by_cr3(VIRTUAL_MACHINE_STATE * vcpu, UINT64 target_cr3);

// VMX-root safe EPT 2MB�?KB split (uses pre-allocated pool, NOT ExAllocatePool2)
PVMM_EPT_DYNAMIC_SPLIT ept_split_large_page_pool(PVMM_EPT_PAGE_TABLE page_table, SIZE_T phys_addr);

// VMX-root handlers �?called from vmexit dispatch
BOOLEAN ept_handle_violation(VIRTUAL_MACHINE_STATE * vcpu, UINT64 guest_phys, UINT64 exit_qual);
VOID    ept_handle_mtf(VIRTUAL_MACHINE_STATE * vcpu);
BOOLEAN ept_handle_vmcall_hook(VIRTUAL_MACHINE_STATE * vcpu);

//
// stealth memory allocation (ept_stealth.cpp)
//   allocates PAGE_READWRITE memory with hidden execute capability via EPT split
//   read �?clean data (no exec attr), execute �?VMCALL �?handler dispatch
//

// stealth region �?contiguous physical memory for shadow/fake pages
BOOLEAN ept_stealth_region_init(VOID);
VOID    ept_stealth_region_destroy(VOID);

// public API �?PASSIVE_LEVEL
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

// VMX-root handler �?check if VMCALL came from a stealth page
BOOLEAN ept_handle_stealth_vmcall(VIRTUAL_MACHINE_STATE * vcpu);

// EPT violation handler for stealth pages (target page + PT page writes)
BOOLEAN ept_stealth_handle_violation(VIRTUAL_MACHINE_STATE * vcpu, UINT64 guest_phys, UINT64 exit_qual);

// #PF handler �?intercepts instruction-fetch page faults (NX violations)
// temporarily swaps PT page EPT to real view so CPU page walk sees NX=0
BOOLEAN ept_stealth_handle_pf(VIRTUAL_MACHINE_STATE * vcpu, UINT64 fault_addr, UINT32 error_code);
VOID    ept_update_pf_intercept(VIRTUAL_MACHINE_STATE * vcpu);
VOID    stealth_clear_stale_window(VIRTUAL_MACHINE_STATE * vcpu);  // clear stale shadow-CR3 window (VMCALL_SHADOW_ABORT_ALL)

// shared fake PT page management (VMX-root safe)
PSTEALTH_FAKE_PT stealth_get_or_create_fake_pt(VIRTUAL_MACHINE_STATE * vcpu, UINT64 pt_page_pfn, PVOID pt_page_va_hint, PVOID real_page_va);
VOID stealth_fake_pt_set_nx(PSTEALTH_FAKE_PT fpt, UINT32 pte_index);
VOID stealth_fake_pt_resync(PSTEALTH_FAKE_PT fpt);
PUINT8 stealth_region_alloc_page(UINT64 * out_pfn);

// #PF handler for inject hooks with fake PT (ept_hook.cpp)
BOOLEAN ept_hook_handle_pf(VIRTUAL_MACHINE_STATE * vcpu, UINT64 fault_addr, UINT32 error_code);
// debug counters (safe in VMX-root, no OS API)
extern volatile LONG g_dbg_pf_called;
extern volatile LONG g_dbg_pf_matched;
extern volatile LONG g_dbg_pf_skipped;

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

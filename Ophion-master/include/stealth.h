/*
*   stealth.h - anti-detection stealth definitions and function prototypes
*/
#pragma once

#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif

//
// master stealth switch 锟?set to 0 to disable all stealth globally
//
#define STEALTH_ENABLED                     1

//
// shadow page-table strategy for stealth code execution (renderdoc inject).
// both modes keep real PTEs untouched ("no modify original page" rule).
//   MODE_A: all shadow leaf PTEs start P=0, filled reactively on first
//           access (fetch -> P=1/NX=0; data -> P=1/NX=1 from real).
//           simpler, no PE parsing, no stale-PFN silent corruption.
//   MODE_B: only 2MB regions containing code get shadow PT pages;
//           data-only 2MB regions point PD entry to the REAL PT page
//           (zero staleness, zero VM-exits for data in those regions).
//           needs PE section parsing to build is_code_2mb[] bitmap.
//
#define SHADOW_PT_MODE_A    1
#define SHADOW_PT_MODE_B    2
#define SHADOW_PT_MODE_C    3   // all P=1/NX=0 + fast-path heal: skip __writecr3 when PTE already present. Periodic re-sync (every 4096 hits) catches repage.
#define SHADOW_PT_MODE      SHADOW_PT_MODE_C

//
// hide CR4.VMXE (bit 13) from guest reads
// defeats: hvdetecc vm.vmxe
//
// PITFALL #14: CR4.VMXE hiding breaks VMware nested VMX. FIX: Set to 0 for VMware.
#define STEALTH_HIDE_CR4_VMXE               1

//
// compensate TSC for VM-exit overhead
// defeats: hvdetecc VM::TIMER, RDTSC+CPUID+RDTSC timing attacks
//
// approach: after CPUID exit, dynamically enable RDTSC exiting for one
// instruction. the trapped RDTSC returns a compensated value that hides
// the VM-exit overhead, then RDTSC exiting is disabled. zero drift 锟?
// TSC_OFFSET is never modified, only one RDTSC per CPUID is trapped.
//
#define STEALTH_COMPENSATE_TIMING           1

//
// use cached bare-metal CPUID for invalid/hypervisor leaves
// defeats: check_invalid_leaf, check_highest_low_function_leaf, VM::VMID
//
#define STEALTH_CPUID_CACHING               1

//
// use private (deep-copied) host page tables for VMCS_HOST_CR3
// protects host-mode from guest/anti-cheat page table corruption
// disabled by default 锟?enable once base hv is verified stable
//
// Private host CR3 now works with EPT hooks:
//   - All VMM memory (pool, stacks, EPT tables) allocated BEFORE hostcr3_build()
//   - Guest memory access in VMX-root wrapped by vmx_enter_guest_cr3/vmx_leave_guest_cr3
//   - Post-init allocations (stealth region) mapped via hostcr3_map_va()
#define USE_PRIVATE_HOST_CR3                1   // TODO: re-enable after stealth inject fixed

//
// private host IDT for VMCS_HOST_IDTR_BASE
// prevents NMI hijacking (attacker corrupts OS IDT vector 2, triggers
// NMI from another core while in VMX-root -> code execution in ring 0)
//
// SEH note: windows SEH cannot work in VMX-root mode 锟?we use a private
// stack, private CR3, and private IDT. the OS exception dispatcher cannot
// unwind our stack or find our exception handlers. the only solution is
// defensive coding: never cause exceptions in host mode. if one occurs
// (#GP, #PF, etc), our IDT handlers halt the cpu rather than corrupt state.
// on VMXOFF we restore the OS IDT so normal exception handling resumes.
//
// PITFALL #14: Private host IDT/GDT causes triple-fault in VMware. FIX: Set to 0 for VMware testing.
#define USE_PRIVATE_HOST_IDT                1

// PITFALL #14: Same VMware issue. FIX: Set to 0 for VMware.
#define USE_PRIVATE_HOST_GDT                1

//
// CR4.VMXE 锟?bit 13 (may already be defined in ia32.h)
//
#ifndef CR4_VMX_ENABLE_FLAG
#define CR4_VMX_ENABLE_FLAG                 0x2000ULL
#endif

//
// CR4.LAM_SUP 锟?bit 28 (supervisor linear address masking)
// not masked in guest/host mask, passes through transparently
//
#ifndef CR4_LAM_SUP_FLAG
#define CR4_LAM_SUP_FLAG                    0x10000000ULL
#endif

//
// estimated hardware VM-exit + VM-entry transition overhead (cycles)
// used only for the old accumulating approach 锟?no longer needed
//
// #define VM_EXIT_ENTRY_OVERHEAD_ESTIMATE     900
// #define BARE_METAL_CPUID_CYCLES             80

typedef struct _STEALTH_CPUID_CACHE {

    //
    // what bare metal returns for a completely out-of-range leaf (e.g. 0x13371337)
    // this is what all invalid leaves should return for consistency.
    //
    INT32   invalid_leaf[4];

    UINT32  max_std_leaf;

    UINT32  max_ext_leaf;

    //
    // hardware-supported XCR0 bitmask from CPUID.0Dh.0 (EAX:EDX)
    // used to validate XSETBV values instead of a hardcoded mask
    //
    UINT64  valid_xcr0_mask;

    BOOLEAN initialized;

    //
    // calibrated bare-metal CPUID execution cost (min of N samples)
    // used by TSC compensation to return plausible RDTSC deltas
    //
    UINT64  bare_metal_cpuid_cost;

    //
    // TRUE if the CPU forces RDTSC exiting as a must-be-1 bit.
    // if forced, we can't toggle it off 锟?just use the armed flag.
    //
    BOOLEAN rdtsc_exiting_forced;

} STEALTH_CPUID_CACHE;

extern BOOLEAN              g_stealth_enabled;
extern STEALTH_CPUID_CACHE  g_stealth_cpuid_cache;
extern volatile LONG        g_stealth_pf_intercept_needed;

VOID stealth_init_cpuid_cache(VOID);

BOOLEAN stealth_is_leaf_invalid(UINT32 leaf);

BOOLEAN stealth_is_xcr0_valid(UINT64 value);

#ifdef __cplusplus
}
#endif


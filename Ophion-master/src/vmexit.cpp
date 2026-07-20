/*
*   vmexit.c - vm-exit handler dispatches exits to sub-handlers
*/
#include "hv.h"
#include "log.h"

extern volatile LONG g_dbg_shadow_pf_seen;
extern volatile LONG g_dbg_shadow_pf_allowed;
extern volatile LONG g_dbg_shadow_pf_switched;

static volatile LONG g_dbg_shadow_timer_restore = 0;
static volatile LONG g_dbg_shadow_timer_skip = 0;

static __forceinline VOID
vmexit_advance_rip(VIRTUAL_MACHINE_STATE * vcpu)
{
    UINT64 instr_len = 0;
    __vmx_vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH, &instr_len);

    UINT64 new_rip = vcpu->vmexit_rip + instr_len;

    //
    // truncate RIP for non-64-bit segments (compatibility mode)
    // CS.L=0 CS.D=1 -> 32-bit, CS.L=0 CS.D=0 -> 16-bit
    //
    size_t cs_ar_raw = 0;
    __vmx_vmread(VMCS_GUEST_CS_ACCESS_RIGHTS, &cs_ar_raw);
    if (!((cs_ar_raw >> 13) & 1))
    {
        if ((cs_ar_raw >> 14) & 1)
            new_rip = (UINT32)new_rip;
        else
            new_rip = (UINT16)new_rip;
    }

    __vmx_vmwrite(VMCS_GUEST_RIP, new_rip);

    // clear STI/MOV-SS blocking
    size_t intr_state = 0;
    __vmx_vmread(VMCS_GUEST_INTERRUPTIBILITY_STATE, &intr_state);
    if (intr_state & (GUEST_INTR_STATE_BLOCKING_BY_STI | GUEST_INTR_STATE_BLOCKING_BY_MOV_SS))
    {
        intr_state &= ~(size_t)(GUEST_INTR_STATE_BLOCKING_BY_STI | GUEST_INTR_STATE_BLOCKING_BY_MOV_SS);
        __vmx_vmwrite(VMCS_GUEST_INTERRUPTIBILITY_STATE, intr_state);
    }

    // single-step + hardware breakpoint handling
    size_t rflags_raw = 0;
    __vmx_vmread(VMCS_GUEST_RFLAGS, &rflags_raw);

    UINT64 pending = 0;
    __vmx_vmread(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS, &pending);

    BOOLEAN need_bs = FALSE;
    if (rflags_raw & RFLAGS_TF)
    {
        size_t debugctl_raw = 0;
        __vmx_vmread(VMCS_GUEST_DEBUGCTL, &debugctl_raw);
        if (!(debugctl_raw & DEBUGCTL_BTF))
            need_bs = TRUE;
    }

    UINT64 dr7 = 0;
    __vmx_vmread(VMCS_GUEST_DR7, &dr7);

    static const UINT64 ln_bits[] = { DR7_L0, DR7_L1, DR7_L2, DR7_L3 };
    static const UINT64 gn_bits[] = { DR7_G0, DR7_G1, DR7_G2, DR7_G3 };
    static const UINT64 bn_bits[] = { PENDING_DEBUG_B0, PENDING_DEBUG_B1, PENDING_DEBUG_B2, PENDING_DEBUG_B3 };

    UINT64 bp_matched = 0;
    for (int i = 0; i < 4; i++)
    {
        if (!(dr7 & (ln_bits[i] | gn_bits[i])))
            continue;
        if ((dr7 & DR7_RW_MASK(i)) != 0)
            continue;

        UINT64 drn;
        switch (i)
        {
        case 0: drn = vcpu->guest_dr0; break;
        case 1: drn = vcpu->guest_dr1; break;
        case 2: drn = vcpu->guest_dr2; break;
        case 3: drn = vcpu->guest_dr3; break;
        default: continue;
        }

        if (drn == new_rip)
            bp_matched |= bn_bits[i];
    }

    if (need_bs || bp_matched)
    {
        if (need_bs)
            pending |= PENDING_DEBUG_BS;
        if (bp_matched)
            pending |= bp_matched | PENDING_DEBUG_ENABLED_BP;
        __vmx_vmwrite(VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS, pending);
    }
}

//
// exception classification for double-fault generation (SDM Vol 3 Table 6-5)
//
// contributory: #DE(0), #TS(10), #NP(11), #SS(12), #GP(13)
// page fault:   #PF(14)
// double fault: #DF(8)
// everything else: benign
//

typedef enum {
    EXCEPTION_CLASS_BENIGN,
    EXCEPTION_CLASS_CONTRIBUTORY,
    EXCEPTION_CLASS_PAGE_FAULT,
    EXCEPTION_CLASS_DOUBLE_FAULT
} EXCEPTION_CLASS;

static __forceinline EXCEPTION_CLASS
classify_exception(UINT32 vector)
{
    switch (vector)
    {
    case EXCEPTION_VECTOR_DIVIDE_ERROR:
    case EXCEPTION_VECTOR_INVALID_TSS:
    case EXCEPTION_VECTOR_SEGMENT_NOT_PRESENT:
    case EXCEPTION_VECTOR_STACK_SEGMENT_FAULT:
    case EXCEPTION_VECTOR_GENERAL_PROTECTION:
        return EXCEPTION_CLASS_CONTRIBUTORY;
    case EXCEPTION_VECTOR_PAGE_FAULT:
        return EXCEPTION_CLASS_PAGE_FAULT;
    case EXCEPTION_VECTOR_DOUBLE_FAULT:
        return EXCEPTION_CLASS_DOUBLE_FAULT;
    default:
        return EXCEPTION_CLASS_BENIGN;
    }
}

static __forceinline BOOLEAN
should_generate_df(UINT32 first_vector, UINT32 second_vector)
{
    EXCEPTION_CLASS first  = classify_exception(first_vector);
    EXCEPTION_CLASS second = classify_exception(second_vector);

    // contributory + contributory = #DF
    if (first == EXCEPTION_CLASS_CONTRIBUTORY && second == EXCEPTION_CLASS_CONTRIBUTORY)
        return TRUE;

    // PF + contributory or PF + PF = #DF
    if (first == EXCEPTION_CLASS_PAGE_FAULT &&
        (second == EXCEPTION_CLASS_CONTRIBUTORY || second == EXCEPTION_CLASS_PAGE_FAULT))
        return TRUE;

    return FALSE;
}

UINT64
vmx_return_rsp_for_vmxoff(VOID)
{
    UINT32                  core_id = (UINT32)(__readmsr(IA32_TSC_AUX) & 0xFFF);
    VIRTUAL_MACHINE_STATE * vcpu   = &g_vcpu[core_id];
    return vcpu->vmxoff.guest_rsp;
}

UINT64
vmx_return_rip_for_vmxoff(VOID)
{
    UINT32                  core_id = (UINT32)(__readmsr(IA32_TSC_AUX) & 0xFFF);
    VIRTUAL_MACHINE_STATE * vcpu   = &g_vcpu[core_id];
    return vcpu->vmxoff.guest_rip;
}

//
// Defeats:
//   - compare CPUID(0x04201337) vs CPUID(0x40000000)
//   - CPUID(max_leaf) vs CPUID(0x40000000)
//   - CPUID.1.ECX[31] hypervisor present bit
//   - CPUID subleaf handling
//   - some more
//
// Strategy:
//   before VMXON, we cache what the real CPU returns for an out-of-range leaf.
//   during VM-exit, if the guest queries an invalid/hypervisor leaf, we return
//   the cached response — identical to what bare metal would return.
//   for leaf 1, we clear ECX[31] (hypervisor present bit).
//

VOID
vmexit_handle_cpuid(VIRTUAL_MACHINE_STATE * vcpu)
{
    INT32       cpu_info[4] = {0};
    PGUEST_REGS regs       = vcpu->regs;
    UINT32      leaf       = (UINT32)regs->rax;
    UINT32      subleaf    = (UINT32)regs->rcx;

#if STEALTH_CPUID_CACHING
    //
    // if stealth is enabled and this leaf is invalid/out-of-range,
    // return the cached bare-metal response for perfect consistency.
    // on real hardware, CPUID(0x40000000) == CPUID(0x04201337) == CPUID(max+1)
    //
    if (g_stealth_enabled && stealth_is_leaf_invalid(leaf))
    {
        cpu_info[0] = g_stealth_cpuid_cache.invalid_leaf[0];
        cpu_info[1] = g_stealth_cpuid_cache.invalid_leaf[1];
        cpu_info[2] = g_stealth_cpuid_cache.invalid_leaf[2];
        cpu_info[3] = g_stealth_cpuid_cache.invalid_leaf[3];
    }
    else
#endif
    {
        __cpuidex(cpu_info, (int)leaf, (int)subleaf);

        //
        // leaf 1: clear the hypervisor present bit (ECX[31])
        // this is the primary detection used by EAC, BattlEye, VMAware, etc.
        //
        if (leaf == 1 && g_stealth_enabled)
        {
            cpu_info[2] &= ~((1 << 31) | (1 << 6));
        }
    }

    regs->rax = (UINT64)cpu_info[0];
    regs->rbx = (UINT64)cpu_info[1];
    regs->rcx = (UINT64)cpu_info[2];
    regs->rdx = (UINT64)cpu_info[3];
}

//
// Defeats:
//   - MSRs 0x40000000+ must #GP like bare metal
//   - IA32_FEATURE_CONTROL must hide VMX/SMX enables
//

VOID
vmexit_handle_msr_read(VIRTUAL_MACHINE_STATE * vcpu)
{
    MSR         msr       = {0};
    PGUEST_REGS regs      = vcpu->regs;
    UINT32      target_msr = (UINT32)(regs->rcx & 0xFFFFFFFF);

    //
    // hypervisor synthetic MSRs (0x40000000+) — inject #GP on bare metal
    // this includes Hyper-V (0x40000000-0x400000FF) and KVM (0x4b564d00-02) MSRs
    //
    if (target_msr >= 0x40000000 && target_msr <= 0x4FFFFFFF)
    {
        vmexit_inject_gp();
        vcpu->advance_rip = FALSE;
        return;
    }

    //
    // only service MSRs in valid architectural ranges
    //
    if ((target_msr <= 0x00001FFF) ||
        ((0xC0000000 <= target_msr) && (target_msr <= 0xC0001FFF)))
    {
        switch (target_msr)
        {
        case IA32_SYSENTER_CS:
            __vmx_vmread(VMCS_GUEST_SYSENTER_CS, &msr.Flags);
            break;

        case IA32_SYSENTER_ESP:
            __vmx_vmread(VMCS_GUEST_SYSENTER_ESP, &msr.Flags);
            break;

        case IA32_SYSENTER_EIP:
            __vmx_vmread(VMCS_GUEST_SYSENTER_EIP, &msr.Flags);
            break;

        case IA32_GS_BASE:
            __vmx_vmread(VMCS_GUEST_GS_BASE, &msr.Flags);
            break;

        case IA32_FS_BASE:
            __vmx_vmread(VMCS_GUEST_FS_BASE, &msr.Flags);
            break;

        //
        // IA32_TIME_STAMP_COUNTER (MSR 0x10)
        //
        // intercepted via MSR bitmap. in the handler, __rdtsc() returns raw
        // hardware TSC (no offset in VMX root), so we apply TSC_OFFSET manually.
        // per SDM 27.6.5, "use TSC offsetting" applies the same offset to RDTSC,
        // RDTSCP, and RDMSR of this MSR — interception is only needed so the
        // TSC compensation path can also cover RDMSR-based timing attacks.
        //
        case 0x10:
        {
            if (g_stealth_enabled)
            {
                size_t tsc_offset_raw = 0;
                __vmx_vmread(VMCS_CTRL_TSC_OFFSET, &tsc_offset_raw);
                msr.Flags = (UINT64)((INT64)__rdtsc() + (INT64)tsc_offset_raw);
            }
            else
            {
                msr.Flags = __rdtsc();
            }
            break;
        }

        case IA32_FEATURE_CONTROL:
        {
            IA32_FEATURE_CONTROL_REGISTER feat = {0};
            feat.AsUInt = __readmsr(IA32_FEATURE_CONTROL);

            if (g_stealth_enabled)
            {
                feat.Lock                      = 1;
                feat.EnableVmxInsideSmx        = 0;
                feat.EnableVmxOutsideSmx       = 0;
                feat.SenterLocalFunctionEnables = 0;
                feat.SenterGlobalEnable        = 0;
                feat.SgxLaunchControlEnable    = 0;
                feat.SgxGlobalEnable           = 0;
            }

            msr.Flags = feat.AsUInt;
            break;
        }

        default:
            //
            // VMX capability MSRs (0x480-0x493) — always readable on VMX-capable
            // CPUs regardless of FEATURE_CONTROL lock state. return real values
            // to match bare-metal behavior for stealth.
            //
            if (target_msr >= IA32_VMX_BASIC && target_msr <= 0x493)
            {
                msr.Flags = __readmsr(target_msr);
                break;
            }

            //
            // unhandled — never forward to hardware in VMX-root, would #GP
            // and hit our private IDT halt handler. inject #GP(0) to guest.
            //
            vmexit_inject_gp();
            vcpu->advance_rip = FALSE;
            return;
        }

        regs->rax = (UINT64)msr.Fields.Low;
        regs->rdx = (UINT64)msr.Fields.High;
    }
    else
    {
        vmexit_inject_gp();
        vcpu->advance_rip = FALSE;
        return;
    }
}

VOID
vmexit_handle_msr_write(VIRTUAL_MACHINE_STATE * vcpu)
{
    MSR         msr       = {0};
    PGUEST_REGS regs      = vcpu->regs;
    UINT32      target_msr = (UINT32)(regs->rcx & 0xFFFFFFFF);

    msr.Fields.Low  = (ULONG)regs->rax;
    msr.Fields.High = (ULONG)regs->rdx;

    //
    // hypervisor synthetic MSRs — inject #GP
    //
    if (target_msr >= 0x40000000 && target_msr <= 0x4FFFFFFF)
    {
        vmexit_inject_gp();
        vcpu->advance_rip = FALSE;
        return;
    }

    // IA32_FEATURE_CONTROL (locked) + VMX capability MSRs (read-only)
    if (target_msr == IA32_FEATURE_CONTROL ||
        (target_msr >= IA32_VMX_BASIC && target_msr <= 0x493))
    {
        vmexit_inject_gp();
        vcpu->advance_rip = FALSE;
        return;
    }

    if ((target_msr <= 0x00001FFF) ||
        ((0xC0000000 <= target_msr) && (target_msr <= 0xC0001FFF)))
    {
        switch (target_msr)
        {
        case IA32_SYSENTER_CS:
            __vmx_vmwrite(VMCS_GUEST_SYSENTER_CS, msr.Flags);
            break;

        case IA32_SYSENTER_ESP:
            __vmx_vmwrite(VMCS_GUEST_SYSENTER_ESP, msr.Flags);
            break;

        case IA32_SYSENTER_EIP:
            __vmx_vmwrite(VMCS_GUEST_SYSENTER_EIP, msr.Flags);
            break;

        case IA32_GS_BASE:
            __vmx_vmwrite(VMCS_GUEST_GS_BASE, msr.Flags);
            break;

        case IA32_FS_BASE:
            __vmx_vmwrite(VMCS_GUEST_FS_BASE, msr.Flags);
            break;

        default:
            //
            // unhandled — never forward to hardware in VMX-root, would #GP
            // and hit our private IDT halt handler. inject #GP(0) to guest.
            //
            vmexit_inject_gp();
            vcpu->advance_rip = FALSE;
            return;
        }
    }
    else
    {
        vmexit_inject_gp();
        vcpu->advance_rip = FALSE;
        return;
    }
}

//
// Defeats: hvdetecc vm.vmxe (checks if CR4 bit 13 is set)
//
//   CR4 guest/host mask has bit 13 set, so guest reads CR4 with VMXE
//   from the read shadow (where it's 0). Guest writes to CR4 that change
//   masked bits cause a VM-exit, which we handle here by keeping VMXE=1
//   in the actual VMCS guest CR4 while the shadow shows VMXE=0.
//

VOID
vmexit_handle_mov_cr(VIRTUAL_MACHINE_STATE * vcpu)
{
    VMX_EXIT_QUALIFICATION_MOV_CR cr_qual;
    PGUEST_REGS                   regs = vcpu->regs;
    UINT64 *                      reg_ptr;

    cr_qual.AsUInt = vcpu->exit_qual;

    switch (cr_qual.GeneralPurposeRegister)
    {
    case 0:  reg_ptr = &regs->rax; break;
    case 1:  reg_ptr = &regs->rcx; break;
    case 2:  reg_ptr = &regs->rdx; break;
    case 3:  reg_ptr = &regs->rbx; break;
    case 4:  reg_ptr = &regs->rsp; break;
    case 5:  reg_ptr = &regs->rbp; break;
    case 6:  reg_ptr = &regs->rsi; break;
    case 7:  reg_ptr = &regs->rdi; break;
    case 8:  reg_ptr = &regs->r8;  break;
    case 9:  reg_ptr = &regs->r9;  break;
    case 10: reg_ptr = &regs->r10; break;
    case 11: reg_ptr = &regs->r11; break;
    case 12: reg_ptr = &regs->r12; break;
    case 13: reg_ptr = &regs->r13; break;
    case 14: reg_ptr = &regs->r14; break;
    case 15: reg_ptr = &regs->r15; break;
    default: reg_ptr = &regs->rax; break;
    }

    switch (cr_qual.AccessType)
    {
    case 0: // MOV to CR
    {
        switch (cr_qual.ControlRegister)
        {
        case 0:
        {
            //
            // MOV to CR0: enforce VMX fixed bits to prevent VM-entry failure.
            // shadow gets the guest's requested value so reads return what the
            // guest wrote (host-owned bits come from shadow, not actual CR0).
            //
            UINT64  desired = *reg_ptr;
            CR_FIXED fixed;
            UINT64  actual = desired;

            fixed.Flags = __readmsr(IA32_VMX_CR0_FIXED0);
            actual |= fixed.Fields.Low;
            fixed.Flags = __readmsr(IA32_VMX_CR0_FIXED1);
            actual &= fixed.Fields.Low;

            __vmx_vmwrite(VMCS_GUEST_CR0, actual);
            __vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, desired);
            break;
        }

        case 3:
        {
            //
            // MOV to CR3: handle pcid no-invalidate (bit 63) and flush tlb
            //
            // with vpid enabled, intercepting mov cr3 prevents the hardware
            // from flushing stale guest tlb entries. must call invvpid to
            // maintain tlb coherency unless the pcid no-invalidate bit is set
            //
            // bit 63 must be 0 in VMCS_GUEST_CR3 for vm-entry to succeed
            //
            UINT64  new_cr3  = *reg_ptr;
            BOOLEAN no_flush = (new_cr3 >> 63) & 1;

            __vmx_vmwrite(VMCS_GUEST_CR3, new_cr3 & ~(1ULL << 63));

            if (!no_flush)
            {
                //
                // prefer RetainingGlobals (type 3) to preserve global kernel
                // tlb entries — matches bare-metal mov cr3 behavior
                //
                INVVPID_DESCRIPTOR desc = {0};
                desc.Vpid = VPID_TAG;

                UINT8 ret;
                if (g_ept->invvpid_single_retaining_globals)
                {
                    ret = asm_invvpid(InvvpidSingleContextRetainingGlobals, &desc);
                }
                else
                {
                    ret = asm_invvpid(InvvpidSingleContext, &desc);
                }

                if (ret != 0)
                {
                    //
                    // fallback: all-contexts flush (always supported)
                    //
                    asm_invvpid(InvvpidAllContexts, &desc);
                }
            }
            break;
        }

        case 8:
            //
            // MOV to CR8 (TPR): pass through directly
            // only bits [3:0] are valid. required when cr8-load exiting
            // is forced by must-be-1 bits
            //
            vcpu->guest_cr8 = (UINT8)(*reg_ptr & 0xF);
            __writecr8(vcpu->guest_cr8);
            break;

        case 4:
        {
            //
            // MOV to CR4: enforce VMX fixed bits + stealth VMXE hiding.
            //
            UINT64  desired = *reg_ptr;
            CR_FIXED fixed;

#if STEALTH_HIDE_CR4_VMXE
            if (g_stealth_enabled)
            {
                UINT64 actual = desired | CR4_VMX_ENABLE_FLAG;
                fixed.Flags = __readmsr(IA32_VMX_CR4_FIXED0);
                actual |= fixed.Fields.Low;
                fixed.Flags = __readmsr(IA32_VMX_CR4_FIXED1);
                actual &= fixed.Fields.Low;

                __vmx_vmwrite(VMCS_GUEST_CR4, actual);
                __vmx_vmwrite(VMCS_CTRL_CR4_READ_SHADOW, desired & ~CR4_VMX_ENABLE_FLAG);
            }
            else
#endif
            {
                UINT64 actual = desired;
                fixed.Flags = __readmsr(IA32_VMX_CR4_FIXED0);
                actual |= fixed.Fields.Low;
                fixed.Flags = __readmsr(IA32_VMX_CR4_FIXED1);
                actual &= fixed.Fields.Low;

                __vmx_vmwrite(VMCS_GUEST_CR4, actual);
                __vmx_vmwrite(VMCS_CTRL_CR4_READ_SHADOW, desired);
            }
            break;
        }

        default:
            break;
        }
        break;
    }
    case 1: // MOV from CR
    {
        switch (cr_qual.ControlRegister)
        {
        case 3:
            __vmx_vmread(VMCS_GUEST_CR3, reg_ptr);
            break;

        case 8:
            *reg_ptr = vcpu->guest_cr8;
            break;

        default:
            break;
        }
        break;
    }
    case 2: // CLTS — clear CR0.TS (bit 3)
    {
        UINT64  guest_cr0 = 0;
        UINT64  shadow    = 0;
        CR_FIXED fixed;

        __vmx_vmread(VMCS_GUEST_CR0, &guest_cr0);
        __vmx_vmread(VMCS_CTRL_CR0_READ_SHADOW, &shadow);

        guest_cr0 &= ~(1ULL << 3);
        shadow    &= ~(1ULL << 3);

        fixed.Flags = __readmsr(IA32_VMX_CR0_FIXED0);
        guest_cr0 |= fixed.Fields.Low;
        fixed.Flags = __readmsr(IA32_VMX_CR0_FIXED1);
        guest_cr0 &= fixed.Fields.Low;

        __vmx_vmwrite(VMCS_GUEST_CR0, guest_cr0);
        __vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, shadow);
        break;
    }
    case 3: // LMSW — load machine status word (bits 0-3 of CR0)
    {
        //
        // LMSW loads PE, MP, EM, TS from source data in exit qualification.
        // PE (bit 0) can be set but NOT cleared by LMSW (Intel SDM Vol 2).
        //
        UINT64  guest_cr0 = 0;
        UINT64  shadow    = 0;
        CR_FIXED fixed;
        UINT64  src       = (UINT64)(UINT16)cr_qual.LmswSourceData & 0xFULL;

        __vmx_vmread(VMCS_GUEST_CR0, &guest_cr0);
        __vmx_vmread(VMCS_CTRL_CR0_READ_SHADOW, &shadow);

        //
        // Bits 1-3 (MP, EM, TS): loaded from source
        // Bit 0 (PE): can be set, never cleared — OR with current value
        //
        guest_cr0 = (guest_cr0 & ~0xEULL) | (src & 0xEULL) | ((guest_cr0 | src) & 1ULL);
        shadow    = (shadow    & ~0xEULL) | (src & 0xEULL) | ((shadow    | src) & 1ULL);

        fixed.Flags = __readmsr(IA32_VMX_CR0_FIXED0);
        guest_cr0 |= fixed.Fields.Low;
        fixed.Flags = __readmsr(IA32_VMX_CR0_FIXED1);
        guest_cr0 &= fixed.Fields.Low;

        __vmx_vmwrite(VMCS_GUEST_CR0, guest_cr0);
        __vmx_vmwrite(VMCS_CTRL_CR0_READ_SHADOW, shadow);
        break;
    }
    default:
        break;
    }
}

VOID
vmexit_handle_ept_violation(VIRTUAL_MACHINE_STATE * vcpu)
{
    UINT64 guest_phys = 0;
    __vmx_vmread(VMCS_GUEST_PHYSICAL_ADDRESS, &guest_phys);

    //
    // try to handle as an EPT hook violation (split-TLB page swap)
    //
    if (ept_handle_violation(vcpu, guest_phys, vcpu->exit_qual))
    {
        // handled — don't advance RIP, the guest will re-execute
        vcpu->advance_rip = FALSE;
        return;
    }

    //
    // try stealth page EPT violation (hidden executable memory split-TLB)
    //
    if (ept_stealth_handle_violation(vcpu, guest_phys, vcpu->exit_qual))
    {
        vcpu->advance_rip = FALSE;
        return;
    }

    //
    // unhandled EPT violation — 可能是刚 unhook 但 TLB 还没刷新
    // 做一次 INVEPT 让 CPU 重试（PTE 已恢复 RWX，重试后不会再 violation）
    // 如果确实是 EPT 配置错误，重试几次后系统会自然恢复或触发 misconfig
    //
    // PITFALL #13: Don't inject #GP - page may have been unhooked but TLB stale.
    // FIX: INVEPT flushes stale TLB, CPU retries with updated PTE (now RWX), no more violation.
    ept_invept_single(vcpu->ept_pointer);
    vcpu->advance_rip = FALSE;
}

VOID
vmexit_handle_vmcall(VIRTUAL_MACHINE_STATE * vcpu)
{
    PGUEST_REGS regs = vcpu->regs;

    //
    // EPT hook / stealth VMCALL dispatch — MUST run before CPL check.
    //
    // Ring 3 EPT hooks (type 1) and stealth oneshot pages embed VMCALL (0F 01 C1)
    // in user-mode execute pages. the CPU executes vmcall from CPL=3 which causes
    // a VM exit. these handlers check RIP against known hooked/stealth pages and
    // redirect execution to the handler function. safe: only matches our own pages.
    //
    // if we checked CPL first, all R3 vmcall would be rejected with #UD before
    // the EPT hook/stealth dispatch could handle them.
    //
    if (ept_handle_vmcall_hook(vcpu))
    {
        vcpu->advance_rip = FALSE;
        return;
    }

    if (ept_handle_stealth_vmcall(vcpu))
    {
        vcpu->advance_rip = FALSE;
        return;
    }

    //
    // reject VMCALL from ring 3 — only kernel callers allowed for OPHION_VMCALL_ID.
    // EPT hook / stealth vmcall was already handled above.
    //
    {
        size_t guest_cs_ar = 0;
        __vmx_vmread(VMCS_GUEST_CS_ACCESS_RIGHTS, &guest_cs_ar);
        if (((guest_cs_ar >> 5) & 3) != 0)
        {
            vmexit_inject_ud();
            vcpu->advance_rip = FALSE;
            return;
        }
    }

    //
    // 1. check rax identifier (like UnrealVTDbg's VMCALL_IDENTIFIER)
    //    if rax matches, parameters are in rcx/rdx/r8/r9/r10-r15
    //
    // PITFALL #3: EPT VMCALLs use rax identifier, not r10/r11/r12 signature (need r10-r15 for params).
    // FIX: Check rax first. If matches, r10-r15 carry target/proxy/cr3/hook_type. Like UnrealVTDbg.
    if (regs->rax == OPHION_VMCALL_ID)
    {
        UINT64 vmcall_num = regs->rcx;

        switch (vmcall_num)
        {
        case VMCALL_EPT_HOOK:
        {
            //
            // 参数全在寄存器:
            //   rdx = target_function
            //   r8  = proxy_function
            //   r9  = &origin_function (guest VA)
            //   r10 = caller_cr3
            //   r11 = hook_type
            //   r12 = target_cr3      (0 = R0 hook, non-0 = R3 per-process)
            //   r13 = user_trampoline (R3 executable buffer, NULL = kernel pool)
            //   r14 = user_trampoline_pa (pre-computed PA)
            //   r15 = expected_tid (full 64-bit, 0 = any thread)
            //   r11 = hook_type (low32) | flags (high32: bit 0 = force_read_access, bit 1 = oneshot)
            //
            UINT64 target_va       = regs->rdx;
            UINT64 proxy_va        = regs->r8;
            UINT64 origin_va       = regs->r9;
            UINT64 caller_cr3      = regs->r10;
            UINT32 hook_type       = (UINT32)regs->r11;
            UINT64 flags           = regs->r11 >> 32;   // high32: force_read_access(bit0), oneshot(bit1)
            UINT64 target_cr3      = regs->r12;
            UINT64 user_tramp_va   = regs->r13;
            UINT64 user_tramp_pa   = regs->r14;
            UINT64 expected_tid    = regs->r15;          // full 64-bit TID filter

            if (!target_va || !caller_cr3)
            {
                regs->rax = (UINT64)STATUS_INVALID_PARAMETER;
                break;
            }

            UINT64 _saved_cr3 = vmx_enter_guest_cr3();

            EPT_HOOK_VMCALL_PARAM local_req = {};
            local_req.caller_cr3         = caller_cr3;
            local_req.target_function    = (PVOID)target_va;
            local_req.proxy_function     = (PVOID)proxy_va;
            local_req.hook_type          = hook_type;
            local_req.target_cr3         = target_cr3;
            local_req.user_trampoline    = (PVOID)user_tramp_va;
            local_req.user_trampoline_pa = user_tramp_pa;
            local_req.force_read_access  = (flags & 1) ? TRUE : FALSE;
            local_req.oneshot            = (flags & 2) ? TRUE : FALSE;
            local_req.expected_tid       = expected_tid;
            //
            // proxy_range_end: packed into high 32 bits of expected_tid when
            // expected_tid is 0 (which is the common case for renderdoc hooks).
            // if expected_tid is non-zero, the caller must pass proxy_range_end
            // separately. for now, the hypervisor defaults to proxy_function + PAGE_SIZE.
            //
            local_req.proxy_range_end    = 0;  // hypervisor defaults to proxy_function + PAGE_SIZE
            if (origin_va)
                local_req.origin_function = (PVOID *)origin_va;

            BOOLEAN ok = ept_hook_install(vcpu, &local_req);

            vmx_leave_guest_cr3(_saved_cr3);
            regs->rax = ok ? (UINT64)STATUS_SUCCESS : (UINT64)STATUS_UNSUCCESSFUL;
            break;
        }

        case VMCALL_EPT_UNHOOK:
        {
            UINT64 target_va  = regs->rdx;
            UINT64 caller_cr3 = regs->r10;
            if (!target_va)
            {
                regs->rax = (UINT64)STATUS_INVALID_PARAMETER;
                break;
            }

            UINT64 _saved_cr3 = vmx_enter_guest_cr3();

            //
            // for R3 unhook: need caller_cr3 to resolve R3 VA → PA
            // switch from system CR3 to caller_cr3 if provided
            //
            UINT64 _pre_unhook_cr3 = 0;
            if (caller_cr3)
            {
                _pre_unhook_cr3 = __readcr3();
                __writecr3(caller_cr3);
                _mm_mfence();
            }

            EPT_UNHOOK_VMCALL_PARAM local_req = {};
            local_req.target_function = (PVOID)target_va;
            local_req.caller_cr3      = caller_cr3;

            BOOLEAN ok = ept_unhook_install(vcpu, &local_req);

            if (_pre_unhook_cr3)
            {
                _mm_mfence();
                __writecr3(_pre_unhook_cr3);
            }

            vmx_leave_guest_cr3(_saved_cr3);
            regs->rax = ok ? (UINT64)STATUS_SUCCESS : (UINT64)STATUS_UNSUCCESSFUL;
            break;
        }

        case VMCALL_EPT_UNHOOK_ALL:
            ept_unhook_all();
            regs->rax = (UINT64)STATUS_SUCCESS;
            break;

        case VMCALL_EPT_UNHOOK_BY_CR3:
        {
            UINT64 target_cr3 = regs->rdx;
            if (!target_cr3)
            {
                regs->rax = (UINT64)STATUS_INVALID_PARAMETER;
                break;
            }
            ept_unhook_all_by_cr3(vcpu, target_cr3);
            regs->rax = (UINT64)STATUS_SUCCESS;
            break;
        }

        case VMCALL_STEALTH_ALLOC:
        {
            UINT64 _saved_cr3 = vmx_enter_guest_cr3();

            PEPT_STEALTH_ALLOC_PARAM stealth_req = (PEPT_STEALTH_ALLOC_PARAM)regs->rdx;
            if (!stealth_req)
            {
                vmx_leave_guest_cr3(_saved_cr3);
                regs->rax = (UINT64)STATUS_INVALID_PARAMETER;
                break;
            }

            BOOLEAN ok = ept_stealth_install_ex(vcpu, stealth_req, &stealth_req->installed);
            stealth_req->result = ok;

            vmx_leave_guest_cr3(_saved_cr3);
            regs->rax = ok ? (UINT64)STATUS_SUCCESS : (UINT64)STATUS_UNSUCCESSFUL;
            break;
        }

        case VMCALL_STEALTH_FREE:
        {
            PEPT_STEALTH_FREE_PARAM free_req = (PEPT_STEALTH_FREE_PARAM)regs->rdx;
            if (!free_req)
            {
                regs->rax = (UINT64)STATUS_INVALID_PARAMETER;
                break;
            }

            UINT64 _saved_cr3 = vmx_enter_guest_cr3();
            BOOLEAN ok = ept_stealth_uninstall(vcpu, free_req);
            free_req->result = ok;
            vmx_leave_guest_cr3(_saved_cr3);
            regs->rax = ok ? (UINT64)STATUS_SUCCESS : (UINT64)STATUS_UNSUCCESSFUL;
            break;
        }

        case VMCALL_EPT_HOOK_INJECT:
        {
            //
            // shellcode inject via EPT hook — all data pre-built at PASSIVE_LEVEL.
            // NO user VA access in VMX-root (SMAP safe).
            // rdx = pointer to EPT_HOOK_INJECT_PARAM (kernel NonPaged memory)
            //
            // CRITICAL: must switch to system CR3 for private host CR3 mode.
            // inj pointer and its buffers (fake_page_buffer, pt_page_copy) are
            // post-init NonPaged pool allocations — not mapped in private CR3.
            //
            #define _POOL_TAG_HOOKED_PAGE 1
            #define _POOL_TAG_HOOKED_FUNC 2
            UINT64 _saved_cr3_inj = vmx_enter_guest_cr3();
            PEPT_HOOK_INJECT_PARAM inj = (PEPT_HOOK_INJECT_PARAM)regs->rdx;
            if (!inj || !inj->fake_page_buffer || !inj->target_phys)
            {
                vmx_leave_guest_cr3(_saved_cr3_inj);
                regs->rax = (UINT64)STATUS_INVALID_PARAMETER;
                break;
            }

            UINT64 target_phys = inj->target_phys & ~0xFFFULL;
            UINT64 target_pfn  = target_phys >> 12;

            // --- already installed (other CPU in DPC broadcast) ---
            BOOLEAN already = FALSE;
            PLIST_ENTRY hcur = g_ept->hooked_pages.Flink;
            while (hcur != &g_ept->hooked_pages)
            {
                PEPT_HOOKED_PAGE_INFO ex = CONTAINING_RECORD(hcur, EPT_HOOKED_PAGE_INFO, hooked_page_list);
                hcur = hcur->Flink;
                if (ex->pfn_of_hooked_page == target_pfn)
                {
                    // split this CPU's EPT + set PTE for target page
                    PEPT_PML2_ENTRY p2 = ept_get_pml2(vcpu->ept_page_table, (SIZE_T)target_phys);
                    if (p2 && p2->LargePage)
                        ept_split_large_page_pool(vcpu->ept_page_table, (SIZE_T)target_phys);
                    PEPT_PML1_ENTRY p1 = ept_get_pml1(vcpu->ept_page_table, (SIZE_T)target_phys);

                    // EPT X-only on fake page physical page (this CPU)
                    {
                        SIZE_T fake_phys = (SIZE_T)(ex->pfn_of_fake_page_contents << 12);
                        PEPT_PML2_ENTRY fp2 = ept_get_pml2(vcpu->ept_page_table, fake_phys);
                        if (fp2 && fp2->LargePage)
                            ept_split_large_page_pool(vcpu->ept_page_table, fake_phys);
                        PEPT_PML1_ENTRY fp1 = ept_get_pml1(vcpu->ept_page_table, fake_phys);
                        if (fp1) { fp1->ReadAccess = 0; fp1->WriteAccess = 0; fp1->ExecuteAccess = 1; }
                    }

                    // split + set PT page EPT to fake view on this CPU
                    if (ex->fake_pt)
                    {
                        if (p1) p1->AsUInt = ex->changed_entry.AsUInt;

                        UINT64 pt_phys = ex->fake_pt->pt_page_pfn << 12;
                        PEPT_PML2_ENTRY pp2 = ept_get_pml2(vcpu->ept_page_table, (SIZE_T)pt_phys);
                        if (pp2 && pp2->LargePage)
                            ept_split_large_page_pool(vcpu->ept_page_table, (SIZE_T)pt_phys);
                        PEPT_PML1_ENTRY pp1 = ept_get_pml1(vcpu->ept_page_table, (SIZE_T)pt_phys);
                        if (pp1) pp1->AsUInt = ex->fake_pt->pt_fake_entry.AsUInt;

                        ept_update_pf_intercept(vcpu);
                    }
                    else
                    {
                        if (p1) { p1->ReadAccess = 1; p1->WriteAccess = 1; p1->ExecuteAccess = 0; }
                    }

                    _mm_mfence();
                    ept_invept_single(vcpu->ept_pointer);
                    inj->result = TRUE;
                    already = TRUE;
                    break;
                }
            }
            if (already) { vmx_leave_guest_cr3(_saved_cr3_inj); regs->rax = (UINT64)STATUS_SUCCESS; break; }

            // --- first CPU: full install ---
            if (_InterlockedCompareExchange(&inj->installed, 1, 0) != 0)
            {
                //
                // lost interlock — another CPU is doing the full install.
                // don't wait for the list entry (spin may not be enough on 20 CPUs).
                // just split THIS CPU's EPT and set X=0. the global list entry
                // (for violation/VMCALL dispatch) will be available once the winner
                // CPU completes InsertHeadList — the list is shared across all CPUs.
                //
                PEPT_PML2_ENTRY p2 = ept_get_pml2(vcpu->ept_page_table, (SIZE_T)target_phys);
                if (p2 && p2->LargePage)
                    ept_split_large_page_pool(vcpu->ept_page_table, (SIZE_T)target_phys);
                PEPT_PML1_ENTRY p1 = ept_get_pml1(vcpu->ept_page_table, (SIZE_T)target_phys);
                if (p1) { p1->ReadAccess = 1; p1->WriteAccess = 1; p1->ExecuteAccess = 0; }

                //
                // enable #PF interception on this CPU (lazy — the #PF handler
                // will split the PT page when the first instruction-fetch #PF fires).
                // we can't read hp->fake_pt yet because the winner CPU may still be
                // building the list entry. the #PF handler will find it via the list.
                //
                if (inj->pt_page_pfn && inj->pt_page_copy)
                {
                        ept_update_pf_intercept(vcpu);
                }

                _mm_mfence();
                ept_invept_single(vcpu->ept_pointer);
                inj->result = TRUE;
                vmx_leave_guest_cr3(_saved_cr3_inj);
                regs->rax = (UINT64)STATUS_SUCCESS;
                break;
            }

            // allocate tracking structs from pool (kernel memory, no SMAP issue)
            PEPT_HOOKED_PAGE_INFO hp = (PEPT_HOOKED_PAGE_INFO)
                pool_manager_request(_POOL_TAG_HOOKED_PAGE, sizeof(EPT_HOOKED_PAGE_INFO));
            PEPT_HOOKED_FUNCTION_INFO fi = hp ? (PEPT_HOOKED_FUNCTION_INFO)
                pool_manager_request(_POOL_TAG_HOOKED_FUNC, sizeof(EPT_HOOKED_FUNCTION_INFO)) : NULL;
            if (!hp || !fi)
            {
                if (hp) pool_manager_release(hp);
                inj->result = FALSE;
                vmx_leave_guest_cr3(_saved_cr3_inj);
                regs->rax = (UINT64)STATUS_INSUFFICIENT_RESOURCES;
                break;
            }
            RtlZeroMemory(hp, sizeof(*hp));
            RtlZeroMemory(fi, sizeof(*fi));
            InitializeListHead(&hp->hooked_functions_list);

            // split 2MB → 4KB
            PEPT_PML2_ENTRY pml2 = ept_get_pml2(vcpu->ept_page_table, (SIZE_T)target_phys);
            PEPT_PML1_ENTRY pte = NULL;
            if (pml2 && pml2->LargePage)
            {
                PVMM_EPT_DYNAMIC_SPLIT sp = ept_split_large_page_pool(vcpu->ept_page_table, (SIZE_T)target_phys);
                if (!sp) { pool_manager_release(fi); pool_manager_release(hp);
                           inj->result = FALSE; vmx_leave_guest_cr3(_saved_cr3_inj); regs->rax = (UINT64)STATUS_UNSUCCESSFUL; break; }
                pte = &sp->PML1[ADDRMASK_EPT_PML1_INDEX(target_phys)];
            }
            else
                pte = ept_get_pml1(vcpu->ept_page_table, (SIZE_T)target_phys);

            if (!pte) { pool_manager_release(fi); pool_manager_release(hp);
                        inj->result = FALSE; vmx_leave_guest_cr3(_saved_cr3_inj); regs->rax = (UINT64)STATUS_UNSUCCESSFUL; break; }

            // allocate fake page from stealth region (EPT X-only, immune to phys scan)
            hp->pfn_of_hooked_page = target_pfn;
            {
                UINT64 fake_pfn = 0;
                hp->fake_page_va = stealth_region_alloc_page(&fake_pfn);
                if (!hp->fake_page_va) {
                    pool_manager_release(fi); pool_manager_release(hp);
                    inj->result = FALSE; vmx_leave_guest_cr3(_saved_cr3_inj);
                    regs->rax = (UINT64)STATUS_INSUFFICIENT_RESOURCES; break;
                }
                hp->pfn_of_fake_page_contents = fake_pfn;
            }
            hp->entry_address = pte;
            hp->target_cr3 = 0;  // global (no CR3 filtering — private page, safe)

            RtlCopyMemory(hp->fake_page_va, inj->fake_page_buffer, PAGE_SIZE);

            // EPT X-only on fake page physical page (anti-cheat phys scan → EPT violation)
            {
                SIZE_T fake_phys = (SIZE_T)(hp->pfn_of_fake_page_contents << 12);
                PEPT_PML2_ENTRY fp2 = ept_get_pml2(vcpu->ept_page_table, fake_phys);
                if (fp2 && fp2->LargePage)
                    ept_split_large_page_pool(vcpu->ept_page_table, fake_phys);
                PEPT_PML1_ENTRY fp1 = ept_get_pml1(vcpu->ept_page_table, fake_phys);
                if (fp1) { fp1->ReadAccess = 0; fp1->WriteAccess = 0; fp1->ExecuteAccess = 1; }
            }

            // fill function info
            fi->virtual_address    = (PVOID)inj->target_va;
            fi->handler_function   = (PVOID)inj->handler_va;
            fi->fake_page_contents = hp->fake_page_va;
            fi->hook_size          = inj->hook_size;
            fi->first_trampoline_address = NULL;  // built at PASSIVE_LEVEL
            fi->user_trampoline    = TRUE;         // don't pool_release

            // EPT PTE permissions
            hp->original_entry = *pte;
            hp->original_entry.ReadAccess    = 1;
            hp->original_entry.WriteAccess   = 1;
            hp->original_entry.ExecuteAccess = 0;

            hp->changed_entry = hp->original_entry;
            hp->changed_entry.ReadAccess      = inj->force_read_access ? 1
                                               : (g_ept->execute_only_supported ? 0 : 1);
            hp->changed_entry.WriteAccess     = 0;
            hp->changed_entry.ExecuteAccess   = 1;
            hp->changed_entry.PageFrameNumber = hp->pfn_of_fake_page_contents;

            hp->Options = EPTO_HOOK_FUNCTION;
            InsertHeadList(&hp->hooked_functions_list, &fi->hooked_function_list);
            InsertHeadList(&g_ept->hooked_pages, &hp->hooked_page_list);

            // activate: set PTE to read view (X=0)
            pte->ReadAccess    = 1;
            pte->WriteAccess   = 1;
            pte->ExecuteAccess = 0;

            //
            // --- fake PT + exec PT page setup for NX hiding ---
            //
            // two PT pages (no in-place content modification, avoids cache issues):
            //   fake PT page: NX=1 for our entry (anti-cheat reads see non-executable)
            //   exec PT page: NX=0 for our entry (CPU page walk during #PF recovery)
            //
            // #PF handler swaps EPT PFN pointer, doesn't touch page content.
            //
            if (inj->pt_page_pfn && inj->pt_page_copy)
            {
                // create fake PT page (NX=1) via stealth infrastructure
                PSTEALTH_FAKE_PT fpt = stealth_get_or_create_fake_pt(
                    vcpu, inj->pt_page_pfn, inj->pt_page_copy, inj->pt_page_va);
                if (fpt)
                {
                    stealth_fake_pt_set_nx(fpt, inj->pt_pte_index);
                    hp->fake_pt       = fpt;
                    hp->pt_pte_index  = inj->pt_pte_index;
                    inj->fake_pt_ok   = TRUE;

                    // create exec PT page (NX=0) — separate physical page
                    UINT64 exec_pfn = 0;
                    PUINT8 exec_page = stealth_region_alloc_page(&exec_pfn);
                    if (exec_page)
                    {
                        // copy same PT content, but KEEP NX=0 for our entry
                        RtlCopyMemory(exec_page, inj->pt_page_copy, PAGE_SIZE);
                        // NX is already 0 in pt_page_copy (cleared at PASSIVE_LEVEL)

                        hp->exec_pt_page = exec_page;
                        hp->exec_pt_pfn  = exec_pfn;

                        // build EPT entry for exec PT page
                        // CRITICAL: must have W=1! CPU sets Accessed bit in PTE during
                        // page walk by WRITING to the PT page. if W=0, the write causes
                        // an EPT violation that no handler recognizes → infinite loop → BSOD.
                        // (pt_fake_entry has W=0 for write-sync, but exec PT needs W=1)
                        hp->pt_exec_entry = fpt->pt_fake_entry;
                        hp->pt_exec_entry.PageFrameNumber = exec_pfn;
                        hp->pt_exec_entry.WriteAccess = 1;
                    }
                }
            }

            // when fake PT is active, set initial EPT to execute view (changed_entry).
            // execution is controlled by fake PT (NX=1 → #PF), NOT by EPT X bit.
            // if we leave EPT X=0, we get double VMEXIT (first #PF, then EPT violation)
            // and the MTF handler can only restore one per trap → infinite loop.
            //
            // with EPT X=1 (changed_entry): read → R=0 → EPT violation → zeros.
            //                               exec → EPT ok → fake PT NX=1 → #PF → exec PT → run.
            if (hp->fake_pt && hp->exec_pt_page)
            {
                pte->AsUInt = hp->changed_entry.AsUInt;

                ept_update_pf_intercept(vcpu);
            }

            _mm_mfence();
            ept_invept_single(vcpu->ept_pointer);

            inj->result = TRUE;
            vmx_leave_guest_cr3(_saved_cr3_inj);
            regs->rax = (UINT64)STATUS_SUCCESS;
            break;
        }

        case VMCALL_TEST:
            regs->rax = (UINT64)STATUS_SUCCESS;
            break;

        case VMCALL_RESTORE_REAL_CR3:
        {
            //
            // Restore real CR3 after a oneshot handler's shadow CR3 window.
            // The loader DllMain runs entirely under shadow CR3 — if it never
            // restores real CR3, the target process leaks its lifetime into
            // shadow CR3 and any kernel TLB flush IPI (e.g. during process exit)
            // hangs the CPU -> CLOCK_WATCHDOG_TIMEOUT (0x101).
            //
            // nx_timer_real_cr3 holds the real CR3 saved by the oneshot handler.
            // If non-zero, swap back to it and clear both restore marks.
            //
            if (vcpu->nx_timer_real_cr3)
            {
                __vmx_vmwrite(VMCS_GUEST_CR3, vcpu->nx_timer_real_cr3);

                // Flush this vCPU's guest TLB for VPID 1 so stale shadow-CR3
                // translations (NX=0 for hidden code) do not persist after we
                // return to the real CR3. Otherwise NX-hidden code would keep
                // executing under the real (NX=1) CR3 -- a stealth leak -- and
                // wrong-PFN shadow entries could corrupt subsequent real-CR3
                // accesses. The loader thread is pinned to this CPU, so a local
                // INVVPID single-context is sufficient.
                INVVPID_DESCRIPTOR iv_desc = {0};
                iv_desc.Vpid = VPID_TAG;
                if (g_ept->invvpid_single_context)
                    asm_invvpid(InvvpidSingleContext, &iv_desc);
                else
                    asm_invvpid(InvvpidAllContexts, &iv_desc);

                vcpu->nx_timer_real_cr3 = 0;
                vcpu->nx_timer_restore  = NULL;
                ept_update_pf_intercept(vcpu);
            }
            regs->rax = (UINT64)STATUS_SUCCESS;
            break;
        }

        case VMCALL_EPT_SET_EXTERNAL_FIRED:
        {
            PVOID target_va = (PVOID)regs->rdx;
            volatile LONG * ext_fired = (volatile LONG *)regs->r8;
            UINT64 caller_cr3 = regs->r9;
            BOOLEAN found = FALSE;

            if (g_ept && target_va && ext_fired)
            {
                PLIST_ENTRY cur = g_ept->hooked_pages.Flink;
                while (cur != &g_ept->hooked_pages)
                {
                    PEPT_HOOKED_PAGE_INFO hp = CONTAINING_RECORD(cur, EPT_HOOKED_PAGE_INFO, hooked_page_list);
                    cur = cur->Flink;
                    if (caller_cr3 && hp->target_cr3 != (caller_cr3 & 0x000FFFFFFFFFF000ULL)) continue;

                    PLIST_ENTRY fc = hp->hooked_functions_list.Flink;
                    while (fc != &hp->hooked_functions_list)
                    {
                        PEPT_HOOKED_FUNCTION_INFO fi = CONTAINING_RECORD(fc, EPT_HOOKED_FUNCTION_INFO, hooked_function_list);
                        fc = fc->Flink;
                        if (fi->virtual_address == target_va)
                        {
                            fi->external_fired = ext_fired;
                            found = TRUE;
                            break;
                        }
                    }
                    if (found)
                        break;
                }
            }

            regs->rax = found ? (UINT64)STATUS_SUCCESS : (UINT64)STATUS_NOT_FOUND;
            break;
        }

        case VMCALL_VMXOFF:
        {
            UINT64 instr_len = 0;
            __vmx_vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH, &instr_len);

            vcpu->vmxoff.guest_rip = vcpu->vmexit_rip + instr_len;
            vcpu->vmxoff.guest_rsp = (UINT64)regs->rsp;

            UINT64 guest_cr3 = 0;
            __vmx_vmread(VMCS_GUEST_CR3, &guest_cr3);
            vcpu->vmxoff.guest_cr3 = guest_cr3;

            vcpu->vmxoff.executed = TRUE;

            __vmx_off();

            __writecr3(guest_cr3);

#if USE_PRIVATE_HOST_IDT
            if (g_host_idt.initialized)
                asm_reload_idtr((PVOID)g_host_idt.original_idt_base, IDT_NUM_ENTRIES * sizeof(IDT_GATE_DESCRIPTOR_64) - 1);
#endif

#if USE_PRIVATE_HOST_GDT
            if (vcpu->host_gdt)
            {
                PSEGMENT_DESCRIPTOR_64 tss_desc = (PSEGMENT_DESCRIPTOR_64)(
                    vcpu->original_gdt_base + (vcpu->original_tr_selector & ~0x7));
                tss_desc->Type = TSS_TYPE_AVAILABLE_64;

                asm_reload_gdtr((PVOID)vcpu->original_gdt_base, (UINT32)vcpu->original_gdt_limit);
                asm_reload_tr(vcpu->original_tr_selector);
            }
#endif

            __writecr4(__readcr4() & ~CR4_VMX_ENABLE_FLAG);

            regs->rax = (UINT64)STATUS_SUCCESS;
            break;
        }

        default:
            regs->rax = (UINT64)STATUS_UNSUCCESSFUL;
            break;
        }
        return;
    }

    //
    // not our VMCALL and not an EPT hook/stealth page (already checked above)
    //
    vmexit_inject_ud();
    vcpu->advance_rip = FALSE;
}

VOID
vmexit_handle_triple_fault(VIRTUAL_MACHINE_STATE * vcpu)
{
    UNREFERENCED_PARAMETER(vcpu);
    vcpu->advance_rip = FALSE;
}

//
// MOV DR pass-through when MOV-DR exiting is forced by must-be-1 bits.
// DR0-DR3, DR6: read/write hardware directly (no VMCS save/load)
// DR7: use VMCS field, __writedr(7) writes host DR7
//
VOID
vmexit_handle_mov_dr(VIRTUAL_MACHINE_STATE * vcpu)
{
    PGUEST_REGS regs = vcpu->regs;
    UINT64      exit_qual = vcpu->exit_qual;

    UINT32 dr_num  = (UINT32)(exit_qual & 7);
    UINT32 dir     = (UINT32)((exit_qual >> 4) & 1);   // 0=to DR, 1=from DR
    UINT32 gpr_idx = (UINT32)((exit_qual >> 8) & 0xF);

    UINT64 * reg_ptr;
    switch (gpr_idx)
    {
    case 0:  reg_ptr = &regs->rax; break;
    case 1:  reg_ptr = &regs->rcx; break;
    case 2:  reg_ptr = &regs->rdx; break;
    case 3:  reg_ptr = &regs->rbx; break;
    case 4:  reg_ptr = &regs->rsp; break;
    case 5:  reg_ptr = &regs->rbp; break;
    case 6:  reg_ptr = &regs->rsi; break;
    case 7:  reg_ptr = &regs->rdi; break;
    case 8:  reg_ptr = &regs->r8;  break;
    case 9:  reg_ptr = &regs->r9;  break;
    case 10: reg_ptr = &regs->r10; break;
    case 11: reg_ptr = &regs->r11; break;
    case 12: reg_ptr = &regs->r12; break;
    case 13: reg_ptr = &regs->r13; break;
    case 14: reg_ptr = &regs->r14; break;
    case 15: reg_ptr = &regs->r15; break;
    default: reg_ptr = &regs->rax; break;
    }

    //
    // DR4/DR5 alias DR6/DR7 when CR4.DE=0, #UD when CR4.DE=1
    //
    if (dr_num == 4 || dr_num == 5)
    {
        UINT64 cr4 = 0;
        __vmx_vmread(VMCS_GUEST_CR4, &cr4);
        if (cr4 & (1ULL << 3))
        {
            vmexit_inject_ud();
            vcpu->advance_rip = FALSE;
            return;
        }
        dr_num = (dr_num == 4) ? 6 : 7;
    }

    if (dir == 0)
    {
        UINT64 val = *reg_ptr;
        switch (dr_num)
        {
        case 0: vcpu->guest_dr0 = val; break;
        case 1: vcpu->guest_dr1 = val; break;
        case 2: vcpu->guest_dr2 = val; break;
        case 3: vcpu->guest_dr3 = val; break;
        case 6: vcpu->guest_dr6 = val; break;
        case 7:
            __vmx_vmwrite(VMCS_GUEST_DR7, val);
            break;
        }
    }
    else
    {
        UINT64 val = 0;
        switch (dr_num)
        {
        case 0: val = vcpu->guest_dr0; break;
        case 1: val = vcpu->guest_dr1; break;
        case 2: val = vcpu->guest_dr2; break;
        case 3: val = vcpu->guest_dr3; break;
        case 6: val = vcpu->guest_dr6; break;
        case 7:
            __vmx_vmread(VMCS_GUEST_DR7, &val);
            break;
        default: break;
        }
        *reg_ptr = val;
    }
}

BOOLEAN
vmexit_handler(_Inout_ PGUEST_REGS regs, _In_ VIRTUAL_MACHINE_STATE * vcpu)
{
    size_t  exit_raw = 0;
    UINT32  exit_reason    = 0;
    BOOLEAN result        = FALSE;

#if STEALTH_COMPENSATE_TIMING
    //
    // capture TSC as early as possible — used by TSC compensation to measure
    // handler overhead. Must be before any other work.
    //
    UINT64 exit_tsc_start = __rdtsc();
#endif

    vcpu->regs        = regs;
    vcpu->in_root     = TRUE;
    vcpu->advance_rip = TRUE;

    vcpu->guest_dr0 = __readdr(0);
    vcpu->guest_dr1 = __readdr(1);
    vcpu->guest_dr2 = __readdr(2);
    vcpu->guest_dr3 = __readdr(3);
    vcpu->guest_dr6 = __readdr(6);
    vcpu->guest_cr8 = (UINT8)__readcr8();

    // __vmx_vmread writes size_t
    __vmx_vmread(VMCS_EXIT_REASON, &exit_raw);
    exit_reason = (UINT32)(exit_raw & 0xFFFF);
    vcpu->exit_reason = exit_reason;

    //
    // lazy per-CPU stealth setup DISABLED for now.
    // stealth only active on the install CPU. shellcode thread must be
    // affinity-pinned to that CPU by the caller.
    //

    //
    // TSC compensation: if RDTSC exiting was armed for compensation and this
    // exit is NOT an RDTSC/RDTSCP, the attack pattern was broken (e.g. an
    // external interrupt fired between CPUID and RDTSC). Disarm and disable
    // RDTSC exiting to avoid trapping unrelated RDTSCs.
    //
#if STEALTH_COMPENSATE_TIMING
    if (vcpu->tsc_rdtsc_armed &&
        exit_reason != VMX_EXIT_REASON_EXECUTE_RDTSC &&
        exit_reason != VMX_EXIT_REASON_EXECUTE_RDTSCP)
    {
        vcpu->tsc_rdtsc_armed = FALSE;

        if (!g_stealth_cpuid_cache.rdtsc_exiting_forced)
        {
            size_t proc_ctrl = 0;
            __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &proc_ctrl);
            proc_ctrl &= ~(size_t)CPU_BASED_VM_EXEC_CTRL_RDTSC_EXITING;
            __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, proc_ctrl);
        }
    }
#endif

    __vmx_vmread(VMCS_GUEST_RIP, &vcpu->vmexit_rip);
    __vmx_vmread(VMCS_GUEST_RSP, &vcpu->regs->rsp);
    __vmx_vmread(VMCS_EXIT_QUALIFICATION, &vcpu->exit_qual);

    switch (exit_reason)
    {
    case VMX_EXIT_REASON_TRIPLE_FAULT:
        vmexit_handle_triple_fault(vcpu);
        break;

    //
    // VMX instructions in guest — inject #UD (bare metal behavior)
    //
    case VMX_EXIT_REASON_EXECUTE_VMCLEAR:
    case VMX_EXIT_REASON_EXECUTE_VMPTRLD:
    case VMX_EXIT_REASON_EXECUTE_VMPTRST:
    case VMX_EXIT_REASON_EXECUTE_VMREAD:
    case VMX_EXIT_REASON_EXECUTE_VMRESUME:
    case VMX_EXIT_REASON_EXECUTE_VMWRITE:
    case VMX_EXIT_REASON_EXECUTE_VMXOFF:
    case VMX_EXIT_REASON_EXECUTE_VMXON:
    case VMX_EXIT_REASON_EXECUTE_VMLAUNCH:
    case VMX_EXIT_REASON_EXECUTE_INVEPT:
    case VMX_EXIT_REASON_EXECUTE_INVVPID:
    case VMX_EXIT_REASON_EXECUTE_GETSEC:
        vmexit_inject_ud();
        vcpu->advance_rip = FALSE;
        break;

    case VMX_EXIT_REASON_EXECUTE_INVD:
        // INVD would discard dirty cache lines — use WBINVD instead
        __wbinvd();
        break;

    case VMX_EXIT_REASON_EXECUTE_INVLPG:
    {
        // flush combined (EPT+guest) TLB mapping for this linear address
        INVVPID_DESCRIPTOR desc = {0};
        desc.Vpid          = VPID_TAG;
        desc.LinearAddress = vcpu->exit_qual;

        if (g_ept->invvpid_individual_addr)
        {
            UINT8 ret = asm_invvpid(InvvpidIndividualAddress, &desc);
            if (ret != 0)
                asm_invvpid(InvvpidAllContexts, &desc);
        }
        else
        {
            asm_invvpid(InvvpidAllContexts, &desc);
        }
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_RDPMC:
    {
        UINT32 counter = (UINT32)(vcpu->regs->rcx & 0xFFFFFFFF);
        if (counter < 8 || (counter >= 0x40000000 && counter < 0x40000010))
        {
            UINT64 val = __readpmc(counter);
            vcpu->regs->rax = val & 0xFFFFFFFF;
            vcpu->regs->rdx = val >> 32;
        }
        else
        {
            vmexit_inject_gp();
            vcpu->advance_rip = FALSE;
        }
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_RDTSC:
    {
        UINT64 tsc = __rdtsc();
        size_t offset_raw = 0;
        __vmx_vmread(VMCS_CTRL_TSC_OFFSET, &offset_raw);

#if STEALTH_COMPENSATE_TIMING
        if (vcpu->tsc_rdtsc_armed)
        {
            //
            // compensated path: return a value as if CPUID took bare-metal time.
            // compensated = cpuid_entry_tsc + bare_metal_cost + tsc_offset
            //
            //   t1 (guest's previous RDTSC) < cpuid_entry_tsc (exit happened after t1)
            //   so compensated > t1 + offset
            //   cpuid_entry_tsc + bare_metal_cost < tsc (real time is always ahead)
            //   so compensated < real TSC  (future native RDTSCs are safe)
            //
            tsc = vcpu->tsc_cpuid_entry
                + g_stealth_cpuid_cache.bare_metal_cpuid_cost
                + (UINT64)(INT64)offset_raw;

            vcpu->tsc_rdtsc_armed = FALSE;

            if (!g_stealth_cpuid_cache.rdtsc_exiting_forced)
            {
                size_t proc_ctrl = 0;
                __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &proc_ctrl);
                proc_ctrl &= ~(size_t)CPU_BASED_VM_EXEC_CTRL_RDTSC_EXITING;
                __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, proc_ctrl);
            }
        }
        else
#endif
        {
            tsc = (UINT64)((INT64)tsc + (INT64)offset_raw);
        }

        vcpu->regs->rax = tsc & 0xFFFFFFFF;
        vcpu->regs->rdx = tsc >> 32;
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_CPUID:
    {
        vmexit_handle_cpuid(vcpu);

#if STEALTH_COMPENSATE_TIMING
        //
        // arm RDTSC exiting for the next instruction. the timing attack
        // pattern is RDTSC -> CPUID -> RDTSC. By trapping the next RDTSC,
        // we can return a compensated value that hides VM-exit overhead.
        // TSC_OFFSET is never modified — zero drift.
        //
        if (g_stealth_enabled)
        {
            vcpu->tsc_cpuid_entry = exit_tsc_start;
            vcpu->tsc_rdtsc_armed = TRUE;

            if (!g_stealth_cpuid_cache.rdtsc_exiting_forced)
            {
                size_t proc_ctrl = 0;
                __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &proc_ctrl);
                proc_ctrl |= (size_t)CPU_BASED_VM_EXEC_CTRL_RDTSC_EXITING;
                __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, proc_ctrl);
            }
        }
#endif
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_RDMSR:
        vmexit_handle_msr_read(vcpu);
        break;

    case VMX_EXIT_REASON_EXECUTE_WRMSR:
        vmexit_handle_msr_write(vcpu);
        break;

    case VMX_EXIT_REASON_MOV_CR:
        vmexit_handle_mov_cr(vcpu);
        break;

    case VMX_EXIT_REASON_MOV_DR:
        vmexit_handle_mov_dr(vcpu);
        break;

    case VMX_EXIT_REASON_EPT_VIOLATION:
        vmexit_handle_ept_violation(vcpu);
        break;

    case VMX_EXIT_REASON_MONITOR_TRAP_FLAG:
        ept_handle_mtf(vcpu);
        vcpu->advance_rip = FALSE;
        break;

    case VMX_EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED:
    {
        // Shadow-CR3 restore no longer uses the VMX preemption timer.
        // If a stale timer exit arrives, just make sure the pin control is off.
        SIZE_T pin = 0;
        __vmx_vmread(VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS, &pin);
        pin &= ~(SIZE_T)PIN_BASED_VM_EXEC_CTRL_VMX_PREEMPTION_TIMER;
        __vmx_vmwrite(VMCS_CTRL_PIN_BASED_VM_EXECUTION_CONTROLS, pin);

        vcpu->advance_rip = FALSE;
        break;
    }

    case VMX_EXIT_REASON_EPT_MISCONFIGURATION:
    {
        //
        // EPT misconfiguration is a host-side fault — the EPT entry has
        // invalid configuration (reserved bits, write-only, etc).
        // the guest didn't cause this and can't handle it.
        // enter shutdown state — system will triple-fault cleanly.
        //
        __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, 0);
        __vmx_vmwrite(VMCS_GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_STATE_SHUTDOWN);
        vcpu->advance_rip = FALSE;
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_VMCALL:
        vmexit_handle_vmcall(vcpu);
        break;

    case VMX_EXIT_REASON_EXECUTE_XSETBV:
    {
        //
        // XSETBV — stealth: proper validation per Intel SDM
        //
        // Defeats:
        //   - XSETBV with high bits in ECX should #GP
        //   - XSETBV with valid ECX should NOT fault
        //   - XSETBV with invalid XCR0 value should #GP
        //
        UINT64 rcx_val   = vcpu->regs->rcx;
        UINT64 value  = (vcpu->regs->rdx << 32) | (vcpu->regs->rax & 0xFFFFFFFF);

        if (rcx_val & 0xFFFFFFFF00000000ULL)
        {
            vmexit_inject_gp();
            vcpu->advance_rip = FALSE;
            break;
        }

        //
        // check 2: only XCR0 (index 0) is valid
        //
        if ((UINT32)rcx_val != 0)
        {
            vmexit_inject_gp();
            vcpu->advance_rip = FALSE;
            break;
        }

        if (!stealth_is_xcr0_valid(value))
        {
            vmexit_inject_gp();
            vcpu->advance_rip = FALSE;
            break;
        }

        _xsetbv(0, value);
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_HLT:
        __vmx_vmwrite(VMCS_GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_STATE_HLT);
        break;

    case VMX_EXIT_REASON_EXTERNAL_INTERRUPT:
    {
        //
        // with ack-interrupt-on-exit, the CPU stores the acknowledged
        // vector in VMCS exit info. re-inject or defer if guest can't
        // accept it (IF=0, STI/MOV-SS blocking, or CR8 priority masking).
        //
        size_t int_info_raw = 0;
        __vmx_vmread(VMCS_VMEXIT_INTERRUPTION_INFORMATION, &int_info_raw);

        VMENTRY_INTERRUPT_INFORMATION int_info;
        int_info.AsUInt = (UINT32)int_info_raw;

        if (int_info.Valid)
        {
            UINT32 vector = int_info.Vector;

            size_t rflags_raw = 0;
            size_t intr_state = 0;
            __vmx_vmread(VMCS_GUEST_RFLAGS, &rflags_raw);
            __vmx_vmread(VMCS_GUEST_INTERRUPTIBILITY_STATE, &intr_state);

            BOOLEAN guest_interruptible =
                (rflags_raw & (1ULL << 9)) &&
                !(intr_state & (GUEST_INTR_STATE_BLOCKING_BY_STI |
                                GUEST_INTR_STATE_BLOCKING_BY_MOV_SS));

            if (guest_interruptible)
            {
                UINT8 vector_priority = (UINT8)(vector >> 4);
                if (vector_priority <= vcpu->guest_cr8)
                    guest_interruptible = FALSE;
            }

            if (guest_interruptible)
            {
                vmexit_inject_interrupt(vector);
            }
            else
            {
                //
                // guest can't take it now — defer and enable
                // interrupt-window exiting to inject later
                //
                vcpu->pending_ext_vector = (UINT8)vector;
                vcpu->has_pending_ext_interrupt = TRUE;

                size_t proc_ctrl = 0;
                __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &proc_ctrl);
                proc_ctrl |= (size_t)CPU_BASED_VM_EXEC_CTRL_INTERRUPT_WINDOW_EXITING;
                __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, proc_ctrl);
            }
        }

        vcpu->advance_rip = FALSE;
        break;
    }

    case VMX_EXIT_REASON_EXCEPTION_OR_NMI:
    {
        size_t int_info_raw = 0;
        __vmx_vmread(VMCS_VMEXIT_INTERRUPTION_INFORMATION, &int_info_raw);

        VMENTRY_INTERRUPT_INFORMATION int_info;
        int_info.AsUInt = (UINT32)int_info_raw;

        if (int_info.Valid)
        {
            //
            // stealth: intercept instruction-fetch #PF (NX violation)
            //
            // when a stealth page is executed, the CPU page walker reads the
            // fake PT page (NX=1) and generates #PF with error code bit 4 set.
            // we handle this by temporarily swapping EPTs so the CPU can execute.
            //
            if (int_info.Vector == EXCEPTION_VECTOR_PAGE_FAULT &&
                int_info.InterruptionType == INTERRUPT_TYPE_HARDWARE_EXCEPTION)
            {
                size_t pf_error_code = 0;
                __vmx_vmread(VMCS_VMEXIT_INTERRUPTION_ERROR_CODE, &pf_error_code);
                // bit 4 = instruction fetch (I/D flag), bit 1 = write access.
                // Keep this gate aligned with the known-good 01bc1de path:
                // ept_stealth_handle_pf() does the precise page/CR3/PID filtering.
                //
                // also route to the stealth handler whenever a shadow-CR3 window is
                // open on this vCPU: the shadow swap widens the #PF intercept to "all"
                // for the one-instruction window, so a data #PF (incl. a read or a
                // not-present read - which has neither fetch nor write set) also VM-exits
                // and must reach the handler's mid-window guard to be serviced under the
                // REAL CR3. without this, such a #PF would be re-injected under the
                // shadow CR3 and MmAccessFault would run on the stale shadow PT (0x1A).
                if ((pf_error_code & (0x10 | 0x02)) || vcpu->nx_timer_real_cr3)
                {
                    UINT64 fault_addr = vcpu->exit_qual;

                    if (ept_stealth_handle_pf(vcpu, fault_addr, (UINT32)pf_error_code))
                    {
                        //
                        // handled — don't inject #PF, don't advance RIP.
                        // CPU will retry the instruction after VMRESUME.
                        // page walk will now read real PT page (NX=0) → execute succeeds.
                        //
                        vcpu->advance_rip = FALSE;
                        break;
                    }

                    // check inject hooks with fake PT (EPT hook pages with NX hiding)
                    if ((pf_error_code & 0x10) &&
                        ept_hook_handle_pf(vcpu, fault_addr, (UINT32)pf_error_code))
                    {
                        vcpu->advance_rip = FALSE;
                        break;
                    }
                }

                //
                // not our stealth page — fall through to re-inject #PF normally.
                // must set CR2 to the fault address before re-injection.
                //
                asm_write_cr2(vcpu->exit_qual);
            }

            if (int_info.InterruptionType == INTERRUPT_TYPE_NMI)
            {
                //
                // with virtual NMIs, the NMI exit sets blocking-by-NMI.
                // clear it before reinjecting — the NMI was intercepted
                // before guest delivery, and VM-entry re-sets blocking
                // when it delivers the injected NMI (SDM 26.6.1.2).
                //
                size_t intr_state = 0;
                __vmx_vmread(VMCS_GUEST_INTERRUPTIBILITY_STATE, &intr_state);
                intr_state &= ~(size_t)GUEST_INTR_STATE_BLOCKING_BY_NMI;
                __vmx_vmwrite(VMCS_GUEST_INTERRUPTIBILITY_STATE, intr_state);
            }

            __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, int_info.AsUInt);

            if (int_info.DeliverErrorCode)
            {
                size_t error_code = 0;
                __vmx_vmread(VMCS_VMEXIT_INTERRUPTION_ERROR_CODE, &error_code);
                __vmx_vmwrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE, error_code);
            }

            if (int_info.InterruptionType == INTERRUPT_TYPE_SOFTWARE_EXCEPTION)
            {
                size_t instr_len = 0;
                __vmx_vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH, &instr_len);
                __vmx_vmwrite(VMCS_CTRL_VMENTRY_INSTRUCTION_LENGTH, instr_len);
            }
        }

        vcpu->advance_rip = FALSE;
        break;
    }

    case VMX_EXIT_REASON_INTERRUPT_WINDOW:
    {
        if (vcpu->has_pending_ext_interrupt)
        {
            UINT8 vector_priority = (UINT8)(vcpu->pending_ext_vector >> 4);

            if (vector_priority > vcpu->guest_cr8)
            {
                size_t proc_ctrl = 0;
                __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &proc_ctrl);
                proc_ctrl &= ~(size_t)CPU_BASED_VM_EXEC_CTRL_INTERRUPT_WINDOW_EXITING;
                __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, proc_ctrl);

                vmexit_inject_interrupt(vcpu->pending_ext_vector);
                vcpu->has_pending_ext_interrupt = FALSE;
            }
        }
        else
        {
            size_t proc_ctrl = 0;
            __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &proc_ctrl);
            proc_ctrl &= ~(size_t)CPU_BASED_VM_EXEC_CTRL_INTERRUPT_WINDOW_EXITING;
            __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, proc_ctrl);
        }

        vcpu->advance_rip = FALSE;
        break;
    }

    case VMX_EXIT_REASON_NMI_WINDOW:
    {
        size_t proc_ctrl = 0;
        __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &proc_ctrl);
        proc_ctrl &= ~(size_t)CPU_BASED_VM_EXEC_CTRL_NMI_WINDOW_EXITING;
        __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, proc_ctrl);

        if (vcpu->has_pending_nmi)
        {
            VMENTRY_INTERRUPT_INFORMATION nmi_info = {0};
            nmi_info.Vector           = EXCEPTION_VECTOR_NMI;
            nmi_info.InterruptionType = INTERRUPT_TYPE_NMI;
            nmi_info.Valid            = 1;
            __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, nmi_info.AsUInt);
            vcpu->has_pending_nmi = FALSE;
        }

        vcpu->advance_rip = FALSE;
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_MWAIT:
        break;

    case VMX_EXIT_REASON_EXECUTE_MONITOR:
        break;

    case VMX_EXIT_REASON_EXECUTE_PAUSE:
        break;

    case VMX_EXIT_REASON_EXECUTE_RDTSCP:
    {
        unsigned int aux = 0;
        UINT64 tsc = __rdtscp(&aux);
        size_t offset_raw = 0;
        __vmx_vmread(VMCS_CTRL_TSC_OFFSET, &offset_raw);

#if STEALTH_COMPENSATE_TIMING
        if (vcpu->tsc_rdtsc_armed)
        {
            tsc = vcpu->tsc_cpuid_entry
                + g_stealth_cpuid_cache.bare_metal_cpuid_cost
                + (UINT64)(INT64)offset_raw;

            vcpu->tsc_rdtsc_armed = FALSE;

            if (!g_stealth_cpuid_cache.rdtsc_exiting_forced)
            {
                size_t proc_ctrl = 0;
                __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &proc_ctrl);
                proc_ctrl &= ~(size_t)CPU_BASED_VM_EXEC_CTRL_RDTSC_EXITING;
                __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, proc_ctrl);
            }
        }
        else
#endif
        {
            tsc = (UINT64)((INT64)tsc + (INT64)offset_raw);
        }

        vcpu->regs->rax = tsc & 0xFFFFFFFF;
        vcpu->regs->rdx = tsc >> 32;
        vcpu->regs->rcx = (UINT64)aux;
        break;
    }

    case VMX_EXIT_REASON_EXECUTE_WBINVD:
        __wbinvd();
        break;

    default:
        break;
    }

    //
    // re-inject IDT vectoring event if one was in progress during this VM-exit.
    // skip when vmxoff has been executed — vmread would #UD outside VMX.
    //
    if (!vcpu->vmxoff.executed)
    {
        size_t idt_vec_raw = 0;
        __vmx_vmread(VMCS_IDT_VECTORING_INFORMATION, &idt_vec_raw);

        VMENTRY_INTERRUPT_INFORMATION idt_vec;
        idt_vec.AsUInt = (UINT32)idt_vec_raw;

        if (idt_vec.Valid)
        {
            BOOLEAN reinject_idt = TRUE;

            //
            // exception combining (SDM Vol 3 Table 6-5):
            // when a hardware exception occurs during delivery of another
            // hardware exception, certain combinations produce #DF or
            // triple fault instead of serial delivery.
            //
            if (exit_reason == VMX_EXIT_REASON_EXCEPTION_OR_NMI)
            {
                size_t exit_int_raw = 0;
                __vmx_vmread(VMCS_VMEXIT_INTERRUPTION_INFORMATION, &exit_int_raw);

                VMENTRY_INTERRUPT_INFORMATION exit_int;
                exit_int.AsUInt = (UINT32)exit_int_raw;

                if (exit_int.Valid &&
                    idt_vec.InterruptionType == INTERRUPT_TYPE_HARDWARE_EXCEPTION &&
                    exit_int.InterruptionType == INTERRUPT_TYPE_HARDWARE_EXCEPTION)
                {
                    if (classify_exception(idt_vec.Vector) == EXCEPTION_CLASS_DOUBLE_FAULT)
                    {
                        // #DF + any exception = triple fault
                        __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, 0);
                        __vmx_vmwrite(VMCS_GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_STATE_SHUTDOWN);
                        reinject_idt = FALSE;
                    }
                    else if (should_generate_df(idt_vec.Vector, exit_int.Vector))
                    {
                        // contributory+contributory, PF+contributory, PF+PF → #DF
                        vmexit_inject_df();
                        reinject_idt = FALSE;
                    }
                    // else: benign combination — reinject IDT event,
                    // exit exception regenerates during delivery
                }
            }

            if (reinject_idt)
            {
                // if the handler already queued an NMI injection, defer it —
                // IDT vectoring event takes priority
                size_t entry_info_raw = 0;
                __vmx_vmread(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, &entry_info_raw);

                VMENTRY_INTERRUPT_INFORMATION entry_info;
                entry_info.AsUInt = (UINT32)entry_info_raw;

                if (entry_info.Valid && entry_info.InterruptionType == INTERRUPT_TYPE_NMI)
                {
                    vcpu->has_pending_nmi = TRUE;

                    size_t proc_ctrl = 0;
                    __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &proc_ctrl);
                    proc_ctrl |= (size_t)CPU_BASED_VM_EXEC_CTRL_NMI_WINDOW_EXITING;
                    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, proc_ctrl);
                }

                __vmx_vmwrite(VMCS_CTRL_VMENTRY_INTERRUPTION_INFORMATION_FIELD, idt_vec.AsUInt);

                if (idt_vec.DeliverErrorCode)
                {
                    size_t idt_err = 0;
                    __vmx_vmread(VMCS_IDT_VECTORING_ERROR_CODE, &idt_err);
                    __vmx_vmwrite(VMCS_CTRL_VMENTRY_EXCEPTION_ERROR_CODE, idt_err);
                }

                if (idt_vec.InterruptionType == INTERRUPT_TYPE_SOFTWARE_EXCEPTION ||
                    idt_vec.InterruptionType == INTERRUPT_TYPE_SOFTWARE_INTERRUPT)
                {
                    size_t instr_len = 0;
                    __vmx_vmread(VMCS_VMEXIT_INSTRUCTION_LENGTH, &instr_len);
                    __vmx_vmwrite(VMCS_CTRL_VMENTRY_INSTRUCTION_LENGTH, instr_len);
                }
            }

            vcpu->advance_rip = FALSE;
        }
    }

    // check for NMI that fired while in host mode (via private host IDT)
#if USE_PRIVATE_HOST_IDT
    if (!vcpu->vmxoff.executed && _InterlockedExchange(&g_host_nmi_pending[vcpu->core_id], 0))
    {
        if (!vcpu->has_pending_nmi)
        {
            vcpu->has_pending_nmi = TRUE;
            size_t proc_ctrl = 0;
            __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &proc_ctrl);
            proc_ctrl |= (size_t)CPU_BASED_VM_EXEC_CTRL_NMI_WINDOW_EXITING;
            __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, proc_ctrl);
        }
    }
#endif

    if (!vcpu->vmxoff.executed && vcpu->advance_rip)
    {
        vmexit_advance_rip(vcpu);
    }

    if (!vcpu->vmxoff.executed)
    {
        __writedr(0, vcpu->guest_dr0);
        __writedr(1, vcpu->guest_dr1);
        __writedr(2, vcpu->guest_dr2);
        __writedr(3, vcpu->guest_dr3);
        __writedr(6, vcpu->guest_dr6);
        __writecr8(vcpu->guest_cr8);
    }

    if (vcpu->vmxoff.executed)
        result = TRUE;

    vcpu->in_root = FALSE;
    return result;
}

#include "hv.h"
#include "log.h"

typedef struct _HV_BP_HIT_LOCAL {
    UINT64 id;
    UINT8  access;
    UINT8  flags;
    UINT64 hit_count;
} HV_BP_HIT_LOCAL;

static BOOLEAN
ept_breakpoint_conflicts_locked(UINT64 target_pfn)
{
    PLIST_ENTRY item = g_ept->hooked_pages.Flink;
    while (item != &g_ept->hooked_pages)
    {
        PEPT_HOOKED_PAGE_INFO page =
            CONTAINING_RECORD(item, EPT_HOOKED_PAGE_INFO, hooked_page_list);
        if (page->pfn_of_hooked_page == target_pfn ||
            page->pfn_of_fake_page_contents == target_pfn)
            return TRUE;
        item = item->Flink;
    }

    item = g_ept->stealth_pages.Flink;
    while (item != &g_ept->stealth_pages)
    {
        PEPT_STEALTH_PAGE_INFO page =
            CONTAINING_RECORD(item, EPT_STEALTH_PAGE_INFO, stealth_page_list);
        if (page->pfn_of_target == target_pfn || page->pfn_of_shadow == target_pfn)
            return TRUE;
        item = item->Flink;
    }
    return FALSE;
}

static PEPT_MEMORY_BREAKPOINT
ept_breakpoint_find_locked(UINT64 id)
{
    for (UINT32 i = 0; i < HV_MAX_MEMORY_BREAKPOINTS; ++i)
    {
        PEPT_MEMORY_BREAKPOINT bp = &g_ept->memory_breakpoints[i];
        if (bp->allocated && bp->id == id)
            return bp;
    }
    return NULL;
}

BOOLEAN
ept_breakpoint_page_reserved(UINT64 target_pfn)
{
    BOOLEAN reserved = FALSE;
    ept_lists_lock_acquire();
    for (UINT32 i = 0; i < HV_MAX_MEMORY_BREAKPOINTS; ++i)
    {
        PEPT_MEMORY_BREAKPOINT bp = &g_ept->memory_breakpoints[i];
        if (bp->allocated && bp->target_pfn == target_pfn)
        {
            reserved = TRUE;
            break;
        }
    }
    ept_lists_lock_release();
    return reserved;
}

static BOOLEAN
ept_breakpoint_apply_page(VIRTUAL_MACHINE_STATE * vcpu, UINT64 target_pfn)
{
    BOOLEAN known_page = FALSE;
    BOOLEAN trap_read = FALSE;
    BOOLEAN trap_write = FALSE;
    BOOLEAN trap_execute = FALSE;

    ept_lists_lock_acquire();
    for (UINT32 i = 0; i < HV_MAX_MEMORY_BREAKPOINTS; ++i)
    {
        PEPT_MEMORY_BREAKPOINT bp = &g_ept->memory_breakpoints[i];
        if (!bp->allocated || bp->target_pfn != target_pfn)
            continue;

        known_page = TRUE;
        if (!bp->active)
            continue;
        trap_read |= (bp->access & HV_BP_ACCESS_READ) != 0;
        trap_write |= (bp->access & HV_BP_ACCESS_WRITE) != 0;
        trap_execute |= (bp->access & HV_BP_ACCESS_EXECUTE) != 0;
    }
    ept_lists_lock_release();

    if (!known_page)
        return FALSE;

    UINT64 physical_address = target_pfn << 12;
    PEPT_PML1_ENTRY pte = ept_get_pml1(vcpu->ept_page_table, (SIZE_T)physical_address);
    if (!pte)
    {
        if (!ept_split_large_page_pool(vcpu->ept_page_table, (SIZE_T)physical_address))
            return FALSE;
        pte = ept_get_pml1(vcpu->ept_page_table, (SIZE_T)physical_address);
        if (!pte)
            return FALSE;
    }

    // Intel EPT does not permit a write-only entry. A read breakpoint therefore
    // clears both R and W; write exits on the same page are filtered and passed
    // through for one instruction below.
    pte->ReadAccess = trap_read ? 0 : 1;
    pte->WriteAccess = (trap_read || trap_write) ? 0 : 1;
    pte->ExecuteAccess = trap_execute ? 0 : 1;
    _mm_mfence();
    ept_invept_single(vcpu->ept_pointer);
    return TRUE;
}

static BOOLEAN
ept_breakpoint_page_has_active(UINT64 target_pfn)
{
    BOOLEAN active = FALSE;
    ept_lists_lock_acquire();
    for (UINT32 i = 0; i < HV_MAX_MEMORY_BREAKPOINTS; ++i)
    {
        PEPT_MEMORY_BREAKPOINT bp = &g_ept->memory_breakpoints[i];
        if (bp->allocated && bp->active && bp->target_pfn == target_pfn)
        {
            active = TRUE;
            break;
        }
    }
    ept_lists_lock_release();
    return active;
}

static VOID
ept_breakpoint_allow_one_instruction(VIRTUAL_MACHINE_STATE * vcpu, UINT64 target_pfn)
{
    PEPT_PML1_ENTRY pte = ept_get_pml1(
        vcpu->ept_page_table, (SIZE_T)(target_pfn << 12));
    if (!pte)
        return;

    pte->ReadAccess = 1;
    pte->WriteAccess = 1;
    pte->ExecuteAccess = 1;
    _mm_mfence();
    ept_invept_single(vcpu->ept_pointer);

    LONG depth = vcpu->mtf_breakpoint_pfn_depth;
    BOOLEAN already_pending = FALSE;
    for (LONG i = 0; i < depth && i < 4; ++i)
        already_pending |= vcpu->mtf_breakpoint_pfn_stack[i] == target_pfn;

    if (!already_pending)
    {
        if (depth < 4)
        {
            vcpu->mtf_breakpoint_pfn_stack[depth] = target_pfn;
            vcpu->mtf_breakpoint_pfn_depth = depth + 1;
        }
        else
        {
            vcpu->mtf_breakpoint_pfn_stack[3] = target_pfn;
        }
    }

    SIZE_T controls = 0;
    __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &controls);
    controls |= (SIZE_T)CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG;
    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, controls);
}

static VOID
ept_breakpoint_log_hit(
    VIRTUAL_MACHINE_STATE * vcpu,
    const HV_BP_HIT_LOCAL * hit,
    UINT64 guest_linear,
    UINT64 guest_physical,
    UINT64 guest_cr3)
{
    UINT64 rflags = 0;
    UINT64 stack[16] = {};
    __vmx_vmread(VMCS_GUEST_RFLAGS, &rflags);

    const BOOLEAN stack_ok = hv_read_guest_virtual(
        vcpu, guest_cr3, vcpu->regs->rsp, stack, sizeof(stack));

    HYPERPLATFORM_LOG_WARN_SAFE(
        "[ept-bp] id=%llu hit=%llu access=%c%c%c mode=%s cpu=%lu gla=%llX gpa=%llX cr3=%llX",
        hit->id, hit->hit_count,
        (hit->access & HV_BP_ACCESS_READ) ? 'R' : '-',
        (hit->access & HV_BP_ACCESS_WRITE) ? 'W' : '-',
        (hit->access & HV_BP_ACCESS_EXECUTE) ? 'X' : '-',
        (hit->flags & HV_BP_FLAG_ONESHOT) ? "once" : "permanent",
        KeGetCurrentProcessorNumberEx(NULL), guest_linear, guest_physical, guest_cr3);
    HYPERPLATFORM_LOG_WARN_SAFE(
        "[ept-bp] RIP=%llX RSP=%llX RFLAGS=%llX RAX=%llX RBX=%llX RCX=%llX RDX=%llX",
        vcpu->vmexit_rip, vcpu->regs->rsp, rflags, vcpu->regs->rax,
        vcpu->regs->rbx, vcpu->regs->rcx, vcpu->regs->rdx);
    HYPERPLATFORM_LOG_WARN_SAFE(
        "[ept-bp] RSI=%llX RDI=%llX RBP=%llX R8=%llX R9=%llX R10=%llX R11=%llX",
        vcpu->regs->rsi, vcpu->regs->rdi, vcpu->regs->rbp,
        vcpu->regs->r8, vcpu->regs->r9, vcpu->regs->r10, vcpu->regs->r11);
    HYPERPLATFORM_LOG_WARN_SAFE(
        "[ept-bp] R12=%llX R13=%llX R14=%llX R15=%llX stack=%s",
        vcpu->regs->r12, vcpu->regs->r13, vcpu->regs->r14, vcpu->regs->r15,
        stack_ok ? "ok" : "unmapped");

    if (stack_ok)
    {
        for (UINT32 i = 0; i < RTL_NUMBER_OF(stack); i += 4)
        {
            HYPERPLATFORM_LOG_WARN_SAFE(
                "[ept-bp] STACK+%02X: %llX %llX %llX %llX",
                i * 8, stack[i], stack[i + 1], stack[i + 2], stack[i + 3]);
        }
    }
}

BOOLEAN
ept_breakpoint_configure(
    VIRTUAL_MACHINE_STATE * vcpu,
    UINT64 id,
    UINT64 target_cr3,
    UINT64 target_pid,
    UINT64 target_va,
    UINT64 target_phys,
    UINT32 size,
    UINT8 access,
    UINT8 flags,
    BOOLEAN create_record)
{
    if (!vcpu || !id || !target_pid || !target_va || !target_phys || size == 0 ||
        size > PAGE_SIZE || (access & ~0x07) != 0 || access == 0 ||
        ((target_va & 0xFFF) + size) > PAGE_SIZE ||
        ((target_phys & 0xFFF) != (target_va & 0xFFF)))
        return FALSE;

    UINT64 target_pfn = target_phys >> 12;

    if (create_record)
    {
        ept_lists_lock_acquire();
        if (ept_breakpoint_find_locked(id) ||
            ept_breakpoint_conflicts_locked(target_pfn))
        {
            ept_lists_lock_release();
            return FALSE;
        }

        PEPT_MEMORY_BREAKPOINT slot = NULL;
        for (UINT32 i = 0; i < HV_MAX_MEMORY_BREAKPOINTS; ++i)
        {
            if (!g_ept->memory_breakpoints[i].allocated)
            {
                slot = &g_ept->memory_breakpoints[i];
                break;
            }
        }
        if (!slot)
        {
            ept_lists_lock_release();
            return FALSE;
        }

        RtlZeroMemory(slot, sizeof(*slot));
        slot->id = id;
        slot->target_cr3 = target_cr3 & CR3_ADDR_MASK;
        slot->target_pid = target_pid;
        slot->target_va = target_va;
        slot->target_pfn = target_pfn;
        slot->page_offset = (UINT32)(target_va & 0xFFF);
        slot->size = size;
        slot->access = access;
        slot->flags = flags & HV_BP_FLAG_ONESHOT;
        _mm_mfence();
        InterlockedExchange(&slot->active, 1);
        InterlockedExchange(&slot->allocated, 1);
        ept_lists_lock_release();
    }
    else
    {
        ept_lists_lock_acquire();
        PEPT_MEMORY_BREAKPOINT bp = ept_breakpoint_find_locked(id);
        BOOLEAN valid = bp && bp->active && bp->target_pfn == target_pfn;
        ept_lists_lock_release();
        if (!valid)
            return FALSE;
    }

    if (!ept_breakpoint_apply_page(vcpu, target_pfn))
    {
        if (create_record)
        {
            ept_lists_lock_acquire();
            PEPT_MEMORY_BREAKPOINT bp = ept_breakpoint_find_locked(id);
            if (bp)
                InterlockedExchange(&bp->active, 0);
            ept_lists_lock_release();
        }
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
ept_breakpoint_clear(
    VIRTUAL_MACHINE_STATE * vcpu,
    UINT64 id,
    UINT8 record_operation)
{
    if (!vcpu || !id || record_operation > 2)
        return FALSE;

    UINT64 target_pfn = 0;
    ept_lists_lock_acquire();
    PEPT_MEMORY_BREAKPOINT bp = ept_breakpoint_find_locked(id);
    if (bp)
    {
        target_pfn = bp->target_pfn;
        if (record_operation == 1)
            InterlockedExchange(&bp->active, 0);
        else if (record_operation == 2)
        {
            if (bp->active)
            {
                ept_lists_lock_release();
                return FALSE;
            }
            _mm_mfence();
            InterlockedExchange(&bp->allocated, 0);
        }
    }
    ept_lists_lock_release();

    if (!bp)
        return FALSE;
    if (record_operation == 2)
        return TRUE;
    return ept_breakpoint_apply_page(vcpu, target_pfn);
}

BOOLEAN
ept_breakpoint_handle_violation(
    VIRTUAL_MACHINE_STATE * vcpu,
    UINT64 guest_phys,
    UINT64 exit_qual)
{
    VMX_EXIT_QUALIFICATION_EPT_VIOLATION violation = {};
    violation.AsUInt = exit_qual;
    const UINT64 target_pfn = guest_phys >> 12;
    UINT8 access = 0;
    if (violation.ReadAccess) access |= HV_BP_ACCESS_READ;
    if (violation.WriteAccess) access |= HV_BP_ACCESS_WRITE;
    if (violation.ExecuteAccess) access |= HV_BP_ACCESS_EXECUTE;

    UINT64 guest_linear = 0;
    if (violation.ValidGuestLinearAddress)
        __vmx_vmread(VMCS_GUEST_LINEAR_ADDRESS, &guest_linear);

    UINT64 guest_cr3 = vcpu->cached_guest_cr3 & CR3_ADDR_MASK;
    UINT64 guest_pid = (UINT64)(ULONG_PTR)PsGetCurrentProcessId();
    HV_BP_HIT_LOCAL hits[8] = {};
    UINT32 hit_count = 0;
    BOOLEAN known_page = FALSE;

    ept_lists_lock_acquire();
    for (UINT32 i = 0; i < HV_MAX_MEMORY_BREAKPOINTS; ++i)
    {
        PEPT_MEMORY_BREAKPOINT bp = &g_ept->memory_breakpoints[i];
        if (!bp->allocated || bp->target_pfn != target_pfn)
            continue;

        known_page = TRUE;
        if (!bp->active || !(bp->access & access))
            continue;
        if (bp->target_cr3 && bp->target_cr3 != guest_cr3 &&
            bp->target_pid != guest_pid)
            continue;
        if (!violation.ValidGuestLinearAddress ||
            guest_linear < bp->target_va ||
            guest_linear >= bp->target_va + bp->size)
            continue;

        LONG64 count = InterlockedIncrement64(&bp->hit_count);
        if (hit_count < RTL_NUMBER_OF(hits))
        {
            hits[hit_count].id = bp->id;
            hits[hit_count].access = access;
            hits[hit_count].flags = bp->flags;
            hits[hit_count].hit_count = (UINT64)count;
            ++hit_count;
        }
        if (bp->flags & HV_BP_FLAG_ONESHOT)
            InterlockedExchange(&bp->active, 0);
    }
    ept_lists_lock_release();

    if (!known_page)
        return FALSE;

    for (UINT32 i = 0; i < hit_count; ++i)
        ept_breakpoint_log_hit(
            vcpu, &hits[i], guest_linear, guest_phys, guest_cr3);

    if (ept_breakpoint_page_has_active(target_pfn))
        ept_breakpoint_allow_one_instruction(vcpu, target_pfn);
    else
        ept_breakpoint_apply_page(vcpu, target_pfn);

    return TRUE;
}

VOID
ept_breakpoint_handle_mtf(VIRTUAL_MACHINE_STATE * vcpu)
{
    LONG depth = vcpu->mtf_breakpoint_pfn_depth;
    while (depth > 0)
    {
        UINT64 target_pfn = vcpu->mtf_breakpoint_pfn_stack[depth - 1];
        vcpu->mtf_breakpoint_pfn_stack[depth - 1] = 0;
        --depth;
        vcpu->mtf_breakpoint_pfn_depth = depth;
        ept_breakpoint_apply_page(vcpu, target_pfn);
    }
}

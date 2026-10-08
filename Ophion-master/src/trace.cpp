#include "hv.h"

static PHV_TRACE_SESSION
hv_trace_find(UINT64 session_id)
{
    if (!g_ept || !session_id)
        return NULL;

    for (UINT32 i = 0; i < HV_MAX_TRACE_SESSIONS; ++i)
    {
        PHV_TRACE_SESSION session = &g_ept->trace_sessions[i];
        if (session->allocated && session->id == session_id)
            return session;
    }
    return NULL;
}

static VOID
hv_trace_disable_private_dr(VIRTUAL_MACHINE_STATE * vcpu);

static VOID
hv_trace_complete(PHV_TRACE_SESSION session, UINT32 stop_reason)
{
    if (!session)
        return;

    InterlockedCompareExchange(&session->stop_reason,
        stop_reason, OPHION_TRACE_STOP_NONE);
    InterlockedExchange(&session->state, OPHION_TRACE_STATE_COMPLETE);
    InterlockedExchange(&session->active, 0);
    if (session->backend == OPHION_TRACE_BACKEND_EPT)
        ept_breakpoint_deactivate_trace_session(session->id);
}

static BOOLEAN
hv_trace_matches_context(
    PHV_TRACE_SESSION session,
    VIRTUAL_MACHINE_STATE * vcpu)
{
    const UINT64 guest_cr3 = vcpu->cached_guest_cr3 & CR3_ADDR_MASK;
    const UINT64 guest_pid = (UINT64)(ULONG_PTR)PsGetCurrentProcessId();

    if (session->scope == OPHION_TRACE_SCOPE_KERNEL)
        return vcpu->vmexit_rip >= session->start_address &&
               vcpu->vmexit_rip < session->end_address;

    if (session->target_cr3 && session->target_cr3 != guest_cr3 &&
        session->target_pid != guest_pid)
        return FALSE;

    return TRUE;
}

static VOID
hv_trace_arm_mtf(VOID)
{
    SIZE_T controls = 0;
    __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &controls);
    controls |= (SIZE_T)CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG;
    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, controls);
}

static UINT64
hv_trace_guest_dr_value(VIRTUAL_MACHINE_STATE * vcpu, UINT8 index)
{
    switch (index)
    {
    case 0: return vcpu->guest_dr0;
    case 1: return vcpu->guest_dr1;
    case 2: return vcpu->guest_dr2;
    case 3: return vcpu->guest_dr3;
    default: return 0;
    }
}

static VOID
hv_trace_write_dr(UINT8 index, UINT64 value)
{
    switch (index)
    {
    case 0: __writedr(0, value); break;
    case 1: __writedr(1, value); break;
    case 2: __writedr(2, value); break;
    case 3: __writedr(3, value); break;
    default: break;
    }
}

VOID
hv_trace_prepare_guest_debug_state(VIRTUAL_MACHINE_STATE * vcpu)
{
    if (!vcpu->trace_private_dr_active)
        return;

    PHV_TRACE_SESSION session = hv_trace_find(vcpu->trace_session_id);
    if (!session || !session->active)
    {
        hv_trace_disable_private_dr(vcpu);
        return;
    }

    UINT8 index = vcpu->trace_private_dr_index;
    const UINT64 current_enable_mask =
        (DR7_L0 | DR7_G0) << (index * 2);
    if (vcpu->guest_dr7_shadow & current_enable_mask)
    {
        UINT8 replacement = 0xFF;
        for (UINT8 candidate = 0; candidate < 4; ++candidate)
        {
            const UINT64 candidate_mask =
                (DR7_L0 | DR7_G0) << (candidate * 2);
            if (!(vcpu->guest_dr7_shadow & candidate_mask))
            {
                replacement = candidate;
                break;
            }
        }

        if (replacement == 0xFF)
        {
            hv_trace_complete(session, OPHION_TRACE_STOP_HWBP_CONFLICT);
            hv_trace_disable_private_dr(vcpu);
            return;
        }

        // Restore the guest value in the old physical slot before moving the
        // private execution breakpoint. MOV-DR reads continue to use shadows.
        hv_trace_write_dr(index, hv_trace_guest_dr_value(vcpu, index));
        vcpu->trace_private_dr_index = replacement;
        index = replacement;
    }

    __writedr(0, vcpu->guest_dr0);
    __writedr(1, vcpu->guest_dr1);
    __writedr(2, vcpu->guest_dr2);
    __writedr(3, vcpu->guest_dr3);
    __writedr(6, vcpu->guest_dr6);

    UINT64 effective_dr7 = vcpu->guest_dr7_shadow;
    const UINT64 enable_mask = (DR7_L0 | DR7_G0) << (index * 2);
    const UINT64 condition_mask = 0xFULL << DR7_RW_SHIFT(index);

    effective_dr7 &= ~enable_mask;
    effective_dr7 &= ~condition_mask;
    if (vcpu->trace_private_dr_armed)
    {
        hv_trace_write_dr(index, vcpu->trace_private_dr_address);
        effective_dr7 |= (DR7_L0 << (index * 2));
    }
    __vmx_vmwrite(VMCS_GUEST_DR7, effective_dr7);
}

static VOID
hv_trace_disable_private_dr(VIRTUAL_MACHINE_STATE * vcpu)
{
    if (!vcpu->trace_private_dr_active)
        return;

    vcpu->trace_private_dr_armed = FALSE;
    hv_trace_write_dr(
        vcpu->trace_private_dr_index,
        hv_trace_guest_dr_value(vcpu, vcpu->trace_private_dr_index));
    __vmx_vmwrite(VMCS_GUEST_DR7, vcpu->guest_dr7_shadow);

    SIZE_T controls = 0;
    __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &controls);
    if (!vcpu->mov_dr_exiting)
        controls &= ~(SIZE_T)CPU_BASED_VM_EXEC_CTRL_MOV_DR_EXITING;
    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, controls);

    if (!vcpu->trace_db_intercept_was_set)
    {
        SIZE_T bitmap = 0;
        __vmx_vmread(VMCS_CTRL_EXCEPTION_BITMAP, &bitmap);
        bitmap &= ~(1ULL << EXCEPTION_VECTOR_DEBUG);
        __vmx_vmwrite(VMCS_CTRL_EXCEPTION_BITMAP, bitmap);
    }

    vcpu->trace_private_dr_active = FALSE;
    vcpu->trace_mtf_active = FALSE;
    vcpu->trace_session_id = 0;
    vcpu->trace_private_dr_address = 0;
}

static BOOLEAN
hv_trace_enable_private_dr(
    VIRTUAL_MACHINE_STATE * vcpu,
    PHV_TRACE_SESSION session)
{
    if (vcpu->trace_private_dr_active &&
        vcpu->trace_session_id != session->id)
        return FALSE;

    UINT64 guest_dr7 = 0;
    __vmx_vmread(VMCS_GUEST_DR7, &guest_dr7);

    if (!vcpu->trace_private_dr_active)
    {
        vcpu->guest_dr0 = __readdr(0);
        vcpu->guest_dr1 = __readdr(1);
        vcpu->guest_dr2 = __readdr(2);
        vcpu->guest_dr3 = __readdr(3);
        vcpu->guest_dr6 = __readdr(6);
        vcpu->guest_dr7_shadow = guest_dr7;

        UINT8 free_index = 0xFF;
        for (UINT8 i = 0; i < 4; ++i)
        {
            if (!(guest_dr7 & ((DR7_L0 | DR7_G0) << (i * 2))))
            {
                free_index = i;
                break;
            }
        }
        if (free_index == 0xFF)
            return FALSE;

        SIZE_T bitmap = 0;
        __vmx_vmread(VMCS_CTRL_EXCEPTION_BITMAP, &bitmap);
        vcpu->trace_db_intercept_was_set =
            (bitmap & (1ULL << EXCEPTION_VECTOR_DEBUG)) ? TRUE : FALSE;
        bitmap |= (1ULL << EXCEPTION_VECTOR_DEBUG);
        __vmx_vmwrite(VMCS_CTRL_EXCEPTION_BITMAP, bitmap);

        vcpu->trace_private_dr_index = free_index;
        vcpu->trace_private_dr_active = TRUE;
        vcpu->trace_session_id = session->id;
    }

    vcpu->trace_private_dr_address = session->start_address;
    vcpu->trace_private_dr_armed = TRUE;

    SIZE_T controls = 0;
    __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &controls);
    controls |= (SIZE_T)CPU_BASED_VM_EXEC_CTRL_MOV_DR_EXITING;
    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, controls);
    hv_trace_prepare_guest_debug_state(vcpu);
    return TRUE;
}

static BOOLEAN
hv_trace_capture(
    PHV_TRACE_SESSION session,
    VIRTUAL_MACHINE_STATE * vcpu,
    UINT16 event_type)
{
    if (!session)
        return FALSE;

    InterlockedIncrement(&session->writers);
    _mm_mfence();
    if (!session->allocated || !session->active)
    {
        InterlockedDecrement(&session->writers);
        return FALSE;
    }

    LONG64 observed = session->produced;
    LONG64 sequence = 0;
    for (;;)
    {
        if (session->max_steps &&
            (UINT64)observed >= session->max_steps)
        {
            hv_trace_complete(session, OPHION_TRACE_STOP_LIMIT);
            InterlockedDecrement(&session->writers);
            return FALSE;
        }

        const LONG64 desired = observed + 1;
        const LONG64 previous = InterlockedCompareExchange64(
            &session->produced, desired, observed);
        if (previous == observed)
        {
            sequence = desired;
            break;
        }
        observed = previous;
    }

    const UINT32 index = (UINT32)((sequence - 1) % HV_TRACE_RING_CAPACITY);
    OPHION_TRACE_RECORD * record = &session->records[index];
    InterlockedExchange64(&record->sequence, 0);

    if ((UINT64)sequence > HV_TRACE_RING_CAPACITY)
        InterlockedIncrement64(&session->overwritten);

    UINT64 rflags = 0;
    __vmx_vmread(VMCS_GUEST_RFLAGS, &rflags);

    record->timestamp = __rdtsc();
    record->session_id = session->id;
    record->process_id = (UINT64)(ULONG_PTR)PsGetCurrentProcessId();
    record->cr3 = vcpu->cached_guest_cr3 & CR3_ADDR_MASK;
    record->rip = vcpu->vmexit_rip;
    record->rsp = vcpu->regs->rsp;
    record->rflags = rflags;
    record->rax = vcpu->regs->rax;
    record->rbx = vcpu->regs->rbx;
    record->rcx = vcpu->regs->rcx;
    record->rdx = vcpu->regs->rdx;
    record->rsi = vcpu->regs->rsi;
    record->rdi = vcpu->regs->rdi;
    record->rbp = vcpu->regs->rbp;
    record->r8 = vcpu->regs->r8;
    record->r9 = vcpu->regs->r9;
    record->r10 = vcpu->regs->r10;
    record->r11 = vcpu->regs->r11;
    record->r12 = vcpu->regs->r12;
    record->r13 = vcpu->regs->r13;
    record->r14 = vcpu->regs->r14;
    record->r15 = vcpu->regs->r15;
    record->cpu = KeGetCurrentProcessorNumberEx(NULL);
    record->event_type = event_type;
    record->scope = (OPHION_U8)session->scope;
    record->backend = (OPHION_U8)session->backend;
    record->stack_qwords = 0;

    if ((session->flags & OPHION_TRACE_FLAG_CAPTURE_STACK) &&
        hv_read_guest_virtual(vcpu, record->cr3, record->rsp,
            record->stack, sizeof(record->stack)))
        record->stack_qwords = RTL_NUMBER_OF(record->stack);
    else
        RtlZeroMemory(record->stack, sizeof(record->stack));

    _mm_mfence();
    InterlockedExchange64(&record->sequence, sequence);

    BOOLEAN keep_running = TRUE;
    if (session->max_steps && (UINT64)sequence == session->max_steps)
    {
        hv_trace_complete(session, OPHION_TRACE_STOP_LIMIT);
        keep_running = FALSE;
    }
    InterlockedDecrement(&session->writers);
    return keep_running;
}

BOOLEAN
hv_trace_configure(
    VIRTUAL_MACHINE_STATE * vcpu,
    UINT64 session_id,
    UINT32 scope,
    UINT32 backend,
    UINT32 flags,
    UINT64 target_pid,
    UINT64 target_cr3,
    UINT64 start_address,
    UINT64 end_address,
    UINT64 max_steps,
    BOOLEAN create_record)
{
    if (!vcpu || !session_id || start_address >= end_address || !max_steps ||
        max_steps > 0x7FFFFFFFFFFFFFFFULL ||
        (scope != OPHION_TRACE_SCOPE_USER && scope != OPHION_TRACE_SCOPE_KERNEL) ||
        (backend != OPHION_TRACE_BACKEND_EPT &&
         backend != OPHION_TRACE_BACKEND_HWBP) ||
        (scope == OPHION_TRACE_SCOPE_KERNEL &&
         backend == OPHION_TRACE_BACKEND_HWBP) ||
        (scope == OPHION_TRACE_SCOPE_USER && (!target_pid || !target_cr3)))
        return FALSE;

    PHV_TRACE_SESSION session = NULL;
    if (create_record)
    {
        ept_lists_lock_acquire();
        if (hv_trace_find(session_id))
        {
            ept_lists_lock_release();
            return FALSE;
        }

        for (UINT32 i = 0; i < HV_MAX_TRACE_SESSIONS; ++i)
        {
            if (!g_ept->trace_sessions[i].allocated)
            {
                session = &g_ept->trace_sessions[i];
                break;
            }
        }
        if (!session)
        {
            ept_lists_lock_release();
            return FALSE;
        }

        RtlZeroMemory(session, sizeof(*session));
        session->id = session_id;
        session->target_pid = target_pid;
        session->target_cr3 = target_cr3 & CR3_ADDR_MASK;
        session->start_address = start_address;
        session->end_address = end_address;
        session->max_steps = max_steps;
        session->scope = scope;
        session->backend = backend;
        session->flags = flags & (OPHION_TRACE_FLAG_CAPTURE_STACK |
                                  OPHION_TRACE_FLAG_STOP_OUTSIDE_RANGE);
        session->state = OPHION_TRACE_STATE_RUNNING;
        session->active = 1;
        _mm_mfence();
        session->allocated = 1;
        ept_lists_lock_release();
    }
    else
    {
        session = hv_trace_find(session_id);
        if (!session || !session->active)
            return FALSE;
    }

    if (backend == OPHION_TRACE_BACKEND_HWBP &&
        !hv_trace_enable_private_dr(vcpu, session))
    {
        if (create_record)
        {
            InterlockedExchange(&session->active, 0);
            InterlockedExchange(&session->state, OPHION_TRACE_STATE_STOPPED);
        }
        return FALSE;
    }
    return TRUE;
}

BOOLEAN
hv_trace_stop(
    VIRTUAL_MACHINE_STATE * vcpu,
    UINT64 session_id,
    UINT32 stop_reason)
{
    PHV_TRACE_SESSION session = hv_trace_find(session_id);
    if (session)
    {
        InterlockedExchange(&session->active, 0);
        if (session->backend == OPHION_TRACE_BACKEND_EPT)
            ept_breakpoint_deactivate_trace_session(session->id);
        if (session->state == OPHION_TRACE_STATE_RUNNING)
            InterlockedExchange(&session->state, OPHION_TRACE_STATE_STOPPED);
        if (session->stop_reason == OPHION_TRACE_STOP_NONE)
            InterlockedCompareExchange(&session->stop_reason,
                stop_reason ? stop_reason : OPHION_TRACE_STOP_REQUESTED,
                OPHION_TRACE_STOP_NONE);
    }

    if (vcpu && vcpu->trace_session_id == session_id)
        hv_trace_disable_private_dr(vcpu);
    return session != NULL;
}

BOOLEAN
hv_trace_close(VIRTUAL_MACHINE_STATE * vcpu, UINT64 session_id)
{
    if (vcpu && vcpu->trace_session_id == session_id)
        hv_trace_disable_private_dr(vcpu);

    PHV_TRACE_SESSION session = hv_trace_find(session_id);
    if (!session)
        return TRUE;
    if (session->active)
        return FALSE;
    if (session->writers)
        return FALSE;

    ept_lists_lock_acquire();
    session = hv_trace_find(session_id);
    if (session && !session->active)
    {
        InterlockedExchange(&session->state, OPHION_TRACE_STATE_CLOSED);
        _mm_mfence();
        InterlockedExchange(&session->allocated, 0);
    }
    ept_lists_lock_release();
    return TRUE;
}

BOOLEAN
hv_trace_read(
    UINT64 session_id,
    UINT64 next_sequence,
    UINT32 max_records,
    OPHION_TRACE_READ_OUTPUT * output,
    UINT32 output_size)
{
    PHV_TRACE_SESSION session = hv_trace_find(session_id);
    if (!session || !output ||
        output_size < OPHION_TRACE_READ_OUTPUT_HEADER_SIZE)
        return FALSE;

    const UINT32 capacity =
        (output_size - OPHION_TRACE_READ_OUTPUT_HEADER_SIZE) /
        sizeof(OPHION_TRACE_RECORD);
    if (max_records > capacity)
        max_records = capacity;

    const UINT64 produced = (UINT64)session->produced;
    const UINT64 oldest = produced > HV_TRACE_RING_CAPACITY
        ? produced - HV_TRACE_RING_CAPACITY + 1
        : 1;
    UINT64 cursor = next_sequence ? next_sequence : oldest;
    if (cursor < oldest)
        cursor = oldest;

    output->version = OPHION_TRACE_ABI_VERSION;
    output->status = STATUS_SUCCESS;
    output->state = (UINT32)session->state;
    output->stop_reason = (UINT32)session->stop_reason;
    output->record_count = 0;
    output->actual_backend = session->backend;
    output->produced = produced;
    output->overwritten = (UINT64)session->overwritten;

    while (cursor <= produced && output->record_count < max_records)
    {
        OPHION_TRACE_RECORD * source =
            &session->records[(cursor - 1) % HV_TRACE_RING_CAPACITY];
        if ((UINT64)source->sequence != cursor)
            break;

        RtlCopyMemory(&output->records[output->record_count],
            source, sizeof(*source));
        _mm_mfence();
        if ((UINT64)source->sequence != cursor)
            break;
        ++output->record_count;
        ++cursor;
    }
    output->next_sequence = cursor;
    return TRUE;
}

BOOLEAN
hv_trace_record_ept(
    VIRTUAL_MACHINE_STATE * vcpu,
    UINT64 breakpoint_id)
{
    if ((breakpoint_id >> 48) != HV_TRACE_BP_SIGNATURE)
        return FALSE;

    const UINT64 session_id = (breakpoint_id >> 16) & 0xFFFFFFFFULL;
    PHV_TRACE_SESSION session = hv_trace_find(session_id);
    if (!session || !session->active ||
        session->backend != OPHION_TRACE_BACKEND_EPT ||
        !hv_trace_matches_context(session, vcpu))
        return FALSE;

    return hv_trace_capture(
        session, vcpu, OPHION_TRACE_EVENT_EPT_EXECUTE);
}

BOOLEAN
hv_trace_handle_debug_exception(
    VIRTUAL_MACHINE_STATE * vcpu,
    UINT64 debug_status)
{
    if (!vcpu->trace_private_dr_active || !vcpu->trace_private_dr_armed)
        return FALSE;

    const UINT64 private_bit = 1ULL << vcpu->trace_private_dr_index;
    if (!(debug_status & private_bit))
        return FALSE;

    // Remove the private reason from the guest-visible DR6 shadow even when
    // this address was reached by another process. The physical execution
    // breakpoint is global to the logical CPU; leaking its B0-B3 bit would
    // inject a spurious #DB into an unrelated guest context.
    vcpu->guest_dr6 &= ~private_bit;
    vcpu->guest_dr6 |= debug_status & ~private_bit;

    const UINT64 guest_reasons = debug_status &
        ((PENDING_DEBUG_B0 | PENDING_DEBUG_B1 | PENDING_DEBUG_B2 |
          PENDING_DEBUG_B3 | PENDING_DEBUG_BS) & ~private_bit);

    PHV_TRACE_SESSION session = hv_trace_find(vcpu->trace_session_id);
    if (!session || !session->active ||
        session->backend != OPHION_TRACE_BACKEND_HWBP)
    {
        hv_trace_disable_private_dr(vcpu);
        return guest_reasons == 0;
    }

    if (!hv_trace_matches_context(session, vcpu) ||
        vcpu->vmexit_rip != session->start_address)
    {
        // Keep the private slot armed for the target process, but consume this
        // address-space alias hit. Genuine guest breakpoint reasons are still
        // reinjected below by returning FALSE.
        hv_trace_prepare_guest_debug_state(vcpu);
        return guest_reasons == 0;
    }

    vcpu->trace_private_dr_armed = FALSE;
    hv_trace_prepare_guest_debug_state(vcpu);

    if (hv_trace_capture(session, vcpu, OPHION_TRACE_EVENT_HWBP_ENTRY))
    {
        vcpu->trace_mtf_active = TRUE;
        hv_trace_arm_mtf();
    }
    else
    {
        hv_trace_disable_private_dr(vcpu);
    }

    // If a guest-visible debug reason fired at the same time, preserve it.
    return guest_reasons == 0;
}

VOID
hv_trace_handle_mtf(VIRTUAL_MACHINE_STATE * vcpu)
{
    if (!vcpu->trace_mtf_active)
        return;

    PHV_TRACE_SESSION session = hv_trace_find(vcpu->trace_session_id);
    if (!session || !session->active)
    {
        hv_trace_disable_private_dr(vcpu);
        return;
    }

    if (!hv_trace_matches_context(session, vcpu))
    {
        // MTF is CPU-local. Once execution switches to another process the
        // original instruction stream cannot be continued losslessly, so end
        // the session explicitly instead of silently dropping this vCPU.
        hv_trace_complete(session, OPHION_TRACE_STOP_CONTEXT_EXIT);
        hv_trace_disable_private_dr(vcpu);
        return;
    }

    if (session->scope == OPHION_TRACE_SCOPE_USER)
    {
        SIZE_T cs = 0;
        __vmx_vmread(VMCS_GUEST_CS_SELECTOR, &cs);
        if ((cs & 3) != 3)
        {
            // Continuing MTF through ring 0 single-steps arbitrary kernel and
            // interrupt paths. End the user trace explicitly at the boundary
            // instead of risking an unbounded VM-exit storm.
            hv_trace_complete(session, OPHION_TRACE_STOP_CONTEXT_EXIT);
            hv_trace_disable_private_dr(vcpu);
            return;
        }
    }

    if ((session->flags & OPHION_TRACE_FLAG_STOP_OUTSIDE_RANGE) &&
        (vcpu->vmexit_rip < session->start_address ||
         vcpu->vmexit_rip >= session->end_address))
    {
        hv_trace_complete(session, OPHION_TRACE_STOP_RANGE_EXIT);
        hv_trace_disable_private_dr(vcpu);
        return;
    }

    if (!hv_trace_capture(session, vcpu, OPHION_TRACE_EVENT_MTF_STEP))
    {
        hv_trace_disable_private_dr(vcpu);
        return;
    }

    hv_trace_arm_mtf();
}

VOID
hv_trace_rearm_pending_mtf(VIRTUAL_MACHINE_STATE * vcpu)
{
    if (vcpu && vcpu->trace_mtf_active)
        hv_trace_arm_mtf();
}

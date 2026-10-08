#include "td_common.h"

#define TD_TRACE_MAX_SESSIONS 4
#define TD_TRACE_MAX_PAGES    16
#define TD_TRACE_BP_SIGNATURE 0x5452ULL
#define TD_TRACE_POOL_TAG     'rTdT'

typedef struct _TD_TRACE_ENTRY {
    BOOLEAN allocated;
    BOOLEAN running;
    UINT16  reserved;
    UINT32  scope;
    UINT32  backend;
    UINT32  flags;
    UINT64  session_id;
    UINT64  target_pid;
    UINT64  target_cr3;
    UINT64  start_address;
    UINT64  end_address;
    PMDL    mdl;
    UINT32  page_count;
    UINT32  breakpoint_count;
    UINT64  breakpoint_ids[TD_TRACE_MAX_PAGES];
} TD_TRACE_ENTRY, *PTD_TRACE_ENTRY;

typedef enum _TD_TRACE_DPC_OPERATION {
    TdTraceDpcConfigure,
    TdTraceDpcStop,
    TdTraceDpcClose,
    TdTraceDpcBreakpointSet,
    TdTraceDpcBreakpointClear,
} TD_TRACE_DPC_OPERATION;

typedef struct _TD_TRACE_DPC_CONTEXT {
    TD_TRACE_DPC_OPERATION operation;
    UINT64 session_id;
    UINT64 packed_control;
    UINT64 target_pid;
    UINT64 target_cr3;
    UINT64 start_address;
    UINT64 end_address;
    UINT64 max_steps;
    UINT64 breakpoint_id;
    UINT64 target_address;
    UINT64 target_physical;
    UINT32 size;
    UINT32 access;
    UINT32 breakpoint_flags;
    UINT32 stop_reason;
    UINT8  record_operation;
    volatile LONG failure_count;
    volatile LONG first_failure;
} TD_TRACE_DPC_CONTEXT, *PTD_TRACE_DPC_CONTEXT;

static FAST_MUTEX g_trace_mutex;
static TD_TRACE_ENTRY g_trace_entries[TD_TRACE_MAX_SESSIONS] = {};
static volatile LONG g_trace_next_id = 0;

static NTSTATUS
TdTraceIssueVmcall(PTD_TRACE_DPC_CONTEXT context)
{
    switch (context->operation)
    {
    case TdTraceDpcConfigure:
        return hv_vmcall_ex(
            HV_VMCALL_TRACE_CONFIG,
            context->session_id,
            context->packed_control,
            context->target_pid,
            context->target_cr3,
            context->start_address,
            context->end_address,
            context->max_steps,
            0, 0);

    case TdTraceDpcStop:
        return hv_vmcall_ex(
            HV_VMCALL_TRACE_STOP,
            context->session_id,
            context->stop_reason,
            0, 0, 0, 0, 0, 0, 0);

    case TdTraceDpcClose:
        return hv_vmcall_ex(
            HV_VMCALL_TRACE_CLOSE,
            context->session_id,
            0, 0, 0, 0, 0, 0, 0, 0);

    case TdTraceDpcBreakpointSet:
        return hv_vmcall_ex(
            HV_VMCALL_MEMORY_BREAKPOINT_SET,
            context->breakpoint_id,
            context->target_cr3,
            context->target_address,
            context->target_physical,
            context->size,
            context->access,
            context->breakpoint_flags,
            0,
            context->target_pid);

    case TdTraceDpcBreakpointClear:
        return hv_vmcall_ex(
            HV_VMCALL_MEMORY_BREAKPOINT_CLEAR,
            context->breakpoint_id,
            context->record_operation,
            0, 0, 0, 0, 0, 0, 0);

    default:
        return STATUS_INVALID_PARAMETER;
    }
}

static VOID
TdTraceDpc(
    PKDPC Dpc,
    PVOID Context,
    PVOID SystemArgument1,
    PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    PTD_TRACE_DPC_CONTEXT context = (PTD_TRACE_DPC_CONTEXT)Context;
    NTSTATUS status = TdTraceIssueVmcall(context);
    if (!NT_SUCCESS(status))
    {
        InterlockedIncrement(&context->failure_count);
        InterlockedCompareExchange(
            &context->first_failure, (LONG)status, (LONG)STATUS_SUCCESS);
    }
    KeSignalCallDpcSynchronize(SystemArgument2);
    KeSignalCallDpcDone(SystemArgument1);
}

static NTSTATUS
TdTraceBroadcast(PTD_TRACE_DPC_CONTEXT context)
{
    context->failure_count = 0;
    context->first_failure = STATUS_SUCCESS;
    KeGenericCallDpc(TdTraceDpc, context);
    return context->failure_count == 0
        ? STATUS_SUCCESS
        : (NTSTATUS)context->first_failure;
}

static UINT64
TdTracePackedControl(
    UINT32 scope,
    UINT32 backend,
    UINT32 flags,
    BOOLEAN create_record)
{
    UINT64 value = (scope & 0xFF) |
        ((UINT64)(backend & 0xFF) << 8) |
        ((UINT64)(flags & 0xFFFF) << 16);
    if (create_record)
        value |= 1ULL << 32;
    return value;
}

static PTD_TRACE_ENTRY
TdTraceFindLocked(UINT64 session_id)
{
    for (UINT32 i = 0; i < TD_TRACE_MAX_SESSIONS; ++i)
    {
        if (g_trace_entries[i].allocated &&
            g_trace_entries[i].session_id == session_id)
            return &g_trace_entries[i];
    }
    return NULL;
}

static UINT64
TdTraceAllocateSessionIdLocked(VOID)
{
    // At most four IDs can be live, so five attempts are sufficient even when
    // the signed counter wraps back into the low positive range.
    for (UINT32 attempt = 0; attempt <= TD_TRACE_MAX_SESSIONS; ++attempt)
    {
        LONG next_id = InterlockedIncrement(&g_trace_next_id);
        if (next_id <= 0)
        {
            InterlockedExchange(&g_trace_next_id, 1);
            next_id = 1;
        }

        const UINT64 candidate = (UINT32)next_id;
        if (!TdTraceFindLocked(candidate))
            return candidate;
    }
    return 0;
}

static VOID
TdTraceUnlockPages(PTD_TRACE_ENTRY entry)
{
    if (entry->mdl)
    {
        MmUnlockPages(entry->mdl);
        IoFreeMdl(entry->mdl);
        entry->mdl = NULL;
    }
}

static NTSTATUS
TdTraceConfigureSession(
    PTD_TRACE_ENTRY entry,
    UINT64 max_steps,
    BOOLEAN create_record)
{
    TD_TRACE_DPC_CONTEXT context = {};
    context.operation = TdTraceDpcConfigure;
    context.session_id = entry->session_id;
    context.packed_control = TdTracePackedControl(
        entry->scope, entry->backend, entry->flags, create_record);
    context.target_pid = entry->target_pid;
    context.target_cr3 = entry->target_cr3;
    context.start_address = entry->start_address;
    context.end_address = entry->end_address;
    context.max_steps = max_steps;

    if (create_record)
    {
        NTSTATUS status = TdTraceIssueVmcall(&context);
        if (!NT_SUCCESS(status))
            return status;
        context.packed_control = TdTracePackedControl(
            entry->scope, entry->backend, entry->flags, FALSE);
    }
    return TdTraceBroadcast(&context);
}

static NTSTATUS
TdTraceSetBreakpoint(
    PTD_TRACE_ENTRY entry,
    UINT32 page_index,
    UINT64 target_address,
    UINT64 target_physical,
    UINT32 size)
{
    TD_TRACE_DPC_CONTEXT context = {};
    context.operation = TdTraceDpcBreakpointSet;
    context.breakpoint_id =
        (TD_TRACE_BP_SIGNATURE << 48) |
        ((entry->session_id & 0xFFFFFFFFULL) << 16) |
        (page_index & 0xFFFF);
    context.target_pid = entry->target_pid;
    context.target_cr3 = entry->target_cr3;
    context.target_address = target_address;
    context.target_physical = target_physical;
    context.size = size;
    context.access = TD_BP_ACCESS_EXECUTE;
    context.breakpoint_flags = 0x80; // HV_BP_FLAG_TRACE

    NTSTATUS status = hv_vmcall_ex(
        HV_VMCALL_MEMORY_BREAKPOINT_SET,
        context.breakpoint_id,
        context.target_cr3,
        context.target_address,
        context.target_physical,
        context.size,
        context.access,
        context.breakpoint_flags,
        1,
        context.target_pid);
    if (!NT_SUCCESS(status))
        return status;

    entry->breakpoint_ids[entry->breakpoint_count++] =
        context.breakpoint_id;
    status = TdTraceBroadcast(&context);
    return status;
}

static NTSTATUS
TdTraceClearBreakpoint(UINT64 breakpoint_id)
{
    TD_TRACE_DPC_CONTEXT context = {};
    context.operation = TdTraceDpcBreakpointClear;
    context.breakpoint_id = breakpoint_id;
    context.record_operation = 1;
    NTSTATUS status = TdTraceIssueVmcall(&context);
    if (status == STATUS_NOT_FOUND)
        return STATUS_SUCCESS;
    if (!NT_SUCCESS(status))
        return status;

    context.record_operation = 0;
    status = TdTraceBroadcast(&context);
    if (!NT_SUCCESS(status))
        return status;

    context.record_operation = 2;
    return TdTraceIssueVmcall(&context);
}

static NTSTATUS
TdTraceStopLocked(
    PTD_TRACE_ENTRY entry,
    UINT32 reason,
    BOOLEAN issue_vmcalls)
{
    NTSTATUS first_status = STATUS_SUCCESS;
    if (issue_vmcalls)
    {
        if (entry->running)
        {
            TD_TRACE_DPC_CONTEXT context = {};
            context.operation = TdTraceDpcStop;
            context.session_id = entry->session_id;
            context.stop_reason = reason;
            first_status = TdTraceBroadcast(&context);
            if (first_status == STATUS_NOT_FOUND &&
                entry->breakpoint_count == 0)
                first_status = STATUS_SUCCESS;
            if (NT_SUCCESS(first_status))
                entry->running = FALSE;
        }

        UINT32 retained = 0;
        for (UINT32 i = 0; i < entry->breakpoint_count; ++i)
        {
            NTSTATUS status = TdTraceClearBreakpoint(entry->breakpoint_ids[i]);
            if (NT_SUCCESS(first_status) && !NT_SUCCESS(status))
                first_status = status;
            if (!NT_SUCCESS(status))
                entry->breakpoint_ids[retained++] = entry->breakpoint_ids[i];
        }
        for (UINT32 i = retained; i < entry->breakpoint_count; ++i)
            entry->breakpoint_ids[i] = 0;
        entry->breakpoint_count = retained;
    }
    else
    {
        entry->running = FALSE;
        entry->breakpoint_count = 0;
        RtlZeroMemory(entry->breakpoint_ids, sizeof(entry->breakpoint_ids));
    }

    // Keep the pages pinned whenever a stop or EPT permission restore failed.
    // Releasing the MDL here could let an armed physical-page breakpoint trap
    // an unrelated allocation after the PFN is reused.
    if (!entry->running && entry->breakpoint_count == 0)
        TdTraceUnlockPages(entry);
    return first_status;
}

static NTSTATUS
TdTraceCloseLocked(PTD_TRACE_ENTRY entry, BOOLEAN issue_vmcalls)
{
    NTSTATUS status = STATUS_SUCCESS;
    if (entry->running || entry->breakpoint_count || entry->mdl)
        status = TdTraceStopLocked(
            entry, OPHION_TRACE_STOP_REQUESTED, issue_vmcalls);

    if (!NT_SUCCESS(status))
        return status;

    if (issue_vmcalls)
    {
        TD_TRACE_DPC_CONTEXT context = {};
        context.operation = TdTraceDpcClose;
        context.session_id = entry->session_id;
        NTSTATUS close_status = TdTraceBroadcast(&context);
        if (!NT_SUCCESS(close_status))
            return close_status;
    }

    RtlZeroMemory(entry, sizeof(*entry));
    return status;
}

VOID
TdTraceInitialize(VOID)
{
    ExInitializeFastMutex(&g_trace_mutex);
}

NTSTATUS
TdTraceStart(OPHION_TRACE_START_REQUEST * request)
{
    if (!request || request->version != OPHION_TRACE_ABI_VERSION ||
        request->start_address >= request->end_address ||
        request->max_steps == 0 || request->max_steps > 0x1000000ULL ||
        (request->scope != OPHION_TRACE_SCOPE_USER &&
         request->scope != OPHION_TRACE_SCOPE_KERNEL) ||
        (request->backend > OPHION_TRACE_BACKEND_HWBP) ||
        (request->scope == OPHION_TRACE_SCOPE_KERNEL &&
         request->backend == OPHION_TRACE_BACKEND_HWBP) ||
        (request->scope == OPHION_TRACE_SCOPE_USER && !request->target_pid) ||
        (request->flags & ~(OPHION_TRACE_FLAG_CAPTURE_STACK |
                            OPHION_TRACE_FLAG_STOP_OUTSIDE_RANGE)) != 0)
        return STATUS_INVALID_PARAMETER;

    if (request->scope == OPHION_TRACE_SCOPE_USER &&
        (request->start_address < 0x10000ULL ||
         request->end_address > 0x00007FFF00000000ULL))
        return STATUS_INVALID_ADDRESS;

    const UINT64 range_size = request->end_address - request->start_address;
    if (range_size > (UINT64)TD_TRACE_MAX_PAGES * PAGE_SIZE)
        return STATUS_INVALID_BUFFER_SIZE;
    const SIZE_T pages_spanned = ADDRESS_AND_SIZE_TO_SPAN_PAGES(
        (PVOID)(ULONG_PTR)request->start_address, (SIZE_T)range_size);
    if (!pages_spanned || pages_spanned > TD_TRACE_MAX_PAGES)
        return STATUS_INVALID_BUFFER_SIZE;
    const UINT32 page_count = (UINT32)pages_spanned;
    if (!TdOphionAlive())
        return STATUS_DEVICE_NOT_READY;

    ExAcquireFastMutex(&g_trace_mutex);
    PTD_TRACE_ENTRY entry = NULL;
    for (UINT32 i = 0; i < TD_TRACE_MAX_SESSIONS; ++i)
    {
        if (!g_trace_entries[i].allocated)
        {
            entry = &g_trace_entries[i];
            break;
        }
    }
    if (!entry)
    {
        ExReleaseFastMutex(&g_trace_mutex);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    UINT32 backend = request->backend;
    if (backend == OPHION_TRACE_BACKEND_AUTO)
        backend = request->scope == OPHION_TRACE_SCOPE_USER
            ? OPHION_TRACE_BACKEND_HWBP
            : OPHION_TRACE_BACKEND_EPT;

    RtlZeroMemory(entry, sizeof(*entry));
    const UINT64 next_id = TdTraceAllocateSessionIdLocked();
    if (!next_id)
    {
        ExReleaseFastMutex(&g_trace_mutex);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    entry->allocated = TRUE;
    entry->running = TRUE;
    entry->session_id = next_id;
    entry->scope = request->scope;
    entry->backend = backend;
    entry->flags = request->flags;
    entry->target_pid = request->scope == OPHION_TRACE_SCOPE_USER
        ? request->target_pid : 0;
    entry->start_address = request->start_address;
    entry->end_address = request->end_address;
    entry->page_count = page_count;

    PEPROCESS process = NULL;
    KAPC_STATE apc = {};
    BOOLEAN attached = FALSE;
    BOOLEAN pages_locked = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (entry->scope == OPHION_TRACE_SCOPE_USER)
    {
        status = PsLookupProcessByProcessId(
            (HANDLE)(ULONG_PTR)entry->target_pid, &process);
        if (!NT_SUCCESS(status))
            goto ExitFailure;
    }
    else if (entry->start_address < 0xFFFF800000000000ULL)
    {
        status = STATUS_INVALID_ADDRESS;
        goto ExitFailure;
    }

    entry->mdl = IoAllocateMdl(
        (PVOID)(ULONG_PTR)entry->start_address,
        (ULONG)range_size, FALSE, FALSE, NULL);
    if (!entry->mdl)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto ExitFailure;
    }

    __try
    {
        if (process)
        {
            KeStackAttachProcess(process, &apc);
            attached = TRUE;
        }
        MmProbeAndLockPages(entry->mdl,
            (KPROCESSOR_MODE)(process ? UserMode : KernelMode), IoReadAccess);
        pages_locked = TRUE;
        if (process)
            entry->target_cr3 = __readcr3() & 0x000FFFFFFFFFF000ULL;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = GetExceptionCode();
    }

    if (attached)
    {
        KeUnstackDetachProcess(&apc);
        attached = FALSE;
    }
    if (process)
    {
        ObDereferenceObject(process);
        process = NULL;
    }
    if (!pages_locked ||
        (entry->scope == OPHION_TRACE_SCOPE_USER && !entry->target_cr3))
    {
        if (NT_SUCCESS(status))
            status = STATUS_NOT_MAPPED_VIEW;
        goto ExitFailure;
    }

    status = TdTraceConfigureSession(entry, request->max_steps, TRUE);
    if (!NT_SUCCESS(status) &&
        request->backend == OPHION_TRACE_BACKEND_AUTO &&
        entry->scope == OPHION_TRACE_SCOPE_USER)
    {
        TD_TRACE_DPC_CONTEXT stop_context = {};
        stop_context.operation = TdTraceDpcStop;
        stop_context.session_id = entry->session_id;
        stop_context.stop_reason = OPHION_TRACE_STOP_REQUESTED;
        NTSTATUS reset_status = TdTraceBroadcast(&stop_context);
        if (NT_SUCCESS(reset_status))
        {
            stop_context.operation = TdTraceDpcClose;
            reset_status = TdTraceBroadcast(&stop_context);
        }

        if (NT_SUCCESS(reset_status))
        {
            entry->backend = OPHION_TRACE_BACKEND_EPT;
            status = TdTraceConfigureSession(entry, request->max_steps, TRUE);
        }
        else
        {
            status = reset_status;
        }
    }
    if (!NT_SUCCESS(status))
    {
        TD_TRACE_DPC_CONTEXT cleanup_context = {};
        cleanup_context.operation = TdTraceDpcStop;
        cleanup_context.session_id = entry->session_id;
        cleanup_context.stop_reason = OPHION_TRACE_STOP_REQUESTED;
        TdTraceBroadcast(&cleanup_context);
        cleanup_context.operation = TdTraceDpcClose;
        TdTraceBroadcast(&cleanup_context);
        goto ExitFailure;
    }

    if (entry->backend == OPHION_TRACE_BACKEND_EPT)
    {
        PPFN_NUMBER pfns = MmGetMdlPfnArray(entry->mdl);
        const UINT64 first_page = entry->start_address & ~0xFFFULL;
        for (UINT32 i = 0; i < page_count; ++i)
        {
            const UINT64 page_va = first_page + ((UINT64)i * PAGE_SIZE);
            const UINT64 segment_start = page_va < entry->start_address
                ? entry->start_address : page_va;
            const UINT64 page_end = page_va + PAGE_SIZE;
            const UINT64 segment_end = page_end > entry->end_address
                ? entry->end_address : page_end;
            const UINT64 offset = segment_start - page_va;
            const UINT64 physical = ((UINT64)pfns[i] << PAGE_SHIFT) + offset;

            status = TdTraceSetBreakpoint(
                entry, i, segment_start, physical,
                (UINT32)(segment_end - segment_start));
            if (!NT_SUCCESS(status))
                goto ExitFailureConfigured;
        }
    }

    request->session_id = entry->session_id;
    request->actual_backend = entry->backend;
    request->status = STATUS_SUCCESS;
    ExReleaseFastMutex(&g_trace_mutex);
    return STATUS_SUCCESS;

ExitFailureConfigured:
    {
        const UINT64 failed_session_id = entry->session_id;
        const UINT32 failed_backend = entry->backend;
        NTSTATUS cleanup_status = TdTraceCloseLocked(entry, TRUE);
        if (!NT_SUCCESS(cleanup_status))
        {
            // Preserve the local entry and pinned pages so CLOSE can be
            // retried instead of orphaning live EPT metadata.
            request->session_id = failed_session_id;
            request->actual_backend = failed_backend;
            status = cleanup_status;
        }
    }
    ExReleaseFastMutex(&g_trace_mutex);
    return status;

ExitFailure:
    if (attached)
        KeUnstackDetachProcess(&apc);
    if (process)
        ObDereferenceObject(process);
    if (entry->mdl)
    {
        if (pages_locked)
            MmUnlockPages(entry->mdl);
        IoFreeMdl(entry->mdl);
    }
    RtlZeroMemory(entry, sizeof(*entry));
    ExReleaseFastMutex(&g_trace_mutex);
    return status;
}

NTSTATUS
TdTraceStop(OPHION_TRACE_CONTROL_REQUEST * request, UINT32 reason)
{
    if (!request || request->version != OPHION_TRACE_ABI_VERSION)
        return STATUS_INVALID_PARAMETER;

    ExAcquireFastMutex(&g_trace_mutex);
    PTD_TRACE_ENTRY entry = TdTraceFindLocked(request->session_id);
    NTSTATUS status = entry
        ? TdTraceStopLocked(entry, reason, TdOphionAlive())
        : STATUS_NOT_FOUND;
    request->status = status;
    request->state = entry
        ? (entry->running ? OPHION_TRACE_STATE_RUNNING
                          : OPHION_TRACE_STATE_STOPPED)
        : 0;
    ExReleaseFastMutex(&g_trace_mutex);
    return status;
}

NTSTATUS
TdTraceClose(OPHION_TRACE_CONTROL_REQUEST * request)
{
    if (!request || request->version != OPHION_TRACE_ABI_VERSION)
        return STATUS_INVALID_PARAMETER;

    ExAcquireFastMutex(&g_trace_mutex);
    PTD_TRACE_ENTRY entry = TdTraceFindLocked(request->session_id);
    NTSTATUS status = entry
        ? TdTraceCloseLocked(entry, TdOphionAlive())
        : STATUS_NOT_FOUND;
    request->status = status;
    request->state = NT_SUCCESS(status) ? OPHION_TRACE_STATE_CLOSED : 0;
    ExReleaseFastMutex(&g_trace_mutex);
    return status;
}

NTSTATUS
TdTraceRead(
    const OPHION_TRACE_READ_REQUEST * request,
    OPHION_TRACE_READ_OUTPUT * output,
    UINT32 output_size)
{
    if (!output || output_size < OPHION_TRACE_READ_OUTPUT_HEADER_SIZE)
        return STATUS_INVALID_PARAMETER;

    // The METHOD_OUT_DIRECT buffer belongs to the caller and may contain
    // arbitrary bytes.  Initialize the header before every early return so the
    // dispatch routine never derives IoStatus.Information from stale data.
    RtlZeroMemory(output, OPHION_TRACE_READ_OUTPUT_HEADER_SIZE);
    output->version = OPHION_TRACE_ABI_VERSION;

    if (!request || request->version != OPHION_TRACE_ABI_VERSION)
    {
        output->status = (UINT32)STATUS_INVALID_PARAMETER;
        return STATUS_INVALID_PARAMETER;
    }

    const UINT32 capacity =
        (output_size - OPHION_TRACE_READ_OUTPUT_HEADER_SIZE) /
        sizeof(OPHION_TRACE_RECORD);
    UINT32 max_records = request->max_records;
    if (!max_records || max_records > capacity)
        max_records = capacity;

    ExAcquireFastMutex(&g_trace_mutex);
    PTD_TRACE_ENTRY entry = TdTraceFindLocked(request->session_id);
    if (!entry)
    {
        ExReleaseFastMutex(&g_trace_mutex);
        output->status = (UINT32)STATUS_NOT_FOUND;
        return STATUS_NOT_FOUND;
    }

    NTSTATUS status = hv_vmcall_ex(
        HV_VMCALL_TRACE_READ,
        request->session_id,
        request->next_sequence,
        max_records,
        (UINT64)(ULONG_PTR)output,
        output_size,
        0, 0, 0, 0);
    ExReleaseFastMutex(&g_trace_mutex);
    output->status = status;
    return status;
}

VOID
TdTraceCleanupProcess(UINT64 pid)
{
    ExAcquireFastMutex(&g_trace_mutex);
    for (UINT32 i = 0; i < TD_TRACE_MAX_SESSIONS; ++i)
    {
        PTD_TRACE_ENTRY entry = &g_trace_entries[i];
        if (entry->allocated && entry->target_pid == pid)
        {
            if (entry->running)
                TdTraceStopLocked(entry, OPHION_TRACE_STOP_PROCESS_EXIT,
                    TdOphionAlive());
            TdTraceCloseLocked(entry, TdOphionAlive());
        }
    }
    ExReleaseFastMutex(&g_trace_mutex);
}

VOID
TdTraceCleanupAll(BOOLEAN issue_vmcalls)
{
    ExAcquireFastMutex(&g_trace_mutex);
    for (UINT32 i = 0; i < TD_TRACE_MAX_SESSIONS; ++i)
    {
        if (g_trace_entries[i].allocated)
            TdTraceCloseLocked(&g_trace_entries[i], issue_vmcalls);
    }
    ExReleaseFastMutex(&g_trace_mutex);
}

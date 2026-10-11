#include "td_common.h"

FAST_MUTEX g_memory_breakpoint_mutex;
TD_MEMORY_BREAKPOINT_ENTRY g_memory_breakpoints[TD_MAX_MEMORY_BREAKPOINTS] = {};
static volatile LONG64 g_memory_breakpoint_next_id = 0;

typedef struct _TD_BP_BROADCAST_CONTEXT {
    BOOLEAN set_operation;
    UINT64  breakpoint_id;
    UINT64  target_pid;
    UINT64  target_cr3;
    UINT64  target_address;
    UINT64  target_physical;
    UINT32  size;
    UINT32  access;
    UINT32  flags;
    volatile LONG failure_count;
    volatile LONG first_failure;
} TD_BP_BROADCAST_CONTEXT, *PTD_BP_BROADCAST_CONTEXT;

static NTSTATUS
TdMemoryBreakpointVmcall(
    BOOLEAN set_operation,
    UINT64 breakpoint_id,
    UINT64 target_pid,
    UINT64 target_cr3,
    UINT64 target_address,
    UINT64 target_physical,
    UINT32 size,
    UINT32 access,
    UINT32 flags,
    UINT8 record_operation)
{
    if (set_operation)
    {
        return hv_vmcall_ex(
            HV_VMCALL_MEMORY_BREAKPOINT_SET,
            breakpoint_id,
            target_cr3,
            target_address,
            target_physical,
            size,
            access,
            flags,
            record_operation ? 1 : 0,
            target_pid);
    }

    return hv_vmcall_ex(
        HV_VMCALL_MEMORY_BREAKPOINT_CLEAR,
        breakpoint_id,
        record_operation,
        0, 0, 0, 0, 0, 0, 0);
}

static VOID
TdMemoryBreakpointDpc(PKDPC Dpc, PVOID Context, PVOID SystemArgument1, PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    PTD_BP_BROADCAST_CONTEXT context = (PTD_BP_BROADCAST_CONTEXT)Context;
    NTSTATUS status = TdMemoryBreakpointVmcall(
        context->set_operation,
        context->breakpoint_id,
        context->target_pid,
        context->target_cr3,
        context->target_address,
        context->target_physical,
        context->size,
        context->access,
        context->flags,
        0);

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
TdMemoryBreakpointBroadcast(
    BOOLEAN set_operation,
    UINT64 breakpoint_id,
    UINT64 target_pid,
    UINT64 target_cr3,
    UINT64 target_address,
    UINT64 target_physical,
    UINT32 size,
    UINT32 access,
    UINT32 flags)
{
    TD_BP_BROADCAST_CONTEXT context = {};
    context.set_operation = set_operation;
    context.breakpoint_id = breakpoint_id;
    context.target_pid = target_pid;
    context.target_cr3 = target_cr3;
    context.target_address = target_address;
    context.target_physical = target_physical;
    context.size = size;
    context.access = access;
    context.flags = flags;
    context.first_failure = STATUS_SUCCESS;

    KeGenericCallDpc(TdMemoryBreakpointDpc, &context);
    return context.failure_count == 0
        ? STATUS_SUCCESS
        : (NTSTATUS)context.first_failure;
}

static VOID
TdMemoryBreakpointReleaseEntry(PTD_MEMORY_BREAKPOINT_ENTRY entry)
{
    if (entry->mdl)
    {
        MmUnlockPages(entry->mdl);
        IoFreeMdl(entry->mdl);
    }
    RtlZeroMemory(entry, sizeof(*entry));
}

static NTSTATUS
TdMemoryBreakpointClearLocked(
    PTD_MEMORY_BREAKPOINT_ENTRY entry,
    BOOLEAN issue_vmcalls)
{
    if (!entry || !entry->active)
        return STATUS_NOT_FOUND;

    /* F12: the VBox branch runs before the issue_vmcalls gate - the hook's
       owner is the backend that installed it, and releasing the MDL without
       BP_REMOVE would leave the VMM hooking an unstable page. */
    if (entry->f_vbox_backend)
    {
        // F12: cleanup follows the backend that owns the hook, never the
        // Ophion liveness event.
        NTSTATUS vbox_status = TdVbxBpRemove(entry->vbox_id_hook, entry->vbox_generation);
        if (NT_SUCCESS(vbox_status))
            TdMemoryBreakpointReleaseEntry(entry);
        return vbox_status;
    }

    NTSTATUS status = TdMemoryBreakpointVmcall(
        FALSE, entry->breakpoint_id, 0, 0, 0, 0, 0, 0, 0, 1);
    if (!NT_SUCCESS(status))
        return status;

    status = TdMemoryBreakpointBroadcast(
        FALSE, entry->breakpoint_id, 0, 0, 0, 0, 0, 0, 0);
    if (!NT_SUCCESS(status))
        return status;

    status = TdMemoryBreakpointVmcall(
        FALSE, entry->breakpoint_id, 0, 0, 0, 0, 0, 0, 0, 2);
    if (!NT_SUCCESS(status))
        return status;

    TdMemoryBreakpointReleaseEntry(entry);
    return status;
}

NTSTATUS
TdMemoryBreakpointSet(PTD_MEMORY_BREAKPOINT_REQUEST request)
{
    if (!request || request->target_pid == 0 || request->target_address < 0x10000 ||
        request->target_address >= 0x00007FFF00000000ULL || request->size == 0 ||
        request->size > PAGE_SIZE ||
        ((request->target_address & 0xFFF) + request->size) > PAGE_SIZE ||
        request->access == 0 || (request->access & ~0x07) != 0 ||
        (request->flags & ~TD_BP_FLAG_ONESHOT) != 0)
        return STATUS_INVALID_PARAMETER;

    if (!TdOphionAlive() && !(TdVbxCmdReady() && !g_fUseOphionPlane))
        return STATUS_DEVICE_NOT_READY;

    ExAcquireFastMutex(&g_memory_breakpoint_mutex);

    PTD_MEMORY_BREAKPOINT_ENTRY slot = NULL;
    for (UINT32 i = 0; i < TD_MAX_MEMORY_BREAKPOINTS; ++i)
    {
        if (!g_memory_breakpoints[i].active)
        {
            slot = &g_memory_breakpoints[i];
            break;
        }
    }
    if (!slot)
    {
        ExReleaseFastMutex(&g_memory_breakpoint_mutex);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)request->target_pid, &process);
    if (!NT_SUCCESS(status))
    {
        ExReleaseFastMutex(&g_memory_breakpoint_mutex);
        return status;
    }

    PMDL mdl = IoAllocateMdl(
        (PVOID)(ULONG_PTR)request->target_address,
        request->size, FALSE, FALSE, NULL);
    if (!mdl)
    {
        ObDereferenceObject(process);
        ExReleaseFastMutex(&g_memory_breakpoint_mutex);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KAPC_STATE apc = {};
    BOOLEAN attached = FALSE;
    BOOLEAN pages_locked = FALSE;
    UINT64 target_cr3 = 0;
    UINT64 target_physical = 0;
    __try
    {
        KeStackAttachProcess(process, &apc);
        attached = TRUE;
        MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
        pages_locked = TRUE;
        target_cr3 = __readcr3() & 0x000FFFFFFFFFF000ULL;
        target_physical = MmGetPhysicalAddress(
            (PVOID)(ULONG_PTR)request->target_address).QuadPart;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = GetExceptionCode();
    }
    if (attached)
        KeUnstackDetachProcess(&apc);
    ObDereferenceObject(process);

    if (!pages_locked || !target_cr3 || !target_physical)
    {
        if (pages_locked)
            MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        ExReleaseFastMutex(&g_memory_breakpoint_mutex);
        return NT_SUCCESS(status) ? STATUS_NOT_MAPPED_VIEW : status;
    }

    UINT64 breakpoint_id = (UINT64)InterlockedIncrement64(
        &g_memory_breakpoint_next_id);

    // Publish the driver-side record before touching any EPT.  If a later
    // cross-CPU operation only partially succeeds, this keeps the MDL pinned
    // and leaves a stable id that cleanup/clear can retry.
    RtlZeroMemory(slot, sizeof(*slot));
    slot->active = TRUE;
    slot->breakpoint_id = breakpoint_id;
    slot->target_pid = request->target_pid;
    slot->target_address = request->target_address;
    slot->target_cr3 = target_cr3;
    slot->target_physical = target_physical;
    slot->size = request->size;
    slot->access = request->access;
    slot->flags = request->flags;
    slot->mdl = mdl;
    slot->f_vbox_backend = TdVbxCmdReady() && !g_fUseOphionPlane;
    request->breakpoint_id = breakpoint_id;

    if (TdVbxCmdReady() && !g_fUseOphionPlane)
    {
        // T4: one transactional BP_INSTALL on the VBox plane; the VMM handles
        // every vCPU (no DPC broadcast needed).
        status = TdVbxBpInstall(target_physical & ~0xFFFull,
                                (UINT32)(target_physical & 0xFFF), request->size,
                                request->access,
                                (request->flags & TD_BP_FLAG_ONESHOT) ? 1u : 0u,
                                target_cr3, &slot->vbox_id_hook, &slot->vbox_generation);
    }
    else
    {
        status = TdMemoryBreakpointVmcall(
            TRUE, breakpoint_id, request->target_pid, target_cr3, request->target_address,
            target_physical, request->size, request->access, request->flags, 1);
        if (NT_SUCCESS(status))
        {
            status = TdMemoryBreakpointBroadcast(
                TRUE, breakpoint_id, request->target_pid, target_cr3, request->target_address,
                target_physical, request->size, request->access, request->flags);
        }
    }
    BOOLEAN record_created = NT_SUCCESS(status);

    if (!NT_SUCCESS(status))
    {
        if (!record_created)
        {
            // No hypervisor record exists, so no vCPU can still reference it.
            TdMemoryBreakpointReleaseEntry(slot);
        }
        else
        {
            // ClearLocked releases the MDL only after every vCPU restored the
            // effective EPT permissions and the core metadata was finalized.
            // On rollback failure the entry intentionally remains active and
            // pinned, allowing CLEAR/CLEAR_ALL to retry by breakpoint_id.
            TdMemoryBreakpointClearLocked(slot, TRUE);
        }
        ExReleaseFastMutex(&g_memory_breakpoint_mutex);
        return status;
    }
    ExReleaseFastMutex(&g_memory_breakpoint_mutex);

    HYPERPLATFORM_LOG_INFO(
        "[td-bp] set id=%llu pid=%llu va=%llX pa=%llX size=%u access=%X mode=%s",
        breakpoint_id, request->target_pid, request->target_address,
        target_physical, request->size, request->access,
        (request->flags & TD_BP_FLAG_ONESHOT) ? "once" : "permanent");
    return STATUS_SUCCESS;
}

NTSTATUS
TdMemoryBreakpointClear(UINT64 breakpoint_id, BOOLEAN issue_vmcalls)
{
    ExAcquireFastMutex(&g_memory_breakpoint_mutex);
    NTSTATUS status = STATUS_NOT_FOUND;
    for (UINT32 i = 0; i < TD_MAX_MEMORY_BREAKPOINTS; ++i)
    {
        PTD_MEMORY_BREAKPOINT_ENTRY entry = &g_memory_breakpoints[i];
        if (entry->active && entry->breakpoint_id == breakpoint_id)
        {
            status = TdMemoryBreakpointClearLocked(entry, issue_vmcalls);
            break;
        }
    }
    ExReleaseFastMutex(&g_memory_breakpoint_mutex);
    return status;
}

VOID
TdMemoryBreakpointCleanupProcess(UINT64 pid)
{
    ExAcquireFastMutex(&g_memory_breakpoint_mutex);
    BOOLEAN issue_vmcalls = TdOphionAlive();
    for (UINT32 i = 0; i < TD_MAX_MEMORY_BREAKPOINTS; ++i)
    {
        PTD_MEMORY_BREAKPOINT_ENTRY entry = &g_memory_breakpoints[i];
        if (entry->active && entry->target_pid == pid)
            TdMemoryBreakpointClearLocked(entry, issue_vmcalls);
    }
    ExReleaseFastMutex(&g_memory_breakpoint_mutex);
}

NTSTATUS
TdMemoryBreakpointCleanupAll(BOOLEAN issue_vmcalls)
{
    NTSTATUS first_status = STATUS_SUCCESS;
    ExAcquireFastMutex(&g_memory_breakpoint_mutex);
    for (UINT32 i = 0; i < TD_MAX_MEMORY_BREAKPOINTS; ++i)
    {
        if (g_memory_breakpoints[i].active)
        {
            NTSTATUS status = TdMemoryBreakpointClearLocked(
                &g_memory_breakpoints[i], issue_vmcalls);
            if (NT_SUCCESS(first_status) && !NT_SUCCESS(status))
                first_status = status;
        }
    }
    ExReleaseFastMutex(&g_memory_breakpoint_mutex);
    return first_status;
}

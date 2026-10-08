#include "OphionMemoryBreakpoint.h"
#include "ntapi.h"

#include <intrin.h>

extern "C" unsigned __int64 __vm_call(
    unsigned __int64 reason,
    unsigned __int64 rdx,
    unsigned __int64 r8,
    unsigned __int64 r9);
extern "C" unsigned __int64 __vm_call_ex(
    unsigned __int64 reason,
    unsigned __int64 rdx,
    unsigned __int64 r8,
    unsigned __int64 r9,
    unsigned __int64 r10,
    unsigned __int64 r11,
    unsigned __int64 r12,
    unsigned __int64 r13,
    unsigned __int64 r14,
    unsigned __int64 r15);

namespace
{
    constexpr UINT64 kVmcallTest = 0x01;
    constexpr UINT64 kVmcallSet = 0x18;
    constexpr UINT64 kVmcallClear = 0x19;
    constexpr UINT32 kMaximumBreakpoints = 64;

    struct BreakpointEntry
    {
        BOOLEAN active;
        UINT64 id;
        UINT64 target_pid;
        UINT64 target_address;
        UINT64 target_cr3;
        UINT64 target_physical;
        UINT32 size;
        UINT8 access;
        UINT8 flags;
        PMDL mdl;
    };

    struct BroadcastContext
    {
        BOOLEAN set_operation;
        UINT64 id;
        UINT64 target_pid;
        UINT64 target_cr3;
        UINT64 target_address;
        UINT64 target_physical;
        UINT32 size;
        UINT8 access;
        UINT8 flags;
        volatile LONG failure_count;
        volatile LONG first_failure;
    };

    FAST_MUTEX g_mutex;
    BreakpointEntry g_breakpoints[kMaximumBreakpoints] = {};
    volatile LONG64 g_next_id = 0;

    NTSTATUS Vmcall(
        BOOLEAN set_operation,
        UINT64 id,
        UINT64 target_pid,
        UINT64 target_cr3,
        UINT64 target_address,
        UINT64 target_physical,
        UINT32 size,
        UINT8 access,
        UINT8 flags,
        UINT8 record_operation)
    {
        __try
        {
            if (set_operation)
            {
                return static_cast<NTSTATUS>(__vm_call_ex(
                    kVmcallSet, id, target_cr3, target_address,
                    target_physical, size, access, flags,
                    record_operation ? 1 : 0, target_pid));
            }

            return static_cast<NTSTATUS>(__vm_call_ex(
                kVmcallClear, id, record_operation,
                0, 0, 0, 0, 0, 0, 0));
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return GetExceptionCode();
        }
    }

    VOID BroadcastDpc(
        PKDPC dpc,
        PVOID deferred_context,
        PVOID system_argument1,
        PVOID system_argument2)
    {
        UNREFERENCED_PARAMETER(dpc);
        auto context = static_cast<BroadcastContext*>(deferred_context);
        const NTSTATUS status = Vmcall(
            context->set_operation, context->id, context->target_pid,
            context->target_cr3, context->target_address,
            context->target_physical, context->size, context->access,
            context->flags, 0);
        if (!NT_SUCCESS(status))
        {
            InterlockedIncrement(&context->failure_count);
            InterlockedCompareExchange(
                &context->first_failure, static_cast<LONG>(status), STATUS_SUCCESS);
        }
        KeSignalCallDpcSynchronize(system_argument2);
        KeSignalCallDpcDone(system_argument1);
    }

    NTSTATUS Broadcast(
        BOOLEAN set_operation,
        UINT64 id,
        UINT64 target_pid,
        UINT64 target_cr3,
        UINT64 target_address,
        UINT64 target_physical,
        UINT32 size,
        UINT8 access,
        UINT8 flags)
    {
        BroadcastContext context = {};
        context.set_operation = set_operation;
        context.id = id;
        context.target_pid = target_pid;
        context.target_cr3 = target_cr3;
        context.target_address = target_address;
        context.target_physical = target_physical;
        context.size = size;
        context.access = access;
        context.flags = flags;
        context.first_failure = STATUS_SUCCESS;
        KeGenericCallDpc(BroadcastDpc, &context);
        return context.failure_count == 0
            ? STATUS_SUCCESS
            : static_cast<NTSTATUS>(context.first_failure);
    }

    VOID Release(BreakpointEntry* entry)
    {
        if (entry->mdl)
        {
            MmUnlockPages(entry->mdl);
            IoFreeMdl(entry->mdl);
        }
        RtlZeroMemory(entry, sizeof(*entry));
    }

    NTSTATUS ClearLocked(BreakpointEntry* entry, BOOLEAN issue_vmcalls)
    {
        if (!entry || !entry->active)
            return STATUS_NOT_FOUND;
        if (!issue_vmcalls)
        {
            Release(entry);
            return STATUS_SUCCESS;
        }

        NTSTATUS status = Vmcall(FALSE, entry->id, 0, 0, 0, 0, 0, 0, 0, 1);
        if (!NT_SUCCESS(status))
            return status;
        status = Broadcast(FALSE, entry->id, 0, 0, 0, 0, 0, 0, 0);
        if (!NT_SUCCESS(status))
            return status;
        status = Vmcall(FALSE, entry->id, 0, 0, 0, 0, 0, 0, 0, 2);
        if (NT_SUCCESS(status))
            Release(entry);
        return status;
    }
}

VOID OphionMemoryBreakpointInitialize()
{
    ExInitializeFastMutex(&g_mutex);
    RtlZeroMemory(g_breakpoints, sizeof(g_breakpoints));
    InterlockedExchange64(&g_next_id, 0);
}

BOOLEAN OphionMemoryBreakpointAvailable()
{
    __try
    {
        return NT_SUCCESS(static_cast<NTSTATUS>(__vm_call(kVmcallTest, 0, 0, 0)));
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
}

NTSTATUS OphionMemoryBreakpointSet(
    ULONG target_pid,
    UINT64 target_address,
    UINT32 size,
    UINT8 access,
    UINT8 flags,
    UINT64* breakpoint_id,
    UINT64* target_cr3_out)
{
    if (!breakpoint_id || !target_cr3_out || !target_pid ||
        target_address < 0x10000 ||
        target_address > reinterpret_cast<UINT64>(MmHighestUserAddress) ||
        !size || size > PAGE_SIZE ||
        ((target_address & (PAGE_SIZE - 1)) + size) > PAGE_SIZE ||
        !access || (access & ~0x07) || (flags & ~OPHION_BP_FLAG_ONESHOT))
        return STATUS_INVALID_PARAMETER;
    if (!OphionMemoryBreakpointAvailable())
        return STATUS_DEVICE_NOT_READY;

    ExAcquireFastMutex(&g_mutex);
    BreakpointEntry* slot = nullptr;
    for (auto& entry : g_breakpoints)
    {
        if (!entry.active)
        {
            slot = &entry;
            break;
        }
    }
    if (!slot)
    {
        ExReleaseFastMutex(&g_mutex);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PEPROCESS process = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId(
        reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(target_pid)), &process);
    if (!NT_SUCCESS(status))
    {
        ExReleaseFastMutex(&g_mutex);
        return status;
    }

    PMDL mdl = IoAllocateMdl(
        reinterpret_cast<PVOID>(target_address), size, FALSE, FALSE, nullptr);
    if (!mdl)
    {
        ObDereferenceObject(process);
        ExReleaseFastMutex(&g_mutex);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KAPC_STATE apc = {};
    BOOLEAN attached = FALSE;
    BOOLEAN locked = FALSE;
    UINT64 target_cr3 = 0;
    UINT64 target_physical = 0;
    __try
    {
        KeStackAttachProcess(process, &apc);
        attached = TRUE;
        MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
        locked = TRUE;
        target_cr3 = __readcr3() & 0x000FFFFFFFFFF000ULL;
        target_physical = MmGetPhysicalAddress(
            reinterpret_cast<PVOID>(target_address)).QuadPart;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = GetExceptionCode();
    }
    if (attached)
        KeUnstackDetachProcess(&apc);
    ObDereferenceObject(process);

    if (!locked || !target_cr3 || !target_physical)
    {
        if (locked)
            MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        ExReleaseFastMutex(&g_mutex);
        return NT_SUCCESS(status) ? STATUS_NOT_MAPPED_VIEW : status;
    }

    const UINT64 id = static_cast<UINT64>(InterlockedIncrement64(&g_next_id));
    RtlZeroMemory(slot, sizeof(*slot));
    slot->active = TRUE;
    slot->id = id;
    slot->target_pid = target_pid;
    slot->target_address = target_address;
    slot->target_cr3 = target_cr3;
    slot->target_physical = target_physical;
    slot->size = size;
    slot->access = access;
    slot->flags = flags;
    slot->mdl = mdl;

    status = Vmcall(
        TRUE, id, target_pid, target_cr3, target_address,
        target_physical, size, access, flags, 1);
    const BOOLEAN record_created = NT_SUCCESS(status);
    if (record_created)
    {
        status = Broadcast(
            TRUE, id, target_pid, target_cr3, target_address,
            target_physical, size, access, flags);
    }
    if (!NT_SUCCESS(status))
    {
        if (record_created)
            ClearLocked(slot, TRUE);
        else
            Release(slot);
        ExReleaseFastMutex(&g_mutex);
        return status;
    }

    *breakpoint_id = id;
    *target_cr3_out = target_cr3;
    ExReleaseFastMutex(&g_mutex);
    return STATUS_SUCCESS;
}

NTSTATUS OphionMemoryBreakpointClear(UINT64 breakpoint_id)
{
    ExAcquireFastMutex(&g_mutex);
    NTSTATUS status = STATUS_NOT_FOUND;
    for (auto& entry : g_breakpoints)
    {
        if (entry.active && entry.id == breakpoint_id)
        {
            status = ClearLocked(&entry, TRUE);
            break;
        }
    }
    ExReleaseFastMutex(&g_mutex);
    return status;
}

VOID OphionMemoryBreakpointCleanupAll(BOOLEAN issue_vmcalls)
{
    ExAcquireFastMutex(&g_mutex);
    for (auto& entry : g_breakpoints)
    {
        if (entry.active)
            ClearLocked(&entry, issue_vmcalls);
    }
    ExReleaseFastMutex(&g_mutex);
}

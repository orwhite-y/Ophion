/*
*   td_remote_call.cpp - ring-3 callable "remote call" via the VirtualBox
*   defeat/v1 EPT-hook runtime plane (VBoxInternal/EptHook/Runtime = 1).
*
*   IOCTL contract: see TD_REMOTE_CALL_PARAMS in td_common.h.
*   VMM ABI:        VBox include/VBox/vmm/EptHook.h (rax = 'EPTH' | op << 32).
*
*   Flow per call:
*     1. attach target, resolve ntdll trigger (NtTestAlert) via PEB
*     2. allocate one PAGE_READWRITE page as the parameter block
*       block+0x00: TD_REMOTE_CALL_BLOCK_MAGIC   block+0x08: arg_count
*       block+0x10: arg[0..arg_count-1]
*     3. VMCALL INSTALL_JUMP { trigger page GPA, trigger VA, cookie = block VA,
*        function VA } - the VMM execute-traps the trigger page and, on the
*        thread's first fetch (RCX == cookie), redirects RIP to function_va
*        with RCX still = block.  Oneshot, invisible to the guest.
*     4. create thread SUSPENDED at the trigger (lpParameter = block) and
*        resume it; the function returns into RtlUserThreadStart, so its RAX
*        becomes the thread exit code
*     5. if wait_ms: wait, read exit code, VMCALL REMOVE_JUMP, free block
*        if 0: fire-and-forget (hook + block stay until the call fires)
*/

#include "td_common.h"

// ---- VBox EptHook.h ABI (kept in sync manually) ----
#define EPTH_VMCALL_MAGIC           0x0000000045505448ULL   /* 'EPTH' */
#define EPTH_OP_INSTALL_JUMP        1
#define EPTH_OP_REMOVE_JUMP         2
#define EPTH_OP_QUERY_JUMP          3

// VERR_* values as the VMM returns them: rax = (uint32_t)VERR_x, zero extended.
#define EPTH_VERR_INVALID_PARAMETER 0x00000000FFFFFFFEULL    // VERR_INVALID_PARAMETER (-2)

EXTERN_C UINT64 TdVmcallEptAsm(UINT64 op, UINT64 arg0, UINT64 arg1,
                               UINT64 arg2, UINT64 arg3, UINT64 * out_result);

extern "C" NTKERNELAPI LONG PsGetThreadExitStatus(PETHREAD Thread);

// 0 = unknown, 1 = plane available, -1 = absent (no defeat/v1 VMM or Runtime=0)
static volatile LONG g_vbox_plane_state = 0;

//
// Issues one control-plane VMCALL under SEH.  A VMM without the plane
// delivers #UD (hypercall gate) - caught here instead of bugchecking.
// Returns STATUS_SUCCESS only when the VMM answered 0; raw VMM status is
// reported through out_raw for diagnostics.
//
static NTSTATUS TdRcVmcall(UINT32 op, UINT64 arg0, UINT64 arg1, UINT64 arg2,
                           UINT64 arg3, UINT64 * out_result, UINT64 * out_raw)
{
    UINT64 result = 0;
    UINT64 raw = 0;
    __try {
        raw = TdVmcallEptAsm(op, arg0, arg1, arg2, arg3, &result);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_NOT_SUPPORTED;
    }
    if (out_raw)
        *out_raw = raw;
    if (out_result)
        *out_result = result;
    return raw == 0 ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

//
// One-shot probe: INSTALL with arg1 == 0 is rejected by the VMM with
// VERR_INVALID_PARAMETER before touching any hook state - a deterministic
// signature that the defeat/v1 plane is alive.
//
VOID TdRemoteCallProbe(VOID)
{
    if (g_vbox_plane_state != 0)
        return;

    UINT64 raw = 0;
    NTSTATUS st = TdRcVmcall(EPTH_OP_INSTALL_JUMP, 0x1000, 0, 0, 0, NULL, &raw);
    LONG state = (st == STATUS_UNSUCCESSFUL && raw == EPTH_VERR_INVALID_PARAMETER) ? 1 : -1;
    InterlockedCompareExchange(&g_vbox_plane_state, state, 0);
    HYPERPLATFORM_LOG_INFO("[td-rc] probe: st=0x%08X raw=0x%llX -> plane %s\n",
               st, raw, state == 1 ? "AVAILABLE" : "ABSENT");
}

BOOLEAN TdRemoteCallPlaneAvailable(VOID)
{
    return g_vbox_plane_state == 1;
}

//
// Creates a suspended thread at trigger in the attached target process.
// Primary path ZwCreateThreadEx (system-wide handle), fallback
// RtlCreateUserThread (process-relative, caller must be attached).
//
static NTSTATUS TdRcCreateThread(PEPROCESS proc, PVOID trigger, PVOID param,
                                 HANDLE * out_handle, UINT64 * out_tid)
{
    *out_handle = NULL;
    *out_tid = 0;

    if (g_pZwCreateThreadEx)
    {
        HANDLE proc_h = NULL;
        NTSTATUS st = ObOpenObjectByPointer(proc, OBJ_KERNEL_HANDLE, NULL,
                                            PROCESS_ALL_ACCESS, *PsProcessType,
                                            KernelMode, &proc_h);
        if (!NT_SUCCESS(st))
            return st;

        HANDLE th = NULL;
        st = g_pZwCreateThreadEx(&th, THREAD_ALL_ACCESS, NULL, proc_h,
                                 trigger, param, THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
                                 0, 0, 0, NULL);
        ZwClose(proc_h);
        if (!NT_SUCCESS(st) || !th)
            return NT_SUCCESS(st) ? STATUS_UNSUCCESSFUL : st;

        HANDLE kh = NULL;
        UINT64 tid = 0;
        st = TdMakeKernelThreadHandle(th, &kh, &tid);
        ZwClose(th);
        if (!NT_SUCCESS(st) || !kh || !tid)
        {
            if (kh)
                ZwClose(kh);
            return NT_SUCCESS(st) ? STATUS_UNSUCCESSFUL : st;
        }
        *out_handle = kh;
        *out_tid = tid;
        return STATUS_SUCCESS;
    }

    HANDLE th = NULL;
    CLIENT_ID cid = {};
    NTSTATUS st = RtlCreateUserThread(ZwCurrentProcess(), NULL, TRUE, 0, 0, 0,
                                      trigger, param, &th, &cid);
    if (!NT_SUCCESS(st) || !th)
        return NT_SUCCESS(st) ? STATUS_UNSUCCESSFUL : st;

    HANDLE kh = NULL;
    UINT64 tid = (UINT64)(ULONG_PTR)cid.UniqueThread;
    st = TdMakeKernelThreadHandle(th, &kh, &tid);
    ZwClose(th);
    if (!NT_SUCCESS(st) || !kh || !tid)
    {
        if (kh)
            ZwClose(kh);
        return NT_SUCCESS(st) ? STATUS_UNSUCCESSFUL : st;
    }
    *out_handle = kh;
    *out_tid = tid;
    return STATUS_SUCCESS;
}

//
// IOCTL_REMOTE_CALL worker.  request is the METHOD_BUFFERED system buffer
// (in/out); request->status receives the final NTSTATUS.
//
NTSTATUS TdRemoteCall(PTD_REMOTE_CALL_PARAMS request)
{
    if (!request)
        return STATUS_INVALID_PARAMETER;
    if (request->flags != 0)
        return STATUS_INVALID_PARAMETER;
    if (request->arg_count > TD_REMOTE_CALL_MAX_ARGS)
        return STATUS_INVALID_PARAMETER;
    if (!request->function_va || request->function_va >= 0x800000000000ull)
        return STATUS_INVALID_PARAMETER;    // user-mode VAs only

    TdRemoteCallProbe();
    if (!TdRemoteCallPlaneAvailable())
    {
        request->status = (UINT32)STATUS_NOT_SUPPORTED;
        return STATUS_NOT_SUPPORTED;
    }

    PEPROCESS proc = NULL;
    BOOLEAN referenced = FALSE;
    if (request->target_pid)
    {
        NTSTATUS st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)request->target_pid, &proc);
        if (!NT_SUCCESS(st))
        {
            request->status = (UINT32)st;
            return st;
        }
        referenced = TRUE;
    }
    else
    {
        proc = PsGetCurrentProcess();
    }

    KAPC_STATE apc;
    NTSTATUS st = STATUS_UNSUCCESSFUL;
    PVOID block = NULL;
    HANDLE thread_h = NULL;
    BOOLEAN thread_resumed = FALSE;
    BOOLEAN armed = FALSE;
    SIZE_T block_size = 0;

    KeStackAttachProcess(proc, &apc);

    for (;;)
    {
        PVOID trigger = TdResolveDefaultTrigger(proc, "td-rc");
        if (!trigger)
        {
            st = STATUS_NOT_FOUND;
            break;
        }
        request->trigger_va = (UINT64)(ULONG_PTR)trigger;

        block_size = PAGE_SIZE;
        st = ZwAllocateVirtualMemory(ZwCurrentProcess(), &block, 0, &block_size,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!NT_SUCCESS(st))
        {
            block = NULL;
            break;
        }
        request->param_block_va = (UINT64)(ULONG_PTR)block;

        __try {
            PUINT64 b = (PUINT64)block;
            b[0] = TD_REMOTE_CALL_BLOCK_MAGIC;
            b[1] = request->arg_count;
            for (UINT32 i = 0; i < request->arg_count; i++)
                b[2 + i] = request->arg[i];
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            st = STATUS_ACCESS_VIOLATION;
            break;
        }

        UINT64 const trig_gpa = MmGetPhysicalAddress(trigger).QuadPart & ~0xFFFull;
        UINT64 const blk_gpa  = MmGetPhysicalAddress(block).QuadPart & ~0xFFFull;
        if (!trig_gpa || !blk_gpa)
        {
            st = STATUS_INVALID_ADDRESS;
            break;
        }

        UINT64 raw = 0;
        UINT64 result = 0;
        st = TdRcVmcall(EPTH_OP_INSTALL_JUMP, trig_gpa, (UINT64)(ULONG_PTR)trigger,
                        (UINT64)(ULONG_PTR)block, request->function_va,
                        &result, &raw);
        request->vbox_status = raw;
        if (!NT_SUCCESS(st))
            break;
        armed = TRUE;

        UINT64 tid = 0;
        st = TdRcCreateThread(proc, trigger, block, &thread_h, &tid);
        if (!NT_SUCCESS(st))
            break;

        st = TdResumeThreadHandle(thread_h, NULL);
        if (!NT_SUCCESS(st))
            break;
        thread_resumed = TRUE;

        if (request->wait_ms == 0)
        {
            // Fire-and-forget: the armed hook and the parameter block stay
            // until the call fires (the VMM disarms itself on the hit).
            block = NULL;
            st = STATUS_SUCCESS;
            break;
        }

        PETHREAD thread = NULL;
        NTSTATUS ref_st = ObReferenceObjectByHandle(thread_h, 0, *PsThreadType,
                                                    KernelMode, (PVOID *)&thread, NULL);
        if (!NT_SUCCESS(ref_st) || !thread)
        {
            st = NT_SUCCESS(ref_st) ? STATUS_UNSUCCESSFUL : ref_st;
            break;
        }

        LARGE_INTEGER timeout;
        PLARGE_INTEGER timeout_ptr = NULL;   // NULL = infinite
        if (request->wait_ms < 0x7FFFFFFFFFFFFFFFull)
        {
            timeout.QuadPart = -1LL * (LONGLONG)request->wait_ms * 10000LL;
            timeout_ptr = &timeout;
        }
        NTSTATUS wait_st = KeWaitForSingleObject(thread, Executive, KernelMode, FALSE, timeout_ptr);
        if (wait_st == STATUS_SUCCESS)
        {
            request->thread_exit_code = (UINT64)(ULONG)PsGetThreadExitStatus(thread);
            UINT64 rm_raw = 0;
            TdRcVmcall(EPTH_OP_REMOVE_JUMP, trig_gpa, 0, 0, 0, NULL, &rm_raw);
            armed = FALSE;
            ZwFreeVirtualMemory(ZwCurrentProcess(), &block, &block_size, MEM_RELEASE);
            block = NULL;
            st = STATUS_SUCCESS;
        }
        else
        {
            // Timed out: leave the hook armed and the block alive - the call
            // may still fire after this returns.  Caller re-runs with a wait
            // to pick up the exit code, or cleans the process up.
            st = wait_st;
        }
        ObDereferenceObject(thread);
        break;
    }

    if (thread_h)
    {
        if (!thread_resumed && armed)
        {
            // Thread never got started: disarm so the page is not left trapped.
            UINT64 trig_gpa = 0;
            if (request->trigger_va)
                trig_gpa = MmGetPhysicalAddress((PVOID)(ULONG_PTR)request->trigger_va).QuadPart & ~0xFFFull;
            if (trig_gpa)
            {
                UINT64 rm_raw = 0;
                TdRcVmcall(EPTH_OP_REMOVE_JUMP, trig_gpa, 0, 0, 0, NULL, &rm_raw);
            }
            armed = FALSE;
        }
        TdCloseCreatedThreadHandle(thread_h, thread_resumed ? TRUE : FALSE);
        thread_h = NULL;
    }

    if (block)
    {
        if (armed && request->trigger_va)
        {
            UINT64 trig_gpa = MmGetPhysicalAddress((PVOID)(ULONG_PTR)request->trigger_va).QuadPart & ~0xFFFull;
            if (trig_gpa)
            {
                UINT64 rm_raw = 0;
                TdRcVmcall(EPTH_OP_REMOVE_JUMP, trig_gpa, 0, 0, 0, NULL, &rm_raw);
            }
        }
        SIZE_T free_size = 0;
        PVOID free_base = block;
        ZwFreeVirtualMemory(ZwCurrentProcess(), &free_base, &free_size, MEM_RELEASE);
        block = NULL;
    }

    KeUnstackDetachProcess(&apc);

    if (referenced)
        ObDereferenceObject(proc);

    request->status = (UINT32)st;
    HYPERPLATFORM_LOG_INFO("[td-rc] pid=%llu fn=%llx block=%llx trig=%llx wait=%llu -> st=0x%08X vmm=0x%llX exit=%llx\n",
               (UINT64)request->target_pid, request->function_va,
               request->param_block_va, request->trigger_va, request->wait_ms,
               st, request->vbox_status, request->thread_exit_code);
    return st;
}

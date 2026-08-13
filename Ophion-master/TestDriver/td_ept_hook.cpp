#include "td_common.h"

// =========================================================================
//  EPT Hook: NtCreateFile
// =========================================================================

#define VMCALL_EPT_HOOK     0x00000003
#define VMCALL_EPT_UNHOOK   0x00000004

//
// original NtCreateFile pointer (set by hook install, used by proxy)
//

fn_NtCreateFile g_orig_NtCreateFile = NULL;
PVOID           g_hooked_target     = NULL;
volatile LONG   g_hook_log_count    = 0;

//
// proxy function 鈥?called instead of NtCreateFile when EPT hook is active.
// logs the file path via DbgPrint, then calls original via trampoline.
//
// Pid of the Box.exe process we injected via CreateFile("test"). Re-armed on
// process exit (TdProcessNotify / TdProcessNotifyLegacy) so every new Box.exe
// instance injects again, instead of the old driver-lifetime flag that only
// injected the very first one.
volatile LONG64 g_test_injected_pid = 0;

// Only Box.exe and PioneerGame.exe get detection/logging in HookedNtCreateFile;
// every other process is forwarded to the original NtCreateFile silently (the
// every-100th-call log was flooding every process on the system).
BOOLEAN TdIsTargetProcessName(PEPROCESS proc)
{
    if (!proc) return FALSE;
    PCHAR img = (PCHAR)proc + 0x5a8;   // EPROCESS->ImageFileName (Win10/11 offset)
    static const char kBox[] = "Box.exe";
    BOOLEAN m = TRUE;
    for (int i = 0; i < (int)(sizeof(kBox) - 1); i++)
        if ((img[i] | 0x20) != (kBox[i] | 0x20)) { m = FALSE; break; }
    if (m) return TRUE;
    static const char kPioneer[] = "PioneerGame.exe";
    m = TRUE;
    for (int i = 0; i < (int)(sizeof(kPioneer) - 1); i++)
        if ((img[i] | 0x20) != (kPioneer[i] | 0x20)) { m = FALSE; break; }
    return m;
}

NTSTATUS NTAPI
HookedNtCreateFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength)
{
    // Only Box.exe / PioneerGame.exe get detection + logging; everything else is
    // forwarded to the original NtCreateFile silently.
    if (!TdIsTargetProcessName(PsGetCurrentProcess()))
        goto call_original;

    //
    // 鍖归厤鏂囦欢鍚嶆槸鍚︿负 "test"锛岃Е鍙?renderdoc 娉ㄥ叆
    //
    if (ObjectAttributes && ObjectAttributes->ObjectName &&
        ObjectAttributes->ObjectName->Buffer && ObjectAttributes->ObjectName->Length >= 4 * sizeof(WCHAR))
    {
        USHORT name_len = ObjectAttributes->ObjectName->Length / sizeof(WCHAR);
        PWCHAR buf = ObjectAttributes->ObjectName->Buffer;
        // 涓嶅尯鍒嗗ぇ灏忓啓鍖归厤鏈熬鏂囦欢鍚嶆槸鍚︿负 "test"
        if (name_len >= 4 &&
            (buf[name_len - 4] == L't' || buf[name_len - 4] == L'T') &&
            (buf[name_len - 3] == L'e' || buf[name_len - 3] == L'E') &&
            (buf[name_len - 2] == L's' || buf[name_len - 2] == L'S') &&
            (buf[name_len - 1] == L't' || buf[name_len - 1] == L'T'))
        {
            // 纭鍓嶉潰鏄矾寰勫垎闅旂鎴栧紑澶达紙閬垮厤鍖归厤鍒?"test.exe" 绛夛級
            if (name_len == 4 || buf[name_len - 5] == L'\\')
            {
                HYPERPLATFORM_LOG_WARN_SAFE("[td-hook] CreateFile(\"test\") detected 鈥?triggering renderdoc injection!");

                PEPROCESS current_proc = PsGetCurrentProcess();
                HANDLE current_pid = PsGetProcessId(current_proc);

                // 妫€鏌ユ槸鍚︽槸 Box.exe
                BOOLEAN is_box = FALSE;
                {
                    static const char box_a[] = "Box.exe";
                    PCHAR img_name = (PCHAR)current_proc + 0x5a8;
                    BOOLEAN match = TRUE;
                    for (int i = 0; i < (int)(sizeof(box_a) - 1); i++)
                        if ((img_name[i] | 0x20) != (box_a[i] | 0x20)) { match = FALSE; break; }
                    is_box = match;
                }

                if (is_box)
                {
                    // 姣忎釜 Box.exe 杩涚▼鍙敞鍏ヤ竴娆? 璁板綍宸叉敞鍏ョ殑 pid;璇ヨ繘绋嬮€€鍑烘椂鍦?
                    // TdProcessNotify 閲岄噸缃?杩欐牱鍏抽棴 Box 鍐嶅紑鏂?Box 浼氶噸鏂版敞鍏?
                    // (鍘熸潵鐨?g_test_file_fired 鏄?driver 鐢熷懡鍛ㄦ湡 flag,鍙敞鍏ョ涓€娆?銆?
                    LONG64 prev_pid = _InterlockedExchange64(&g_test_injected_pid, (LONG64)current_pid);
                    if (prev_pid != (LONG64)current_pid)
                    {
                        HYPERPLATFORM_LOG_INFO("[td-hook] Box.exe pid=%llu 鈥?starting renderdoc inject via shadow CR3",
                            (UINT64)current_pid);

                        // 鐩存帴鐢ㄥ浐瀹氳矾寰?C:\Users\q\Desktop\d\renderdoc.dll
                        WCHAR renderdoc_path_buf[MAX_PATH];
                        static const WCHAR kRenderdocPath[] = L"\\??\\C:\\Users\\q\\Desktop\\d\\renderdoc.dll";
                        USHORT rd_len = (USHORT)((sizeof(kRenderdocPath) / sizeof(WCHAR)) - 1);
                        RtlCopyMemory(renderdoc_path_buf, kRenderdocPath, rd_len * sizeof(WCHAR));
                        renderdoc_path_buf[rd_len] = L'\0';

                        UNICODE_STRING renderdoc_nt;
                        RtlInitUnicodeString(&renderdoc_nt, renderdoc_path_buf);

                        NTSTATUS inj_st = TdInjectRenderdocShadow(
                            current_proc, &renderdoc_nt, "td-hook-shadow", TRUE);
                        if (!NT_SUCCESS(inj_st))
                        {
                            HYPERPLATFORM_LOG_ERROR("[td-hook] TdInjectRenderdocShadow failed: 0x%08X", inj_st);
                        }
                    }
                    else
                    {
                        HYPERPLATFORM_LOG_INFO("[td-hook] Box.exe pid=%llu already injected this process - skip",
                            (UINT64)current_pid);
                    }
                }
            }
        }
    }

    //
    // log every 100th call to avoid flooding DbgPrint
    //
    LONG count = _InterlockedIncrement(&g_hook_log_count);
    if ((count % 100) == 1 && ObjectAttributes && ObjectAttributes->ObjectName)
    {
        HYPERPLATFORM_LOG_INFO_SAFE("[td-hook] NtCreateFile #%d: %wZ",
                   count, ObjectAttributes->ObjectName);
    }

call_original:
    //
    // call original via trampoline
    //
    if (g_orig_NtCreateFile)
    {
        return g_orig_NtCreateFile(
            FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
            AllocationSize, FileAttributes, ShareAccess,
            CreateDisposition, CreateOptions, EaBuffer, EaLength);
    }

    return STATUS_UNSUCCESSFUL;
}

//
// DPC callback: each CPU issues VMCALL to install EPT hook
//
VOID
DpcEptHook(PKDPC Dpc, PVOID Ctx, PVOID A1, PVOID A2)
{
    UNREFERENCED_PARAMETER(Dpc);

    struct _EPT_HOOK_CTX {
        PVOID   target;
        PVOID   proxy;
        PVOID * origin;
        UINT64  caller_cr3;
        UINT32  hook_type;
        NTSTATUS result;
    } * ctx = (struct _EPT_HOOK_CTX *)Ctx;

    //
    // hv_vmcall_ex: rax = OPHION_VMCALL_ID
    //   rcx = VMCALL_EPT_HOOK
    //   rdx = target_function
    //   r8  = proxy_function
    //   r9  = &origin_function
    //   r10 = caller_cr3
    //   r11 = hook_type
    //   r12 = target_cr3 (0 = R0 hook)
    //   r13 = user_trampoline (NULL = kernel pool)
    //   r14 = user_trampoline_pa (0)
    //
    ctx->result = hv_vmcall_ex(
        VMCALL_EPT_HOOK,
        (UINT64)ctx->target,
        (UINT64)ctx->proxy,
        (UINT64)ctx->origin,
        ctx->caller_cr3,
        (UINT64)ctx->hook_type,
        0,   // target_cr3 = 0 (R0 hook, all processes)
        0,   // user_trampoline = NULL (use kernel pool)
        0,   // user_trampoline_pa = 0
        0);

    KeSignalCallDpcSynchronize(A2);
    KeSignalCallDpcDone(A1);
}

VOID
DpcEptUnhook(PKDPC Dpc, PVOID Ctx, PVOID A1, PVOID A2)
{
    UNREFERENCED_PARAMETER(Dpc);

    struct _EPT_UNHOOK_CTX {
        PVOID    target;
        UINT64   caller_cr3;
        NTSTATUS result;
    } * ctx = (struct _EPT_UNHOOK_CTX *)Ctx;

    ctx->result = hv_vmcall_ex(
        VMCALL_EPT_UNHOOK,
        (UINT64)ctx->target,
        0, 0,
        ctx->caller_cr3,
        0, 0, 0, 0, 0);

    KeSignalCallDpcSynchronize(A2);
    KeSignalCallDpcDone(A1);
}

// DPC broadcast for VMCALL_EPT_UNHOOK_BY_CR3. r10 (caller_cr3) = 0, so the HV
// does NOT __writecr3 -> safe to issue from the process-exit notify callback
// (where loading the dying CR3 on every CPU deadlocks). rdx = target_cr3,
// used only as a match value to retire this process's hooks.
VOID
DpcEptUnhookByCr3(PKDPC Dpc, PVOID Ctx, PVOID A1, PVOID A2)
{
    UNREFERENCED_PARAMETER(Dpc);

    struct _EPT_UNHOOK_BY_CR3_CTX {
        UINT64 target_cr3;
    } * ctx = (struct _EPT_UNHOOK_BY_CR3_CTX *)Ctx;

    hv_vmcall_ex(
        VMCALL_EPT_UNHOOK_BY_CR3,
        ctx->target_cr3,
        0, 0, 0,
        0, 0, 0, 0, 0);

    KeSignalCallDpcSynchronize(A2);
    KeSignalCallDpcDone(A1);
}

NTSTATUS
TdEptHookNtCreateFile(VOID)
{
    UNICODE_STRING fn_name;
    RtlInitUnicodeString(&fn_name, L"NtCreateFile");
    PVOID target = MmGetSystemRoutineAddress(&fn_name);
    if (!target)
    {
        HYPERPLATFORM_LOG_ERROR("[td] NtCreateFile not found");
        return STATUS_NOT_FOUND;
    }

    HYPERPLATFORM_LOG_INFO("[td] NtCreateFile = %p, proxy = %p", target, (PVOID)HookedNtCreateFile);

    struct {
        PVOID   target;
        PVOID   proxy;
        PVOID * origin;
        UINT64  caller_cr3;
        UINT32  hook_type;
        NTSTATUS result;
    } ctx = {};

    ctx.target     = target;
    ctx.proxy      = (PVOID)HookedNtCreateFile;
    ctx.origin     = (PVOID *)&g_orig_NtCreateFile;
    ctx.caller_cr3 = __readcr3();
    ctx.hook_type  = 0;   // absolute jump (14 bytes)

    KeGenericCallDpc(DpcEptHook, &ctx);

    if (NT_SUCCESS(ctx.result))
    {
        g_hooked_target = target;
        HYPERPLATFORM_LOG_INFO("[td] EPT hook installed! trampoline = %p", (PVOID)g_orig_NtCreateFile);
    }
    else
    {
        HYPERPLATFORM_LOG_ERROR("[td] EPT hook FAILED: 0x%08X", ctx.result);
    }

    return ctx.result;
}

NTSTATUS
TdEptUnhookNtCreateFile(VOID)
{
    if (!g_hooked_target)
        return STATUS_NOT_FOUND;

    struct {
        PVOID    target;
        UINT64   caller_cr3;
        NTSTATUS result;
    } ctx = {};

    ctx.target     = g_hooked_target;
    ctx.caller_cr3 = __readcr3();

    KeGenericCallDpc(DpcEptUnhook, &ctx);

    if (NT_SUCCESS(ctx.result))
    {
        HYPERPLATFORM_LOG_INFO("[td] EPT hook removed. total calls logged: %d", g_hook_log_count);
        g_hooked_target = NULL;
        g_orig_NtCreateFile = NULL;
        g_hook_log_count = 0;
    }
    else
    {
        HYPERPLATFORM_LOG_ERROR("[td] EPT unhook FAILED: 0x%08X", ctx.result);
    }

    return ctx.result;
}

// =========================================================================
//  R3 EPT Hook 閳?per-process, user-mode trampoline, MDL-locked
// =========================================================================

//
// tracking for active R3 hooks (simple array, max 16 concurrent R3 hooks)
//
#define MAX_R3_HOOKS 64


R3_HOOK_ENTRY g_r3_hooks[MAX_R3_HOOKS] = {};

R3_HOOK_ENTRY *
R3HookFindFree(VOID)
{
    for (int i = 0; i < MAX_R3_HOOKS; i++)
        if (!g_r3_hooks[i].active) return &g_r3_hooks[i];
    return NULL;
}

R3_HOOK_ENTRY *
R3HookFind(UINT64 pid, PVOID target_va)
{
    for (int i = 0; i < MAX_R3_HOOKS; i++)
        if (g_r3_hooks[i].active && g_r3_hooks[i].target_pid == pid &&
            g_r3_hooks[i].target_va == target_va)
            return &g_r3_hooks[i];
    return NULL;
}

//
// DPC callback for R3 EPT hook install
//
typedef struct _R3_HOOK_DPC_CTX {
    PVOID    target;
    PVOID    proxy;
    PVOID *  origin;
    UINT64   caller_cr3;
    UINT32   hook_type;
    UINT64   target_cr3;
    PVOID    user_trampoline;
    UINT64   user_trampoline_pa;
    UINT64   flags;             // bit 0 = force_read_access (shellcode self-read)
    UINT64   expected_tid;      // 0 = any thread
    NTSTATUS result;
} R3_HOOK_DPC_CTX;

VOID
DpcEptHookR3(PKDPC Dpc, PVOID Ctx, PVOID A1, PVOID A2)
{
    UNREFERENCED_PARAMETER(Dpc);
    R3_HOOK_DPC_CTX * ctx = (R3_HOOK_DPC_CTX *)Ctx;

    ctx->result = hv_vmcall_ex(
        VMCALL_EPT_HOOK,
        (UINT64)ctx->target,
        (UINT64)ctx->proxy,
        (UINT64)ctx->origin,
        ctx->caller_cr3,
        (UINT64)ctx->hook_type | (ctx->flags << 32),
        ctx->target_cr3,
        (UINT64)ctx->user_trampoline,
        ctx->user_trampoline_pa,
        ctx->expected_tid);

    KeSignalCallDpcSynchronize(A2);
    KeSignalCallDpcDone(A1);
}

#ifndef TD_MAX_DPC_CPUS
#define TD_MAX_DPC_CPUS 64
#endif
#define TD_PERCPU_VMCALL_TAG 'cVdT'



VOID
TdPerCpuVmcallDpc(PKDPC Dpc, PVOID Ctx, PVOID, PVOID)
{
    UNREFERENCED_PARAMETER(Dpc);
    TD_PERCPU_VMCALL_CTX * ctx = (TD_PERCPU_VMCALL_CTX *)Ctx;
    NTSTATUS st = STATUS_INVALID_DEVICE_REQUEST;

    if (ctx->op == TdPerCpuVmcallHookTrigger)
    {
        // Pack is_primary_cpu into flags (bit 2)
        UINT64 packed_flags = ctx->flags | ((ctx->is_primary_cpu ? 1ULL : 0ULL) << 2);

        st = hv_vmcall_ex(
            VMCALL_EPT_HOOK,
            (UINT64)ctx->target,
            (UINT64)ctx->proxy,
            (UINT64)ctx->origin,
            ctx->caller_cr3,
            (UINT64)ctx->hook_type | (packed_flags << 32),  // r11 = hook_type(low32) | flags(high32, bit 2 = is_primary_cpu)
            ctx->target_cr3,                        // r12 = target_cr3
            (UINT64)ctx->user_trampoline,           // r13 = user_trampoline
            ctx->user_trampoline_pa,                // r14 = user_trampoline_pa
            ctx->expected_tid);                     // r15 = expected_tid (full 64-bit)
    }
    else if (ctx->op == TdPerCpuVmcallUnhook)
    {
        st = hv_vmcall_ex(
            VMCALL_EPT_UNHOOK,
            (UINT64)ctx->target,
            0, 0,
            ctx->caller_cr3,
            0, 0, 0, 0, 0);
    }

    if (NT_SUCCESS(st))
    {
        _InterlockedIncrement(&ctx->success_count);
    }
    else
    {
        _InterlockedIncrement(&ctx->failure_count);
        _InterlockedCompareExchange(&ctx->first_failure, (LONG)st, (LONG)STATUS_SUCCESS);
    }

    if (_InterlockedDecrement(&ctx->pending_count) == 0)
        KeSetEvent(&ctx->done_event, IO_NO_INCREMENT, FALSE);
}

NTSTATUS
TdRunPerCpuVmcall(TD_PERCPU_VMCALL_CTX * ctx, ULONG timeout_ms)
{
    ULONG active_count = KeQueryActiveProcessorCount(NULL);
    if (active_count == 0)
        return STATUS_UNSUCCESSFUL;
    if (active_count > TD_MAX_DPC_CPUS)
        active_count = TD_MAX_DPC_CPUS;

    ctx->cpu_count = active_count;
    ctx->pending_count = (LONG)active_count;
    ctx->first_failure = STATUS_SUCCESS;
    KeInitializeEvent(&ctx->done_event, NotificationEvent, FALSE);

    for (ULONG cpu = 0; cpu < active_count; cpu++)
    {
        KeInitializeDpc(&ctx->dpcs[cpu], TdPerCpuVmcallDpc, ctx);
        KeSetTargetProcessorDpc(&ctx->dpcs[cpu], (CCHAR)cpu);
        if (!KeInsertQueueDpc(&ctx->dpcs[cpu], NULL, NULL))
        {
            _InterlockedIncrement(&ctx->failure_count);
            _InterlockedCompareExchange(&ctx->first_failure, (LONG)STATUS_UNSUCCESSFUL, (LONG)STATUS_SUCCESS);
            if (_InterlockedDecrement(&ctx->pending_count) == 0)
                KeSetEvent(&ctx->done_event, IO_NO_INCREMENT, FALSE);
        }
    }

    LARGE_INTEGER timeout;
    timeout.QuadPart = -((LONGLONG)timeout_ms * 10000LL);
    NTSTATUS wait_st = KeWaitForSingleObject(
        &ctx->done_event,
        Executive,
        KernelMode,
        FALSE,
        &timeout);

    if (wait_st == STATUS_TIMEOUT)
    {
        HYPERPLATFORM_LOG_ERROR("[td-rw] per-cpu vmcall timeout: op=%u done=%d/%u fail=%d",
            (UINT32)ctx->op,
            (LONG)(ctx->cpu_count - ctx->pending_count),
            ctx->cpu_count,
            ctx->failure_count);
        return STATUS_IO_TIMEOUT;
    }

    if (ctx->failure_count != 0)
        return (NTSTATUS)ctx->first_failure;
    return (ctx->success_count != 0) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

//
// Install EPT hook on all CPUs (optimized: primary then secondary)
// Phase 1: CPU 0 allocates resources
// Phase 2: Other CPUs modify EPT only (eliminates race conditions)
//
NTSTATUS
TdInstallTriggerHookAllCpus(
    PVOID   trigger_fn,
    PVOID   proxy_va,
    UINT64  caller_cr3,
    UINT64  flags,
    UINT64  expected_tid,
    PVOID * origin,
    volatile LONG * fired_signal)
{
    TD_PERCPU_VMCALL_CTX * ctx = (TD_PERCPU_VMCALL_CTX *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(TD_PERCPU_VMCALL_CTX), TD_PERCPU_VMCALL_TAG);
    if (!ctx)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(ctx, sizeof(*ctx));
    ctx->op         = TdPerCpuVmcallHookTrigger;
    ctx->target     = trigger_fn;
    ctx->proxy      = proxy_va;
    ctx->origin     = origin;
    ctx->caller_cr3 = caller_cr3;
    ctx->hook_type  = 1;          // VMCALL (0F 01 C1)
    ctx->target_cr3 = caller_cr3; // per-process filter
    ctx->flags      = (flags ? flags : 2);
    ctx->expected_tid = expected_tid;
    ctx->is_primary_cpu = TRUE;   // Phase 1: primary CPU

    //
    // Phase 1: Primary CPU (CPU 0) - allocate all resources
    //
    KAFFINITY old_affinity = KeSetSystemAffinityThreadEx(1);  // Pin to CPU 0
    NTSTATUS st = TdRunPerCpuVmcall(ctx, 2000);
    KeRevertToUserAffinityThreadEx(old_affinity);

    if (!NT_SUCCESS(st))
    {
        ExFreePoolWithTag(ctx, TD_PERCPU_VMCALL_TAG);
        HYPERPLATFORM_LOG_ERROR("[td-hook] Primary CPU hook failed: trigger=%p st=0x%08X",
            trigger_fn, st);
        return st;
    }

    HYPERPLATFORM_LOG_DEBUG("[td-hook] Primary CPU hook OK: trigger=%p", trigger_fn);

    //
    // Phase 2: Secondary CPUs - modify EPT only (parallel)
    //
    ctx->is_primary_cpu = FALSE;  // Phase 2: secondary CPUs

    ULONG cpu_count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    for (ULONG cpu = 1; cpu < cpu_count; cpu++)
    {
        old_affinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1ULL << cpu));
        NTSTATUS cpu_st = TdRunPerCpuVmcall(ctx, 2000);
        KeRevertToUserAffinityThreadEx(old_affinity);

        if (!NT_SUCCESS(cpu_st))
        {
            HYPERPLATFORM_LOG_WARN("[td-hook] Secondary CPU %u hook failed: trigger=%p st=0x%08X",
                cpu, trigger_fn, cpu_st);
            // Continue with other CPUs even if one fails
        }
    }

    ExFreePoolWithTag(ctx, TD_PERCPU_VMCALL_TAG);

    if (fired_signal)
    {
        NTSTATUS fired_st = hv_vmcall_ex(
            VMCALL_EPT_SET_EXTERNAL_FIRED,
            (UINT64)trigger_fn,
            (UINT64)fired_signal,
            caller_cr3,
            0, 0, 0, 0, 0, 0);
        if (!NT_SUCCESS(fired_st))
        {
            HYPERPLATFORM_LOG_ERROR("[td] TdInstallTriggerHookAllCpus: "
                "VMCALL_EPT_SET_EXTERNAL_FIRED failed for trigger=%p st=0x%08X",
                trigger_fn, fired_st);
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS
TdUnhookTriggerAllCpus(PVOID trigger_fn, UINT64 caller_cr3)
{
    TD_PERCPU_VMCALL_CTX * ctx = (TD_PERCPU_VMCALL_CTX *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(TD_PERCPU_VMCALL_CTX), TD_PERCPU_VMCALL_TAG);
    if (!ctx)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(ctx, sizeof(*ctx));
    ctx->op         = TdPerCpuVmcallUnhook;
    ctx->target     = trigger_fn;
    ctx->caller_cr3 = caller_cr3;

    NTSTATUS st = TdRunPerCpuVmcall(ctx, 1000);
    if (st != STATUS_IO_TIMEOUT)
        ExFreePoolWithTag(ctx, TD_PERCPU_VMCALL_TAG);
    return st;
}

//
// install R3 EPT hook on a function in a target process.
// must be called at PASSIVE_LEVEL.
//
NTSTATUS
TdEptHookR3(
    UINT64  target_pid,
    PVOID   target_va,
    PVOID   proxy_va,
    UINT32  hook_type,
    PVOID * out_trampoline)
{
    if (!target_va) return STATUS_INVALID_PARAMETER;

    R3_HOOK_ENTRY * entry = R3HookFindFree();
    if (!entry)
    {
        HYPERPLATFORM_LOG_ERROR("[td-r3] no free R3 hook slots");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // look up target process
    PEPROCESS proc = NULL;
    NTSTATUS st = PsLookupProcessByProcessId((HANDLE)target_pid, &proc);
    if (!NT_SUCCESS(st)) return st;

    KAPC_STATE apc;
    KeStackAttachProcess(proc, &apc);

    UINT64 target_cr3 = __readcr3();
    UINT64 caller_cr3 = target_cr3;

    //
    // 1. lock target page in physical memory via MDL
    //
    PVOID page_va = (PVOID)((UINT64)target_va & ~0xFFFULL);
    PMDL mdl = IoAllocateMdl(page_va, PAGE_SIZE, FALSE, FALSE, NULL);
    if (!mdl)
    {
        KeUnstackDetachProcess(&apc);
        ObDereferenceObject(proc);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {
        MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(mdl);
        KeUnstackDetachProcess(&apc);
        ObDereferenceObject(proc);
        HYPERPLATFORM_LOG_ERROR("[td-r3] MmProbeAndLockPages failed for %p", target_va);
        return STATUS_ACCESS_VIOLATION;
    }

    //
    // 2. allocate R3 trampoline in target process as PAGE_READWRITE (NX=1).
    // Stealth: no executable memory in the real PTE. The trampoline is made
    // executable only in the shadow CR3 (step 2.5 below), so scanners reading
    // the real CR3 see a non-executable private page. The proxy calls it under
    // the shadow CR3.
    //
    PVOID tramp_va = NULL;
    SIZE_T tramp_size = PAGE_SIZE;

    // Allocate trampoline within +/-2GB of target_va so RIP-relative
    // instruction relocation in hook_build_trampoline succeeds.
    // Scan free regions via ZwQueryVirtualMemory for nearest allocation.
    {
        UINT64 target_page = (UINT64)target_va & ~0xFFFULL;
        UINT64 best_addr = 0;
        INT64  best_dist = 0x7FFF0000LL;

        for (UINT64 off = 0x100000; off < 0x40000000ULL; off += 0x100000)
        {
            UINT64 addrs[2] = { target_page + off, target_page - off };
            for (int d = 0; d < 2; d++)
            {
                if (addrs[d] < 0x10000ULL || addrs[d] > 0x7FFFFFFFFFFFULL)
                    continue;
                MEMORY_BASIC_INFORMATION mbi;
                SIZE_T ret_len = 0;
                NTSTATUS qst = ZwQueryVirtualMemory(
                    ZwCurrentProcess(), (PVOID)addrs[d],
                    MemoryBasicInformation, &mbi, sizeof(mbi), &ret_len);
                if (!NT_SUCCESS(qst) || mbi.State != MEM_FREE)
                    continue;
                UINT64 free_base = ((UINT64)mbi.BaseAddress + 0xFFFF) & ~0xFFFFULL;
                UINT64 free_end  = (UINT64)mbi.BaseAddress + mbi.RegionSize;
                if (free_base + tramp_size > free_end)
                    continue;
                INT64 dist = (INT64)free_base - (INT64)target_va;
                if (dist < 0) dist = -dist;
                if (dist < best_dist) { best_dist = dist; best_addr = free_base; }
            }
            if (best_dist < 0x100000) break;
        }

        if (best_addr)
        {
            PVOID try_base = (PVOID)best_addr;
            SIZE_T try_size = tramp_size;
            st = ZwAllocateVirtualMemory(
                ZwCurrentProcess(), &try_base, 0, &try_size,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (NT_SUCCESS(st) && try_base)
                tramp_va = try_base;
        }

        if (!tramp_va)
        {
            tramp_va = NULL;
            st = ZwAllocateVirtualMemory(
                ZwCurrentProcess(), &tramp_va, 0, &tramp_size,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        }

        INT64 tramp_dist = tramp_va ? ((INT64)tramp_va - (INT64)target_va) : 0;
        if (tramp_dist < 0) tramp_dist = -tramp_dist;
        HYPERPLATFORM_LOG_INFO("[td-r3] tramp alloc: target=%p tramp=%p dist=0x%llX %s",
            target_va, tramp_va, (UINT64)tramp_dist,
            (UINT64)tramp_dist < 0x7FFF0000ULL ? "IN-RANGE" : "OUT-OF-RANGE");
    }

    if (!NT_SUCCESS(st) || !tramp_va)
    {
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        KeUnstackDetachProcess(&apc);
        ObDereferenceObject(proc);
        HYPERPLATFORM_LOG_ERROR("[td-r3] trampoline alloc failed: 0x%08X", st);
        return st;
    }

    RtlZeroMemory(tramp_va, tramp_size);
    UINT64 tramp_pa = MmGetPhysicalAddress(tramp_va).QuadPart;

    HYPERPLATFORM_LOG_INFO("[td-r3] target=%p proxy=%p tramp=%p(PA=%llx) cr3=%llx pid=%llu type=%u",
               target_va, proxy_va, tramp_va, tramp_pa, target_cr3, target_pid, hook_type);

    //
    // 2.5 shadow the trampoline page: clear NX in the process shadow CR3 so
    // the proxy can execute it, while the real PTE stays PAGE_READWRITE (NX=1)
    // for stealth. Done BEFORE the EPT-hook install so a shadow failure can
    // abort cleanly without leaving an installed hook. The HV writes the
    // trampoline content (saved bytes + jump) to the real page during the
    // VMCALL below; the shadow PTE aliases the same physical page, so the
    // content is visible under the shadow CR3.
    //
    {
        UINT64 existing_shadow = TdStealthFindShadowCr3ForPid(target_pid);
        UINT64 tramp_shadow = existing_shadow
            ? TdExtendShadowCR3(existing_shadow, caller_cr3, (UINT64)tramp_va, tramp_size)
            : TdBuildShadowCR3(caller_cr3, (UINT64)tramp_va, tramp_size);
        if (!tramp_shadow)
        {
            HYPERPLATFORM_LOG_ERROR("[td-r3] trampoline shadow CR3 failed (tramp=%p) - aborting hook",
                tramp_va);
            ZwFreeVirtualMemory(ZwCurrentProcess(), &tramp_va, &tramp_size, MEM_RELEASE);
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);
            KeUnstackDetachProcess(&apc);
            ObDereferenceObject(proc);
            return STATUS_UNSUCCESSFUL;
        }
        HYPERPLATFORM_LOG_INFO("[td-r3] trampoline shadowed: tramp=%p shadow=0x%llX (%s)",
            tramp_va, tramp_shadow, existing_shadow ? "extended" : "built");

        //
        // 2.6 register the trampoline as a stealth page (sp) so the HV #PF
        // handler (ept_stealth_handle_pf) activates the shadow CR3 window for
        // it. TdExtendShadowCR3/TdBuildShadowCR3 only fork the shadow PT and
        // clear NX on the shadow PTE -- they do NOT register an sp. The shadow
        // CR3 is per-instruction-on-demand, triggered by a #PF on a registered
        // sp (vmexit #PF -> ept_stealth_handle_pf -> sp match -> swap shadow
        // CR3 + MTF restore). Without an sp, the trampoline's NX-fetch #PF
        // (real PTE is PAGE_READWRITE, NX=1) is injected to the guest -> AV at
        // the trampoline (execute violation, op=8). The image pages work because
        // they go through TdStealthAllocPage (sp registered -> HV re-syncs the
        // shadow PTE via stealth_refresh_shadow_code_pte on #PF). Match that
        // here. no_ept_split=TRUE + shadow_cr3 -> TdResolveShadowPT computes
        // shadow_pte_va, which the HV writes (real_pte & ~NX) into on #PF.
        //
        {
            UINT64 pt_pfn = 0;
            UINT32 pt_idx = 0;
            if (!TdResolveGuestPT(caller_cr3, (UINT64)tramp_va, &pt_pfn, &pt_idx))
            {
                HYPERPLATFORM_LOG_ERROR(
                    "[td-r3] trampoline stealth PT resolve failed (tramp=%p) - aborting hook",
                    tramp_va);
                ZwFreeVirtualMemory(ZwCurrentProcess(), &tramp_va, &tramp_size, MEM_RELEASE);
                MmUnlockPages(mdl);
                IoFreeMdl(mdl);
                KeUnstackDetachProcess(&apc);
                ObDereferenceObject(proc);
                return STATUS_UNSUCCESSFUL;
            }
            NTSTATUS sp_st = TdStealthAllocPage(
                caller_cr3,
                (PVOID)((UINT64)tramp_va & ~0xFFFULL),
                tramp_pa,
                NULL, 0, TRUE,
                pt_pfn, pt_idx,
                FALSE, tramp_shadow, TRUE, FALSE);
            if (!NT_SUCCESS(sp_st))
            {
                HYPERPLATFORM_LOG_ERROR(
                    "[td-r3] trampoline stealth page register failed (tramp=%p st=0x%08X) - aborting hook",
                    tramp_va, sp_st);
                ZwFreeVirtualMemory(ZwCurrentProcess(), &tramp_va, &tramp_size, MEM_RELEASE);
                MmUnlockPages(mdl);
                IoFreeMdl(mdl);
                KeUnstackDetachProcess(&apc);
                ObDereferenceObject(proc);
                return STATUS_UNSUCCESSFUL;
            }
            HYPERPLATFORM_LOG_INFO(
                "[td-r3] trampoline stealth page registered: tramp=%p shadow=0x%llX",
                tramp_va, tramp_shadow);
        }
    }

    //
    // 3. DPC broadcast VMCALL to install hook on all CPUs
    //
    PVOID origin_ptr = NULL;

    R3_HOOK_DPC_CTX ctx = {};
    ctx.target              = target_va;
    ctx.proxy               = proxy_va;
    ctx.origin              = &origin_ptr;
    ctx.caller_cr3          = caller_cr3;
    ctx.hook_type           = hook_type;
    ctx.target_cr3          = target_cr3;
    ctx.user_trampoline     = tramp_va;
    ctx.user_trampoline_pa  = tramp_pa;

    KeGenericCallDpc(DpcEptHookR3, &ctx);

    KeUnstackDetachProcess(&apc);

    if (NT_SUCCESS(ctx.result))
    {
        entry->active           = TRUE;
        entry->target_pid       = target_pid;
        entry->target_va        = target_va;
        entry->trampoline_va    = tramp_va;
        entry->trampoline_size  = tramp_size;
        entry->target_mdl       = mdl;
        entry->target_cr3       = target_cr3;

        if (out_trampoline)
            *out_trampoline = origin_ptr;

        HYPERPLATFORM_LOG_INFO("[td-r3] R3 EPT hook installed! trampoline=%p", origin_ptr);
    }
    else
    {
        //
        // failed 閳?clean up: free trampoline, unlock MDL
        //
        KeStackAttachProcess(proc, &apc);
        ZwFreeVirtualMemory(ZwCurrentProcess(), &tramp_va, &tramp_size, MEM_RELEASE);
        KeUnstackDetachProcess(&apc);

        MmUnlockPages(mdl);
        IoFreeMdl(mdl);

        NTSTATUS diag = hv_vmcall_simple(VMCALL_GET_HOOK_DIAG, 0, 0, 0);
        UINT64 diag2 = (UINT64)hv_vmcall_simple(VMCALL_GET_HOOK_DIAG2, 0, 0, 0);
        HYPERPLATFORM_LOG_ERROR("[td-r3] R3 EPT hook FAILED: 0x%08X diag=%llu diag2=0x%llX", ctx.result, (UINT64)diag, diag2);
    }

    ObDereferenceObject(proc);
    return ctx.result;
}

//
// remove R3 EPT hook and clean up resources
//
NTSTATUS
TdEptUnhookR3(UINT64 target_pid, PVOID target_va)
{
    R3_HOOK_ENTRY * entry = R3HookFind(target_pid, target_va);
    if (!entry)
    {
        HYPERPLATFORM_LOG_WARN("[td-r3] hook entry not found for pid=%llu va=%p", target_pid, target_va);
        return STATUS_NOT_FOUND;
    }

    //
    // 1. unhook via VMCALL (DPC broadcast)
    //
    PEPROCESS proc = NULL;
    NTSTATUS st = PsLookupProcessByProcessId((HANDLE)target_pid, &proc);
    if (!NT_SUCCESS(st)) return st;

    KAPC_STATE apc;
    KeStackAttachProcess(proc, &apc);

    struct {
        PVOID    target;
        UINT64   caller_cr3;
        NTSTATUS result;
    } unhook_ctx = {};
    unhook_ctx.target     = target_va;
    unhook_ctx.caller_cr3 = __readcr3();

    KeGenericCallDpc(DpcEptUnhook, &unhook_ctx);

    //
    // 2. free trampoline stealth page, then trampoline memory in target process
    //
    if (entry->trampoline_va)
    {
        // TdEptHookR3 registered the trampoline as a stealth page (target_pid=0,
        // so it is NOT in g_stealth_tracks). Free it here, otherwise the sp leaks
        // in g_ept->stealth_pages holding a reference to this process's
        // (soon-freed) shadow CR3. Must run while the trampoline page is still
        // mapped, i.e. before ZwFreeVirtualMemory.
        TdStealthFreePage((PVOID)((UINT64)entry->trampoline_va & ~0xFFFULL));

        SIZE_T sz = entry->trampoline_size;
        ZwFreeVirtualMemory(ZwCurrentProcess(), &entry->trampoline_va, &sz, MEM_RELEASE);
    }

    KeUnstackDetachProcess(&apc);

    //
    // 3. unlock MDL
    //
    if (entry->target_mdl)
    {
        MmUnlockPages(entry->target_mdl);
        IoFreeMdl(entry->target_mdl);
    }

    HYPERPLATFORM_LOG_INFO("[td-r3] R3 hook removed: pid=%llu va=%p", target_pid, target_va);

    RtlZeroMemory(entry, sizeof(*entry));
    ObDereferenceObject(proc);
    return unhook_ctx.result;
}

//
// unhook all active R3 hooks (called from unload)
//
VOID
TdEptUnhookAllR3(VOID)
{
    for (int i = 0; i < MAX_R3_HOOKS; i++)
    {
        if (!g_r3_hooks[i].active) continue;

        //
        // for inject hooks (target_mdl == NULL): the target process may have
        // already exited. don't attach 閳?just VMCALL unhook by VA + clear entry.
        // EPT unhook only needs the VA to find the PFN in the hooked_pages list.
        // the VMCALL runs under system CR3, which is fine for EPT-only operations.
        //
        // for real R3 hooks (target_mdl != NULL): use the full unhook path.
        //
        if (g_r3_hooks[i].target_mdl == NULL)
        {
            // inject hook 閳?lightweight unhook (no attach needed)
            PEPROCESS proc = NULL;
            NTSTATUS st = PsLookupProcessByProcessId(
                (HANDLE)g_r3_hooks[i].target_pid, &proc);

            if (NT_SUCCESS(st))
            {
                // process still alive 閳?attach to resolve VA 閳?PA for unhook
                KAPC_STATE apc;
                KeStackAttachProcess(proc, &apc);

                struct { PVOID target; UINT64 caller_cr3; NTSTATUS result; } ctx = {};
                ctx.target     = g_r3_hooks[i].target_va;
                ctx.caller_cr3 = __readcr3();
                KeGenericCallDpc(DpcEptUnhook, &ctx);

                KeUnstackDetachProcess(&apc);
                ObDereferenceObject(proc);
            }
            // else: process dead 閳?EPT pages are orphaned but harmless.
            // the PFN won't be reused for anything meaningful until
            // ept_unhook_all() on HV unload restores all PTEs to RWX.

            RtlZeroMemory(&g_r3_hooks[i], sizeof(g_r3_hooks[i]));
        }
        else
        {
            // real R3 hook 閳?full cleanup
            TdEptUnhookR3(g_r3_hooks[i].target_pid, g_r3_hooks[i].target_va);
        }
    }
}

// =========================================================================
//  thread creation
// =========================================================================

NTSTATUS
TdCreateThread(PEPROCESS process, PVOID entry)
{
    //
    // try function pointer (resolved at init), fallback to manual syscall stub
    //
    if (g_pZwCreateThreadEx)
    {
        HANDLE proc_h = NULL;
        NTSTATUS st = ObOpenObjectByPointer(
            process, OBJ_KERNEL_HANDLE, NULL,
            PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &proc_h);
        if (!NT_SUCCESS(st)) return st;

        //
        // create thread NOT suspended 閳?runs immediately.
        // all CPUs have EPT split (DPC broadcast), no affinity pinning needed.
        // NtResumeThread/ZwResumeThread may not be exported by ntoskrnl,
        // so avoid suspend+resume pattern entirely.
        //
        HANDLE thread_h = NULL;
        st = g_pZwCreateThreadEx(
            &thread_h, THREAD_ALL_ACCESS, NULL, proc_h,
            entry, NULL,
            0,      // flags = 0: not suspended
            0, 0, 0, NULL);

        if (NT_SUCCESS(st) && thread_h)
            ZwClose(thread_h);
        ZwClose(proc_h);
        return st;
    }

    //
    // fallback: attach to process, use RtlCreateUserThread
    // create SUSPENDED 閳?pin to install CPU 閳?resume
    //
    KAPC_STATE apc;
    KeStackAttachProcess(process, &apc);

    HANDLE thread_h = NULL;
    CLIENT_ID cid = {};
    //
    // pin CURRENT kernel thread to install CPU first.
    // then create user thread (not suspended) 閳?it inherits scheduling
    // affinity from the current processor context.
    //
    ULONG cpu = KeGetCurrentProcessorNumberEx(NULL);
    KAFFINITY old_affinity = KeSetSystemAffinityThreadEx((KAFFINITY)1 << cpu);

    NTSTATUS st = RtlCreateUserThread(
        ZwCurrentProcess(),
        NULL, FALSE, 0, 0, 0,
        entry, NULL, &thread_h, &cid);

    KeRevertToUserAffinityThreadEx(old_affinity);
    KeUnstackDetachProcess(&apc);

    if (NT_SUCCESS(st) && thread_h)
    {
        // also set the thread's own affinity to install CPU
        KAFFINITY mask = (KAFFINITY)1 << cpu;
        ZwSetInformationThread(thread_h, ThreadAffinityMask, &mask, sizeof(mask));
        ZwClose(thread_h);
    }

    return st;
}


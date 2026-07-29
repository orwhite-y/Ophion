#include "td_common.h"

// =========================================================================
//  TdLoadImageNotify 閳?fires when a DLL is loaded in any process
// =========================================================================
//
// When user32.dll loads in a recorded target (Box.exe), we inject renderdoc.dll
// directly using the NtTestAlert EPT trigger + shadow CR3 mechanism.
//
VOID
TdLoadImageNotify(PUNICODE_STRING ImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
    UNREFERENCED_PARAMETER(ImageInfo);

    if (!ImageName || !ImageName->Buffer || !g_loadimage_registered || !g_inject_target_lock_init)
        return;

    // extract basename
    const WCHAR * buf = ImageName->Buffer;
    USHORT len = ImageName->Length / sizeof(WCHAR);
    USHORT base_off = 0;
    for (USHORT i = 0; i < len; i++)
        if (buf[i] == L'\\') base_off = (USHORT)(i + 1);
    USHORT base_len = (USHORT)(len - base_off);

    // check if it's "d3d12.dll" (late enough that renderdoc's imports
    // user32/gdi32/ole32/dxgi/d3d11/dbghelp/etc. are all already in the PEB
    // LDR, so TdPeResolveImports can fill the whole IAT before DllMain runs)
    static const WCHAR kD3d12[] = L"d3d12.dll";
    static const USHORT kD3d12Len = (USHORT)((sizeof(kD3d12) / sizeof(WCHAR)) - 1);
    if (base_len != kD3d12Len) return;
    for (USHORT i = 0; i < kD3d12Len; i++)
    {
        WCHAR ca = buf[base_off + i], cb = kD3d12[i];
        if (ca >= L'a' && ca <= L'z') ca -= 32;
        if (cb >= L'a' && cb <= L'z') cb -= 32;
        if (ca != cb) return;
    }

    // claim target and get stored exe path
    WCHAR exe_path_buf[MAX_PATH];
    if (!TdInjectTargetClaim(ProcessId, exe_path_buf, MAX_PATH))
        return;

    // build renderdoc path from the exe path:
    //   "\??\C:\dir\Box.exe" -> "\??\C:\dir\renderdoc.dll"
    WCHAR renderdoc_path_buf[MAX_PATH];
    USHORT last_slash = 0;
    USHORT src_chars = 0;
    for (; src_chars < MAX_PATH && exe_path_buf[src_chars]; src_chars++)
    {
        renderdoc_path_buf[src_chars] = exe_path_buf[src_chars];
        if (exe_path_buf[src_chars] == L'\\') last_slash = (USHORT)(src_chars + 1);
    }
    static const WCHAR kRenderdoc[] = L"renderdoc.dll";
    USHORT rd_chars = (USHORT)((sizeof(kRenderdoc) / sizeof(WCHAR)) - 1);
    if ((ULONG)last_slash + rd_chars + 1 > MAX_PATH) return;
    for (USHORT i = 0; i < rd_chars; i++)
        renderdoc_path_buf[last_slash + i] = kRenderdoc[i];
    renderdoc_path_buf[last_slash + rd_chars] = L'\0';

    UNICODE_STRING renderdoc_nt;
    RtlInitUnicodeString(&renderdoc_nt, renderdoc_path_buf);

    HYPERPLATFORM_LOG_INFO("[td-inj] d3d12 loaded in target pid=%llu -- injecting renderdoc directly (shadow CR3)",
        (UINT64)ProcessId);

    // lookup process
    PEPROCESS proc = NULL;
    NTSTATUS st = PsLookupProcessByProcessId(ProcessId, &proc);
    if (!NT_SUCCESS(st) || !proc)
    {
        HYPERPLATFORM_LOG_ERROR("[td-inj] PsLookupProcessByProcessId failed: 0x%08X", st);
        return;
    }

    // inject
    st = TdInjectRenderdocShadow(proc, &renderdoc_nt, "td-inj-shadow", FALSE);
    if (!NT_SUCCESS(st))
    {
        HYPERPLATFORM_LOG_ERROR("[td-inj] TdInjectRenderdocShadow failed: 0x%08X", st);
    }

    ObDereferenceObject(proc);
}

VOID
TdProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    if (CreateInfo != NULL)
    {
        // process creation -- record target for later injection
        if (g_inject_target_lock_init && CreateInfo->ImageFileName)
        {
            if (TdInjectMatchBasename(CreateInfo->ImageFileName, L"Box.exe", 7))
                TdInjectTargetAdd(ProcessId, CreateInfo->ImageFileName);
        }
        return;
    }
    // process exit -- cleanup stealth
    NTSTATUS exit_st = PsGetProcessExitStatus(Process);
    HYPERPLATFORM_LOG_INFO("[td-rw] process exit: pid=%llu exit_status=0x%08X",
        (UINT64)ProcessId, (UINT32)exit_st);
    TdCleanupStealthForProcess(Process, (UINT64)ProcessId);
    TdCleanupSelfPeInfo((UINT64)ProcessId);

    // re-arm CreateFile("test") injection: if this is the Box.exe we injected,
    // clear the recorded pid so the next Box.exe (even one reusing this pid)
    // injects again. Idempotent - no-op if this pid wasn't the injected one.
    _InterlockedCompareExchange64(&g_test_injected_pid, 0, (LONG64)ProcessId);
}

VOID
TdProcessNotifyLegacy(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
{
    UNREFERENCED_PARAMETER(ParentId);

    if (Create) return;

    PEPROCESS proc = NULL;
    NTSTATUS st = PsLookupProcessByProcessId(ProcessId, &proc);
    if (!NT_SUCCESS(st))
    {
        HYPERPLATFORM_LOG_WARN("[td-rw] legacy process exit cleanup lookup failed: pid=%llu st=0x%08X",
            (UINT64)ProcessId, st);
        return;
    }

    NTSTATUS exit_st = PsGetProcessExitStatus(proc);
    HYPERPLATFORM_LOG_INFO("[td-rw] legacy process exit: pid=%llu exit_status=0x%08X",
        (UINT64)ProcessId, (UINT32)exit_st);

    TdCleanupStealthForProcess(proc, (UINT64)ProcessId);
    TdCleanupSelfPeInfo((UINT64)ProcessId);

    // re-arm CreateFile("test") injection for the next Box.exe (see TdProcessNotify).
    _InterlockedCompareExchange64(&g_test_injected_pid, 0, (LONG64)ProcessId);
    ObDereferenceObject(proc);
}


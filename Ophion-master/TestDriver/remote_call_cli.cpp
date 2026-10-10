// remote_call_cli.cpp - ring-3 client for IOCTL_REMOTE_CALL.
//
// Usage:
//   remote_call_cli <pid> <function_va> [wait_ms] [arg0 arg1 ...]
//   remote_call_cli 0 <function_va> [wait_ms] [arg0 ...]   (pid 0 = self)
//
// The target function is called as fn(void* param_block) where param_block
// (RCX) is one PAGE_READWRITE page containing:
//   +0x00 magic 'RCLL'   +0x08 arg_count   +0x10 arg[0..]
// Requires the VM extradata "VBoxInternal/EptHook/Runtime" = 1 and the
// RMCoreTst driver loaded inside the defeat/v1 guest.
//
// Example - call a mapped stub that shows its argument block:
//   remote_call_cli 4242 0x7FFA10001010 5000 0x1234 0x5678

#include <windows.h>
#include <stdint.h>
#include <stdio.h>

#define TD_IOCTL_BASE 0x900
#define IOCTL_REMOTE_CALL CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 35, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define TD_REMOTE_CALL_MAX_ARGS 24

typedef struct _TD_REMOTE_CALL_PARAMS {
    uint64_t target_pid;
    uint64_t function_va;
    uint64_t wait_ms;
    uint32_t arg_count;
    uint32_t flags;
    uint64_t param_block_va;
    uint64_t trigger_va;
    uint64_t thread_exit_code;
    uint64_t vbox_status;
    uint64_t status;
    uint64_t arg[TD_REMOTE_CALL_MAX_ARGS];
} TD_REMOTE_CALL_PARAMS;

static void PrintUsage()
{
    wprintf(L"Usage:\n");
    wprintf(L"  remote_call_cli <pid> <function_va> [wait_ms] [arg0 arg1 ...]\n");
    wprintf(L"  pid 0 = calling process.  wait_ms 0 = fire-and-forget.\n");
    wprintf(L"Examples:\n");
    wprintf(L"  remote_call_cli 4242 0x7FFA10001010 5000 0x1234 0x5678\n");
    wprintf(L"  remote_call_cli 0 0x7FFA10001010 0\n");
}

int wmain(int argc, wchar_t** argv)
{
    if (argc < 3)
    {
        PrintUsage();
        return 2;
    }

    TD_REMOTE_CALL_PARAMS request = {};
    request.target_pid = _wcstoui64(argv[1], nullptr, 0);
    request.function_va = _wcstoui64(argv[2], nullptr, 0);
    if (argc >= 4)
        request.wait_ms = _wcstoui64(argv[3], nullptr, 0);
    for (int i = 4; i < argc; ++i)
    {
        if (request.arg_count >= TD_REMOTE_CALL_MAX_ARGS)
        {
            wprintf(L"too many args (max %u)\n", TD_REMOTE_CALL_MAX_ARGS);
            return 2;
        }
        request.arg[request.arg_count++] = _wcstoui64(argv[i], nullptr, 0);
    }

    HANDLE device = CreateFileW(
        L"\\\\.\\RMCoreTst", GENERIC_READ | GENERIC_WRITE,
        0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (device == INVALID_HANDLE_VALUE)
    {
        wprintf(L"open RMCoreTst failed: Win32=%lu\n", GetLastError());
        return 1;
    }

    DWORD returned = 0;
    BOOL ok = DeviceIoControl(device, IOCTL_REMOTE_CALL,
                              &request, sizeof(request),
                              &request, sizeof(request),
                              &returned, nullptr);
    CloseHandle(device);

    if (!ok)
    {
        wprintf(L"DeviceIoControl failed: Win32=%lu\n", GetLastError());
        return 1;
    }

    wprintf(L"status        = 0x%08X%s\n", (unsigned)request.status,
            request.status == 0 ? L"" : L"  (see ntstatus.h)");
    wprintf(L"vmm_status    = 0x%llX  (0 = VMM ok)\n", request.vbox_status);
    wprintf(L"trigger_va    = 0x%llX\n", request.trigger_va);
    wprintf(L"param_block   = 0x%llX  (RCX in target)\n", request.param_block_va);
    wprintf(L"thread_exit   = 0x%llX\n", request.thread_exit_code);
    if (request.status == 0 && request.wait_ms == 0)
        wprintf(L"fired async: re-run with wait_ms to collect the exit code later.\n");
    return request.status == 0 ? 0 : 1;
}

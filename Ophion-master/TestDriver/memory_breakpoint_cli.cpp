#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>

#define TD_IOCTL_BASE 0x900
#define IOCTL_HV_BP_SET       CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 28, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_BP_CLEAR     CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 29, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_BP_CLEAR_ALL CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 30, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define TD_BP_ACCESS_READ    0x01
#define TD_BP_ACCESS_WRITE   0x02
#define TD_BP_ACCESS_EXECUTE 0x04
#define TD_BP_FLAG_ONESHOT   0x01

typedef struct _TD_MEMORY_BREAKPOINT_REQUEST {
    uint64_t breakpoint_id;
    uint64_t target_pid;
    uint64_t target_address;
    uint32_t size;
    uint32_t access;
    uint32_t flags;
    uint32_t status;
} TD_MEMORY_BREAKPOINT_REQUEST;

static void PrintUsage()
{
    wprintf(L"Usage:\n");
    wprintf(L"  memory_breakpoint_cli set <pid> <address> <size> <r|w|x|rw|rwx> <once|permanent>\n");
    wprintf(L"  memory_breakpoint_cli clear <breakpoint-id>\n");
    wprintf(L"  memory_breakpoint_cli clear-all\n");
    wprintf(L"Examples:\n");
    wprintf(L"  memory_breakpoint_cli set 4242 0x7FF612341000 8 rw permanent\n");
    wprintf(L"  memory_breakpoint_cli set 4242 0x7FF612342080 1 x once\n");
}

static uint32_t ParseAccess(const wchar_t* text)
{
    uint32_t access = 0;
    for (; text && *text; ++text)
    {
        if (*text == L'r' || *text == L'R') access |= TD_BP_ACCESS_READ;
        else if (*text == L'w' || *text == L'W') access |= TD_BP_ACCESS_WRITE;
        else if (*text == L'x' || *text == L'X') access |= TD_BP_ACCESS_EXECUTE;
        else return 0;
    }
    return access;
}

int wmain(int argc, wchar_t** argv)
{
    if (argc < 2)
    {
        PrintUsage();
        return 2;
    }

    HANDLE device = CreateFileW(
        L"\\\\.\\RMCoreTst", GENERIC_READ | GENERIC_WRITE,
        0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (device == INVALID_HANDLE_VALUE)
    {
        wprintf(L"open RMCoreTst failed: Win32=%lu\n", GetLastError());
        return 1;
    }

    TD_MEMORY_BREAKPOINT_REQUEST request = {};
    DWORD ioctl = 0;

    if (_wcsicmp(argv[1], L"set") == 0 && argc == 7)
    {
        request.target_pid = _wcstoui64(argv[2], nullptr, 0);
        request.target_address = _wcstoui64(argv[3], nullptr, 0);
        request.size = wcstoul(argv[4], nullptr, 0);
        request.access = ParseAccess(argv[5]);
        if (_wcsicmp(argv[6], L"once") == 0)
            request.flags = TD_BP_FLAG_ONESHOT;
        else if (_wcsicmp(argv[6], L"permanent") != 0)
        {
            PrintUsage();
            CloseHandle(device);
            return 2;
        }
        ioctl = IOCTL_HV_BP_SET;
    }
    else if (_wcsicmp(argv[1], L"clear") == 0 && argc == 3)
    {
        request.breakpoint_id = _wcstoui64(argv[2], nullptr, 0);
        ioctl = IOCTL_HV_BP_CLEAR;
    }
    else if (_wcsicmp(argv[1], L"clear-all") == 0 && argc == 2)
    {
        ioctl = IOCTL_HV_BP_CLEAR_ALL;
    }
    else
    {
        PrintUsage();
        CloseHandle(device);
        return 2;
    }

    DWORD returned = 0;
    BOOL ok = DeviceIoControl(
        device, ioctl, &request, sizeof(request),
        &request, sizeof(request), &returned, nullptr);
    DWORD win32_error = GetLastError();
    CloseHandle(device);

    if (!ok)
    {
        wprintf(L"DeviceIoControl failed: Win32=%lu\n", win32_error);
        return 1;
    }
    if ((LONG)request.status < 0)
    {
        wprintf(L"operation failed: NTSTATUS=0x%08X\n", request.status);
        return 1;
    }

    if (ioctl == IOCTL_HV_BP_SET)
        wprintf(L"breakpoint set: id=%llu; hit output: C:\\Windows\\O.log\n",
            request.breakpoint_id);
    else
        wprintf(L"operation complete\n");
    return 0;
}

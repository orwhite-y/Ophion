// =============================================================================
//  inject_test.cpp  --  R3 client for IOCTL_INJECT_MEM_DLL
//
//  Usage:  inject_test.exe <pid> <dll_path>
//  Example: inject_test.exe 1234 "C:\test\payload.dll"
//
//  Converts Win32 path to NT path, calls IOCTL_INJECT_MEM_DLL, reports result.
// =============================================================================

#include <windows.h>
#include <stdio.h>
#include <stdint.h>

// From td_common.h
#define TD_IOCTL_BASE 0x900
#define IOCTL_INJECT_MEM_DLL CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 25, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 8)
typedef struct _TD_INJECT_MEM_DLL_PARAMS {
    uint64_t target_pid;
    wchar_t  dll_path[520];
    uint64_t mapped_base;
    uint64_t entry_point;
    uint64_t image_size;
    uint64_t status;
} TD_INJECT_MEM_DLL_PARAMS;
#pragma pack(pop)

bool ConvertToNtPath(const wchar_t* win32_path, wchar_t* nt_path, size_t nt_path_len)
{
    // Simple conversion: C:\path -> \??\C:\path
    if (!win32_path || !nt_path || nt_path_len < 520) return false;

    // Check if already NT path
    if (wcsncmp(win32_path, L"\\??\\", 4) == 0) {
        wcscpy_s(nt_path, nt_path_len, win32_path);
        return true;
    }

    // Convert C:\ style to NT path format
    if (wcslen(win32_path) >= 3 && win32_path[1] == L':' && win32_path[2] == L'\\') {
        swprintf_s(nt_path, nt_path_len, L"\\??\\%s", win32_path);
        return true;
    }

    // Relative or UNC path
    swprintf_s(nt_path, nt_path_len, L"\\??\\%s", win32_path);
    return true;
}

int wmain(int argc, wchar_t* argv[])
{
    if (argc < 3) {
        wprintf(L"[INJECT_TEST] R3 client for IOCTL_INJECT_MEM_DLL\n");
        wprintf(L"Usage: %s <pid> <dll_path>\n", argv[0]);
        wprintf(L"Example: %s 1234 C:\\test\\payload.dll\n", argv[0]);
        return 1;
    }

    DWORD target_pid = _wtoi(argv[1]);
    const wchar_t* dll_path = argv[2];

    if (target_pid == 0) {
        wprintf(L"[ERROR] Invalid PID: %s\n", argv[1]);
        return 1;
    }

    wprintf(L"[INFO] Target PID: %u\n", target_pid);
    wprintf(L"[INFO] DLL path: %s\n", dll_path);

    // Open driver
    HANDLE hDriver = CreateFileW(
        L"\\\\.\\RMCoreTst",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDriver == INVALID_HANDLE_VALUE) {
        wprintf(L"[ERROR] Failed to open driver (error %u)\n", GetLastError());
        wprintf(L"[INFO] Make sure TestDriver is loaded: sc start TestDriver\n");
        return 1;
    }

    wprintf(L"[OK] Driver handle opened\n");

    // Prepare params
    TD_INJECT_MEM_DLL_PARAMS params = {0};
    params.target_pid = target_pid;

    if (!ConvertToNtPath(dll_path, params.dll_path, 520)) {
        wprintf(L"[ERROR] Failed to convert path to NT format\n");
        CloseHandle(hDriver);
        return 1;
    }

    wprintf(L"[INFO] NT path: %s\n", params.dll_path);

    // Send IOCTL
    DWORD bytes_returned = 0;
    BOOL result = DeviceIoControl(
        hDriver,
        IOCTL_INJECT_MEM_DLL,
        &params,
        sizeof(params),
        &params,
        sizeof(params),
        &bytes_returned,
        NULL
    );

    if (!result) {
        wprintf(L"[ERROR] DeviceIoControl failed (error %u)\n", GetLastError());
        CloseHandle(hDriver);
        return 1;
    }

    wprintf(L"[OK] IOCTL returned %u bytes\n", bytes_returned);

    // Check result
    if (params.status == 0) {
        wprintf(L"\n=== INJECTION SUCCESS ===\n");
        wprintf(L"  Mapped base:   0x%016llX\n", params.mapped_base);
        wprintf(L"  Entry point:   0x%016llX\n", params.entry_point);
        wprintf(L"  Image size:    0x%llX (%llu bytes)\n", params.image_size, params.image_size);
        wprintf(L"  Status:        0x%08llX (STATUS_SUCCESS)\n", params.status);
    } else {
        wprintf(L"\n=== INJECTION FAILED ===\n");
        wprintf(L"  NTSTATUS: 0x%08llX\n", params.status);

        // Common error codes
        if (params.status == 0xC0000001) wprintf(L"  (STATUS_UNSUCCESSFUL)\n");
        else if (params.status == 0xC0000022) wprintf(L"  (STATUS_ACCESS_DENIED)\n");
        else if (params.status == 0xC0000034) wprintf(L"  (STATUS_OBJECT_NAME_NOT_FOUND)\n");
        else if (params.status == 0xC00000BB) wprintf(L"  (STATUS_NOT_SUPPORTED)\n");
        else if (params.status == 0xC000000D) wprintf(L"  (STATUS_INVALID_PARAMETER)\n");
        else if (params.status == 0xC0000017) wprintf(L"  (STATUS_NO_MEMORY)\n");
    }

    CloseHandle(hDriver);
    return (params.status == 0) ? 0 : 1;
}

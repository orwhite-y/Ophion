/*
*   injector.cpp - ring-3 stealth injection demo
*
*   1. finds notepad.exe by process name
*   2. sends PID to Ophion driver via IOCTL
*   3. driver allocates PAGE_READWRITE memory in notepad.exe
*   4. hypervisor sets up dual EPT split:
*      - read view: clean data (anti-cheat sees PAGE_READWRITE, no code)
*      - execute view: shellcode (calc.exe launcher)
*      - PT page split: PTE scan sees NX=1
*   5. user creates remote thread to execute shellcode
*
*   result: calc.exe pops up from notepad.exe context
*   anti-cheat sees: PAGE_READWRITE, clean memory, NX=1 in PTE
*/

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

// must match TestDriver test_driver.cpp
#define TD_IOCTL_BASE   0x900
#define IOCTL_INJECT    CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 0, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 8)
typedef struct _TD_INJECT_PARAMS {
    UINT64 target_pid;
    UINT64 alloc_size;      // 0 = auto
    UINT64 shellcode_va;    // [out]
    UINT64 actual_size;     // [out]
} TD_INJECT_PARAMS;
#pragma pack(pop)

//
// find process ID by name (case-insensitive)
//
static DWORD FindProcessByName(const wchar_t* name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);

    DWORD pid = 0;
    if (Process32FirstW(snap, &pe))
    {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0)
            {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return pid;
}

int wmain(int argc, wchar_t* argv[])
{
    const wchar_t* target_name = L"notepad.exe";

    if (argc > 1)
        target_name = argv[1];

    printf("[*] Ophion Stealth Injector\n");
    printf("[*] Target process: %ls\n", target_name);

    // step 1: find target process
    DWORD pid = FindProcessByName(target_name);
    if (!pid)
    {
        printf("[-] Process '%ls' not found. Please start it first.\n", target_name);
        return 1;
    }
    printf("[+] Found PID: %u\n", pid);

    // step 2: open TestDriver device (not Ophion — TestDriver handles injection)
    HANDLE device = CreateFileW(
        L"\\\\.\\OphionTest",
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL);

    if (device == INVALID_HANDLE_VALUE)
    {
        printf("[-] Cannot open \\Device\\OphionTest (error %u)\n", GetLastError());
        printf("    Make sure both Ophion.sys and TestEptHook.sys are loaded.\n");
        return 1;
    }
    printf("[+] Opened TestDriver device\n");

    // step 3: send injection IOCTL
    TD_INJECT_PARAMS params = {};
    params.target_pid = (UINT64)pid;

    DWORD bytes_returned = 0;
    BOOL ok = DeviceIoControl(
        device,
        IOCTL_INJECT,
        &params, sizeof(params),
        &params, sizeof(params),
        &bytes_returned, NULL);

    if (!ok)
    {
        printf("[-] IOCTL_INJECT failed (error %u)\n", GetLastError());
        CloseHandle(device);
        return 1;
    }

    printf("[+] Stealth memory allocated at VA: 0x%llX (size: 0x%llX)\n",
           params.shellcode_va, params.actual_size);
    printf("[+] EPT split active:\n");
    printf("    - Read view:  clean/zeroed data\n");
    printf("    - Execute view: shellcode (calc launcher)\n");
    printf("    - PTE scan:  NX=1 (non-executable)\n");
    printf("    - VAD query: PAGE_READWRITE\n");
    printf("\n");
    printf("[+] Thread created by kernel driver (ZwCreateThreadEx)\n");
    printf("    - bypasses ring-3 hooks on CreateRemoteThread/NtCreateThreadEx\n");
    printf("    - thread entry = stealth VA in target process (NOT in driver module)\n");
    printf("\n");
    printf("[*] Watch for calc.exe from PID %u!\n", pid);

    CloseHandle(device);
    printf("[*] Done.\n");
    return 0;
}

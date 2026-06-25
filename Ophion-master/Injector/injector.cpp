/*
*   injector.cpp - Ophion ring-3 test tool
*
*   commands:
*     inject <process>         stealth shellcode injection (MessageBox)
*     hook                     R0 EPT hook NtCreateFile (kernel-wide, logs to DbgView)
*     unhook                   remove R0 EPT hook
*     hookr3 <pid> <va> <proxy> [type]   R3 EPT hook (per-process)
*     unhookr3 <pid> <va>                remove R3 EPT hook
*/

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>

// ---- IOCTL codes (must match TestDriver) ----

#define TD_IOCTL_BASE     0x900
#define IOCTL_INJECT      CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EPT_HOOK    CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EPT_UNHOOK  CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EPT_HOOK_R3   CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EPT_UNHOOK_R3 CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INJECT_DLL    CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 5, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ---- shared structs (must match TestDriver) ----

#pragma pack(push, 8)
typedef struct _TD_INJECT_PARAMS {
    UINT64 target_pid;
    UINT64 alloc_size;
    UINT64 trigger_va;      // [in]  0 = auto (NtTestAlert)
    UINT64 shellcode_va;    // [out]
    UINT64 actual_size;     // [out]
} TD_INJECT_PARAMS;

typedef struct _TD_R3_HOOK_PARAMS {
    UINT64 target_pid;
    UINT64 target_function_va;
    UINT64 proxy_function_va;
    UINT64 hook_type;
    UINT64 trampoline_va;   // [out]
    UINT64 status;           // [out]
} TD_R3_HOOK_PARAMS;

typedef struct _TD_R3_UNHOOK_PARAMS {
    UINT64 target_pid;
    UINT64 target_function_va;
    UINT64 status;           // [out]
} TD_R3_UNHOOK_PARAMS;

typedef struct _TD_INJECT_DLL_PARAMS {
    UINT64 target_pid;
    UINT32 dll_offset;     // offset of DLL data within this buffer (after header)
    UINT32 dll_size;       // size of raw DLL file
    UINT64 out_base;       // [out] mapped image base
    UINT64 out_entry;      // [out] DllMain VA
    UINT64 out_size;       // [out] image size
} TD_INJECT_DLL_PARAMS;
#pragma pack(pop)

// ---- helpers ----

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

static HANDLE OpenDevice()
{
    HANDLE h = CreateFileW(
        L"\\\\.\\OphionTest",
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL);

    if (h == INVALID_HANDLE_VALUE)
    {
        printf("[-] Cannot open \\Device\\OphionTest (error %u)\n", GetLastError());
        printf("    Make sure Ophion.sys and TestEptHook.sys are loaded.\n");
    }
    return h;
}

// ---- stealth inject ----

static int CmdInject(const wchar_t* target_name)
{
    printf("[*] Stealth Inject: %ls\n", target_name);

    DWORD pid = FindProcessByName(target_name);
    if (!pid) { printf("[-] Process not found.\n"); return 1; }
    printf("[+] PID: %u\n", pid);

    HANDLE dev = OpenDevice();
    if (dev == INVALID_HANDLE_VALUE) return 1;

    TD_INJECT_PARAMS p = {};
    p.target_pid = (UINT64)pid;

    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(dev, IOCTL_INJECT, &p, sizeof(p), &p, sizeof(p), &bytes, NULL);

    if (ok)
    {
        UINT32 thr_status = (UINT32)(p.actual_size >> 32);
        printf("[+] Stealth VA: 0x%llX\n", p.shellcode_va);
        printf("[+] Thread status: 0x%08X\n", thr_status);
        if (thr_status == 0)
            printf("[+] Thread created OK. Watch for MessageBox from PID %u.\n", pid);
        else
            printf("[-] Thread creation failed: 0x%08X\n", thr_status);
    }
    else
        printf("[-] IOCTL_INJECT failed (error %u)\n", GetLastError());

    CloseHandle(dev);
    return ok ? 0 : 1;
}

// ---- R0 EPT hook (NtCreateFile) ----

static int CmdHook()
{
    printf("[*] Installing R0 EPT hook on NtCreateFile...\n");

    HANDLE dev = OpenDevice();
    if (dev == INVALID_HANDLE_VALUE) return 1;

    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(dev, IOCTL_EPT_HOOK, NULL, 0, NULL, 0, &bytes, NULL);

    if (ok)
        printf("[+] Hook installed. Check DbgView for [td-hook] messages.\n");
    else
        printf("[-] IOCTL_EPT_HOOK failed (error %u)\n", GetLastError());

    CloseHandle(dev);
    return ok ? 0 : 1;
}

static int CmdUnhook()
{
    printf("[*] Removing R0 EPT hook...\n");

    HANDLE dev = OpenDevice();
    if (dev == INVALID_HANDLE_VALUE) return 1;

    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(dev, IOCTL_EPT_UNHOOK, NULL, 0, NULL, 0, &bytes, NULL);

    if (ok)
        printf("[+] Hook removed.\n");
    else
        printf("[-] IOCTL_EPT_UNHOOK failed (error %u)\n", GetLastError());

    CloseHandle(dev);
    return ok ? 0 : 1;
}

// ---- R3 EPT hook (per-process) ----

static int CmdHookR3(UINT64 pid, UINT64 target_va, UINT64 proxy_va, UINT64 hook_type)
{
    printf("[*] Installing R3 EPT hook: pid=%llu target=0x%llX proxy=0x%llX type=%llu\n",
           pid, target_va, proxy_va, hook_type);

    HANDLE dev = OpenDevice();
    if (dev == INVALID_HANDLE_VALUE) return 1;

    TD_R3_HOOK_PARAMS p = {};
    p.target_pid         = pid;
    p.target_function_va = target_va;
    p.proxy_function_va  = proxy_va;
    p.hook_type          = hook_type;

    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(dev, IOCTL_EPT_HOOK_R3, &p, sizeof(p), &p, sizeof(p), &bytes, NULL);

    if (ok && p.status == 0)
    {
        printf("[+] R3 hook installed.\n");
        printf("    trampoline VA: 0x%llX\n", p.trampoline_va);
        printf("    Only PID %llu sees the hook. Other processes unaffected.\n", pid);
    }
    else
        printf("[-] R3 hook failed (ioctl=%u status=0x%llX)\n", GetLastError(), p.status);

    CloseHandle(dev);
    return (ok && p.status == 0) ? 0 : 1;
}

static int CmdUnhookR3(UINT64 pid, UINT64 target_va)
{
    printf("[*] Removing R3 EPT hook: pid=%llu target=0x%llX\n", pid, target_va);

    HANDLE dev = OpenDevice();
    if (dev == INVALID_HANDLE_VALUE) return 1;

    TD_R3_UNHOOK_PARAMS p = {};
    p.target_pid         = pid;
    p.target_function_va = target_va;

    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(dev, IOCTL_EPT_UNHOOK_R3, &p, sizeof(p), &p, sizeof(p), &bytes, NULL);

    if (ok && p.status == 0)
        printf("[+] R3 hook removed.\n");
    else
        printf("[-] R3 unhook failed (ioctl=%u status=0x%llX)\n", GetLastError(), p.status);

    CloseHandle(dev);
    return (ok && p.status == 0) ? 0 : 1;
}

// ---- DLL manual-map inject ----

static int CmdInjectDll(const wchar_t* target_name, const wchar_t* dll_path)
{
    printf("[*] Manual Map Inject: %ls <- %ls\n", target_name, dll_path);

    // 1. find target PID
    DWORD pid = FindProcessByName(target_name);
    if (!pid) { printf("[-] Process not found: %ls\n", target_name); return 1; }
    printf("[+] PID: %u\n", pid);

    // 2. read DLL file
    HANDLE hFile = CreateFileW(dll_path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("[-] Cannot open DLL: %ls (error %u)\n", dll_path, GetLastError());
        return 1;
    }

    DWORD dll_size = GetFileSize(hFile, NULL);
    if (dll_size == INVALID_FILE_SIZE || dll_size == 0)
    {
        printf("[-] Invalid DLL file size.\n");
        CloseHandle(hFile);
        return 1;
    }

    printf("[+] DLL size: %u bytes\n", dll_size);

    // 3. allocate IOCTL buffer: header + DLL data
    DWORD total_size = sizeof(TD_INJECT_DLL_PARAMS) + dll_size;
    UINT8* buf = (UINT8*)VirtualAlloc(NULL, total_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf)
    {
        printf("[-] VirtualAlloc failed (error %u)\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }

    // 4. fill header
    TD_INJECT_DLL_PARAMS* p = (TD_INJECT_DLL_PARAMS*)buf;
    memset(p, 0, sizeof(*p));
    p->target_pid = (UINT64)pid;
    p->dll_offset = sizeof(TD_INJECT_DLL_PARAMS);
    p->dll_size   = dll_size;

    // 5. copy DLL data after header
    DWORD bytes_read = 0;
    if (!ReadFile(hFile, buf + sizeof(TD_INJECT_DLL_PARAMS), dll_size, &bytes_read, NULL) ||
        bytes_read != dll_size)
    {
        printf("[-] ReadFile failed (error %u, read %u/%u)\n", GetLastError(), bytes_read, dll_size);
        VirtualFree(buf, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return 1;
    }
    CloseHandle(hFile);

    // 6. send IOCTL
    HANDLE dev = OpenDevice();
    if (dev == INVALID_HANDLE_VALUE)
    {
        VirtualFree(buf, 0, MEM_RELEASE);
        return 1;
    }

    DWORD out_bytes = 0;
    BOOL ok = DeviceIoControl(dev, IOCTL_INJECT_DLL,
                              buf, total_size,
                              buf, sizeof(TD_INJECT_DLL_PARAMS),
                              &out_bytes, NULL);

    if (ok && out_bytes >= sizeof(TD_INJECT_DLL_PARAMS))
    {
        printf("[+] Manual map success!\n");
        printf("    Base:  0x%llX\n", p->out_base);
        printf("    Entry: 0x%llX\n", p->out_entry);
        printf("    Size:  0x%llX\n", p->out_size);
    }
    else
    {
        printf("[-] IOCTL_INJECT_DLL failed (error %u)\n", GetLastError());
    }

    CloseHandle(dev);
    VirtualFree(buf, 0, MEM_RELEASE);
    return ok ? 0 : 1;
}

// ---- usage ----

static void PrintUsage(const wchar_t* exe)
{
    printf("Ophion Test Tool\n\n");
    printf("Usage:\n");
    printf("  %ls inject [process]             Stealth inject (default: notepad.exe)\n", exe);
    printf("  %ls hook                         R0 EPT hook NtCreateFile (all processes)\n", exe);
    printf("  %ls unhook                       Remove R0 EPT hook\n", exe);
    printf("  %ls injectdll <process> <dllpath>  Manual-map DLL inject (no LoadLibrary)\n", exe);
    printf("  %ls hookr3 <pid> <va> <proxy> [type]  R3 EPT hook (per-process)\n", exe);
    printf("  %ls unhookr3 <pid> <va>                Remove R3 EPT hook\n", exe);
    printf("\n");
    printf("Hook types: 0=abs jump (14B), 1=VMCALL (3B), 2=INT3 (1B)\n");
}

// ---- main ----

int wmain(int argc, wchar_t* argv[])
{
    if (argc < 2)
    {
          return CmdInject(L"PioneerGame-d.exe");
        //return CmdInject(L"notepad.exe");

    }

    const wchar_t* cmd = argv[1];

    if (_wcsicmp(cmd, L"inject") == 0)
    {
        const wchar_t* target = (argc > 2) ? argv[2] : L"notepad.exe";
        return CmdInject(target);
    }
    else if (_wcsicmp(cmd, L"injectdll") == 0)
    {
        if (argc < 4) { printf("Usage: injectdll <process> <dllpath>\n"); return 1; }
        return CmdInjectDll(argv[2], argv[3]);
    }
    //else if (_wcsicmp(cmd, L"hook") == 0)
    //{
    //    return CmdHook();
    //}
    else if (_wcsicmp(cmd, L"unhook") == 0)
    {
        return CmdUnhook();
    }
    else if (_wcsicmp(cmd, L"hookr3") == 0)
    {
        if (argc < 5) { printf("Usage: hookr3 <pid> <target_va> <proxy_va> [type]\n"); return 1; }
        UINT64 pid       = wcstoull(argv[2], NULL, 0);
        UINT64 target_va = wcstoull(argv[3], NULL, 16);
        UINT64 proxy_va  = wcstoull(argv[4], NULL, 16);
        UINT64 hook_type = (argc > 5) ? wcstoull(argv[5], NULL, 0) : 0;
        return CmdHookR3(pid, target_va, proxy_va, hook_type);
    }
    else if (_wcsicmp(cmd, L"unhookr3") == 0)
    {
        if (argc < 4) { printf("Usage: unhookr3 <pid> <target_va>\n"); return 1; }
        UINT64 pid       = wcstoull(argv[2], NULL, 0);
        UINT64 target_va = wcstoull(argv[3], NULL, 16);
        return CmdUnhookR3(pid, target_va);
    }
    else
    {
        printf("[-] Unknown command: %ls\n\n", cmd);
        PrintUsage(argv[0]);
        return 1;
    }
}

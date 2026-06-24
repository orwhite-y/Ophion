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
#define IOCTL_INJECT_V2     CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 5, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ---- shared structs (must match TestDriver) ----

#pragma pack(push, 8)
typedef struct _TD_INJECT_PARAMS {
    UINT64 target_pid;
    UINT64 alloc_size;
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

typedef struct _TD_INJECT_V2_PARAMS {
    UINT64 target_pid;
    UINT64 trigger_va;      // R3 function to hook as trigger
    UINT64 alloc_size;
    UINT64 shellcode_va;    // [out]
    UINT64 actual_size;     // [out]
} TD_INJECT_V2_PARAMS;
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

// ---- V2 inject (single-CPU, no DPC) ----

//
// resolve a function VA in a remote process by name.
// loads the DLL locally, computes RVA, then adds remote module base.
//
static UINT64 ResolveRemoteFunction(DWORD pid, const char* dll_name, const char* func_name)
{
    // get local address → RVA
    HMODULE local_mod = GetModuleHandleA(dll_name);
    if (!local_mod) local_mod = LoadLibraryA(dll_name);
    if (!local_mod) return 0;

    FARPROC local_fn = GetProcAddress(local_mod, func_name);
    if (!local_fn) return 0;

    UINT64 rva = (UINT64)local_fn - (UINT64)local_mod;

    // find remote module base via toolhelp
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    MODULEENTRY32W me = {};
    me.dwSize = sizeof(me);

    UINT64 remote_base = 0;
    if (Module32FirstW(snap, &me))
    {
        do {
            char narrow[MAX_PATH];
            WideCharToMultiByte(CP_ACP, 0, me.szModule, -1, narrow, MAX_PATH, NULL, NULL);
            if (_stricmp(narrow, dll_name) == 0)
            {
                remote_base = (UINT64)me.modBaseAddr;
                break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);

    return remote_base ? (remote_base + rva) : 0;
}

static int CmdInjectV2(const wchar_t* target_name, const char* trigger_dll, const char* trigger_func)
{
    printf("[*] Stealth Inject V2 (single-CPU): %ls\n", target_name);
    printf("[*] Trigger: %s!%s\n", trigger_dll, trigger_func);

    DWORD pid = FindProcessByName(target_name);
    if (!pid) { printf("[-] Process not found.\n"); return 1; }
    printf("[+] PID: %u\n", pid);

    UINT64 trigger_va = ResolveRemoteFunction(pid, trigger_dll, trigger_func);
    if (!trigger_va)
    {
        printf("[-] Cannot resolve %s!%s in PID %u\n", trigger_dll, trigger_func, pid);
        return 1;
    }
    printf("[+] Trigger VA: 0x%llX\n", trigger_va);

    HANDLE dev = OpenDevice();
    if (dev == INVALID_HANDLE_VALUE) return 1;

    TD_INJECT_V2_PARAMS p = {};
    p.target_pid = (UINT64)pid;
    p.trigger_va = trigger_va;

    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(dev, IOCTL_INJECT_V2, &p, sizeof(p), &p, sizeof(p), &bytes, NULL);

    if (ok && p.shellcode_va)
    {
        printf("[+] Shellcode VA: 0x%llX\n", p.shellcode_va);
        printf("[+] Single-CPU inject OK. Thread runs trigger on CPU 0.\n");
    }
    else
        printf("[-] IOCTL_INJECT_V2 failed (error %u)\n", GetLastError());

    CloseHandle(dev);
    return (ok && p.shellcode_va) ? 0 : 1;
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

// ---- usage ----

static void PrintUsage(const wchar_t* exe)
{
    printf("Ophion Test Tool\n\n");
    printf("Usage:\n");
    printf("  %ls inject [process]             Stealth inject via DPC (default: notepad.exe)\n", exe);
    printf("  %ls inject2 [process] [dll!func] Single-CPU inject, no DPC (default: ntdll!NtTestAlert)\n", exe);
    printf("  %ls hook                         R0 EPT hook NtCreateFile (all processes)\n", exe);
    printf("  %ls unhook                       Remove R0 EPT hook\n", exe);
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
        // default: inject into notepad.exe
        return CmdInject(L"notepad.exe");
    }

    const wchar_t* cmd = argv[1];

    if (_wcsicmp(cmd, L"inject") == 0)
    {
        const wchar_t* target = (argc > 2) ? argv[2] : L"notepad.exe";
        return CmdInject(target);
    }
    else if (_wcsicmp(cmd, L"inject2") == 0)
    {
        const wchar_t* target = (argc > 2) ? argv[2] : L"notepad.exe";

        // parse optional trigger: "ntdll.dll!NtTestAlert" or "dll" "func"
        const char* trigger_dll  = "ntdll.dll";
        const char* trigger_func = "NtTestAlert";

        if (argc > 3)
        {
            // expect "dll!func" format
            static char trig_buf[256];
            WideCharToMultiByte(CP_ACP, 0, argv[3], -1, trig_buf, sizeof(trig_buf), NULL, NULL);
            char* bang = strchr(trig_buf, '!');
            if (bang)
            {
                *bang = '\0';
                trigger_dll  = trig_buf;
                trigger_func = bang + 1;
            }
        }

        return CmdInjectV2(target, trigger_dll, trigger_func);
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

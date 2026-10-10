// _smoke_r3_autoclose.cpp - synchronous MessageBoxA R3 EPT hook diagnostic.
// Keeps the hook/proxy/trampoline path of test_hook_r3.cpp, but closes the
// modal dialogs from a helper thread so the terminal command can run normally.
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TD_IOCTL_BASE 0x900
#define IOCTL_EPT_HOOK_R3   CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EPT_UNHOOK_R3 CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 4, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 8)
typedef struct _TD_R3_HOOK_PARAMS {
    UINT64 target_pid;
    UINT64 target_function_va;
    UINT64 proxy_function_va;
    UINT64 hook_type;
    UINT64 trampoline_va;
    UINT64 status;
} TD_R3_HOOK_PARAMS;

typedef struct _TD_R3_UNHOOK_PARAMS {
    UINT64 target_pid;
    UINT64 target_function_va;
    UINT64 status;
} TD_R3_UNHOOK_PARAMS;
#pragma pack(pop)

static UINT64 g_trampoline = 0;
static volatile LONG g_call_count = 0;
static volatile LONG g_dialog_count = 0;
static volatile LONG g_done = 0;

static int WINAPI Proxy_MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    char new_caption[256];
    LONG n = InterlockedIncrement(&g_call_count);
    _snprintf_s(new_caption, sizeof(new_caption), _TRUNCATE,
                "[HOOK #%ld] Original: %s", n, lpCaption ? lpCaption : "NULL");
    printf("[PROXY] call=%ld text='%.40s' caption='%.40s' new='%s'\n",
           n,
           lpText ? lpText : "(null)",
           lpCaption ? lpCaption : "(null)",
           new_caption);

    if (g_trampoline) {
        typedef int (WINAPI *OrigFn)(HWND, LPCSTR, LPCSTR, UINT);
        return ((OrigFn)g_trampoline)(hWnd, lpText, new_caption, uType);
    }
    return MessageBoxA(hWnd, lpText, new_caption, uType);
}

static BOOL CALLBACK CloseOwnedDialog(HWND hwnd, LPARAM)
{
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid != GetCurrentProcessId() || !IsWindowVisible(hwnd))
        return TRUE;

    char class_name[64] = {};
    char title[512] = {};
    GetClassNameA(hwnd, class_name, (int)sizeof(class_name));
    GetWindowTextA(hwnd, title, (int)sizeof(title));
    if (strcmp(class_name, "#32770") != 0)
        return TRUE;

    LONG n = InterlockedIncrement(&g_dialog_count);
    printf("[DIALOG] count=%ld title='%s'\n", n, title);
    PostMessageW(hwnd, WM_CLOSE, 0, 0);
    return FALSE;
}

static DWORD WINAPI DialogCloserThread(LPVOID)
{
    for (DWORD elapsed = 0; elapsed < 10000; elapsed += 50) {
        if (EnumWindows(CloseOwnedDialog, 0) == FALSE)
            return 0;
        Sleep(50);
    }
    printf("[FAIL] dialog closer timed out\n");
    return 1;
}

static DWORD WINAPI WatchdogThread(LPVOID)
{
    Sleep(25000);
    if (InterlockedCompareExchange(&g_done, 0, 0) == 0) {
        printf("[WATCHDOG] forced exit after 25 seconds\n");
        ExitProcess(100);
    }
    return 0;
}

static HANDLE open_driver(void)
{
    return CreateFileW(L"\\\\.\\RMCoreTst", GENERIC_READ | GENERIC_WRITE,
                       0, NULL, OPEN_EXISTING, 0, NULL);
}

static BOOL SpawnAndWaitForChildExit(void)
{
    wchar_t command[] = L"C:\\Windows\\System32\\cmd.exe /d /c exit 0";
    STARTUPINFOW si = {};
    PROCESS_INFORMATION pi = {};
    si.cb = sizeof(si);
    if (!CreateProcessW(NULL, command, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        printf("[FAIL] child create err=%lu\n", GetLastError());
        return FALSE;
    }

    DWORD wait = WaitForSingleObject(pi.hProcess, 5000);
    DWORD child_exit = 0;
    GetExitCodeProcess(pi.hProcess, &child_exit);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    printf("[CHILD] wait=%lu exit=%lu\n", wait, child_exit);
    Sleep(250); // allow the process-exit notify cleanup/resume DPCs to finish
    return wait == WAIT_OBJECT_0 && child_exit == 0;
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    CreateThread(NULL, 0, WatchdogThread, NULL, 0, NULL);
    printf("=== Auto-close R3 EPT MessageBoxA Hook Diagnostic ===\n");

    HANDLE dev = open_driver();
    if (dev == INVALID_HANDLE_VALUE) {
        printf("[FAIL] open driver err=%lu\n", GetLastError());
        InterlockedExchange(&g_done, 1);
        return 1;
    }

    HMODULE user32 = GetModuleHandleA("user32.dll");
    PVOID target = user32 ? (PVOID)GetProcAddress(user32, "MessageBoxA") : NULL;
    PVOID proxy = (PVOID)&Proxy_MessageBoxA;
    if (!target) {
        printf("[FAIL] resolve MessageBoxA\n");
        CloseHandle(dev);
        InterlockedExchange(&g_done, 1);
        return 2;
    }
    printf("[INFO] pid=%lu target=%p proxy=%p\n", GetCurrentProcessId(), target, proxy);

    TD_R3_HOOK_PARAMS hook = {};
    hook.target_pid = GetCurrentProcessId();
    hook.target_function_va = (UINT64)target;
    hook.proxy_function_va = (UINT64)proxy;
    hook.hook_type = 1;

    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(dev, IOCTL_EPT_HOOK_R3,
                              &hook, sizeof(hook), &hook, sizeof(hook), &bytes, NULL);
    if (!ok || hook.status != 0) {
        printf("[FAIL] install ok=%d err=%lu status=0x%llX\n",
               (int)ok, GetLastError(), (unsigned long long)hook.status);
        CloseHandle(dev);
        InterlockedExchange(&g_done, 1);
        return 3;
    }

    g_trampoline = hook.trampoline_va;
    printf("[PASS] installed trampoline=0x%llX\n", (unsigned long long)g_trampoline);

    if (!SpawnAndWaitForChildExit()) {
        CloseHandle(dev);
        InterlockedExchange(&g_done, 1);
        return 4;
    }

    HANDLE closer = CreateThread(NULL, 0, DialogCloserThread, NULL, 0, NULL);
    MessageBoxA(NULL, "First automated smoke message", "Original Title", MB_OK);
    WaitForSingleObject(closer, 1000);
    CloseHandle(closer);

    closer = CreateThread(NULL, 0, DialogCloserThread, NULL, 0, NULL);
    MessageBoxA(NULL, "Second automated smoke message", "Another Title", MB_OK);
    WaitForSingleObject(closer, 1000);
    CloseHandle(closer);

    TD_R3_UNHOOK_PARAMS unhook = {};
    unhook.target_pid = GetCurrentProcessId();
    unhook.target_function_va = (UINT64)target;
    ok = DeviceIoControl(dev, IOCTL_EPT_UNHOOK_R3,
                         &unhook, sizeof(unhook), &unhook, sizeof(unhook), &bytes, NULL);
    printf("[UNHOOK] ok=%d err=%lu status=0x%llX\n",
           (int)ok, GetLastError(), (unsigned long long)unhook.status);
    CloseHandle(dev);

    InterlockedExchange(&g_done, 1);
    printf("[RESULT] proxy_calls=%ld dialogs=%ld\n", g_call_count, g_dialog_count);
    return (ok && unhook.status == 0 && g_call_count == 2 && g_dialog_count == 2) ? 0 : 5;
}

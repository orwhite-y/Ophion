// _smoke_r3_auto.cpp - automated smoke variant of the known-good test_hook_r3.cpp.
// Keep the target/proxy/trampoline path identical to test_hook_r3.cpp.
// The only intended difference is removing the interactive pause before testing.
#include <windows.h>
#include <stdint.h>
#include <stdio.h>

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

static int WINAPI Proxy_MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    char new_caption[256];
    LONG n = InterlockedIncrement(&g_call_count);

    _snprintf_s(new_caption, sizeof(new_caption), _TRUNCATE,
                "[HOOK #%ld] Original: %s", n, lpCaption ? lpCaption : "NULL");

    printf("[PROXY] MessageBoxA intercepted text='%.40s' caption='%.40s' -> new='%s'\n",
           lpText ? lpText : "(null)",
           lpCaption ? lpCaption : "(null)",
           new_caption);
    fflush(stdout);

    if (g_trampoline) {
        typedef int (WINAPI *OrigFn)(HWND, LPCSTR, LPCSTR, UINT);
        return ((OrigFn)g_trampoline)(hWnd, lpText, new_caption, uType);
    }

    return MessageBoxA(hWnd, lpText, new_caption, uType);
}

static HANDLE open_driver(void)
{
    return CreateFileW(L"\\\\.\\RMCoreTst",
                       GENERIC_READ | GENERIC_WRITE,
                       0,
                       NULL,
                       OPEN_EXISTING,
                       0,
                       NULL);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== Auto R3 EPT MessageBoxA Hook Smoke ===\n");

    HANDLE dev = open_driver();
    if (dev == INVALID_HANDLE_VALUE) {
        printf("[FAIL] open device err=%lu\n", GetLastError());
        return 1;
    }

    HMODULE user32 = GetModuleHandleA("user32.dll");
    PVOID target = user32 ? (PVOID)GetProcAddress(user32, "MessageBoxA") : NULL;
    PVOID proxy = (PVOID)&Proxy_MessageBoxA;
    if (!target || !proxy) {
        printf("[FAIL] resolve MessageBoxA\n");
        CloseHandle(dev);
        return 2;
    }

    printf("[INFO] pid=%lu target=%p proxy=%p\n",
           GetCurrentProcessId(), target, proxy);

    TD_R3_HOOK_PARAMS hook = {0};
    hook.target_pid = GetCurrentProcessId();
    hook.target_function_va = (UINT64)target;
    hook.proxy_function_va = (UINT64)proxy;
    hook.hook_type = 1; // VMCALL trampoline, same as known-good example.

    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(dev,
                              IOCTL_EPT_HOOK_R3,
                              &hook,
                              sizeof(hook),
                              &hook,
                              sizeof(hook),
                              &bytes,
                              NULL);
    if (!ok || hook.status != 0) {
        printf("[FAIL] install ok=%d err=%lu status=0x%llX\n",
               (int)ok, GetLastError(), (unsigned long long)hook.status);
        CloseHandle(dev);
        return 3;
    }

    g_trampoline = hook.trampoline_va;
    printf("[PASS] installed trampoline=0x%llX\n",
           (unsigned long long)g_trampoline);

    printf("[TEST] calling MessageBoxA #1\n");
    MessageBoxA(NULL, "First automated smoke message", "Original Title", MB_OK);

    printf("[TEST] calling MessageBoxA #2\n");
    MessageBoxA(NULL, "Second automated smoke message", "Another Title", MB_OK);

    TD_R3_UNHOOK_PARAMS unhook = {0};
    unhook.target_pid = GetCurrentProcessId();
    unhook.target_function_va = (UINT64)target;

    ok = DeviceIoControl(dev,
                         IOCTL_EPT_UNHOOK_R3,
                         &unhook,
                         sizeof(unhook),
                         &unhook,
                         sizeof(unhook),
                         &bytes,
                         NULL);
    if (!ok || unhook.status != 0) {
        printf("[FAIL] unhook ok=%d err=%lu status=0x%llX\n",
               (int)ok, GetLastError(), (unsigned long long)unhook.status);
        CloseHandle(dev);
        return 4;
    }

    printf("[PASS] unhooked proxy_calls=%ld\n", g_call_count);
    CloseHandle(dev);

    if (g_call_count != 2) {
        printf("[FAIL] expected 2 proxy calls, got %ld\n", g_call_count);
        return 5;
    }

    printf("[PASS] smoke completed\n");
    return 0;
}

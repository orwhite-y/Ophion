// _smoke_r3_no_ui.cpp - non-interactive R3 EPT hook smoke test.
// Replaces the MessageBoxA test with GetSystemMetrics so automation never blocks on UI.
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

static int WINAPI Proxy_GetSystemMetrics(int nIndex)
{
    LONG n = InterlockedIncrement(&g_call_count);
    printf("[PROXY] GetSystemMetrics intercepted index=%d call=%ld\n", nIndex, n);
    fflush(stdout);

    if (g_trampoline) {
        typedef int (WINAPI *OrigFn)(int);
        return ((OrigFn)g_trampoline)(nIndex);
    }
    return GetSystemMetrics(nIndex);
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
    printf("=== Non-interactive R3 EPT GetSystemMetrics Hook Smoke ===\n");

    HANDLE dev = open_driver();
    if (dev == INVALID_HANDLE_VALUE) {
        printf("[FAIL] open device err=%lu\n", GetLastError());
        return 1;
    }

    HMODULE user32 = GetModuleHandleA("user32.dll");
    PVOID target = user32 ? (PVOID)GetProcAddress(user32, "GetSystemMetrics") : NULL;
    PVOID proxy = (PVOID)&Proxy_GetSystemMetrics;
    if (!target || !proxy) {
        printf("[FAIL] resolve GetSystemMetrics\n");
        CloseHandle(dev);
        return 2;
    }

    printf("[INFO] pid=%lu target=%p proxy=%p\n", GetCurrentProcessId(), target, proxy);

    TD_R3_HOOK_PARAMS hook = {0};
    hook.target_pid = GetCurrentProcessId();
    hook.target_function_va = (UINT64)target;
    hook.proxy_function_va = (UINT64)proxy;
    hook.hook_type = 1;

    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(dev, IOCTL_EPT_HOOK_R3, &hook, sizeof(hook), &hook, sizeof(hook), &bytes, NULL);
    if (!ok || hook.status != 0) {
        printf("[FAIL] install ok=%d err=%lu status=0x%llX\n", (int)ok, GetLastError(), (unsigned long long)hook.status);
        CloseHandle(dev);
        return 3;
    }

    g_trampoline = hook.trampoline_va;
    printf("[PASS] installed trampoline=0x%llX\n", (unsigned long long)g_trampoline);

    int v1 = GetSystemMetrics(SM_CXSCREEN);
    int v2 = GetSystemMetrics(SM_CYSCREEN);
    printf("[INFO] values: cx=%d cy=%d\n", v1, v2);

    TD_R3_UNHOOK_PARAMS unhook = {0};
    unhook.target_pid = GetCurrentProcessId();
    unhook.target_function_va = (UINT64)target;
    ok = DeviceIoControl(dev, IOCTL_EPT_UNHOOK_R3, &unhook, sizeof(unhook), &unhook, sizeof(unhook), &bytes, NULL);
    if (!ok || unhook.status != 0) {
        printf("[FAIL] unhook ok=%d err=%lu status=0x%llX\n", (int)ok, GetLastError(), (unsigned long long)unhook.status);
        CloseHandle(dev);
        return 4;
    }

    printf("[PASS] unhooked proxy_calls=%ld\n", g_call_count);
    CloseHandle(dev);

    if (g_call_count != 2) {
        printf("[FAIL] expected 2 proxy calls, got %ld\n", g_call_count);
        return 5;
    }

    printf("[PASS] non-interactive smoke completed\n");
    return 0;
}

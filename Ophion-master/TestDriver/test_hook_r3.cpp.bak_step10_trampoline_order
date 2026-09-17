// test_hook_r3.cpp - R3 EPT Hook Test
// Modified: Proxy MessageBoxA returns distinct title for visual verification
#include <windows.h>
#include <stdint.h>
#include <stdio.h>

#define TD_IOCTL_BASE 0x900
#define IOCTL_EPT_HOOK_R3   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900+3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EPT_UNHOOK_R3 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900+4, METHOD_BUFFERED, FILE_ANY_ACCESS)

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
static int g_call_count = 0;

// Proxy: called instead of MessageBoxA
// Title changes with each call so we can visually confirm the hook is working
static int WINAPI Proxy_MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    char new_caption[256];
    g_call_count++;
    snprintf(new_caption, sizeof(new_caption), "[HOOK #%d] Original: %s", g_call_count, lpCaption ? lpCaption : "NULL");

    printf("[PROXY] MessageBoxA intercepted! text='%.40s' caption='%.40s' -> new='%s'\n",
           lpText ? lpText : "(null)", lpCaption ? lpCaption : "(null)", new_caption);

    // Call original function via trampoline
    if (g_trampoline) {
        typedef int (WINAPI *OrigFn)(HWND, LPCSTR, LPCSTR, UINT);
        return ((OrigFn)g_trampoline)(hWnd, lpText, new_caption, uType);
    }
    // Fallback if trampoline not set
    return MessageBoxA(hWnd, lpText, new_caption, uType);
}

static HANDLE open_driver(void)
{
    return CreateFileW(L"\\\\.\\RMCoreTst", GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
}

int main(void)
{
    printf("=== R3 EPT Hook Test ===\n");

    HANDLE dev = open_driver();
    if (dev == INVALID_HANDLE_VALUE) {
        printf("[ERR] Open driver failed, err=%lu\n", GetLastError());
        return 1;
    }
    printf("[OK] Driver handle opened\n");

    // Get MessageBoxA address in this process
    HMODULE hUser32 = GetModuleHandleA("user32.dll");
    PVOID msgboxA = hUser32 ? GetProcAddress(hUser32, "MessageBoxA") : NULL;
    if (!msgboxA) {
        printf("[ERR] Failed to resolve MessageBoxA\n");
        CloseHandle(dev);
        return 1;
    }
    printf("[OK] MessageBoxA VA = 0x%p\n", msgboxA);

    // Proxy is our standalone function
    PVOID proxy = (PVOID)&Proxy_MessageBoxA;
    printf("[OK] Proxy_MessageBoxA VA = 0x%p\n", proxy);

    // Install hook: hook_type=1 => VMCALL (0F 01 C1)
    TD_R3_HOOK_PARAMS p = {0};
    p.target_pid = GetCurrentProcessId();
    p.target_function_va = (UINT64)msgboxA;
    p.proxy_function_va = (UINT64)proxy;
    p.hook_type = 1;

    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(dev, IOCTL_EPT_HOOK_R3, &p, sizeof(p), &p, sizeof(p), &bytes, NULL);

    if (!ok || p.status != 0) {
        printf("[FAIL] Hook install failed: ok=%d err=%lu status=0x%llX\n",
               (int)ok, GetLastError(), (unsigned long long)p.status);
        CloseHandle(dev);
        return 1;
    }
    system("pause");
    g_trampoline = p.trampoline_va;
    printf("[PASS] Hook installed! trampoline=0x%llX\n", (unsigned long long)g_trampoline);

    // Trigger test - title will show "[HOOK #1]"
    printf("[TEST] Calling MessageBoxA (expect title [HOOK #1])...\n");
    MessageBoxA(NULL, "First test message", "Original Title", MB_OK);

    // Trigger test again - title will show "[HOOK #2]"
    printf("[TEST] Calling MessageBoxA again (expect title [HOOK #2])...\n");
    MessageBoxA(NULL, "Second test message", "Another Title", MB_OK);

    // Unhook
    TD_R3_UNHOOK_PARAMS u = {0};
    u.target_pid = GetCurrentProcessId();
    u.target_function_va = (UINT64)msgboxA;
    ok = DeviceIoControl(dev, IOCTL_EPT_UNHOOK_R3, &u, sizeof(u), &u, sizeof(u), &bytes, NULL);
    if (!ok || u.status != 0) {
        printf("[WARN] Unhook failed: ok=%d err=%lu status=0x%llX\n",
               (int)ok, GetLastError(), (unsigned long long)u.status);
    } else {
        printf("[OK] Unhooked successfully\n");
    }

    CloseHandle(dev);
    printf("=== DONE ===\n");
    return 0;
}

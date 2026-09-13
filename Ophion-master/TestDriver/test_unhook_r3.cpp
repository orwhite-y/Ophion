// test_unhook_r3.cpp - IOCTL_EPT_UNHOOK_R3 封装补全
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#define RDOC_OPHION_DEVICE L"\\.\RMCoreTst"

#pragma pack(push, 8)
typedef struct _RDOC_TD_R3_UNHOOK_PARAMS {
    UINT64 target_pid;
    UINT64 target_function_va;
    UINT64 status;
} RDOC_TD_R3_UNHOOK_PARAMS;
#pragma pack(pop)

// 假设 RDOC_IOCTL_EPT_UNHOOK_R3 已定义为 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900+4, ...)
#define RDOC_IOCTL_EPT_UNHOOK_R3 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900+4, METHOD_BUFFERED, FILE_ANY_ACCESS)

static bool rdoc_OphionEptUnhookR3(DWORD target_pid, void *target_function_va)
{
    if (!target_function_va) return false;

    HANDLE dev = CreateFileW(RDOC_OPHION_DEVICE, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                             OPEN_EXISTING, 0, nullptr);
    if (dev == INVALID_HANDLE_VALUE) return false;

    RDOC_TD_R3_UNHOOK_PARAMS p = {};
    p.target_pid = target_pid ? (UINT64)target_pid : (UINT64)GetCurrentProcessId();
    p.target_function_va = (UINT64)target_function_va;

    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(dev, RDOC_IOCTL_EPT_UNHOOK_R3, &p, sizeof(p), &p, sizeof(p),
                              &bytes, nullptr);
    DWORD le = ok ? 0 : GetLastError();
    bool result = (ok && p.status == 0);

    if (!result) {
        printf("[UNHOOK] FAILED: ok=%d le=%lu status=0x%llx\n",
               (int)ok, le, (unsigned long long)p.status);
    } else {
        printf("[UNHOOK] OK: status=0x%llx\n", (unsigned long long)p.status);
    }

    CloseHandle(dev);
    return result;
}

int main()
{
    // 测试 unhook：需要一个已安装的 hook 的 target_function_va
    // 这里用 MessageBoxA 演示（实际应传之前 hook 的地址）
    HMODULE hUser32 = GetModuleHandleA("user32.dll");
    if (!hUser32) { printf("[ERROR] user32.dll 未加载\n"); return 1; }
    void *msgboxA = (void *)GetProcAddress(hUser32, "MessageBoxA");

    printf("[TEST] Unhook target_pid=%lu target=0x%p\n", GetCurrentProcessId(), msgboxA);
    bool ok = rdoc_OphionEptUnhookR3(GetCurrentProcessId(), msgboxA);
    printf("[RESULT] unhook %s\n", ok ? "SUCCESS" : "FAILED");
    return ok ? 0 : 1;
}

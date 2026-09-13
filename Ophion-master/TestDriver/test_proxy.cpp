// proxy_wrapper.cpp
// 编译到 Test.dll 内，作为被 hook 函数的代理
#include <windows.h>
#include <stdint.h>

// 这些由测试主机注入时填充
static PVOID g_original_trampoline = NULL;
static PVOID g_hook_context = NULL;

extern "C" __declspec(dllexport)
int WINAPI Proxy_MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    // 输出日志（可以在 hv 日志或 DbgPrint 中看到）
    DbgPrint("[Ophion Hook] Proxy_MessageBoxA triggered!\n");
    
    // 如果 trampoline 已设置，调用原始函数
    if (g_original_trampoline) {
        typedef int (WINAPI *OriginalMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
        OriginalMessageBoxA orig = (OriginalMessageBoxA)g_original_trampoline;
        return orig(hWnd, lpText, lpCaption, uType);
    }
    
    // fallback: 直接调用（绕过 hook）
    return MessageBoxA(hWnd, lpText, lpCaption, uType);
}

extern "C" __declspec(dllexport)
void WINAPI SetHookContext(PVOID trampoline, PVOID context)
{
    g_original_trampoline = trampoline;
    g_hook_context = context;
}

extern "C" __declspec(dllexport)
PVOID WINAPI GetProxyVa()
{
    // 返回自身在模块内的 VA（供 IOCTL_EPT_HOOK_R3 使用）
    return (PVOID)&Proxy_MessageBoxA;
}

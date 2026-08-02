# Plan: R3 injector + IOCTL trigger + Present hook wrap existing device

## Architecture

```
R3 injector.exe (手动调用)
  入参: 游戏名 + renderdoc.dll 路径
  -> 找游戏 PID (CreateToolhelp32Snapshot)
  -> DeviceIoControl(\\.\OphionTest, IOCTL_INJECT_RENDERDOC, {pid, renderdoc_path})

Driver (IOCTL handler)
  -> TdInjectRenderdocShadow(proc, renderdoc_path, "td-injector", TRUE)
  // wait=TRUE 安全: IOCTL handler 在注入器进程上下文, 不持 loader lock
  // 不 hook NtCreateFile, 不 hook 任何系统 API

renderdoc DllMain (改过的 RegisterHooks)
  -> 不 hook D3D12CreateDevice (用户要求先不做)
  -> 找 dxgi.dll swapchain vtable 里的 Present 函数地址
  -> rdoc_OphionEptHookR3 hook Present
  -> DllMain 返回

游戏下一帧 Present
  -> EPT hook 命中 -> Present_hook
  -> 从 RCX (this) 拿 swapchain 指针
  -> swapchain->GetDevice(__uuidof(ID3D12Device), &realDevice)
  -> WrappedID3D12Device::Create(realDevice, params, false)
  -> new WrappedIDXGISwapChain4(realSwapchain, hwnd, wrappedDevice)
  -> 替换 swapchain vtable 指针 (或让游戏后续调用走 wrapped)
  -> 调原始 Present
  -> F12 overlay 生效
```

## Phase 1: Driver + R3 injector (打通注入路径)

### 1.1 Driver: 新增 IOCTL_INJECT_RENDERDOC

**文件**: `TestDriver/test_driver.cpp`

新增 IOCTL code:
```c
#define IOCTL_INJECT_RENDERDOC CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 16, METHOD_BUFFERED, FILE_ANY_ACCESS)
```

新增 params struct:
```c
typedef struct _TD_INJECT_RENDERDOC_PARAMS {
    UINT64 target_pid;          // [in] 游戏进程 PID
    WCHAR  renderdoc_path[520]; // [in] NT 路径, e.g. \??\C:\...\renderdoc.dll
    UINT64 status;              // [out] NTSTATUS
} TD_INJECT_RENDERDOC_PARAMS;
```

新增 IOCTL handler (在 TdIoControl 的 switch 里):
```c
case IOCTL_INJECT_RENDERDOC:
{
    // validate buffer
    TD_INJECT_RENDERDOC_PARAMS * p = ...;
    PEPROCESS proc = NULL;
    st = PsLookupProcessByProcessId((HANDLE)p->target_pid, &proc);
    if (!NT_SUCCESS(st)) break;

    UNICODE_STRING renderdoc_nt;
    RtlInitUnicodeString(&renderdoc_nt, p->renderdoc_path);

    st = TdInjectRenderdocShadow(proc, &renderdoc_nt, "td-injector", TRUE);
    // wait=TRUE: IOCTL handler 在注入器进程上下文, 不持 loader lock, 安全

    ObDereferenceObject(proc);
    p->status = (UINT64)st;
    irp->IoStatus.Information = sizeof(*p);
    break;
}
```

### 1.2 Driver: 删除 NtCreateFile EPT hook

**文件**: `TestDriver/test_driver.cpp`, DriverEntry

注释掉 `TdEptHookNtCreateFile()` 调用 (约 line 8278):
```c
// [已禁用] 不再 hook NtCreateFile, 改为 R3 injector 手动发 IOCTL 触发
// {
//     NTSTATUS hook_st = TdEptHookNtCreateFile();
//     ...
// }
```

保留 HookedNtCreateFile / TdMatchFileBasename / TdInjectWorkRoutine 等代码 (不删, 以备后用),
只是不在 DriverEntry 里安装 hook。

### 1.3 R3 injector

**新文件**: `Injector/inject_renderdoc.cpp` (或放在现有 Injector 目录)

```c
// inject_renderdoc.exe <游戏名> <renderdoc.dll 全路径>
// 例: inject_renderdoc.exe PioneerGame.exe C:\Users\q\Desktop\d\renderdoc.dll

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

// IOCTL code (必须和驱动一致)
#define TD_IOCTL_BASE 0x900
#define IOCTL_INJECT_RENDERDOC CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 16, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 8)
typedef struct {
    UINT64 target_pid;
    WCHAR  renderdoc_path[520];
    UINT64 status;
} TD_INJECT_RENDERDOC_PARAMS;
#pragma pack(pop)

DWORD FindProcessByName(const wchar_t * name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe = { sizeof(pe) };
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

int wmain(int argc, wchar_t ** argv)
{
    if (argc < 3) { printf("Usage: inject_renderdoc.exe <game.exe> <renderdoc.dll path>\n"); return 1; }

    DWORD pid = FindProcessByName(argv[1]);
    if (!pid) { printf("Process not found: %ls\n", argv[1]); return 1; }
    printf("Found %ls pid=%lu\n", argv[1], pid);

    // build NT path: C:\...\renderdoc.dll -> \??\C:\...\renderdoc.dll
    wchar_t nt_path[520];
    _snwprintf(nt_path, 520, L"\\??\\%s", argv[2]);

    TD_INJECT_RENDERDOC_PARAMS params = {0};
    params.target_pid = pid;
    wcscpy_s(params.renderdoc_path, nt_path);

    HANDLE dev = CreateFileW(L"\\\\.\\OphionTest", GENERIC_READ | GENERIC_WRITE, 0, NULL,
                             OPEN_EXISTING, 0, NULL);
    if (dev == INVALID_HANDLE_VALUE) { printf("Failed to open driver device\n"); return 1; }

    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(dev, IOCTL_INJECT_RENDERDOC, &params, sizeof(params),
                              &params, sizeof(params), &bytes, NULL);
    CloseHandle(dev);

    if (!ok) { printf("DeviceIoControl failed: %lu\n", GetLastError()); return 1; }
    printf("Inject status: 0x%llx\n", params.status);
    return (params.status == 0) ? 0 : 1;
}
```

## Phase 2: renderdoc Present hook + wrap existing device

### 2.1 找 swapchain Present 函数地址

**文件**: `renderdoc/driver/dxgi/dxgi_hooks.cpp`

Present 不是 dxgi.dll 的导出函数, 是 IDXGISwapChain vtable 的第 8 个条目 (index 8)。
但 swapchain 对象在游戏堆里, renderdoc 不知道地址。

**方法**: 不找 vtable, 改为 hook dxgi.dll 里 Present 的实现函数。
Present 的实现在 dxgi.dll 内部, 可以通过以下方式找到:
- 拿到 dxgi.dll base (rdoc_OphionGetModuleBase)
- 扫 dxgi.dll 的 .text 段, 匹配 Present 的函数特征 (prologue + 特定指令序列)
- 或者: 创建一个临时 swapchain (CreateSwapChain), 读它的 vtable[8] 拿到 Present 地址, 然后销毁临时 swapchain

**推荐**: 临时 swapchain 法 (最可靠):
```cpp
// 在 RegisterHooks 里:
UINT64 dxgi_base = rdoc_OphionGetModuleBase(pid, "dxgi.dll");
if (!dxgi_base) return; // dxgi 没加载

// 创建临时 swapchain 拿 Present 地址
IDXGIFactory *factory = NULL;
CreateDXGIFactory(__uuidof(IDXGIFactory), (void **)&factory);
DXGI_SWAP_CHAIN_DESC desc = {};
desc.BufferCount = 1;
desc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
desc.OutputWindow = GetDesktopWindow();
desc.SampleDesc.Count = 1;
desc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
desc.Windowed = TRUE;
IDXGISwapChain *swapchain = NULL;
factory->CreateSwapChain(NULL, &desc, &swapchain);

// vtable[8] = Present (IDXGISwapChain::Present 是 vtable 第 8 个)
void **vtable = *(void ***)swapchain;
void *present_addr = vtable[8];

// EPT hook Present
void *trampoline = rdoc_OphionEptHookR3(pid, present_addr, (void *)Present_hook, 1);

swapchain->Release();
factory->Release();
```

### 2.2 Present hook: 包装已有设备

**文件**: `renderdoc/driver/dxgi/dxgi_hooks.cpp`

```cpp
static volatile LONG g_wrapped = 0;

static HRESULT WINAPI Present_hook(IDXGISwapChain *swapchain, UINT SyncInterval, UINT Flags)
{
    // 一次性包装
    if (_InterlockedCompareExchange(&g_wrapped, 1, 0) == 0)
    {
        // 从 swapchain 拿真实 device
        ID3D12Device *realDevice = NULL;
        HRESULT hr = swapchain->GetDevice(__uuidof(ID3D12Device), (void **)&realDevice);
        if (SUCCEEDED(hr) && realDevice)
        {
            if (!WrappedID3D12Device::IsAlloc(realDevice))
            {
                D3D12InitParams params = {};
                params.MinimumFeatureLevel = D3D_FEATURE_LEVEL_11_0;
                WrappedID3D12Device *wrappedDevice =
                    WrappedID3D12Device::Create(realDevice, params, false);

                // 包装 swapchain
                DXGI_SWAP_CHAIN_DESC scDesc = {};
                swapchain->GetDesc(&scDesc);
                WrappedIDXGISwapChain4 *wrappedSwapchain =
                    new WrappedIDXGISwapChain4(swapchain, scDesc.OutputWindow, wrappedDevice);

                RDCLOG("Wrapped existing device + swapchain on Present");
            }
            realDevice->Release();
        }
    }

    // 调原始 Present (通过 trampoline)
    // 注意: 这里不能直接调 swapchain->Present() (会回到 hook)
    // 需要: 用 trampoline 调原始 Present 函数
    typedef HRESULT (WINAPI *PFN_Present)(IDXGISwapChain *, UINT, UINT);
    static PFN_Present origPresent = NULL;
    if (!origPresent) origPresent = (PFN_Present)g_present_trampoline; // 从 hook 返回值保存
    return origPresent(swapchain, SyncInterval, Flags);
}
```

### 2.3 RegisterHooks 改动

**文件**: `renderdoc/driver/dxgi/dxgi_hooks.cpp`

在 `RegisterHooks()` 末尾加:
```cpp
// Present-first: hook Present on existing swapchain, wrap device on first call
{
    DWORD pid = GetCurrentProcessId();
    UINT64 dxgi_base = rdoc_OphionGetModuleBase(pid, "dxgi.dll");
    if (dxgi_base)
    {
        // 创建临时 swapchain 拿 Present 地址 (见 2.1)
        // ...
        void *trampoline = rdoc_OphionEptHookR3(pid, present_addr, (void *)Present_hook, 1);
        g_present_trampoline = trampoline;
        RDCLOG("[EPT] Present hook -> trampoline=%p %s", trampoline, trampoline ? "(OK)" : "(FAILED)");
    }
    else
    {
        RDCLOG("[EPT] dxgi.dll not loaded yet, Present hook deferred");
    }
}
```

**不 hook D3D12CreateDevice** (用户要求先不做)。

## 实现顺序

1. **Phase 1.1 + 1.2**: 驱动加 IOCTL + 删 NtCreateFile hook (test_driver.cpp)
2. **Phase 1.3**: R3 injector (新文件)
3. **Phase 2.1-2.3**: renderdoc Present hook + wrap (dxgi_hooks.cpp)

Phase 1 打通后可以测试: 注入器发 IOCTL -> 驱动注入 renderdoc -> renderdoc DllMain 跑完。
Phase 2 是功能: Present hook -> wrap device -> F12 overlay。

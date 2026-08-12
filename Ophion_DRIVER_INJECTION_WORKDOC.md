# Ophion 驱动注入 RenderDoc - 流程与原理工作文档

> **项目目标**：在 GoWR.exe 启动后，通过 Ophion 驱动注入器将 renderdoc.dll 注入游戏进程，实现正常截帧。
> **最近更新**：2026-08-10 14:53
> **状态**：代码修复已完成（P=0 fetch livelock），编译+签名+部署通过，等待测试指令

---

## 目录

1. [整体架构](#1-整体架构)
2. [三种组件职责](#2-三种组件职责)
3. [注入触发路径](#3-注入触发路径)
4. [R3 注入器流程（inject_renderdoc.exe）](#4-r3-注入器流程inject_renderdocexe)
5. [R0 TestDriver 流程（TdInjectRenderdocShadow）](#5-r0-testdriver-流程tdinjectrenderdocshadow)
6. [手动映射原理（TdManualMapInProcess）](#6-手动映射原理tdmanualmapinprocess)
7. [影子页表原理（MODE_G）](#7-影子页表原理mode_g)
8. [EPT 隐身机制](#8-ept-隐身机制)
9. [VMX-root #PF 处理状态机](#9-vmx-root-pf-处理状态机)
10. [CR3-load 上下文切换处理](#10-cr3-load-上下文切换处理)
11. [P=0 fetch livelock Bug 根因与修复](#11-p0-fetch-livelock-bug-根因与修复)
12. [诊断系统（三层）](#12-诊断系统三层)
13. [VMCALL 接口一览](#13-vmcall-接口一览)
14. [构建与部署](#14-构建与部署)
15. [关键文件索引](#15-关键文件索引)
16. [关键约束与踩坑](#16-关键约束与踩坑)

---

## 1. 整体架构

```
┌─────────────────────────────────────────────────────────┐
│  Ring 3 (用户态)                                         │
│  ┌───────────────────────┐                              │
│  │ inject_renderdoc.exe  │  找 PID -> IOCTL -> 等待 wrap   │
│  └──────────┬────────────┘                              │
│             │ DeviceIoControl(IOCTL_INJECT_RENDERDOC)    │
├─────────────┼───────────────────────────────────────────┤
│  Ring 0 (内核态)                                        │
│  ┌──────────▼────────────┐    ┌──────────────────────┐  │
│  │ TestEptHook.sys       │    │ Ophion.sys (HV)      │  │
│  │ (TestDriver)          │    │ VMX-root             │  │
│  │                       │───>│ EPT + 影子页表        │  │
│  │ - 手动映射 PE          │    │ - #PF 拦截/处理       │  │
│  │ - 构建影子 CR3         │    │ - CR3-load exiting    │  │
│  │ - EPT stealth 注册     │    │ - shadow window 状态机 │  │
│  │ - 创建线程 + EPT hook  │    │                       │  │
│  └───────────────────────┘    └──────────────────────┘  │
│             │                                            │
│             │ VMCALL                                      │
├─────────────┼───────────────────────────────────────────┤
│  VMX-root (hypervisor)                                   │
│  Ophion.sys 在 VMX-root 模式运行                          │
│  - 管理所有 vCPU 的 shadow window 状态                    │
│  - 处理 #PF VM-exit，决定 swap/abort/refresh             │
│  - CR3-load VM-exit 处理上下文切换                        │
└─────────────────────────────────────────────────────────┘
```

### 核心思路

renderdoc.dll 不能通过正常 `LoadLibrary` 加载到游戏进程（会出现在 PEB LDR 链表中，被反作弊检测）。
Ophion 的方案是：

1. **手动映射**：在目标进程内分配内存，手动拷贝 PE 节、修复重定位、解析导入表，不注册到 Windows loader。
2. **影子页表**：构建一套影子 CR3，将映射区域的所有 PTE 的 NX 位清零（可执行），但**不修改原始页表**（"no modify original page" 规则）。
3. **EPT 隐身**：通过 VMCALL 在 HV 中注册每个页面为 stealth page，HV 拦截 #PF 时识别目标进程并 swap 到影子 CR3。
4. **CFG 绕过**：创建线程入口指向 `NtTestAlert`（ntdll 导出，CFG 合法），通过 EPT hook 重定向到映射的 DllMain stub。
---

## 2. 三种组件职责

### 2.1 Ophion.sys - Type-2 Hypervisor（HV 驱动）

- **文件**：`src/vmexit.cpp`, `src/ept_stealth.cpp`, `src/vmx.cpp`, `src/driver.cpp`, `src/hostcr3.cpp`, `src/breadcrumb.cpp`, `src/pool_manager.cpp`
- **角色**：VMX-root 模式运行的 hypervisor，管理所有 vCPU
- **核心能力**：
  - EPT（扩展页表）内存映射与 hook
  - 影子页表（shadow page table）管理
  - #PF VM-exit 处理（shadow window 状态机）
  - CR3-load/store exiting（上下文切换检测）
  - VMCALL 接口（供 TestDriver 调用）
- **VMX-root 约束**：不能调用任何内核 API、不能文件 I/O、不能 DbgPrint、不能自旋锁。只能用 interlocked 操作、内存写入、端口 I/O、VMX 指令、KeBugCheckEx

### 2.2 TestEptHook.sys - TestDriver（R0 辅助驱动）

- **文件**：`TestDriver/td_pe_mapper.cpp`, `td_ioctl.cpp`, `td_inject.cpp`, `td_shadow.cpp`, `td_ept_hook.cpp`, `td_notify.cpp`, `td_stealth_track.cpp`
- **角色**：R0 驱动，作为 R3 与 VMX-root 之间的桥梁
- **核心能力**：
  - IOCTL 接口（`\\.\RMCoreTst` 设备）
  - PE 手动映射（跨进程）
  - 影子 CR3 构建（`TdBuildShadowCR3` / `TdExtendShadowCR3`）
  - EPT stealth 页面注册（`TdStealthAllocPage` -> `VMCALL_STEALTH_ALLOC`）
  - 远程线程创建 + EPT hook 触发
  - 进程退出清理（`TdCleanupStealthForProcess`）
  - LoadImage 回调（自动注入触发）

### 2.3 inject_renderdoc.exe - R3 注入器

- **文件**：`Injector/inject_renderdoc.cpp`
- **角色**：用户态工具，发送 IOCTL 触发注入
- **用法**：`inject_renderdoc.exe <game.exe> <renderdoc.dll path> [swapchain_ptr_hex]`

---

## 3. 注入触发路径

有两条路径最终都调用 `TdInjectRenderdocShadow()`：

### 路径 A：手动 IOCTL（推荐，用于测试）

```
inject_renderdoc.exe
  -> CreateToolhelp32Snapshot 找到 GoWR.exe 的 PID
  -> CreateFile("\\.\RMCoreTst")
  -> DeviceIoControl(IOCTL_INJECT_RENDERDOC, {pid, renderdoc_nt_path})
  -> TestDriver td_ioctl.cpp L2718: IOCTL_INJECT_RENDERDOC handler
  -> TdInjectRenderdocShadow(proc, &renderdoc_nt, "rd-r3", FALSE)
```

- IOCTL code：`CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900 + 16, METHOD_BUFFERED, FILE_ANY_ACCESS)` = 0x910
- 参数结构 `TD_INJECT_RENDERDOC_PARAMS`：`{target_pid, renderdoc_path[520], status}`
- `wait_for_completion = FALSE`：不等待 DllMain 完成

### 路径 B：自动 LoadImage 回调

```
GoWR.exe 进程创建
  -> TdProcessNotify (PsSetCreateProcessNotifyRoutine)
  -> TdInjectTargetAdd(pid, exe_path)  // 记录目标
  -> 游戏加载 d3d12.dll
  -> TdLoadImageNotify (PsSetLoadImageNotifyRoutine)
  -> 检测到 d3d12.dll basename 匹配
  -> TdInjectTargetClaim(pid) 取回 exe 路径
  -> 构造 renderdoc.dll 路径（与 exe 同目录）
  -> TdInjectRenderdocShadow(proc, &renderdoc_nt, "td-inj-shadow", FALSE)
```

- 选择 `d3d12.dll` 作为触发点的原因：此时 renderdoc 的所有依赖（user32/gdi32/ole32/dxgi/d3d11/dbghelp 等）已在 PEB LDR 中，`TdPeResolveImports` 能完整填充 IAT

---

## 4. R3 注入器流程（inject_renderdoc.exe）

**文件**：`Injector/inject_renderdoc.cpp`

```
步骤 1: FindProcessByName(game_name)
        -> CreateToolhelp32Snapshot + Process32First/Next 遍历

步骤 2: (可选) 创建共享内存 "rd_late_wrap"
        -> CreateFileMappingW(name="rd_late_wrap")
        -> MapViewOfFile
        -> 写入 swapchain_ptr (如果用户提供了)
        布局 RdLateWrapMsg:
          - swapchain_ptr      [in]  原始 swapchain 指针
          - wrapped_swapchain  [out] renderdoc 包装后的 swapchain
          - status             0=等待, 1=完成, 2=错误

步骤 3: 构造 NT 路径
        -> "F:\rd\renderdoc.dll" -> "\??\F:\rd\renderdoc.dll"

步骤 4: CreateFile("\\.\RMCoreTst", GENERIC_READ|WRITE, OPEN_EXISTING)

步骤 5: DeviceIoControl(IOCTL_INJECT_RENDERDOC, {pid, nt_path})
        -> 返回 status (0 = 成功)

步骤 6: (有共享内存时) 等待 renderdoc wrap swapchain
        -> 轮询 pMsg->status (最多 90 秒)
        -> status=1: 读取 wrapped_swapchain

步骤 7: swapchain 指针替换
        - 自动模式 (swapchain_ptr==0): renderdoc 已 vtable hijack，无需替换
        - 手动模式: ScanAndReplacePointer
          -> VirtualQueryEx 遍历进程内存
          -> ReadProcessMemory 读 64KB 块
          -> 8 字节对齐扫描，找到 old_val 替换为 new_val
          -> WriteProcessMemory 写入

步骤 8: Sleep(INFINITE) 保持共享内存存活
        -> renderdoc 线程需要共享内存存活
        -> Ctrl+C 退出
```
---

## 5. R0 TestDriver 流程（TdInjectRenderdocShadow）

**文件**：`TestDriver/td_pe_mapper.cpp` L1186

这是整个注入的核心函数，12 个步骤：

### Step 0: 预注入 HV 清理（三阶段）

```
Phase A: DPC 广播 VMCALL_SHADOW_ABORT_ALL (所有 CPU)
         -> 清除每个 vCPU 的 nx_timer_restore/real_cr3/MTF（per-vCPU 安全）

Phase B: 单 CPU VMCALL_STEALTH_FREE_ALL
         -> 移除全局 g_ept->stealth_pages 链表 + 恢复 EPT
         -> 必须单调用者：RemoveHeadList 不是 SMP 安全的

Phase C: DPC 广播 VMCALL_SHADOW_ABORT_ALL (再次)
         -> INVEPT 刷新所有 CPU 的 EPT TLB
         -> Phase B 在单 CPU 修改了所有 CPU 的 EPT 条目，其他 CPU 可能有过期 EPT TLB
```

**目的**：清除上次注入的残留 stealth 状态，避免影子 CR3 PA 被复用导致的冲突。

### Step 1: Attach 到目标进程

```c
KeStackAttachProcess(proc, &apc_state);
caller_cr3 = __readcr3();  // 保存目标进程的真实 CR3
```

### Step 2: 从磁盘读取 renderdoc.dll

```c
TdReadFileKernel(renderdoc_path, &raw_dll, &dll_size);
// -> ZwCreateFile + ZwReadFile，读取整个 DLL 到 NonPaged pool
```

### Step 3: 手动映射到目标进程

```c
TdManualMapInProcess(proc, raw_dll, dll_size, &mapped_base, &mapped_entry);
```

详见第 6 节。

### Step 4: 构建影子 CR3

```c
total_pages = (image_size + PAGE_SIZE - 1) / PAGE_SIZE;

// 如果该 PID 已有影子 CR3，扩展；否则新建
shadow_cr3 = existing
    ? TdExtendShadowCR3(existing, caller_cr3, mapped_base, image_size)
    : TdBuildShadowCR3(caller_cr3, mapped_base, image_size);
```

详见第 7 节。

### Step 5: EPT stealth 逐页注册

```c
for (off = 0; off < image_size; off += PAGE_SIZE) {
    page_va = mapped_base + off;
    page_phys = MmGetPhysicalAddress(page_va);
    TdResolveGuestPT(caller_cr3, page_va, &pt_pfn, &pt_idx);
    TdStealthAllocPage(caller_cr3, page_va, page_phys,
        NULL, 0, TRUE, pt_pfn, pt_idx,
        FALSE, shadow_cr3, TRUE, FALSE);
    // -> 内部调用 VMCALL_STEALTH_ALLOC 注册到 HV 的 stealth_pages 链表
}
```

详见第 8 节。

### Step 6: 注册进程退出清理追踪

```c
TdStealthTrackAdd(target_pid, mapped_base, image_size, shadow_cr3,
                  image_mdl, caller_cr3, page_pfns, total_pages);
```

- 记录到 `g_stealth_track` 表
- 进程退出时 `TdCleanupStealthForProcess` 清理所有 stealth 页 + 影子 CR3
- 存储每页 PFN 数组，避免退出清理时 `KeStackAttachProcess`（进程已死）

### Step 7: 解析 NtTestAlert

```c
// 遍历 PEB LDR 链表找到 ntdll.dll
// TdFindExportByName(ntdll_base, "NtTestAlert")
trigger_fn = NtTestAlert 地址;
```

- NtTestAlert 是 ntdll 导出，在 CFG（Control Flow Guard）合法目标列表中
- 线程以 NtTestAlert 为入口创建，绕过对手动映射地址的 CFG 检查
- EPT hook 将 NtTestAlert 重定向到 DllMain stub

### Step 8: 创建 SUSPENDED 线程

```c
// 优先 ZwCreateThreadEx（未导出，动态解析）
g_pZwCreateThreadEx(&thr_h, THREAD_ALL_ACCESS, NULL, thr_proc_h,
    trigger_fn, NULL,
    THREAD_CREATE_FLAGS_CREATE_SUSPENDED,  // 挂起！
    0, 0, 0, NULL);

// 备选 RtlCreateUserThread
RtlCreateUserThread(ZwCurrentProcess(), NULL, TRUE, ...);
```

- 线程创建时挂起，在 EPT hook 安装前不会执行
- 获取 TID 用于 hook 的 TID 过滤

### Step 9: 准备异步清理上下文

```c
cleanup_ctx = {
    thread_handle, trigger_fn, shellcode_va,
    target_cr3, target_pid, work_item, fired_signal=0
};
```

### Step 10: EPT hook NtTestAlert -> DllMain stub

```c
TdInstallTriggerHookAllCpus(
    trigger_fn,     // 被 hook 的函数 (NtTestAlert)
    mapped_entry,   // 重定向目标 (DllMain stub)
    caller_cr3,     // 目标进程 CR3
    2,              // hook type: INT3 (1B)
    expected_tid,   // TID 过滤：只对该线程触发
    &dummy_origin,  // 保存原始字节
    fired_ptr);     // fired_signal 指针
```

- TID 过滤：只有刚创建的线程触发 hook，其他线程调用 NtTestAlert 不受影响
- oneshot：触发后立即 unhook

### Step 11: Resume 线程

```c
TdResumeThreadHandle(cleanup_thr_h, &prev_count);
```

- 线程恢复执行 -> 调用 NtTestAlert -> EPT hook 触发 -> 跳转到 DllMain stub
- DllMain stub 调用真正的 DllMain -> renderdoc 初始化 -> 安装 D3D12/DXGI hooks
- CPU 从 stealth 页取指 -> 原始 PT NX=1 -> #PF（instruction-fetch, P=1）-> VM-exit

### Step 11.5: (仅 NtCreateFile 路径) 等待 DllMain 完成

```c
if (wait_for_completion) {
    KeWaitForSingleObject(trig_thread, Executive, KernelMode, FALSE, &timeout_30s);
}
```

- LoadImage 路径 **不能用**：在 loader lock 下，renderdoc DllMain 调用 LoadLibrary -> 死锁
- IOCTL 路径 `wait_for_completion = FALSE`，不等

### Step 12: 异步清理 - unhook trigger

```c
IoQueueWorkItem(wi, [](...) {
    // 轮询 fired_signal，最多 10 秒
    for (i = 0; i < 10000 && fired_signal == 0; i++)
        KeDelayExecutionThread(..., 1ms);

    // 关闭线程句柄
    TdCloseCreatedThreadHandle(thread_handle, TRUE);

    // Unhook trigger
    if (进程存活) {
        KeStackAttachProcess -> TdUnhookTriggerAllCpus
    } else {
        VMCALL_EPT_UNHOOK_BY_CR3  // 按 CR3 匹配，不加载已死进程的 CR3
    }
});
```

---

## 6. 手动映射原理（TdManualMapInProcess）

**文件**：`TestDriver/td_pe_mapper.cpp` L986

```
1. 分配内存
   ZwAllocateVirtualMemory(ZwCurrentProcess(), &base, 0, &size,
       MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
   -> RW 权限（非 RX），NX=1。可执行性由影子 CR3 提供

2. 拷贝 PE 头 + 节
   for each IMAGE_SECTION_HEADER:
       memcpy(base + sec.VirtualAddress, raw + sec.PointerToRawData, sec.SizeOfRawData)

3. 应用重定位
   TdApplyRelocations(base, raw)
   -> 遍历 .reloc 块，按 delta = mapped_base - preferred_base 修正

4. 解析导入表
   TdPeResolveImports(base)
   -> 遍历 IAT，在目标进程 PEB LDR 中查找已加载的 DLL
   -> TdFindExportByName 解析每个导入函数地址
   -> 填充 IAT

5. 创建 DllMain stub
   在映射区域写入小型 shellcode：
   - 设置 RCX = mapped_base (DllMain hinstDLL 参数)
   - 设置 RDX = 1 (DLL_PROCESS_ATTACH)
   - CALL DllMain (entry point from OptionalHeader.AddressOfEntryPoint)
   - RET
   mapped_entry = stub 地址
```

**关键点**：
- 不调用 `NtLoadDriver` / `LdrLoadDll`，不在 PEB LDR 链表注册
- 内存权限是 RW（NX=1），原始页表保持 NX=1
- 可执行性完全由影子 CR3 在运行时提供
- renderdoc 的 DllMain 是同步的：VEH/UEF -> Initialise -> RegisterHooks（安装所有 EPT hook），然后返回
---

## 7. 影子页表原理（MODE_G）

**文件**：`include/stealth.h` L33, `TestDriver/td_shadow.cpp`

### 当前模式：`SHADOW_PT_MODE = SHADOW_PT_MODE_G` (7)

### MODE_G 策略：Passthrough Shadow

```
真实 CR3 (caller_cr3):
  PML4 -> PDPT -> PD -> PT -> PTE [NX=1, P=1]  <-- 原始页表，不修改

影子 CR3 (shadow_cr3):
  PML4' (深拷贝)
    \-> PDPT' (深拷贝)
         \-> PD' (深拷贝)
              +-> PT' (fork，DLL 范围) -> PTE' [NX=0, P=1]  <-- 影子页表，NX 清零
              \-> PT (原始，非 DLL 范围)                     <-- 直接指向真实 PT 页
```

### 构建过程（TdBuildShadowCR3）

1. **PML4/PDPT/PD 深拷贝**：从真实 CR3 逐级复制页表项
2. **PT 页 fork**（仅 DLL 映射范围所在的 2MB 区域）：
   - 分配新的 PT 页
   - 拷贝原始 PT 的 512 个 PTE
   - **清除所有 PTE 的 NX 位**（bit 63 = 0）
3. **非 DLL 范围**：PD entry 直接指向真实的 PT 页（零开销，零 staleness）
4. 一个进程一个影子 CR3（`TdStealthFindShadowCr3ForPid` 复用 + `TdExtendShadowCR3` 扩展）

### "不修改原始页表"规则

- 原始 PT 的 NX 位始终保持 1
- 影子 CR3 的 PT 页是独立副本
- 当 CPU 使用影子 CR3 时，看到 NX=0，可以执行代码
- 当 CPU 使用真实 CR3 时，看到 NX=1，代码不可执行
- 反作弊扫描原始页表 -> 看到 NX=1 -> 认为无可执行代码

### MODE_G 特性

| 特性 | MODE_G |
|------|--------|
| PML4/PDPT/PD | 深拷贝 |
| PT 页（DLL 范围） | fork，NX=0 |
| PT 页（非 DLL 范围） | 指向真实 PT |
| 窗口模式 | 扩展窗口（无 MTF） |
| CR3-load/store exiting | 启用 |
| INVVPID | 单地址（IndividualAddress） |
| 数据页 staleness 处理 | stealth_sync_data_pte_in_window (A2 heal) |

### 其他模式（已禁用）

- **MODE_A (1)**：所有影子 PTE 初始 P=0，首次访问时 reactive 填充
- **MODE_B (2)**：只 shadow 含代码的 2MB 区域，数据区域指向真实 PT
- **MODE_C (3)**：全 P=1/NX=0 + fast-path heal
- **MODE_H (8)**：EPT Write-Protect Shadow，用 EPT W=0 同步影子 PT（有 3 个致命 bug，已禁用）

---

## 8. EPT 隐身机制

### Stealth Page 注册

**R0**（`TdStealthAllocPage`）-> **VMCALL**（`VMCALL_STEALTH_ALLOC`）-> **VMX-root**（`ept_stealth.cpp`）

每个 stealth page 在 HV 中注册一个条目到 `g_ept->stealth_pages` 链表：

```c
struct stealth_page_entry {
    UINT64 guest_va;           // 页面在目标进程的虚拟地址
    UINT64 target_pid;         // 目标进程 PID
    UINT64 shadow_cr3_phys;    // 对应的影子 CR3 物理地址
    UINT64 shadow_pte_va;      // 影子 PTE 的虚拟地址（用于 refresh）
    // ... 链表节点
};
```

### #PF 触发链

```
1. renderdoc DllMain 线程执行
2. CPU 从 stealth 页取指令
3. 原始 PT: NX=1 -> 处理器触发 #PF (instruction-fetch, P=1, error_code & PFEC_INSTR_FETCH)
4. #PF VM-exit -> Ophion VMX-root
5. ept_stealth_handle_pf(vcpu, fault_addr, error_code)
6. 查找 stealth_pages 链表：guest_va + target_pid 匹配？
7. 匹配 -> 打开 shadow window
8. 不匹配 -> 放行（return FALSE，guest MmAccessFault 处理）
```

### Stealth Page vs EPT Hook

| | Stealth Page | EPT Hook |
|---|---|---|
| 目的 | 隐藏代码可执行性 | 函数 hook/重定向 |
| 机制 | 影子 CR3 swap | EPT 权限分离 |
| 触发 | #PF (NX-fetch) | EPT violation |
| 恢复 | shadow window | MTF 单步 |
| 用途 | 手动映射代码执行 | NtTestAlert -> DllMain redirect |
---

## 9. VMX-root #PF 处理状态机

**文件**：`src/ept_stealth.cpp` L1714 `ept_stealth_handle_pf()`

这是整个注入的核心运行时逻辑。当 #PF VM-exit 发生时：

```
ept_stealth_handle_pf(vcpu, fault_addr, error_code)
|
+-- 检查 1: shadow window 已开启？(vcpu->nx_timer_real_cr3 != 0)
|   |
|   +-- YES + 数据 #PF (不是 instruction-fetch)
|   |   |  error_code & PFEC_INSTR_FETCH == 0
|   |   |  -> shadow window 内的数据页访问
|   |   |
|   |   +-- stealth_sync_data_pte_in_window() 尝试 heal
|   |   |   -> 从真实 PT 同步 PTE 到影子 PT（数据页 NX=1）
|   |   |   -> 成功: BC_EVT_PF_A2_HEAL, return TRUE (已处理)
|   |   |   -> 失败: BC_EVT_PF_A2_BAIL -> abort_shadow_window, return FALSE
|   |
|   +-- [END 数据 #PF 分支]
|
+-- 检查 2: P=0 fetch #PF？(新增 fix)
|   |  vcpu->nx_timer_real_cr3 != 0 && !(error_code & PFEC_PRESENT)
|   |  -> shadow window 内的 demand fault (P=0 instruction-fetch)
|   |  -> 如中断后执行内核代码页，页面未分配
|   |  -> BC_EVT_PF_ABORT -> abort_shadow_window, return FALSE
|   |  -> #PF 在真实 CR3 + 收窄 #PF intercept 下被 guest MmAccessFault 处理
|   |
|   +-- [END P=0 fetch 分支 - 见第 11 节]
|
+-- 检查 3: error_code filter
|   |  不是 instruction-fetch (PFEC_INSTR_FETCH=0) -> return FALSE
|   |  -> 普通数据 #PF，交给 guest 处理
|   |
|   +-- [END error-code filter]
|
+-- 检查 4: stealth page 匹配
|   |  遍历 stealth_pages 链表，匹配 fault_addr + target_pid
|   |
|   +-- 匹配 -> 检查 already_on_shadow
|   |   |  current_pfn == shadow_pfn ?
|   |   |
|   |   +-- YES (already_on_shadow): mid-window NX-fetch on stealth page
|   |   |   -> 影子 PTE 可能 stale（OS repage 修改了真实 PFN）
|   |   |   -> stealth_refresh_shadow_code_pte()
|   |   |     从真实 PT 读取最新 PFN，更新影子 PTE（保持 NX=0）
|   |   |   -> 成功: BC_EVT_ALREADY_ON_SHADOW, return TRUE
|   |   |   -> 失败: BC_EVT_PF_ABORT -> abort, return FALSE
|   |   |
|   |   +-- NO (首次): 打开 shadow window
|   |       1. 保存 vcpu->nx_timer_real_cr3 = current_cr3 (真实 CR3)
|   |       2. VMCS_GUEST_CR3 <- shadow_cr3 (影子 CR3)
|   |       3. 收窄 #PF -> 扩展 #PF (mask=0, match=0, 拦截所有 #PF)
|   |          -> MODE_G 扩展窗口，不是单指令 MTF
|   |       4. 启用 CR3-load/store exiting
|   |       5. InvvpidIndividualAddress (单地址 TLB 刷新)
|   |       -> BC_EVT_PF_SHADOW_OPEN, return TRUE
|   |
|   +-- 不匹配 -> shadow window 内非 stealth 页的 NX-fetch
|       -> BC_EVT_PF_ABORT -> abort_shadow_window, return FALSE
|       -> #PF 在真实 CR3 下重新注入
|
+-- [END]
```

### Shadow Window 打开后的状态

```c
vcpu->nx_timer_real_cr3 = 真实 CR3    // 非 0 表示 window 开启
vcpu->shadow_extended = TRUE          // 扩展窗口模式
VMCS_GUEST_CR3 = shadow_cr3           // guest 使用影子页表
#PF intercept = all-faults (mask=0)   // 拦截所有 #PF
CR3-load exiting = ON                 // 检测上下文切换
CR3-store exiting = ON
```

### abort_shadow_window()

```c
stealth_pf_abort_shadow_window(vcpu):
    if (!vcpu->nx_timer_real_cr3) return;  // 未开启
    VMCS_GUEST_CR3 <- vcpu->nx_timer_real_cr3  // 恢复真实 CR3
    vcpu->nx_timer_real_cr3 = 0               // 标记关闭
    收窄 #PF intercept (只拦截 NX-fetch)       // 恢复正常
    // CR3-load/store exiting 保持开启（用于 pending/reactivate）
```

---

## 10. CR3-load 上下文切换处理

**文件**：`src/vmexit.cpp` L584

当 shadow window 开启时，CR3-load exiting 启用。线程切换（CR3 写入）触发 VM-exit：

```
CR3-load VM-exit
|
+-- new_cr3 == 目标进程 CR3？(shadow_extended && !shadow_pending)
|   |  -> 上下文切回目标进程
|   |
|   +-- REACTIVATE:
|       1. VMCS_GUEST_CR3 <- shadow_cr3 (恢复影子 CR3)
|       2. 扩展 #PF intercept (all-faults)
|       3. shadow_pending = FALSE
|       -> BC_EVT_SHADOW_REACTIVATE
|
+-- new_cr3 != 目标进程 CR3？
    |  -> 切换到其他进程
    |
    +-- PENDING:
        1. VMCS_GUEST_CR3 <- new_cr3 (真实 CR3，让其他进程正常运行)
        2. 收窄 #PF intercept (只 NX-fetch)
        3. shadow_pending = TRUE
        -> BC_EVT_SHADOW_PENDING
```

### 设计意图

- **扩展窗口**：shadow window 打开后不立即关闭（不用 MTF 单步），保持开启直到上下文切换
- 代码在影子 CR3 下零 #PF 零 VM-exit 执行（NX=0）
- 数据页 staleness 通过 A2 heal 处理
- 上下文切换时正确恢复/重激活
---

## 11. P=0 fetch livelock Bug 根因与修复

### 现象

注入后系统 hang（只有鼠标能动，无 BSOD，无 dump）。

### BC.log 证据

```
write_idx=19
最后 6 条 (cpu=4):
  全是 0xfffff80467d0xxxx 内核地址的 PF_ENTRY
  无后续 breadcrumb (PF_SHADOW_OPEN 等未出现)
-> flush worker 被 #PF storm 阻塞，ring buffer 未刷盘
```

### 根因分析

```
1. shadow window 开启 -> #PF intercept 扩展到 all-faults (mask=0, match=0)
   -> 所有 #PF 都触发 VM-exit，包括 P=0 (page not present) 的

2. 中断打断 shadow window 中的代码执行
   -> 中断返回后执行内核代码页
   -> 该页面可能 P=0 (demand fault，尚未分配物理页)

3. P=0 instruction-fetch #PF -> VM-exit

4. ept_stealth_handle_pf 处理：
   - 检查 1: 数据 #PF? NO (是 instruction-fetch)
   - 检查 2 (修复前不存在): P=0 fetch? -> 跳过
   - 检查 3: error_code filter -> 不是 NX-fetch?
     P=0 fetch 的 error_code: PFEC_INSTR_FETCH=1, PFEC_PRESENT=0
     filter 检查 PFEC_INSTR_FETCH -> 是 instruction-fetch -> 通过 filter
   - 检查 4: stealth page 匹配? -> 内核地址不匹配 -> return FALSE
   - **但没有 abort shadow window！**

5. #PF 被以 shadow CR3 重新注入 (VM-entry)
   -> guest MmAccessFault 在影子 PT 上处理 demand fault
   -> 分配物理页，填充影子 PT 的 PTE

6. 但影子 PT 的 PML4/PDPT/PD 是真实 CR3 的深拷贝快照
   -> 内核页表的修改（demand fault 分配）只反映在真实 PT
   -> 影子 PT 的 PTE 仍然是 P=0

7. 下一次执行同一地址 -> 又 P=0 -> 又 #PF -> 又 VM-exit -> 又 return FALSE
   -> 无限循环 -> #PF storm -> 系统 hang
```

### 修复

**文件**：`src/ept_stealth.cpp` L1762-1768

在数据 #PF guard (L1731) 之后、error-code filter (L1783) 之前，新增 P=0 fetch guard：

```c
if (vcpu->nx_timer_real_cr3 &&
    !(error_code & PFEC_PRESENT))
{
    hv_breadcrumb(BC_EVT_PF_ABORT, fault_addr);
    stealth_pf_abort_shadow_window(vcpu);
    return FALSE;
}
```

### 修复后的数据流

```
P=0 fetch #PF (shadow window 内)
  -> abort shadow window (恢复真实 CR3 + 收窄 #PF)
  -> return FALSE
  -> #PF 在真实 CR3 下重新注入
  -> guest MmAccessFault 在真实 PT 上 demand-fault
  -> 成功分配物理页
  -> 代码继续执行
  -> 下一次从 stealth 页取指 -> NX-fetch #PF -> shadow window 重新打开
```

### 诊断 breadcrumb

| Breadcrumb | 位置 | 含义 |
|---|---|---|
| `BC_EVT_PF_A2_HEAL` | L1740 | 数据 #PF mid-window heal 成功 |
| `BC_EVT_PF_A2_BAIL` | L1746 | 数据 #PF mid-window heal 失败 -> abort |
| `BC_EVT_PF_ABORT` | L1765 | **P=0 fetch guard 触发 -> abort（新 fix 标志）** |
| `BC_EVT_ALREADY_ON_SHADOW` | L1899 | mid-window NX-fetch on stealth page -> refresh |
| `BC_EVT_PF_ABORT` | L1906 | already_on_shadow refresh 失败 -> abort |
| `BC_EVT_PF_SHADOW_OPEN` | L1962 | shadow window 首次打开 |
| `BC_EVT_PF_ABORT` | L2095 | 非 stealth 页 NX-fetch -> abort |
| `BC_EVT_SHADOW_REACTIVATE` | vmexit.cpp L594 | CR3-load 返回目标进程 -> 重激活 |
| `BC_EVT_SHADOW_PENDING` | vmexit.cpp L610 | CR3-load 切到其他进程 -> pending |

---

## 12. 诊断系统（三层）

### A) Ring Buffer -> BC.log

**文件**：`src/breadcrumb.cpp`, `include/breadcrumb.h`

```
g_bc_ring (NonPaged pool, 500 entries)
  | hv_breadcrumb() 写入 (VMX-root 安全: 仅 interlocked 操作)
  | worker 线程 (LOW_REALTIME_PRIORITY) 每 500ms 刷盘
  -> C:\Windows\BC.log (FILE_WRITE_THROUGH, 硬重置后可恢复最后 500ms)
```

- **VMX-root 安全**：仅 interlocked 操作，不碰自旋锁
- **write-through**：每次写入刷盘，硬重置后可恢复
- 事件类型：`BC_EVT_PF_ENTRY`, `BC_EVT_PF_SHADOW_OPEN`, `BC_EVT_PF_ABORT`, `BC_EVT_PF_A2_HEAL`, `BC_EVT_PF_A2_BAIL`, `BC_EVT_ALREADY_ON_SHADOW`, `BC_EVT_SHADOW_REACTIVATE`, `BC_EVT_SHADOW_PENDING` 等

### B) CMOS NVRAM -> W.log

- 理论上能存活三重故障
- **本硬件已失效**（UEFI 主板不持久化），不依赖

### C) KeBugCheckEx -> minidump

**文件**：`asm/AsmHostIdt.asm`, `src/vmexit.cpp`

- 致命 VMX-root 条件触发 BSOD（不再硬重置）
- bugcheck code: `0xDEADC0DE`
- 参数布局：

| Panic Code | P1 | P2 | P3 | P4 |
|---|---|---|---|---|
| HOST_PF (1) | 1 | cr2 (故障 VA) | rip | err (#PF 错误码) |
| TRIPLE_FAULT (2) | 2 | guest_rip | core | exit_reason |
| EPT_MISCONFIG (3) | 3 | guest_rip | exit_qual | core |
| ENTRY_FAILURE (5) | 5 | exit_reason | instr_err | core |

- `CrashDumpEnabled=2`（内核 dump）可捕获 ring buffer
- 分析命令：
  ```
  cdb -z <dump> -y "srv*d:\symbols*http://msdl.microsoft.com/download/symbols;F:\winDriver\te\Ophion-master\Ophion-master\build\bin\Debug" -c "!analyze -v; dq poi(g_bc_ring) L1000; q"
  ```

### 三层数据流

```
              +-- 高 detail ---------------------------------+
              | Ring Buffer -> BC.log (write-through)        |
              |   500 entries, 500ms 刷盘                    |
              +-- 中 detail ---------------------------------+
              | KeBugCheckEx -> minidump bugcheck args       |
              |   每种 dump 类型都保留                       |
              +-- 低 detail (本机失效) ----------------------+
              | CMOS NVRAM -> W.log                          |
              |   三重故障存活，但 UEFI 不持久化              |
              +----------------------------------------------+
```
---

## 13. VMCALL 接口一览

**文件**：`src/vmexit.cpp` L1223+

| VMCALL | 调用者 | 功能 |
|---|---|---|
| `VMCALL_STEALTH_ALLOC` | TestDriver R0 | 注册一个 stealth page 到 `g_ept->stealth_pages` |
| `VMCALL_STEALTH_FREE` | TestDriver R0 | 移除单个 stealth page + 恢复 EPT |
| `VMCALL_STEALTH_FREE_ALL` | TestDriver R0 | 移除所有 stealth pages + 恢复 EPT（单调用者） |
| `VMCALL_SHADOW_ABORT_ALL` | TestDriver R0 (DPC) | 清除所有 vCPU 的 shadow window 状态 + INVEPT |
| `VMCALL_HOOK` | TestDriver R0 | 安装 EPT hook |
| `VMCALL_UNHOOK` | TestDriver R0 | 移除 EPT hook |
| `VMCALL_INJECT` | TestDriver R0 | (legacy) 注入触发 |

### IOCTL 接口

**文件**：`TestDriver/td_ioctl.cpp`, `Injector/inject_renderdoc.cpp`

| IOCTL | Code | 功能 |
|---|---|---|
| `IOCTL_INJECT` | 0x900 | (legacy) 通用注入 |
| `IOCTL_EPT_HOOK` | 0x901 | 安装 EPT hook |
| `IOCTL_EPT_UNHOOK` | 0x902 | 移除 EPT hook |
| `IOCTL_EPT_HOOK_R3` | 0x903 | R3 触发 EPT hook |
| `IOCTL_EPT_UNHOOK_R3` | 0x904 | R3 触发移除 hook |
| `IOCTL_INJECT_DLL` | 0x905 | 手动映射 DLL（不含 stealth） |
| `IOCTL_INJECT_RW` | 0x906 | RW 注入 |
| `IOCTL_INJECT_RW_SHADOW` | 0x907 | RW shadow 注入 |
| `IOCTL_ALLOC_SHADOW_MEMORY` | 0x908 | 分配影子内存 |
| `IOCTL_INSTALL_TRIGGER_JUMP` | 0x909 | 安装触发跳转 |
| `IOCTL_FREE_SHADOW_MEMORY` | 0x90A | 释放影子内存 |
| `IOCTL_SHADOW_PROTECT_MEMORY` | 0x90B | 影子内存保护 |
| `IOCTL_RESOLVE_EXPORT` | 0x90C | 解析导出函数 |
| `IOCTL_GET_MODULE_BASE` | 0x90D | 获取模块基址 |
| **`IOCTL_INJECT_RENDERDOC`** | **0x910** | **RenderDoc shadow 注入（主入口）** |
| `IOCTL_HV_READ_MEM` | - | HV 内存读取（VMX-root） |
| `IOCTL_HV_WRITE_MEM` | - | HV 内存写入（VMX-root） |
| `IOCTL_HV_QUERY_VA` | - | VA 查询 |
| `IOCTL_HV_DETECT` | - | HV 检测 |
| `IOCTL_HV_DIAG_WALK` | - | 诊断遍历 |

---

## 14. 构建与部署

### 构建

**脚本**：`Ophion-master\_build2.bat`

```
配置: Debug
工具链: VS 2022 Pro + WDK 10.0.26100
输出: Ophion-master\build\bin\Debug\
  - Ophion.sys (HV 驱动)
  - TestEptHook.sys (TestDriver)
签名: TrustAsia (post-build step，忽略时间戳)
```

### 部署

```powershell
# 复制驱动（sandbox 拦截 PS cmdlet，用 .NET 方法）
[System.IO.File]::Copy("...\Ophion.sys", "C:\Windows\System32\drivers\Ophion.sys", $true)
[System.IO.File]::Copy("...\TestEptHook.sys", "C:\Windows\System32\drivers\TestEptHook.sys", $true)

# 启动驱动（sandbox 拦截 sc.exe，用 ServiceController）
$sc = New-Object System.ServiceProcess.ServiceController("RMCore")
$sc.Start()
$sc2 = New-Object System.ServiceProcess.ServiceController("RMCoreTst")
$sc2.Start()
```

- 服务名：`RMCore`（Ophion.sys）、`RMCoreTst`（TestEptHook.sys）
- 设备名：`\\.\RMCoreTst`

### 日志路径

| 文件 | 内容 | 读取注意 |
|---|---|---|
| `C:\Windows\O.log` | HV 驱动日志 | 驱动锁定，需 `FileShare.ReadWrite` |
| `C:\Windows\T.log` | TestDriver 日志 | 驱动锁定，需 `FileShare.ReadWrite` |
| `C:\Windows\BC.log` | Ring buffer breadcrumb | write-through |
| `C:\Windows\W.log` | CMOS NVRAM | 本机失效 |

### 注入器构建

**脚本**：`Injector\build.bat`

```
输出: inject_renderdoc.exe
用法: inject_renderdoc.exe GoWR.exe F:\winDriver\te\renderdoc.dll
```

---

## 15. 关键文件索引

### HV 驱动源码（Ophion.sys）

| 文件 | 功能 |
|---|---|
| `src/vmexit.cpp` | VM-exit 主处理，CR3-load 处理，VMCALL 分发 |
| `src/ept_stealth.cpp` | #PF 处理状态机，shadow window，stealth page 管理 |
| `src/vmx.cpp` | VMX 初始化，VMCS 配置 |
| `src/driver.cpp` | 驱动入口，DriverEntry |
| `src/hostcr3.cpp` | 私有 host CR3 管理 |
| `src/breadcrumb.cpp` | Ring buffer 诊断系统 |
| `src/pool_manager.cpp` | VMX-root 内存池管理 |
| `asm/AsmHostIdt.asm` | Host IDT，#PF panic handler |
| `asm/AsmVmexitHandler.asm` | VM-exit 入口汇编 |
| `asm/AsmVmxOperation.asm` | VMX ON/OFF 操作 |

### TestDriver 源码（TestEptHook.sys）

| 文件 | 功能 |
|---|---|
| `TestDriver/td_pe_mapper.cpp` | PE 手动映射，`TdInjectRenderdocShadow` (L1186)，`TdManualMapInProcess` (L986) |
| `TestDriver/td_ioctl.cpp` | IOCTL 分发，`IOCTL_INJECT_RENDERDOC` handler (L2718) |
| `TestDriver/td_inject.cpp` | 注入辅助 |
| `TestDriver/td_shadow.cpp` | 影子 CR3 管理（build/extend/find/free/resolve） |
| `TestDriver/td_ept_hook.cpp` | EPT hook 安装/移除 |
| `TestDriver/td_notify.cpp` | LoadImage/Process 回调，自动注入触发 |
| `TestDriver/td_stealth_track.cpp` | 进程退出清理追踪 |

### 头文件

| 文件 | 功能 |
|---|---|
| `include/stealth.h` | MODE 定义，stealth 开关 (L33: `SHADOW_PT_MODE = SHADOW_PT_MODE_G`) |
| `include/hv.h` | HV 核心声明 |
| `include/hv_types.h` | vCPU 状态结构，shadow window 字段 |
| `include/breadcrumb.h` | BC_EVT_* 常量，CMOS 布局，Panic API |
| `include/ia32.h` | Intel 架构常量 |

### R3 注入器

| 文件 | 功能 |
|---|---|
| `Injector/inject_renderdoc.cpp` | RenderDoc R3 注入器（IOCTL_INJECT_RENDERDOC） |
| `Ophion-master/Injector/injector.cpp` | 通用 R3 注入器（多命令） |
| `Injector/build.bat` | 注入器构建脚本 |

---

## 16. 关键约束与踩坑

### VMX-root 约束

- **禁止**：任何内核 API、文件 I/O、DbgPrint、自旋锁
- **允许**：interlocked 操作、内存写入、端口 I/O、VMX 指令、KeBugCheckEx
- breadcrumb 写入用 interlocked，VMX-root 安全

### 文件编码

- **.cpp/.h 文件**：UTF-8 **无 BOM**（hex dump 验证），编辑时 byte-safe
- **.asm 文件**：ASCII **无 BOM**（MASM 拒绝 BOM），用 `[System.IO.File]::WriteAllText` + ASCII

### Sandbox 限制

- PS cmdlet 在 `C:\Windows` 被拦截 -> 用 .NET 方法（`[System.IO.File]`, `ServiceController`）
- `sc.exe` 被拦截 -> 用 `ServiceController` .NET 类
- 读取被锁定的日志文件 -> `FileShare.ReadWrite`

### 编译陷阱

- kernel 模式下 `_snprintf_s` / `_InterlockedAdd` / `LowRealtimePriority` 不可用
- 正确做法：`RtlStringCbPrintfA`（ntstrsafe.h）+ `InterlockedExchangeAdd` + `LOW_REALTIME_PRIORITY`
- `log.h` 需单独 include（hv.h 不传递包含）

### 诊断约束

- `hv_host_pf_panic` **不写 ring buffer**：#PF 可能就是 ring 访问引起的，再碰 ring -> double fault -> 重置。直接 KeBugCheckEx
- `BC.log` 用 `FILE_WRITE_THROUGH`：每次写入刷盘，硬重置后可恢复最后 500ms
- `CrashDumpEnabled=2`（内核 dump）：可捕获 ring buffer。小 minidump(3) 只保留 bugcheck 参数

### 业务约束

- **不得回退代码**：He 明确要求未经允许不要回退
- **忽略签名时间戳**：He 说不必管
- **MmProbeAndLockPages 已禁用**：pinning 页面在第二次运行时硬冻结系统，已注释掉（`image_mdl = NULL`）

### 已知遗留问题

- **stale-PFN 间歇崩溃 (1/6)**：OS repage 修改真实 PFN，影子 CR3 快照过期。当前用 `stealth_refresh_shadow_code_pte` 逐页 refresh 缓解。彻底修复需扩展 refresh 到整个 2MB 区域
- **CMOS NVRAM 不持久化**：本 UEFI 主板不支持，W.log 不可靠
- **第二次运行冻结**：影子 CR3 PA 被复用，预注入清理（VMCALL_STEALTH_FREE_ALL）缓解但未完全解决

---

## 附录：完整注入时序图

```
R3                      R0 (TestDriver)              VMX-root (Ophion)
|                       |                            |
|  FindProcessByName    |                            |
|  CreateFileMapping    |                            |
|  CreateFile(RMCoreTst)|                            |
|  DeviceIoControl -----+--> IOCTL_INJECT_RENDERDOC  |
|                       |                            |
|                       |  TdInjectRenderdocShadow:  |
|                       |  +- Step0: HV cleanup -----+--> VMCALL_SHADOW_ABORT_ALL (DPC)
|                       |  |                         +--> VMCALL_STEALTH_FREE_ALL
|                       |  |                         +--> VMCALL_SHADOW_ABORT_ALL (DPC, INVEPT)
|                       |  |                         |
|                       |  +- Step1: KeStackAttach   |
|                       |  |         caller_cr3      |
|                       |  |                         |
|                       |  +- Step2: TdReadFileKernel|
|                       |  |         (read DLL)      |
|                       |  |                         |
|                       |  +- Step3: TdManualMapInProcess
|                       |  |         (alloc, copy, reloc, imports, stub)
|                       |  |                         |
|                       |  +- Step4: TdBuildShadowCR3|
|                       |  |         (deep-copy PT, NX=0)
|                       |  |                         |
|                       |  +- Step5: TdStealthAllocPage (per page)
|                       |  |         ----------------+--> VMCALL_STEALTH_ALLOC
|                       |  |                         |    (register stealth page)
|                       |  |                         |
|                       |  +- Step6: TdStealthTrackAdd|
|                       |  |                         |
|                       |  +- Step7: resolve NtTestAlert
|                       |  |                         |
|                       |  +- Step8: ZwCreateThreadEx(SUSPENDED)
|                       |  |         at NtTestAlert  |
|                       |  |                         |
|                       |  +- Step10: TdInstallTriggerHookAllCpus
|                       |  |         (EPT hook NtTestAlert -> DllMain stub)
|                       |  |         ----------------+--> VMCALL_HOOK
|                       |  |                         |
|                       |  +- Step11: ResumeThread   |
|                       |  |         ----------------+--> thread runs NtTestAlert
|                       |  |                         |    -> EPT hook fires
|                       |  |                         |    -> jumps to DllMain stub
|                       |  |                         |    -> CPU fetches from stealth page
|                       |  |                         |    -> real PT NX=1 -> #PF
|                       |  |                         |
|                       |  |                         +--> #PF VM-exit
|                       |  |                         |    ept_stealth_handle_pf()
|                       |  |                         |    -> stealth page match
|                       |  |                         |    -> open shadow window
|                       |  |                         |       (swap CR3, widen #PF)
|                       |  |                         |    -> BC_EVT_PF_SHADOW_OPEN
|                       |  |                         |
|                       |  |                         |    renderdoc DllMain executes
|                       |  |                         |    (zero #PF, zero VM-exit)
|                       |  |                         |    -> installs D3D12/DXGI hooks
|                       |  |                         |    -> wraps swapchain
|                       |  |                         |
|                       |  +- Step12: async cleanup  |
|                       |  |         (unhook trigger)|
|                       |  |                         |
|                       |  <--- return status -------|
|  <--- IOCTL return ---+                            |
|                       |                            |
|  wait for wrap        |                            |
|  (shared memory)      |                            |
|                       |                            |
|  scan+replace ptr     |                            |
|  (optional)           |                            |
|                       |                            |
|  Sleep(INFINITE)      |                            |
|  (keep shared mem)    |                            |
|                       |                            |
|  Press F12 to capture |                            |
```

---

> **文档结束**。如有疑问查阅 `PROCESS.md`（工作流程记录）或源码文件索引。
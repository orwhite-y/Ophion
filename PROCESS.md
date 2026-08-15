# Codex 工作流程记录

> 记录已完成、进行中、待办的工作。上下文压缩后必读。

## 当前状态
- **项目路径**：F:\winDriver\te\Ophion-master\renderdoc-1.36
- **最近更新**：2026-08-15 08:41
- **最近会话**：session-late-injection-wrap2
- **进行中**：late descriptor/resource wrapping 已实现并通过 Release x64 编译，等待允许部署测试
- **下一步**：经允许后部署注入并验证 .rdc 体积/可打开性/资源引用

## 变更日志
### 2026-08-14 18:57  [session late-injection-fix3]
- 动作：接管（新会话已读取 PROCESS.md，恢复上下文）
- 结论：FIX 3 尚未应用，立即着手修复 descriptor handle 崩溃

### 2026-08-14 18:50  [session late-injection-fix3]
- 动作：应用 FIX 3 - 4 个文件的 late-injection descriptor heap 安全处理
- 文件：
  - d3d12_manager.h: GetWrapped 添加 IsWrappedDescHeapPtr 检查，unwrapped handle 返回 g_dummyDescriptors
  - d3d12_manager.cpp: 添加 g_lateInjectionMode, g_dummyDescriptors, 范围跟踪 (SRWLOCK + 256 entry array)，GetCPU/GetGPU/GetPortableHandle/GetHeapResourceId 添加 NULL heap 检查，Unwrap 添加 unwrapped handle passthrough
  - d3d12_resources.cpp: 构造函数 RegisterWrappedDescHeapRange，析构函数 UnregisterWrappedDescHeapRange
  - d3d12_hooks.cpp: ApplyVTableHijack 设置 g_lateInjectionMode=true
- 结论：编译通过，注入后游戏存活，但截帧在 OMSetRenderTargets 不再崩溃

### 2026-08-14 18:53  [session late-injection-fix3]
- 动作：修复 D3D12ResourceRecord::Bake() NULL bakedCommands 崩溃
- 文件：d3d12_manager.h (Bake 函数添加 if(!bakedCommands) return;)
- 结论：pre-injection CL 的 bakedCommands 为 NULL（从未通过 wrapper Reset），Bake() 解引用 NULL 导致 crash。添加 guard 后截帧成功

### 2026-08-14 18:55  [session late-injection-fix3]
- 动作：部署测试 - kill GoWR, 编译, 复制 DLL, 启动游戏, 注入, 触发截帧
- 结论：? 截帧成功！生成 frame_capture.rdc (1,463,563 bytes / 1.4MB)
  - "Captured D3D12 frame with 4.912354 MB capture section in 0.049056 seconds"
  - "Written to disk: C:\ProgramData\WinComp\captures\frame_capture.rdc"
  - "EndFrameCapture -> SUCCESS"
  - 游戏存活，无 renderdoc 崩溃（crash log 仅有 sl.interposer.dll 自身问题）

## 关键发现
- **Late injection real descriptor handle 安全边界**：`GetWrapped()` 对未知 real handle 只能给 serialisation 用 dummy；`Unwrap()` 必须把未知 real handle 原样传给真实 D3D12，否则 dummy descriptor 会译成 NULL handle，容易触发 invalid argument / Device Remove。
- **Real descriptor heap get-start hook 递归坑**：`WrapExistingDescriptorHeap()` 构造函数会调用 real heap 的 CPU/GPU GetStart；共享 vtable hook 后必须用内部调用 guard 防止再入，否则 SRWLOCK 死锁。
- **Late-injection descriptor heap 问题**：pre-injection 创建的 descriptor heap 未被 wrapped，其 CPU descriptor handle 指向真实 GPU descriptor memory 而非 D3D12Descriptor 对象。GetWrapped() 盲目 cast 导致 NULL deref
- **解决方案**：范围跟踪 wrapped descriptor heap 内存区域，unwrapped handle 在 GetWrapped 返回 dummy descriptor（零内存+NULL heap check），在 Unwrap 直接 passthrough 原始 handle
- **bakedCommands NULL 问题**：pre-injection CL 从未通过 wrapper Reset，bakedCommands 为 NULL。Close() 调用 Bake() 解引用 NULL->cmdInfo 崩溃。Fix: Bake() 添加 NULL guard
- **d3d12_manager.h/cpp 用 LF 行尾，d3d12_resources.cpp/hooks.cpp 用 CRLF**：Python binary mode 替换时必须匹配对应行尾
- **sl.interposer.dll VEH 异常**：游戏自身的 Streamline interposer 有 AV 异常 (sl.interposer.dll+0x25e94)，与 renderdoc 无关，VEH 捕获后游戏继续运行
- **Python 编辑 CRLF 文件**：text 模式自动将 \r\n 转 \n，搜索时要搜 \n 不是 \r\n。用 binary mode (open(f,"rb")/open(f,"wb")) 替换

## 待办 / 下一步
1. 验证 .rdc 文件是否能在 RenderDoc UI 中正常打开
2. 截帧内容可能不完整（pre-injection 资源未被记录），评估是否需要进一步改进
3. 考虑多次截帧测试稳定性
4. 提交代码到 git

### 2026-08-15 08:20  [session late-injection-resync]
- 动作：接管（新会话已读取 PROCESS.md，恢复上下文）
- 结论：已确认截帧管线成功但 .rdc 过小（约 1.4MB），根因方向为 pre-injection descriptor/resource 未包装导致资源引用被 dummy 掉；待办 = 实现按需包装与 descriptor/resource 重建


### 2026-08-15 08:25  [session late-injection-wrap1]
- 动作：接管（新会话已读取 PROCESS.md，恢复上下文）
- 结论：已确认当前工作树尚未实现 late-wrap 主体；待办 = 实现真实 descriptor/resource 按需包装与翻译路径



### 2026-08-15 08:32  [session late-injection-wrap2]
- 动作：接管（新会话已读取 PROCESS.md，恢复上下文）
- 结论：继续实现 device descriptor API hook 与 late-wrap 修复；暂不部署测试


### 2026-08-15 08:41  [session late-injection-wrap2]
- ????? late-injection descriptor ?????
- ???renderdoc/driver/d3d12/d3d12_hooks.cpp?d3d12_manager.cpp?d3d12_device_wrap.cpp?d3d12_device_rescreate_wrap.cpp?d3d12_command_list_wrap.cpp?d3d12_resources.cpp
- ???device descriptor API vtable hooks?real heap get-start hooks?real handle?fake descriptor ???real resource/heap ?? wrapping ?????? real descriptor handle ??? API ????? passthrough??? dummy?NULL ???? Device Remove?Release x64 ??????????

### 2026-08-15 08:43  [session late-injection-audit]
- 动作：接管（新会话已读取 PROCESS.md，恢复上下文）
- 结论：继续静态审计 late descriptor/resource wrapping；未经允许不部署不测试

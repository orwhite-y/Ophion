# Codex 工作流程记录 (Ophion/renderdoc 注入项目)

> 记录已完成、进行中、待办的工作。上下文压缩后必读。

## 当前状态
- **项目路径**：F:\winDriver\te\Ophion-master (驱动) + F:\winDriver\te\Ophion-master\renderdoc-1.36 (renderdoc)
- **最近更新**：2026-08-12 10:15
- **最近会话**：session-32-process-commit
- **基线**：HEAD = b5c2e07 (session 29-31 全部修复已提交)
- **工作树**：干净（仅 untracked 临时文件）
- **进行中**：无。驱动源码已全部提交，注入稳定。
- **下一步**：He 决定是否重新启动游戏测试截帧（用 flag file 触发，不要用 F12）。

## 变更日志
### 2026-08-12 10:15  [session 32]
- 动作：接管 + 检查 git 状态 + 修复 PROCESS.md 编码损坏 + 提交
- 发现：b5c2e07 提交时 PROCESS.md 被 GBK 双重编码损坏（UTF-8 BOM + GBK 字节），从 8f7be9c 恢复干净版本
- 文件：PROCESS.md（重写为正确 UTF-8 BOM + CRLF）
- 结论：驱动源码已在 b5c2e07 提交，工作树干净。PROCESS.md 编码修复后待提交。

### 2026-08-12 09:51  [session 31]
- 动作：接管 + 分析蓝屏 dump + 修复 SEH + 编译部署测试
- 蓝屏分析：081226-10703-01.dmp (09:30:58)
  - BUGCHECK: KMODE_EXCEPTION_NOT_HANDLED (0x1E)
  - Arg1: 0xC0000005 (STATUS_ACCESS_VIOLATION)
  - Arg2: fffff8024d3e4957 (Ntfs.sys)
  - 栈：bc_worker_thread -> hv_breadcrumb_write_log+0x41f -> NtWriteFile -> Ntfs -> AV
  - 根因：BC.log 后台线程写 ZwWriteFile 时 Ntfs 内部 AV。BC.log 只是调试日志，失败不应拖垮 OS
- 修复：breadcrumb.cpp
  - hv_breadcrumb_write_log: __try/__except(EXCEPTION_EXECUTE_HANDLER) 包裹 ZwWriteFile
  - ZwClose 也包了 SEH
  - bc_worker_thread 和 hv_breadcrumb_flush_now 的调用也包了 SEH (防御)
  - 文件用 UTF-8 BOM + LF，使用 UTF-8 编码编辑
- VMCALL 误报修复：TdStealthFreePageSafe 每页对全部 CPU 发 VMCALL，renderdoc.dll=2094 页 -> 2094 VMCALLs/CPU。safety-net streak 计数排除 VMCALL。
- 重量级记录：
  - Ophion.sys@FFFFF8024A700000, TestEptHook.sys@FFFFF8024AC0000
  - ntoskrnl@FFFFF8057D800000
  - GoWR PID=12248 WS=1786MB Threads=79
  - BC.log: 2024 EPT violation, 22 EPT misconfig, 1 VMCALL, 1 MOV_CR breaker, 0 panic
  - 系统稳定 15+ 分钟，无新 dump
- 编译：_build2.bat 成功，签名通过
- 测试结果：注入成功，系统稳定 15+ 分钟，无 BSOD
- 提交：b5c2e07（源码 + PROCESS.md 一起提交，但 PROCESS.md 编码损坏）

### 2026-08-11 17:01  [session 30]
- 动作：接管 + MTF handler 方向反转修复 + 编译通过
- 修复：ept_hook.cpp ~L1109 MTF handler 用 sp->pt_page_va (shadow->shadow) 而非 sp->real_pt_page_va (real->shadow)。旧代码导致无限 EPT W=0 重触发 -> 系统卡死。
- 其他修复（均在 b5c2e07）：
  - #PF TRUE-path liveloop breaker (vmexit.cpp ~L2530)
  - MOV_CR liveloop breaker (vmexit.cpp ~L2117)：连续 1024 次 MOV_CR 后中止
  - Safety-net bugcheck (vmexit.cpp ~L2130)：ws>=4096(非VMCALL) 或 wrs>=65536 -> hv_panic
  - TdShadowFreePageList SEH (td_shadow.cpp ~L42)：stale VA 清理 -> BSOD 0x3B
  - TdShadowUnmapRealPage SEH (td_shadow.cpp ~L121)
  - ept_stealth_abort_shadow_window 公开接口 (ept_stealth.cpp ~L505)

### 2026-08-11 15:18  [session 28]
- 动作：接管（新会话已读 PROCESS.md，恢复上下文）+ 修复 MODE_G->MODE_H 回归 + 编译部署测试
- 文件：
  - Ophion-master/include/stealth.h L33：#define SHADOW_PT_MODE SHADOW_PT_MODE_G -> SHADOW_PT_MODE_H（beeb4a5 备份补丁意外回退的回归，stale PFN 根因）
- 编译：_build2.bat 成功，Ophion.sys(134760)/TestEptHook.sys(137832) 签名通过
- 部署测试结果：**全部通过** ✅
  - Ophion(VMXON) -> TestEptHook(VMCALL) -> GoWR(pid=5524) -> inject_renderdoc -> "Inject successful!"
  - 注入后 GoWR 存活 87s+（上次会话 22s 就 CFG 崩溃），working set 3.7GB->4.9GB（renderdoc hook 中）
  - 无 BSOD、无卡死、无 GoWR 崩溃、无新 crash dump
  - BC.log 正常 stealth 事件（evt 0x14/0x2a/0x2b），无 panic
- 结论：MODE_H 修复同时解决了 (1) BSOD/卡死 和 (2) CFG 崩溃。CFG 崩溃是 stale PFN 的症状（CPU 执行错误字节 -> 虚假间接调用 -> CFG 检查失败），正如 session 27 推测。He 用 trigger 绕 CFG 的判断正确，不需要碰 CFG。

### 2026-08-11 14:26  [session 26]
- 动作：接管 + 回退到 HEAD(27279a8 MODE_H) + 加 VMX-root 蓝屏机制 + 提交
- 结论：提交为 da8fe39。待办 = 重新应用坑修复到 MODE_H。

## 关键发现
- **【session 31】BC.log 后台线程 Ntfs AV**：bc_worker_thread 写 BC.log 时 ZwWriteFile -> Ntfs 内部 AV。SEH 包裹解决。确切根因未定。
- **【session 31】AutoReboot=1**：蓝屏一分钟自动重启，He 看到的是直接重启。Dump 仍然生成在 C:\Windows\Minidump\。
- **【session 31】breadcrumb.cpp 是 UTF-8 BOM + LF**：不是 CRLF+GBK。编辑用 UTF-8。
- **【session 31】VMCALL streak**：TdStealthFreePageSafe 用 KeGenericCallDpc -> hv_vmcall_simple 对全部 CPU 每页发 VMCALL。renderdoc.dll=2094 页 -> 2094 VMCALLs/CPU。safety-net 必须排除 VMCALL。
- **【session 31】renderdoc 截帧触发**：不要用 F12！F12 启用 overlay -> late-wrap 模式下 GPU device removal。正确方式：创建 flag file C:\ProgramData\WinComp\capture.flag。CheckCaptureTrigger() 每次 Present 检查此文件，删除后设 g_captureStarted=true，下一帧 EndFrameCapture 写 C:\ProgramData\WinComp\captures\frame_XXXXXX.bmp。
- **【session 30】MTF handler 方向反转 = 卡死根因**：MODE_H 下 MTF handler 必须 shadow->shadow（用 sp->pt_page_va），不能用 sp->real_pt_page_va（real->shadow 覆盖 OS 写入 -> 无限循环卡死）。
- **不得回退（全局规则）**：He 明确要求未经允许不要回退代码。已写入 C:\Users\Administrator\.codex\AGENTS.md。
- **本次回退是 He 明确授权**：会话 26 He 说"你直接回退到head把"。这是特例，不是先例。
- **【已验证】MODE_G->MODE_H 回归是 stale PFN 根因**：beeb4a5 的备份补丁（基于 MODE_G worktree 6232bd0）重应用时未排除 stealth.h，把 MODE_H 改回 MODE_G。MODE_G 无 EPT W=0 自动同步 -> 代码页 repage 后 shadow PT 指向旧 PFN -> CPU 读错误字节 -> 执行垃圾 -> 虚假间接调用 -> CFG 检查失败（0xc0000409 fast fail 10）。改回 MODE_H 后全部消失。
- **CFG 不用碰**：He 用 trigger 绕过线程入口 CFG。内部间接调用的 CFG 失败是 stale PFN 的症状，修了 MODE_H 就没了。不要加 CFG call target 注册。
- **VMX-root 约束**：无 API 调用、无文件 I/O、无 DbgPrint。只能用互锁 + 内存写 + VMX 指令 + 端口 I/O + __invlpg + __writecr4。
- **USE_PRIVATE_HOST_CR3 = 1**：VMX-root 跑在私有 host CR3 上。hostcr3_build 深拷贝系统 PML4 256-511 -> ntoskrnl + KeBugCheckEx 在 VMX-root 有映射 -> 蓝屏机制能产生真正 minidump。
- **BSOD 机制（da8fe39）**：Bugcheck=0xDEADC0DE。参数1=0xFF01(#PF)/0xFF02(其它)，参数2=cr2/向量，参数3=RIP，参数4=err。CMOS 0x50-0x6F 崩溃记录（电池备份）。
- **asm_host_pf_handler 符号**：g_pf_safe_start/g_pf_safe_end/g_pf_recovery_count 定义在 breadcrumb.cpp（初值0）。safe-range 包住 stealth_walk_pte/stealth_walk_pt_page，由 ept_stealth_init_pf_safe_range() 在 vmx.cpp:528 设置。handler 结构正确，无需改动。
- **dual-EPT 不能替代 shadow CR3**：guest PTE NX 在 EPT 之前被 CPU 硬件 PT walk 强制检查，EPT 盖不过 guest NX。要「guest 自省见 NX=1 + 实际可执行」必须解耦两份 PT 视图 = shadow CR3（或 EPT 级全 SPT，更复杂）。MODE_H 思路正确。
- **TdNeuterCFG / trigger 不要碰**：He 明确拒绝。He 用 trigger 绕 CFG。
- **构建**：_build2.bat（/t:Rebuild），Debug 配置，输出 build\bin\Debug。TrustAsia 签名在 post-build。签名工具会把文件 mtime 设成 2015（正常现象，看 CreationTime 判断新鲜度）。
- **启动顺序**：必须 Ophion 先(VMXON) 再 TestEptHook(VMCALL)。否则 VMCALL -> #UD。
- **AsmHostIdt.asm 必须 无 BOM**（MASM 不认 UTF-8 BOM）。
- **关键路径**：
  - 项目 F:\winDriver\te\Ophion-master
  - 构建 Ophion-master\_build2.bat
  - 驱动 build\bin\Debug\Ophion.sys, TestEptHook.sys
  - 注入器 F:\winDriver\te\Ophion-master\Injector\inject_renderdoc.exe
  - renderdoc.dll F:\winDriver\te\renderdoc.dll
  - 游戏 E:\God of War Ragnarok\GoWR.exe
  - BC.log C:\Windows\BC.log
  - 模块快照 C:\Windows\MOD_SNAPSHOT2.txt（ntoskrnl@FFFFF80581600000）
  - 符号 srv*C:\Symbols*https://msdl.microsoft.com/download/symbols;F:\winDriver\te\Ophion-master\Ophion-master\build\bin\Debug

## 待办 / 下一步
1. He 决定是否重新启动游戏测试截帧
2. 如测截帧：用 flag file 触发（不要用 F12）
3. 如截帧成功 -> 确认流程完整
4. 如截帧有问题 -> 分析 renderdoc RDCLOG 输出
5. （可选）提交后清理工作树 .bak/.rej 临时文件

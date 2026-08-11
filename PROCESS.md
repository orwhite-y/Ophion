# Codex 工作流程记录 (Ophion/renderdoc 注入项目)

> 记录已完成、进行中、待办的工作。上下文压缩后必读。

## 当前状态
- **项目路径**：F:\winDriver\te\Ophion-master (驱动) + F:\winDriver\te\Ophion-master\renderdoc-1.36 (renderdoc)
- **最近更新**：2026-08-11 15:18
- **最近会话**：session-28-mode-h-fix-success
- **基线**：HEAD = beeb4a5 + 工作树改动 stealth.h (MODE_G->MODE_H，未提交)
- **进行中**：无。注入测试成功，等 He 确认 F12 截帧。
- **下一步**：He 验证 F12 overlay/截帧；如成功可提交 stealth.h 改动。

## 变更日志
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
1. He 验证 F12 overlay / renderdoc 截帧是否正常
2. 如截帧成功 -> 提交 stealth.h (MODE_G->MODE_H) 改动
3. 如截帧有问题 -> 分析 renderdoc hook 状态
4. （可选）提交后清理工作树的 .bak/.rej 临时文件
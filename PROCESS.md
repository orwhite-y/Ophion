# Codex 工作流程记录 (Ophion/renderdoc 注入项目)

> 记录已完成、进行中、待办的工作。上下文压缩后必读。

## 当前状态
- **项目路径**：F:\winDriver\te\Ophion-master (驱动) + F:\winDriver\te\Ophion-master\renderdoc-1.36 (renderdoc)
- **最近更新**：2026-08-11 14:26
- **最近会话**：session-26-bsod-mechanism
- **基线**：HEAD = da8fe39（27279a8 MODE_H EPT Write-Protect Shadow + BSOD 机制）。工作树干净。
- **进行中**：BSOD+CMOS panic 机制已提交。准备重新应用记录的坑修复到 MODE_H 基线，然后编译部署测试。
- **下一步**：核对备份补丁里 4 个坑修复是否适用 MODE_H -> 应用 -> 构建 -> 部署 -> 测试

## 变更日志
### 2026-08-11 14:26  [session 26]
- 动作：接管 + 回退到 HEAD(27279a8 MODE_H) + 加 VMX-root 蓝屏机制 + 提交
- 文件：
  - asm/AsmHostIdt.asm：#PF/#DF/#GP/default 改为调用 C panic（替代 add[rsp+8],1 / cli;hlt）
  - src/hostidt.cpp：hv_host_pf_panic / hv_host_exc_panic（CMOS 0x50-0x6F 写崩溃记录 + KeBugCheckEx(0xDEADC0DE,...)）
  - 会话 17-22 的全部修改保存为 _backup_session25_worktree.patch（98KB，可恢复）
- 结论：提交为 da8fe39。工作树干净。待办 = 重新应用坑修复到 MODE_H。

### 2026-08-04 20:01  [session renderdoc-capture-fix-mode-f]
- 动作：MODE_F 全部修复（3 致命 bug + INVVPID 风暴），Debug 编译+签名通过
- 结论：后被回退（He 授权回 HEAD），MODE_F 修复已存档于备份补丁

## 关键发现
- **不得回退（全局规则）**：He 明确要求未经允许不要回退代码。已写入 C:\Users\Administrator\.codex\AGENTS.md。
- **本次回退是 He 明确授权**：会话 26 He 说"你直接回退到head把"。这是特例，不是先例。
- **VMX-root 约束**：无 API 调用、无文件 I/O、无 DbgPrint。只能用互锁 + 内存写 + VMX 指令 + 端口 I/O + __invlpg + __writecr4。
- **USE_PRIVATE_HOST_CR3 = 1**（stealth.h L68）：VMX-root 跑在私有 host CR3 上。hostcr3_build 深拷贝系统 PML4 条目 256-511，所以 ntoskrnl + KeBugCheckEx 在 VMX-root 里有映射 -> 蓝屏机制能产生真正的 minidump。
- **BSOD 机制（da8fe39）**：
  - Bugcheck = 0xDEADC0DE。参数1=0xFF01(#PF)/0xFF02(其它异常)，参数2=cr2/向量，参数3=RIP，参数4=错误码。
  - CMOS 崩溃记录在 0x50-0x6F：0x50 magic 0xA5 / 0x51 type / 0x52 向量 / 0x54-0x5B CR2 / 0x5C-0x63 RIP / 0x64-0x67 err / 0x68-0x6F CR3。电池备份，能扛三重故障硬复位。
  - g_host_panic_fired 互锁保护 -> 每个 boot 最多一个 CPU 写 CMOS。
  - NMI 处理程序不变（非致命）。
- **为什么之前 #PF 会导致"只有鼠标能动"**：旧 asm_host_pf_handler 做 add[rsp+8],1 跳过1字节 -> 落到指令中间 -> #UD -> default handler -> cli;hlt -> 静默冻结。现在改为 panic。
- **VMCALL 导致 #UD**：说明 Ophion hypervisor 没在运行。测试前必须先启动 Ophion（VMXON）再启动 TestEptHook。
- **TdNeuterCFG 不要重做**：He 明确拒绝。He 用 trigger 绕过 CFG，不要碰。
- **备份补丁里的坑修复（_backup_session25_worktree.patch，针对 self-map walk 方法，需核对是否适用 MODE_H）**：
  1. VM-entry 失败检测（vmexit.cpp）：exit_raw & 0x80000000 -> hv_panic(HV_PANIC_ENTRY_FAILURE)。补丁 694-705 行。
  2. 内核地址 #PF 活锁（vmexit.cpp 重注入路径）：bit47=1 内核地址 阈值2 -> CMOS 快照；bit47=0 阈值8。补丁 759-771 行。
  3. NULL 页 #PF 活锁破坏器（streak>=32 禁 #PF 位图 + MTF）。会话 17 工作。
  4. ept_stealth_handle_pf bit47 检查（会话 16）：内核地址 #PF 导致系统挂起。
  - 注意：这些是为 self-map walk 方法（会话 14-22，已回退）调的。MODE_H 用 EPT write-protect（不切 CR3）。应用前必须核对每个修复的上下文是否仍然成立。
- **构建**：_build2.bat（/t:Rebuild），Debug 配置，输出 build\bin\Debug。TrustAsia 签名在 post-build。
- **关键路径**：
  - 项目 F:\winDriver\te\Ophion-master
  - 构建 F:\winDriver\te\Ophion-master\Ophion-master\_build2.bat
  - 驱动 build\bin\Debug\Ophion.sys, TestEptHook.sys
  - 注入器 F:\winDriver\te\Ophion-master\Injector\inject_renderdoc.exe
  - renderdoc.dll F:\winDriver\te\renderdoc.dll
  - 游戏 E:\God of War Ragnarok\GoWR.exe
  - 符号 srv*C:\Symbols*https://msdl.microsoft.com/download/symbols;F:\winDriver\te\Ophion-master\Ophion-master\build\bin\Debug

## 待办 / 下一步
1. 核对备份补丁里 4 个坑修复是否适用 MODE_H（先读补丁上下文，再决定应用哪些）
2. 应用适用 MODE_H 的修复 -> 构建（_build2.bat）-> 签名
3. 部署前先抓模块基地址快照（MOD_SNAPSHOT.txt）以便 BSOD RIP 解析到模块/函数
4. 部署：先 Ophion（VMXON）-> 验证 BC.log seq=3 -> 再 TestEptHook -> GoWR -> 注入
5. 如果 BSOD：读 minidump（C:\Windows\Minidump\*.dmp，0xDEADC0DE 参数）+ CMOS 0x50-0x6F + BC.log
6. 根据转储证据迭代修复
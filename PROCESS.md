# Codex 工作流程记录 (Ophion/renderdoc 注入项目)

> 记录已完成、进行中、待办的工作。上下文压缩后必读。

## 当前状态
- **项目路径**：F:\winDriver\te\Ophion-master (驱动) + F:\winDriver\te\Ophion-master\renderdoc-1.36 (renderdoc)
- **最近更新**：2026-08-12 14:18
- **最近会话**：session-48
- **基线**：HEAD = 041ccc9
- **工作树**：clean（已提交 session 48 修复）
- **进行中**：KPTI CR3 修复已编译，待部署测试
- **下一步**：部署测试（停驱动 -> kill游戏 -> 部署新驱动 -> 启动Ophion -> 启动TestEptHook -> 模块快照 -> 启动游戏 -> 注入）

## 变更日志
### 2026-08-12 14:18  [session 48]
- 动作：接管 + 分析 W.log/T.log/BC.log + 修复 KPTI CR3 mismatch + 编译 + 提交
- 根因分析（He 的问题：注入后系统卡死）：
  - W.log: marker=0x13 (boot), trig_seen=0, match_seen=0
  - T.log: cleanup 在 thread resume 后 2ms 执行（13:35:16.733 -> .735）
  - BC.log: 只有 3 个 init 事件，无 #PF 事件
  - 根因：KPTI 使 user/kernel CR3 有不同的 PML4 物理地址
  - EPT violation handler (L1004) 和 VMCALL handler (L1490) 比较 guest_cr3 (user) 和 target_cr3 (kernel)
  - 不匹配 -> trigger 线程被当非目标进程 passthrough -> VMCALL 永远不触发
- 修复：
  - Bug 1（根因 - KPTI CR3 mismatch）：ept_hook.cpp + hv_types.h
    - 新增 has_tid_filter 字段到 EPT_HOOKED_PAGE_INFO
    - 3 处 hook install 路径设置 has_tid_filter
    - EPT violation handler (L1007) + VMCALL handler (L1493) 跳过 CR3 预过滤
    - TID 过滤是 TID-filtered hook 的权威过滤器
  - Bug 2（cleanup poll 太快）：td_pe_mapper.cpp
    - -1ms/10000 -> -10ms/2000 (20s max)
    - LOG_INFO -> LOG_WARN (fired= 消息可见)
  - Bug 3（VMCALL 无诊断标记）：ept_hook.cpp
    - wedge_cmos_mark(0x01) 在 trigger fire 后写入
  - Bug 4（#PF safe range 不够）：ept_stealth.cpp
    - 扩展包含 stealth_sync_data_pte_in_window + stealth_refresh_shadow_code_pte
    - 加了前向声明
  - Bug 5（PML4 sync 无 KPTI fallback）：ept_stealth.cpp L927
    - stealth_real_va(sp, real_cr3) 返回 NULL 时 fallback 到 sp->guest_cr3
- 文件：hv_types.h, ept_hook.cpp, ept_stealth.cpp, td_pe_mapper.cpp, td_common.h, td_inject.cpp, td_shadow.cpp, vmexit.cpp
- 编译：Ophion.sys + TestEptHook.sys 成功签名
- 提交：041ccc9
- 结论：等待 He 决定是否测试
### 2026-08-12 14:30  [session 37]
- 动作：接管 + 分析 stealth #PF handler + 修复4个 bug + 编译
- 根因分析（He 的问题：stealth #PF handler 为什么不判断是不是目标页）：
  - handler 确实在 L1789 检查 sp->guest_va != fault_page，但用的是 O(n) 链表遍历（2152+ 条目）
  - He 的建议（用 shadow CR3 PTE NX 位做 O(1) 快速判断）是有效的优化方向，但不是当前崩溃的直接原因
  - 当前崩溃根因是 stealth_refresh_shadow_code_pte 的 CR3 泄漏
- Bug 1（根因 - CR3 泄漏）：ept_stealth.cpp stealth_refresh_shadow_code_pte L1163
  - mx_enter_cr3(sp->guest_cr3) 在 L1099 切换 CR3 + 禁中断 + 刷 TLB
  - stealth_walk_pte 失败（real PTE not present，renderdoc 页被 page out）时
  - eturn FALSE 在 L1163 跳过了 leave: 标签的 mx_leave_guest_cr3(saved_cr3)
  - 结果：中断永久禁用 + CR3 停在 guest 进程 CR3 + TLB 全刷 -> 系统卡死
  - 修复：在 return FALSE 前加 mx_leave_guest_cr3(saved_cr3);
- Bug 2（用户态 livelock breaker 缺 total 计数）：vmexit.cpp L2653
  - 内核态有 wtotal >= 4 兜底，用户态只有 ws >= 32（per-address streak）
  - 两个用户态地址交替 #PF -> per-address streak 反复重置 -> 永远到不了 32
  - 修复：if (ws >= 32 || wtotal >= 64) do_reinj_break = TRUE;
- Bug 3（breaker 不清 shadow window 状态）：vmexit.cpp L2666-2685
  - FALSE-path breaker 重置 streak/total 但不清 nx_timer_restore/nx_timer_real_cr3
  - MTF handler (session 35 fall-through fix) 处理 nx_timer_restore -> 恢复 shadow CR3
  - -> #PF 立即复发 -> breaker 再触发 -> 循环 -> streak 在 0?32 振荡 -> 到 128/256 触发 CMOS snap
  - 修复：breaker 中加 if (vcpu->nx_timer_real_cr3) 块：恢复 real CR3 + 清状态 + 禁 CR3-load/store exiting
  - 注意：不全调 stealth_pf_abort_shadow_window（会冲突 MTF 和 #PF interception 设置）
- Bug 4（write-protected reject 不 abort shadow window）：ept_stealth.cpp L1836
  - write #PF 到 W=0 的 stealth 页 -> reject -> return FALSE 不 abort
  - mid-window 时 -> shadow PTE W=0 -> write #PF 递归 -> livelock
  - 修复：return FALSE 前加 if (vcpu->nx_timer_real_cr3) stealth_pf_abort_shadow_window(vcpu);
- 文件：Ophion-master/src/ept_stealth.cpp, Ophion-master/src/vmexit.cpp
- 编译：_build2.bat 成功，Ophion.sys + TestEptHook.sys 签名通过
- 结论：4 个 bug 已修复并编译，等待 He 决定是否测试

### 2026-08-12 12:11  [session 38]
- 动作：接管 + 分析 W.log (7 CPU 卡在 0x06) + 修复根因 + 编译
- 根因分析（7 CPU 卡在 marker 0x06）：
  - stealth_refresh_shadow_code_pte 和 stealth_sync_data_pte_in_window 中
  - vmx_enter_cr3/vmx_leave_guest_cr3 窗口内有 HYPERPLATFORM_LOG_WARN_SAFE 调用
  - host #PF 安全范围只覆盖 stealth_walk_pte + stealth_walk_pt_page
  - 日志代码调用 LogpMakePrefix -> PsGetProcessImageFileName 等
  - 如果这些函数在 guest CR3 + 中断禁用下触发 host #PF
  - RIP 不在安全范围 -> pf_panic -> jmp $ (死循环) -> CPU 卡死
  - 7 个 CPU 同时卡死 = 系统冻结
- 修复1（根因）：移除两个 CR3 窗口内的所有 HYPERPLATFORM_LOG_WARN_SAFE 调用
  - stealth_refresh_shadow_code_pte: 5 处日志移除 (shadow-pml4 diag, bail-realwalk, BAIL-noshadowpteva, code-sync, MATCH)
  - stealth_sync_data_pte_in_window: 2 处日志移除 (cow-fix, data-sync)
  - 保留：stealth_walk_pte (安全范围), shadow PTE 写 (NonPaged pool), INVVPID (VMX指令), CMOS markers (端口I/O), 计数器自增 (互锁内存写)
  - 新增 CMOS markers 0x07 (pre-shadow-write) 和 0x08 (post-shadow-write) 用于诊断
- 修复2（次要）：FALSE-path breaker 重置 g_wedge_pfloop_streak
  - 之前 FALSE-path breaker 只重置 reinj_streak 和 reinj_total，不重置 pfloop_streak
  - 导致 pfloop_streak 持续增长 -> 每 8 次 #PF 触发一次 CMOS snap (端口 I/O)
  - 384 次 #PF = 48 次 CMOS snap = 576 次端口 I/O
  - W.log 中 pf_err=0x180=384 实际是 pfloop_streak，不是 reinj_streak
- 关键发现：W.log 中 pf_err 字段存储的是 streak 值（不是错误码）
  - wedge_cmos_snap_reinj 存储 pf_va=addr, pf_err=streak
  - pfloop 检测器和 reinj 检测器都写同一 CMOS 字段
  - pf_err=0x180=384 是 pfloop_streak（未被 FALSE breaker 重置），不是 reinj_streak
  - reinj_streak 在 0?32 之间振荡（breaker 正常工作）
- 文件：Ophion-master/src/ept_stealth.cpp, Ophion-master/src/vmexit.cpp
- 编译：_build2.bat 成功，Ophion.sys + TestEptHook.sys 签名通过
- 结论：CR3 窗口日志移除修复已完成，等待部署测试
### 2026-08-12 13:45  [session 35]
- 动作：分析 trigger 时灵时不灵根因 + 修复 + 编译
- 根因：MTF handler 优先级反转（ept_hook.cpp ept_handle_mtf）
- 修复：pf_passthrough_armed + shadow_ept_wp_pending handler 移除 early return，fall through 到 mtf_restore_page
- 文件：Ophion-master/src/ept_hook.cpp
- 编译：_build2.bat 成功
- 结论：trigger flaky 根因已修复，等待 He 决定是否测试

### 2026-08-12 10:26  [session 33]
- 动作：接管 + 分析 dump 081226-10578-01 + 准备测试
- Dump 分析：0x0A IRQL_NOT_LESS_OR_EQUAL at nt!KeFlushMultipleRangeTb+0x142
- 根因链：#PF@0x12 (shadow PT bug) -> WEDGE C-heal -> 游戏崩溃 -> VAD teardown BSOD -> 系统 reset

### 2026-08-12 10:15  [session 32]
- 动作：接管 + 检查 git 状态 + 修复 PROCESS.md 编码损坏 + 提交

### 2026-08-12 09:51  [session 31]
- 动作：接管 + 分析蓝屏 dump + 修复 SEH + 编译部署测试
- 修复：breadcrumb.cpp SEH 包裹 ZwWriteFile
- VMCALL streak 排除修复

## 关键发现
- **【session 38】CR3 窗口内禁止 HYPERPLATFORM_LOG_WARN_SAFE**：vmx_enter_cr3/vmx_leave_guest_cr3 窗口内只能有 stealth_walk_pte（安全范围）、shadow PTE 写（NonPaged pool）、INVVPID（VMX 指令）、CMOS markers（端口 I/O）、计数器自增（互锁内存写）。任何其他函数调用都可能触发不可恢复的 host #PF -> pf_panic -> jmp $ -> CPU 卡死。
- **【session 38】W.log pf_err 字段存储 streak 值**：wedge_cmos_snap_reinj 存储 pf_va=addr, pf_err=streak。pfloop 检测器和 reinj 检测器都写同一 CMOS 字段。pf_err=0x180=384 是 pfloop_streak。
- **【session 38】FALSE-path breaker 必须重置 pfloop_streak**：之前只重置 reinj_streak 和 reinj_total，导致 pfloop_streak 持续增长，每 8 次 #PF 触发一次 CMOS snap。
- **【session 37】CR3 泄漏 = 系统卡死根因**：stealth_refresh_shadow_code_pte 的 eturn FALSE 跳过 mx_leave_guest_cr3。renderdoc 页 page out 后触发。所有 vmx_enter_cr3/vmx_leave_guest_cr3 对之间的 early return 都必须先调 leave。
- **【session 37】FALSE-path breaker 必须独立清 shadow window**：不能全调 stealth_pf_abort_shadow_window（会冲突 MTF 和 #PF interception），需要手动恢复 CR3 + 清状态 + 禁 CR3-load/store exiting。
- **【session 37】write-protected reject 路径 (L1836) 是 shadow window 泄漏的边界 case**：ept_stealth_handle_pf 中唯一的 return FALSE 不 abort 路径（已修）。
- **【session 37】用户态 livelock breaker 缺 total 兜底**：内核态有 wtotal>=4，用户态只有 ws>=32。交替地址永远到不了。
- **【session 37】stealth #PF handler 确实检查目标页**：L1789 sp->guest_va != fault_page。但用 O(n) 链表遍历（2152+ 条目）。用 shadow CR3 PTE NX 位做 O(1) 判断是有效优化方向（设计改进，非 bug）。
- **【session 31】BC.log 后台线程 Ntfs AV**：SEH 包裹解决。
- **【session 31】AutoReboot=1**：蓝屏一分钟自动重启。Dump 仍生成。
- **【session 31】breadcrumb.cpp 是 UTF-8 BOM + LF**。
- **【session 31】VMCALL streak**：TdStealthFreePageSafe 每页对全部 CPU 发 VMCALL。
- **【session 31】renderdoc 截帧触发**：flag file C:\ProgramData\WinComp\capture.flag，不要用 F12。
- **【session 30】MTF handler 方向反转 = 卡死根因**：MODE_H 下 MTF handler 必须 shadow->shadow。
- **【已验证】MODE_G->MODE_H 回归是 stale PFN 根因**。
- **CFG 不用碰**：He 用 trigger 绕 CFG。
- **VMX-root 约束**：无 API、无文件 I/O、无 DbgPrint。只能互锁 + 内存写 + VMX 指令 + 端口 I/O + __invlpg + __writecr4。
- **USE_PRIVATE_HOST_CR3 = 1**：VMX-root 跑在私有 host CR3 上。
- **BSOD 机制（da8fe39）**：Bugcheck=0xDEADC0DE。CMOS 0x50-0x6F 崩溃记录。
- **dual-EPT 不能替代 shadow CR3**：guest PTE NX 在 EPT 之前被 CPU 硬件检查。
- **TdNeuterCFG / trigger 不要碰**。
- **构建**：_build2.bat（/t:Rebuild），Debug 配置。
- **启动顺序**：必须 Ophion 先(VMXON) 再 TestEptHook(VMCALL)。
- **AsmHostIdt.asm 必须 无 BOM**。
- **关键路径**：
  - 项目 F:\winDriver\te\Ophion-master
  - 构建 Ophion-master\_build2.bat
  - 驱动 build\bin\Debug\Ophion.sys, TestEptHook.sys
  - 注入器 F:\winDriver\te\Ophion-master\Injector\inject_renderdoc.exe
  - renderdoc.dll F:\winDriver\te\renderdoc.dll
  - 游戏 E:\God of War Ragnarok\GoWR.exe
  - BC.log C:\Windows\BC.log
  - 模块快照 C:\Windows\MOD_SNAPSHOT2.txt
  - 符号 srv*C:\Symbols*https://msdl.microsoft.com/download/symbols;F:\winDriver\te\Ophion-master\Ophion-master\build\bin\Debug

## 待办 / 下一步
1. 部署测试（停驱动 -> kill游戏 -> 部署新驱动 -> 启动Ophion -> 启动TestEptHook -> 模块快照 -> 启动游戏 -> 注入 -> flag file 触发截帧）
2. 如仍卡死：检查 W.log 新增 markers 0x07/0x08 确定卡死位置
3. 如注入成功：检查截帧是否生成 .rdc 文件
4. （可选）用 shadow CR3 PTE NX 位优化 stealth_pages 链表遍历（O(n) -> O(1)）
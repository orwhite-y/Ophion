# Codex 工作流程记录 (Ophion/renderdoc 注入项目)

> 记录已完成、进行中、待办的工作。上下文压缩后必读。

## 当前状态
- **项目路径**：F:\winDriver\te\Ophion-master (驱动) + F:\winDriver\te\Ophion-master\renderdoc-1.36 (renderdoc)
- **最近更新**：2026-08-04 20:01
- **最近会话**：renderdoc-capture-fix-mode-f
- **进行中**：MODE_F 全部修复完成（3 个致命 bug + INVVPID 风暴），Debug 编译+签名通过
- **下一步**：等 He 确认再部署测试截帧

## 变更日志
### 2026-08-04 20:01  [session renderdoc-capture-fix-mode-f]
- 动作：接管 + 修复 MODE_F 三个致命 bug + INVVPID 风暴根因
- 文件：
  - src/ept_stealth.cpp：first-swap 加 #PF widen + INVVPID 改单地址
  - src/vmexit.cpp：PENDING 清 guard + 收窄 #PF；re-activate 恢复 guard + widen #PF + 去掉全量 INVVPID
  - include/stealth.h, include/hv_types.h：MODE_F 定义和状态字段
- 结论：Debug 编译+签名通过，等 He 确认部署

## 关键发现（根因分析 - MODE_F 卡死/BSOD 根因）
- **Bug 1（BSOD）**：first-swap 没 widen #PF -> 数据 #PF 直达 guest MmAccessFault 在影子 PT
  上跑 -> PFN 数据库腐败 -> 0x1A/BSOD。修复：widen #PF 到 all-faults。
- **Bug 2（BSOD）**：PENDING 路径没清 nx_timer_real_cr3 + 没收窄 #PF -> 其他进程 #PF 误触发
  guard -> abort 写回目标 CR3 -> BSOD。修复：清 guard + ept_update_pf_intercept。
- **Bug 3（硬 hang）**：INVVPID 风暴。first-swap 和 re-activate 都用 InvvpidSingleContext
  （全量 TLB flush）。非 stealth 数据页在 stale 2MB 区域 -> 数据 #PF -> abort+reinject ->
  re-open(first-swap) -> 全量 INVVPID -> TLB 全刷 -> 百万级 TLB miss/秒 -> 硬卡死。
  修复：first-swap 改 InvvpidIndividualAddress（单地址）；re-activate 去掉 INVVPID
  （PCID 下不冲突，stale 条目由 already_on_shadow 逐个处理）。
- **MODE_F 正确数据流（修复后）**：
  1. 首次 NX-fetch #PF -> swap 影子 CR3 + 单地址 INVVPID + widen #PF + CR3-load/store exiting
  2. 代码执行 NX=0（零 #PF，零 VM-exit）
  3. stealth 数据页 stale #PF -> A2 heal（写 shadow PTE + 单地址 INVVPID）-> 继续执行
  4. 非 stealth 数据页 stale #PF -> A2 bail -> abort+reinject+reopen（单地址 INVVPID，低开销）
  5. 上下文切换 CR3-load -> PENDING（真实 CR3，收窄 #PF，清 guard）
  6. 回到目标 -> re-activate（影子 CR3，widen #PF，恢复 guard，无 INVVPID）
  7. 首次代码执行后 re-activate -> already_on_shadow（单地址 INVVPID）
- **TdBuildShadowCR3**：影子 PML4/PDPT/PD 是 real 深拷贝。非 DLL 范围指向 real 下级页。
  一个进程一个 shadow CR3（TdStealthFindShadowCr3ForPid 复用 + TdExtendShadowCR3 扩展）。
- **A2 heal**：stealth 数据页写 shadow_pte_va + 单地址 INVVPID（已实现）。非 stealth 数据页
  bail -> abort+reinject（低开销因单地址 INVVPID）。
- **构建**：Debug 配置，deploy_drivers.ps1 用 build\bin\Debug。TrustAsia 签名在 post-build。
- **不得回退**：He 明确要求未经允许不要回退代码。

## 待办 / 下一步
1. 等 He 确认 -> 部署驱动（deploy_drivers.ps1 -Start）
2. 启动 GoWR -> 注入 renderdoc -> 触发 capture.flag -> 验证 .rdc > 1.5MB 有 draw call
3. 验证无 BSOD/卡死
4. 如果截帧成功，提交代码
5. shadow CR3 只 shadow 代码页、数据页用真实 PTE 的优化（后续）
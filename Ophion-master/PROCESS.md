# Codex 工作流程记录

> 记录已完成、进行中、待办的工作。上下文压缩后必读。

## 当前状态
- **项目路径**：F:\winDriver\te\Ophion-master\Ophion-master (branch: shadow-passthrough)
- **最近更新**：2026-08-09 16:49
- **最近会话**：session-livelock-watchdog
- **进行中**：liveloop bugcheck watchdog 已实现+编译通过，未部署测试（He 指示先不测试）
- **下一步**：He 允许后部署测试；下次 hang 会产生 0xDEADC0DE minidump

## 变更日志
### 2026-08-09 16:12  [session fix-0x1a-batch-refresh]
- 动作：分析 0x1A 0x61941 BSOD dump + 实现 batch refresh 修复
- 文件：src/ept_stealth.cpp (新增 stealth_batch_refresh_shadow_ptes 函数 + 修改 !already_on_shadow 路径)
- 结论：
  - BSOD 根因：shadow PT 是构建时快照，代码页 PTE (P=1/NX=0) 保留 stale PFN。
    物理页被释放后复用为页表页时，游戏通过 stale writable PTE 写入 -> 破坏真实页表 -> 0x1A
  - 修复：shadow window 打开时，batch refresh 所有 shadow PT 页的全部 512 PTE 从当前 real PT
    - 代码页 (P=1/NX=0): P=1/NX=0 with current PFN
    - 数据页 (P=1/NX=1): P=0 (reactive sync)
    - 不存在页 (P=0): P=0
  - 编译通过，未部署测试（按 He 指示先不测试）
### 2026-08-09 16:49  [session livelock-watchdog]
- 动作：分析 16:24 无 dump 重启 + 实现 liveloop bugcheck watchdog
- 文件：src/vmexit.cpp（新增 vmx_livelock_panic + g_vmx_panic + 3 处 streak 阈值调用 + handler 入口冻结检查）
- 结论：
  - 16:24 重启 = 无注入（TESTPLAN 写于 16:24:20，重启 16:24:39，inject_out/err 空）。所有未提交 shadow/batch-refresh 改动只在注入期运行 -> 本次崩溃与它们无关。
  - 根本诊断缺口：WEDGE CMOS 诊断全部 stub（hv.h:160-234，因 port I/O 跨 CPU 竞争被禁），且 liveloop 路径无 KeBugCheckEx。内存 liveloop 检测器（reason/rip/reinj streak）每 exit 都跑，但唯一响应 wedge_cmos_snap_reinj() 是 no-op -> 任何 VMX-root liveloop = 静默卡死 = 无 dump。这就是每次'重启没 dump 查不出原因'的根因。
  - 修复（纯增量，不动 shadow 逻辑）：streak >= 0x10000(65536) 时 __vmx_off + KeBugCheckEx(0xDEADC0DE)，handler 入口检查 g_vmx_panic 冻结其他 CPU。下次 liveloop -> minidump（含卡死 exit reason+RIP）。
  - Ophion.sys 编译+签名通过，未部署。

### 2026-08-09 15:30  [session fix-modeg-data-stale]
- 动作：接管（新会话已读取 PROCESS.md，恢复上下文）
- 结论：已确认进度，准备修复 MODE_G 数据页 stale 问题

## 关键发现
- **0x1A 0x61941 根因**：shadow PT 代码页 PTE 的 stale PFN 问题。batch refresh 全部 512 PTE 是正确修复。
  只刷新 faulting page 的单个 PTE 不够——同一 shadow PT 页中的其他代码页 PTE 仍然是 stale 的。
- **MODE_G 数据页 stale 是 AV 崩溃根因**：shadow PT 构建时把所有 PTE 设为 P=1/NX=0（包括数据页），扩展窗口期间数据访问直接走 stale shadow PTE（PFN 是构建时的快照），导致数据写入错误物理页 -> 损坏 ntdll 数据 -> AV
- **MODE_C 已有正确做法**：数据页 P=0 (reactive sync)，代码页 P=1/NX=0。MODE_G 需要应用同样的逻辑
- **NULL shadow_pte_va bug**：stealth_refresh_shadow_code_pte 在 shadow_pte_va==NULL 时返回 TRUE（不刷新 PTE），应该返回 FALSE
- **部署顺序**：stop+delete RMCoreTst -> delay -> stop+delete RMCore -> 3s delay -> deploy
- **正确 Injector**：F:\winDriver\te\Ophion-master\Injector\build\bin\Debug\Injector.exe（不是 Ophion-master\build\bin\Debug\）
- **SHADOW_PT_MODE = SHADOW_PT_MODE_G (7)** (stealth.h line 32)
- **USE_PRIVATE_HOST_CR3 = 1** (stealth.h line 67)
- **不能改原 PTE NX 位**（隐匿性要求）
- **截帧是底线**，Overlay 尽量解决
- **不要回退代码**，除非 He 明确允许

## 待办 / 下一步
1. Fix 1: ept_stealth.cpp - NULL shadow_pte_va -> return FALSE
2. Fix 2: ept_stealth.cpp - MODE_G #PF handler allows fetch #PFs
3. Fix 3: td_shadow.cpp - TdBuildShadowCR3 MODE_G data PTE P=0
4. Fix 4: td_shadow.cpp - TdExtendShadowCR3 MODE_G data PTE P=0
5. Fix 5: td_ioctl.cpp - IOCTL_PROTECT MODE_G data P=0
6. Build + deploy + test

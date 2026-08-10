# Shadow CR3 架构审计与重新设计

## 一、当前架构的根本问题

### 1. 单指令窗口 (per-instruction MTF) = 性能死亡

当前 MODE_C/D 的流程:
`
NX-fetch #PF → refresh shadow PTE → swap to shadow CR3 → enable MTF
→ 执行1条指令 → MTF VM-exit → swap back to real CR3 → restore #PF intercept
`

**每条指令 2 次 VM-exit**。renderdoc.dll 8.5MB, DllMain 百万条指令级。
= 百万级 VM-exit = 系统假死 5+ 分钟。

### 2. ept_update_pf_intercept 遍历 2152 节点链表

每次 MTF 退出都调用 ept_update_pf_intercept, 遍历整个 stealth_pages 链表 (2152节点)
+ hooked_pages 链表。即使修成 fast-path (cached), 单指令窗口本身的 2 次 VM-exit
开销已经不可接受。

### 3. stealth_walk_pte 的 pa_to_va 死锁

commit 9f8d515 的 stealth_walk_pte 用 pa_to_va (= MmGetVirtualForPhysical)
在 VMX-root + private host CR3 下死锁 (PFN DB lock)。stash 里的 self-map walk 修了
这个，但 MODE_D + __halt() 引入了新的冻死。

### 4. data P=0 (MODE_D) 额外 #PF

MODE_D 把数据页设 P=0, 每次数据访问都 #PF → 遍历 2152 节点链表找 sp_data →
vmx_enter_cr3 + 4级页表遍历 + vmx_leave_guest_cr3。紧密循环里 = 假死。

## 二、根本约束

`
真实 PTE NX=1 (反作弊扫描看到不可执行)
  ↓ 代码要执行
需要另一个页表视图 (shadow CR3 或 fake PT) 让 NX=0
  ↓ x86 硬件限制
guest PTE NX=1 → #PF, EPT 无法覆盖 (EPT 在 guest 翻译之后才检查)
`

**唯一办法**: 提供 shadow 页表让 NX=0, 同时不修改真实 PTE。

## 三、优雅方案: MODE_E — 扩展影子窗口 (Extended Shadow Window)

### 核心思想

**不用 MTF 单步。影子 CR3 保持激活, 直到上下文切换 (CR3 write) 才关闭。**

代码在 shadow CR3 上以 **原生速度** 执行, 零 per-instruction VM-exit。

### 状态机

`
状态 INACTIVE (无影子):
  CR3-load exiting: OFF
  #PF intercept: NX-fetch only (正常 stealth 检测)
  
  → NX-fetch #PF 命中 stealth page → 切到 ACTIVE

状态 ACTIVE (影子 CR3 激活):
  CR3-load exiting: ON
  #PF intercept: P=0 only (VM-exit on demand fault, inject P=1 protection)
  GUEST_CR3 = shadow CR3
  
  → 代码原生速度执行
  → 数据 #PF (P=0) → reactive sync, 继续
  → CR3 write (上下文切换) → 切到 PENDING

状态 PENDING (影子暂停, 等待 GoWR 回来):
  CR3-load exiting: ON
  #PF intercept: NX-fetch only
  GUEST_CR3 = 新进程的真实 CR3
  
  → CR3 write 到 GoWR 的 CR3 → 切到 ACTIVE (换回 shadow CR3)
  → CR3 write 到其他进程 → 留在 PENDING
`

### 上下文切换处理

VMX CR3-load exiting 拦截 MOV CR3:
1. VM-exit, 读取新 CR3 值 (从 guest GPR)
2. 如果 shadow active 且新 CR3 ≠ GoWR CR3:
   - 恢复真实 CR3 到 GUEST_CR3
   - 恢复 NX-fetch-only #PF intercept
   - 保持 CR3-load exiting ON (等 GoWR 回来)
3. 写新 CR3 到 GUEST_CR3
4. advance RIP
5. 如果新 CR3 == GoWR CR3:
   - 换回 shadow CR3
   - 设 P=0-only #PF intercept

**性能**: 每次 context switch 1 次 VM-exit (~100-1000次/秒), 可忽略。
**代码执行**: 零 VM-exit (shadow CR3 保持激活)。

### 数据一致性

- **data-only 2MB 区域**: shadow PD entry 直接指向 real PT page → 零 staleness, 零 VM-exit
- **code 2MB 区域中的数据页**: shadow PT 有 P=1 副本, 可能 stale → P=0 reactive sync
- **非 DLL 区域**: shadow PML4 是 real PML4 的副本 → 正常工作
  - 如果 OS 修改了非 DLL 的 PML4/PDPT/PD entry → #PF → 从 real 同步

### 隐匿性

- 真实 PTE: NX=1 (反作弊扫描 ✓)
- CR3 读取: guest MOV CR3 读到 shadow CR3 ≠ real CR3 → **检测向量**
  → 修复: CR3-store exiting, 读 CR3 时返回 real CR3
- VirtualQuery: 无 VAD (manual mapped) → 不可见 ✓

## 四、实现计划

### 文件修改

1. **stealth.h**: #define SHADOW_PT_MODE_E 5, #define SHADOW_PT_MODE SHADOW_PT_MODE_E
2. **hv_types.h**: 新增字段
   - UINT64 shadow_cr3_value — 影子 CR3 值
   - UINT64 shadow_real_cr3_value — GoWR 真实 CR3 (匹配用)
   - BOOLEAN shadow_extended — MODE_E 扩展窗口激活标志
3. **ept_stealth.cpp**: ept_stealth_handle_pf MODE_E 路径
   - 不 enable MTF, 改为 enable CR3-load + CR3-store exiting
   - #PF intercept: mask=PRESENT, match=PRESENT (P=0 VM-exit, P=1 inject)
4. **vmexit.cpp**: mexit_handle_mov_cr CR3 处理
   - CR3 write: shadow 状态机切换
   - CR3 read: 返回 real CR3 (不是 shadow CR3)
5. **ept_hook.cpp**: ept_handle_mtf — MODE_E 不走 MTF, 保留 MODE_C/D 路径
6. **td_shadow.cpp**: MODE_E 的 TdBuildShadowCR3 (同 MODE_C: 全部 P=1/NX=0)

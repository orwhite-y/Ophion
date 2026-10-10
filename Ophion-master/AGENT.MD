# EXE → DLL 行为兼容逆向 Agent

## 目标

把指定 EXE 所依赖的功能，以替代 DLL（或 DLL + 适配层）复现出来。验收标准是：在约定的输入域和运行环境内，EXE 使用替代件时，与使用原始实现时的输入、输出、状态变化、功能结果、错误结果、回调和外部副作用完整一致；不是函数名相似、导出齐全或伪代码相似。

原 EXE + 原组件是唯一的 **行为 Oracle**。Agent 的工作不是“实现一个功能类似的 DLL”，而是用同一输入驱动两套组合并让可观察结果逐项相等。

### 完整一致的比较对象

| 类别 | 必须一致的内容 |
| --- | --- |
| 输入接收 | 参数、配置、文件、环境变量、消息、回调和调用顺序的接受/拒绝方式 |
| 直接输出 | 返回值、输出参数、异常、错误码、标准输出/错误、日志事件 |
| 功能结果 | EXE 界面/命令结果、生成数据、协议结果、可继续执行的后续操作 |
| 状态 | 初始化、就绪、工作、失败、停止等状态及迁移时序 |
| 外部副作用 | 文件内容与顺序、注册表、命名对象、网络请求、线程、回调、资源释放 |
| 失败语义 | 失败条件、错误类别、清理程度、是否可重试及重试后的结果 |
| 时间与并发 | 超时、重试、回调先后、重复调用与并发下的可观察顺序 |

仅 `compatibility_scope.md` 中明确列出的非确定性字段（随机值、时间戳、地址或系统分配的句柄）可以规范化比较；同一规范化规则必须同时用于原件和替代件，且不得掩盖功能差异。

## 硬规则：EXE 行为是规格，导出表只是线索

导出函数仅表示“可能的入口”，不表示 EXE 实际调用了它，也不说明前置状态、参数约束、错误语义和副作用。

- 以原 EXE 的真实调用链与运行观察作为规格来源。
- 原 DLL 导出、符号名、字符串、反编译代码只能用来建立假设。
- 未被 EXE 证据引用的导出统一标记为 `unreached`，实现优先级为 `deferred`。
- EXE 经由 `GetProcAddress`、对象虚表、COM、回调或 IPC 到达的行为，即使不在导出表中，也属于核心范围。
- 不得按导出表顺序实现，更不得仅凭名字猜测行为。

以下均不构成“兼容完成”：逐个复刻导出；单次正常调用返回相同；只验证 DLL 自己可加载；把未到达的诊断/旧入口当作主体。

## 兼容边界

开工前在 `case/compatibility_scope.md` 固化：

- 调用方式：加载路径、导出名/序号、调用约定、参数和结构体布局。
- 生命周期：加载、初始化、重复初始化、停止、重复停止、卸载。
- 功能行为：输入、输出、状态迁移、文件/注册表/网络/回调等副作用。
- 异常行为：非法输入、依赖缺失、资源不足、超时的返回、错误码、日志与清理。
- 并发行为：线程、重入、锁、回调时序与竞态。
- 环境：位数、OS、运行库、依赖、配置和工作目录。

若 EXE 不直接加载 DLL，必须先定义 “EXE 可见功能 → 适配 DLL 接口” 的映射；没有映射不进入实现阶段。

## 必须建立的 FLOW 证据链

每项实现必须先建立 `FLOW-xxx`，由 EXE 触发点反向追到组件边界：

```json
{
  "flow_id": "FLOW-001",
  "trigger": "用户操作、消息、定时器、配置或网络事件",
  "exe_entry": "target.exe+0x123456",
  "dispatch": "direct-import | GetProcAddress | vtable | COM | IPC | callback",
  "callee_chain": ["target.exe+0x...", "original.dll!symbol_or_rva"],
  "preconditions": ["runtime initialized", "config present"],
  "observable_contract": {
    "input": "...",
    "output": "...",
    "state_transition": "READY -> WORKING -> READY",
    "side_effects": ["callback", "file write"]
  },
  "evidence": ["CASE-011 trace", "xref target.exe+0x..."],
  "status": "pending | implemented | verified"
}
```

每个核心功能回答并用证据支持：

1. EXE 在什么条件下走到它？
2. EXE 如何准备参数、解释成功/失败、处理回调并清理？
3. 外部实际能观察到什么结果？

任一问题无证据时，标记 `unknown`，不得以导出名填空。

## 全量行为矩阵（强制）

Agent 必须把 EXE 可达到的功能按触发器列入行为矩阵，而不是只挑容易通过的调用。每行代表一个完整用户/系统可见场景：

```json
{
  "scenario_id": "SCN-012",
  "title": "已初始化状态下重新加载有效配置",
  "trigger": "EXE command/config/message",
  "input_domain": ["valid", "empty", "malformed", "missing", "duplicate", "out-of-order"],
  "covered_flows": ["FLOW-003", "FLOW-007"],
  "oracle_observations": ["return", "state", "output_file", "callback", "log", "cleanup"],
  "original_cases": ["CASE-031", "CASE-032"],
  "replacement_cases": ["CASE-131", "CASE-132"],
  "status": "uncovered | mismatching | matching"
}
```

场景包含：启动、正常主功能、全部由 EXE 可达的功能分支、配置变化、错误输入、依赖缺失、恢复/重试、关闭/卸载、重复生命周期调用，以及已知的并发或回调场景。任何 `uncovered` 或 `mismatching` 场景都禁止输出 `compatible`。输入空间很大时采用等价类、边界值和状态转换覆盖；每个缩减规则要登记理由。

## 工作流

### 1. 固定原件基线

建立目录：

```text
case/
  target.exe
  original.dll
  fixtures/
  harness/
  observations/
  compatibility_scope.md
artifacts/
  baseline.json
  flow_inventory.json
  interface_inventory.json
  behavior_model.md
  diff_results.json
  unresolved.md
```

记录样本 SHA-256、PE 架构、依赖、配置、工作目录和运行环境。每次原件运行以 `CASE-xxx` 编号保存前置状态、完整输入、返回、输出、日志、外部副作用、耗时和退出状态。相同输入必须原样喂给“EXE + 替代件”，然后逐字段对比；不得只单独调用 DLL 来代替 EXE 端到端测试。

### 2. 先找 EXE 触发与编排，再看 DLL

按顺序分析：

1. EXE 触发层：用户操作、命令行、配置、消息、定时器、网络或系统事件。
2. EXE 编排层：模块选择、对象构造、参数准备、状态检查、返回值解释和资源清理。
3. 组件行为层：DLL/对象的状态机、算法和副作用。
4. 交付层：文件名、导出、序号、ABI 与部署布局。

没有第 1、2 层的 `FLOW-xxx`，不得把第 4 层当作完成。导出与 ABI 的任务只服务于让 EXE 走到已验证行为。

### 3. 接口盘点

盘点导入/导出、动态装载、调用点、回调、异常处理、线程入口和外部依赖。接口记录必须包含可达性：

```json
{
  "id": "API-001",
  "symbol": "ExampleInit",
  "calling_convention": "x64",
  "parameters": [{"name":"config","type":"const Config*"}],
  "return": {"type":"int","success_values":[0],"failure_values":[87]},
  "reached_by_flows": ["FLOW-001"],
  "implementation_priority": "core | supporting | deferred",
  "evidence": ["CASE-003", "target.exe+0x..."]
}
```

`reached_by_flows` 为空时必须为 `deferred`。不得把出现 `mov eax, 1` 自动视为成功，必须验证调用者如何判定返回值。

### 4. 行为模型与最小差分实验

为每个 `FLOW-xxx` 建立状态机，覆盖正常、失败、清理、重复调用和并发路径。事实、推断和未知分别标为 `confirmed`、`probable`、`unknown`。

原件和替代件以 **同一个 EXE、同一份输入、同一环境快照** 做端到端单变量差分：正常、空/边界/乱序输入、缺少依赖、权限失败、超时、重复初始化/停止、回调重入、并发和长运行。每条差分保存：

```json
{
  "case_id": "CASE-014",
  "flow_id": "FLOW-001",
  "original": {"return": 87, "output": "...", "files": [], "state": "READY", "callbacks": []},
  "replacement": {"return": 87, "output": "...", "files": [], "state": "READY", "callbacks": []},
  "comparison": "match | mismatch | allowed-difference"
}
```

### 5. 实现

1. 先实现被 EXE 调到的核心 `FLOW-xxx`，其次是其所需生命周期和 ABI。
2. 构建期锁定导出名、序号、调用约定与结构体打包；运行期实现状态和错误语义。
3. 每项代码必须引用至少一个 `FLOW-xxx` 和 `CASE-xxx`；没有引用的代码标注实验性，不计兼容覆盖率。
4. 未证实逻辑使用 `TODO(UNKNOWN-xxx)`；不得静默编造默认行为。
5. 失败初始化必须完整回滚；重复停止与重复卸载的行为需与原件差分验证。
6. 不为单一案例硬编码输入、路径、时间戳或哈希。

## 验收

仅当以下全部满足，结论才可为 `compatible`：

  - 行为矩阵中所有 EXE 可达场景均为 `matching`；无 `uncovered`、无 `mismatching`。
  - 每个场景都在同一 EXE 的“原件/替代件”组合上完成端到端差分，而非只测 DLL。
  - 所有核心 `FLOW-xxx` 都有 EXE 触发证据、实现和通过的差分案例。
  - 所有已确认接口都有 ABI 测试；未可达导出没有冒充功能覆盖。
  - 输入接受方式、输出、状态迁移、功能结果、副作用、错误、回调和清理在声明边界内一致。
  - 生命周期和并发/重入路径已测试，而不只是正常单次调用。
  - `unresolved.md` 不含影响任何已声明输入域或功能的未知项。
- 干净环境下可构建并跑完回归，命令、版本和结果已保存。

报告固定格式：

```text
结论：compatible / partially-compatible / not-yet-verifiable
核心 Flow：N；已验证：X；失败：Y
ABI 覆盖：...
允许差异：...
未决项：UNKNOWN-...
复现命令：...
证据目录：...
```

## 每轮输出

1. 完成：新增或更新的文件。
2. 证据：`FLOW-xxx`、`CASE-xxx`、RVA、日志或差分记录。
3. 结论：事实与推断分开。
4. 未决：具体缺什么证据。
5. 下一步：一个最小且可复现的实验或实现任务。

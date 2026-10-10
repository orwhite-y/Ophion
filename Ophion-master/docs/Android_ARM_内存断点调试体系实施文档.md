# Android ARM 内存断点调试体系实施文档

*面向可修改 Android 内核的硬件监视点 页保护追踪与 CoreSight 联动方案*

本文给出一套可以分阶段落地的 Android ARM 调试体系。主路线使用 Linux perf/hw_breakpoint 管理 ARM 调试寄存器，由用户态守护进程负责地址解析、线程生命周期、符号化和控制协议；扩展路线覆盖 ptrace、内核模块、ARM64 核心补丁、页保护监视、快照差分、CoreSight ETM、软件断点和外部调试。针对带反调试、完整性校验或可能攻击观测面的漏洞样本，另设无进程修改观测模式、对照实验流程和调试器自身加固要求。

实施结论：先交付 EL0 写监视点的连续采集链，再加入停止与单步，随后增加页保护和 CoreSight。内核命中路径只采集固定尺寸事件，不做动态分配、文件操作或复杂栈展开。

| 项目项 | 实施基线 |
| --- | --- |
| 目标平台 | Android ARM64，兼顾 AArch32 兼容进程和 ARMv7 分支 |
| 内核基线 | GKI/ACK 5.10、5.15、6.1、6.6 及厂商下游分支 |
| 首期范围 | 用户进程 EL0 数据写监视点、事件采集、符号化、CLI |
| 后续范围 | 执行断点、读监视、停止单步、EL1、页保护、ETM |
| 文档版本 | 1.1  反调试与漏洞观测增强版  2026 年 9 月 |

## 目录

1 决策摘要与交付边界

2 术语与 ARM 调试模型

3 需求与验收指标

4 全部技术路线比较

5 推荐总体架构

6 地址模型和目标生命周期

7 用户态 perf_event_open 路线

8 ptrace 硬件调试寄存器路线

9 内核模块路线

10 ARM64 核心补丁路线

11 停止 单步与继续状态机

12 页保护监视路线

13 快照差分与硬件槽虚拟化

14 CoreSight ETM 联动路线

15 软件断点 uprobe kprobe 与外部调试

16 Android ART JIT MTE PAC 与 DMA 特殊处理

17 UAPI 事件格式与控制协议

18 工程目录 构建与部署

19 SELinux 与设备访问控制

20 测试 验收 性能与稳定性

21 故障恢复 回滚与版本维护

22 分阶段实施计划

23 漏洞利用与反调试分析模式

附录 A 代码骨架

附录 B 验收检查表

附录 C 参考资料

## 1 决策摘要与交付边界

推荐实现由 ophiond、ophion-cli 和内核后端组成。第一版直接调用 perf_event_open 或 register_user_hw_breakpoint，复用 Linux 对调试寄存器、任务迁移、CPU 热插拔和断点槽的管理。只有在需要原始 ESR/FAR、EL1 断点、内核停车或专用事件协议时，才进入内核模块和 ARM64 核心补丁。

系统需要同时提供 Trace 和 Stop 两种工作方式。Trace 模式记录事件后继续运行，适合高频数据写入和调用来源分析；Stop 模式在命中后冻结目标线程，允许读写寄存器、查看内存、单步和继续。首期优先完成 Trace，因为它能先验证地址、线程、槽管理、事件链和符号链。

首期完成条件：对一个指定 PID 的全部现存线程和后续线程安装 1、2、4、8 字节写监视点；目标线程跨 CPU 迁移、应用冷启动和休眠唤醒后仍能命中；事件包含时间、CPU、PID、TID、PC、SP、LR、通用寄存器、目标地址和丢包状态；CLI 能按 Build-ID 加模块 RVA 下发监视点并输出符号化位置。

## 2 术语与 ARM 调试模型

| 术语 | 含义 | 本体系中的用途 |
| --- | --- | --- |
| 执行断点 Breakpoint | 指令取址匹配后产生 Debug Exception | 定位函数入口、分支和 JIT 代码执行 |
| 数据监视点 Watchpoint | 读或写指定虚拟地址时产生 Debug Exception | 定位谁读取或修改目标数据 |
| BRP WRP | ARM 实现的执行断点和数据监视比较器槽 | 稀缺硬件资源，由 perf 统一分配 |
| EL0 EL1 EL2 | 应用、内核和虚拟化异常级别 | 决定断点权限范围和异常路由 |
| FAR ESR | 故障地址寄存器和异常综合寄存器 | 补充实际访问地址、读写类型和异常原因 |
| Single Step | 执行一条指令后再次进入调试异常 | 越过执行断点或临时解除的页保护 |
| CoreSight ETM | ARM 指令路径硬件追踪 | 补齐命中点之前和之后的执行轨迹 |

AArch64 执行断点通常以 4 字节指令对齐；数据监视点常见长度为 1、2、4、8 字节。跨越 8 字节边界的范围需要拆成两个槽。AArch32 兼容任务还要处理 ARM 指令与 2 字节 Thumb 指令。实际 BRP/WRP 数量由处理器实现决定，系统启动后应查询并公开能力，而不是写死槽数。

CPU 调试比较器观察 CPU 发起的指令和数据访问。DMA、GPU 或其他总线主设备直接写内存时通常不会触发 CPU Watchpoint；这类写入应转到 SMMU/IOMMU 观测、驱动 tracepoint 或快照差分路线。

## 3 需求与验收指标

### 3.1 功能需求

- 按 TID、线程组、进程映射或内核地址定义断点作用域。
- 支持 EXEC、READ、WRITE、READWRITE，支持一次命中、命中计数、线程过滤和模块范围过滤。
- 支持原始地址以及 Build-ID 加模块 RVA 两种地址描述，处理 ASLR、重启和 dlopen。
- 采集寄存器、命中地址、PC、调用上下文和可选栈窗口，支持离线符号化。
- 事件传输支持 read/poll 的简单模式和 mmap per-CPU 环形缓冲的高吞吐模式。
- 断点槽耗尽时给出明确结果，并允许转入页保护、快照或采样式轮换。
- 设备重启、内核模块卸载、目标退出和守护进程崩溃后有确定的清理路径。

### 3.2 非功能指标

| 指标 | 首期目标 | 量产调试目标 | 验证方法 |
| --- | --- | --- | --- |
| 命中完整性 | 单线程连续 100 万次写入无逻辑漏报 | 在槽容量范围内保持确定性 | 固定写循环和事件序列对拍 |
| 事件延迟 | P99 小于 2 ms | P99 小于 500 us | 内核时间戳与用户接收时间差 |
| 丢包可见性 | 任何丢包都递增计数 | 支持 per-CPU 丢包统计 | 缩小环形缓冲制造压力 |
| CPU 开销 | 低频命中场景小于 2% | 按场景制定阈值 | perf stat 和业务基线对比 |
| 稳定性 | 24 小时压力无锁死和引用泄漏 | 72 小时含热插拔与休眠 | KASAN/KCSAN/lockdep 调试内核 |
| 版本适配 | 至少覆盖一条目标 ACK 分支 | 覆盖设备支持的全部内核分支 | 自动构建和设备回归矩阵 |

## 4 全部技术路线比较

| 路线 | 内核改动 | 精度 | 容量 | 停止能力 | 适用场景 |
| --- | --- | --- | --- | --- | --- |
| perf_event_open | 无或只调权限 | 指令级 | 受 BRP WRP 限制 | sigtrap 或配合 ptrace | 最快 MVP、应用 EL0 |
| ptrace regset | 通常无 | 指令级 | 受硬件槽限制 | 完整 | 传统交互式调试器 |
| 内核模块 | KMI 允许时为模块 | 指令级 | 受硬件槽限制 | 可扩展 | 专用事件和受信守护进程 |
| ARM64 核心补丁 | 有 | 指令级且可取 ESR FAR | 受硬件槽限制 | 完整可定制 | EL1、专用停车和元数据 |
| 用户态 mprotect userfaultfd | 无或配置调整 | 页级触发 | 大量页面 | 可控 | 协作式进程或注入代理 |
| 内核 PTE 页保护 | 有 | 页级触发后软件过滤 | 大量页面 | 完整 | 硬件槽不足的大范围监视 |
| 快照差分 | 无 | 时间窗级 | 大范围 | 无 | 缩小候选范围和 DMA 写检测 |
| CoreSight ETM | 驱动和平台配置 | 指令路径 | 由 Trace Buffer 决定 | 通常不停车 | 回溯命中前执行轨迹 |
| BRK uprobe kprobe | 按对象而定 | 执行点 | 较多 | 可扩展 | 函数入口与代码路径 |
| JTAG 外部调试 | 板级配置 | 处理器级 | 由探针决定 | 可停核 | 早期启动、死机和底层内核 |

路线选择原则：已知少量精确地址时优先硬件断点；地址范围大或槽不足时采用页保护；只知道数据发生变化时先快照差分；需要命中前完整指令路径时联动 ETM；需要早期启动或内核完全失去调度能力时使用外部调试。

当目标包含反调试或会主动攻击观测面时，默认优先级调整为：内核内被动硬件监视点、CoreSight ETM、内核 PTE 页监视、perf 只采集模式、ptrace 停止模式、进程内代理或代码补丁。该顺序的目标是减少目标进程可直接读取的变化；它不构成“不可检测”承诺，所有机制都必须通过未观测基线与逐项启用实验量化差异。

## 5 推荐总体架构

```
ophion-cli / IDE adapter
        |
        | Unix domain socket: JSON-RPC or compact binary protocol
        v
ophiond
  - package / process / thread discovery
  - Build-ID + module RVA resolution
  - breakpoint policy and slot planning
  - symbolization and stack reconstruction
  - persistence and session recording
        |
        +-------- perf_event_open / ptrace backend
        |
        +-------- /dev/ophion-bp ioctl + poll/mmap
                            |
                    perf/hw_breakpoint
                            |
             DBGBVR DBGBCR / DBGWVR DBGWCR
                            |
                      Debug Exception
                            |
                 fixed-size event record
```

| 组件 | 职责 | 实现建议 |
| --- | --- | --- |
| ophion-cli | 设置、删除、列出、继续、单步、查看寄存器和事件 | C++ 或 Rust；输出文本和 JSON |
| ophiond | 统一会话、地址解析、线程跟踪、符号化和策略 | vendor daemon；epoll 驱动 |
| libophion | 协议、ELF Build-ID、maps 和符号公共库 | 避免 CLI 与 daemon 重复实现 |
| ophion-bp.ko | 专用内核控制面和事件采集 | miscdevice；先 kfifo 后 mmap ring |
| arm64 hook patch | 补 ESR FAR、访问类型、停车点和单步协作 | 小补丁，保留 perf 原路径 |
| symbol server | 保存未剥离 ELF、Build-ID 和源码映射 | 按 Build-ID 建目录，可离线部署 |

## 6 地址模型和目标生命周期

### 6.1 地址标识

持久配置不得只保存运行时虚拟地址。原生模块使用 Build-ID、模块路径、映射文件偏移和 RVA；匿名映射使用进程启动标识、VMA 起止、权限和映射代数；ART/JIT 使用方法标识加当前代码缓存地址，并在代码失效后重装。

```
runtime_va = map_start + (symbol_file_offset - map_file_offset)
watch_id   = build_id + module_path + rva + type + length + scope
process_id = pid + /proc/PID/stat.starttime
```

### 6.2 线程组管理

- 初次附加时枚举 /proc/PID/task，逐 TID 安装 task breakpoint。
- 守护进程监听线程创建和退出；简单实现可短周期增量扫描，稳定后接入 sched 事件。
- 目标 exec 后清除旧映射与断点，等待新 maps 稳定后按 Build-ID 重建。
- 目标退出时先禁止新命中，再注销 perf_event，最后释放 task 和会话对象。
- PID 重用通过 starttime 或 pidfd 识别，控制协议内部使用会话 ID。

### 6.3 地址对齐和拆分

在 AArch64 上把数据范围按 8 字节比较窗口拆分。1、2、4、8 字节请求如果跨边界，拆成两个物理 Watchpoint，并在用户态合并为一个逻辑断点。事件中保留请求范围、实际比较器范围和 FAR 三个地址。

## 7 用户态 perf_event_open 路线

这是最短实施路径。内核已经提供 PERF_TYPE_BREAKPOINT、mmap perf ring、按线程事件和同步 SIGTRAP 选项。Android 上需要确保 CONFIG_PERF_EVENTS、CONFIG_HAVE_HW_BREAKPOINT 以及目标域的 perf 访问权限。

### 7.1 创建数据监视点

```
struct perf_event_attr attr = {0};
attr.type           = PERF_TYPE_BREAKPOINT;
attr.size           = sizeof(attr);
attr.bp_addr        = address;
attr.bp_len         = HW_BREAKPOINT_LEN_4;
attr.bp_type        = HW_BREAKPOINT_W;
attr.sample_period  = 1;
attr.sample_type    = PERF_SAMPLE_IP | PERF_SAMPLE_TID |
                      PERF_SAMPLE_TIME | PERF_SAMPLE_ADDR |
                      PERF_SAMPLE_CPU | PERF_SAMPLE_REGS_USER;
attr.sample_regs_user = (1ULL << PERF_REG_ARM64_MAX) - 1;
attr.exclude_kernel = 1;
attr.disabled       = 1;

fd = syscall(__NR_perf_event_open, &attr, tid, -1, -1,
             PERF_FLAG_FD_CLOEXEC);
ioctl(fd, PERF_EVENT_IOC_RESET, 0);
ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
```

为每个 TID 打开独立 fd，然后把多个 fd 通过 PERF_EVENT_IOC_SET_OUTPUT 汇聚到共享 ring，或每线程单独 mmap。首期更容易验证的是每线程 ring；线程数较多后再汇聚。读取端必须按 perf_event_mmap_page 的 head/tail 内存屏障规则处理并识别 PERF_RECORD_LOST。

### 7.2 停止模式

目标内核支持 perf_event_attr.sigtrap 时，可要求命中后产生同步 SIGTRAP；交互式寄存器和单步仍建议由 ptrace 接管。若内核版本缺少该字段或厂商限制 perf，则切换至 ptrace 或专用模块。

### 7.3 优点和限制

- 优点：内核改动最少、接口稳定、天然拥有 perf ring 和任务调度支持。
- 限制：Android 权限策略可能限制 perf_event_open；自定义 ESR/FAR 和停车语义较弱。
- 限制：硬件槽是全系统共享资源，pinned 事件创建失败时应返回槽不足而不是静默轮换。

## 8 ptrace 硬件调试寄存器路线

ARM64 ptrace 通过 PTRACE_GETREGSET 和 PTRACE_SETREGSET 暴露 NT_ARM_HW_BREAK 与 NT_ARM_HW_WATCH。user_hwdebug_state 的 dbg_info 低位可用于查询槽数量，每个槽包含 addr 和 ctrl。内核最终仍通过 register_user_hw_breakpoint 创建 perf 事件。

```
struct user_hwdebug_state state = {0};
struct iovec iov = {
    .iov_base = &state,
    .iov_len  = sizeof(state),
};

ptrace(PTRACE_GETREGSET, tid, NT_ARM_HW_WATCH, &iov);
/* 填充 state.dbg_regs[n].addr 与架构控制字段 */
ptrace(PTRACE_SETREGSET, tid, NT_ARM_HW_WATCH, &iov);
```

ctrl 编码应直接复用目标内核 UAPI 头和 GDB/LLDB 已验证实现，不在协议里固化位定义。命中后 waitpid 获取 SIGTRAP，读取 siginfo 和寄存器；继续执行时使用 PTRACE_CONT，单步使用 PTRACE_SINGLESTEP。进程级作用域仍需逐线程附加。

ptrace 路线适合 Stop 模式，是第一版交互式调试最稳妥的控制后端。Trace 模式下，大量停顿会显著改变时序，因此保留 perf 或模块的非停车采集路径。

## 9 内核模块路线

### 9.1 模块边界

模块提供 miscdevice、断点对象管理、事件缓冲和统计。它调用 register_user_hw_breakpoint 绑定目标 task；内核地址使用 register_wide_hw_breakpoint。若这些符号不在目标 GKI KMI allowlist，则把驱动编入同一内核树或采用第 10 章的小型核心补丁。

### 9.2 命中回调规则

- 回调只访问预分配对象，不执行 GFP_KERNEL 分配。
- 不调用 printk、文件 API、用户态 RPC 或可能睡眠的锁。
- 只复制 pt_regs、事件上下文和少量 nofault 栈窗口。
- 每个 CPU 独立写入位置，使用 release/acquire 发布 head。
- ring 满时丢弃新事件或覆盖最旧事件必须配置明确，并递增 dropped。

### 9.3 生命周期

```
ADD:
  validate request
  resolve task reference
  validate user VMA and alignment
  reserve context and ring capacity
  register_user_hw_breakpoint
  publish breakpoint id

DELETE:
  mark disabling
  unregister_hw_breakpoint
  wait for in-flight readers
  drop task reference
  free context
```

### 9.4 缓冲实现

MVP 使用固定记录的 kfifo 加 read/poll，便于先验证 ABI 和并发。生产版改为 per-CPU mmap ring：每个 ring 包含 head、tail、size、dropped 和 generation；用户态按 CPU 轮询并按 timestamp 加 sequence 合并。设备关闭不自动删除全局断点，断点所有权应绑定 session fd，最后一个 owner 关闭时注销该会话全部断点。

## 10 ARM64 核心补丁路线

核心补丁的目标是补信息和停车能力，不替换已有 hw_breakpoint 调度器。主要修改点位于 arch/arm64/kernel/hw_breakpoint.c，保留 perf_bp_event 调用和原有单步恢复逻辑。

| 位置 | 修改内容 | 验收重点 |
| --- | --- | --- |
| watchpoint_handler | 在匹配完成后记录原始 FAR、ESR、访问类型、槽号和匹配距离 | 多地址访存和 tagged address |
| watchpoint_report | 向专用 tracepoint 或静态回调发布扩展元数据 | 不改变现有 perf 事件语义 |
| breakpoint_handler | 为 EXEC 补槽号、EL 和单步状态 | 避免同一 PC 重复异常 |
| single_step_handler | 加入会话状态通知和恢复确认 | 已有单步与调试器单步共存 |
| hw_breakpoint_reset | 记录 CPU hotplug 和 resume 后的重装结果 | 异构 CPU 和电源状态 |

ARM64 对部分访存指令报告的 Watchpoint 地址可能接近而非精确等于被监视字节。事件必须同时记录 requested_addr、programmed_addr、trigger_addr、distance 和 instruction_pc，离线端可结合指令反汇编计算真实访问范围。

EL1 内核断点使用 per-CPU wide breakpoint。当前 ARM64 实现对按任务绑定的内核地址断点有额外限制，设计中不要把它当作进程级内核断点使用。内核执行断点优先考虑 kprobe/fprobe，内核数据监视再使用 wide watchpoint。

## 11 停止 单步与继续状态机

```
RUNNING
   | hit
   v
HIT_CAPTURED --trace mode--> RUNNING
   |
   | stop mode
   v
STOP_PENDING -> STOPPED -> STEP_ARMED -> SINGLE_STEP_EXCEPTION
                                ^                 |
                                |                 v
                           CONTINUE <------- REARM_BREAKPOINT
```

### 11.1 数据监视点

数据监视异常通常在触发访问附近上报。Stop 模式保存寄存器和访问元数据，然后冻结当前线程。继续时遵循目标内核现有 perf/ptrace 行为；自定义核心路径若临时关闭 WRP，应执行一条单步后恢复。

### 11.2 执行断点

执行断点命中时 PC 仍指向目标指令。继续流程必须临时禁止当前 BRP、启用单步、执行原指令、在单步异常中恢复 BRP，再进入 RUNNING。多个调试器或已有 TIF_SINGLESTEP 时保存原状态，恢复时只撤销本会话新增的单步。

### 11.3 线程组停车

先实现单线程停车。线程组停车由 daemon 向其他 TID 发起 ptrace interrupt 并等待全部进入 stop，设置超时和部分停车状态。内核命中回调中直接等待其他线程会引入死锁风险，因此停车协调放在返回用户态路径或用户态 tracer。

## 12 页保护监视路线

### 12.1 协作式用户态方案

目标进程可加载 agent 时，使用 mprotect 或 userfaultfd write-protect。agent 注册目标页，故障后通过信号或 userfaultfd 线程采集上下文，临时放开页面，单步或执行受控访问，再重新保护。它不占 WRP，适合大范围写监视。

### 12.2 内核 PTE 方案

```
arm page watch:
  pin mm and identify target VMA
  split huge page when required
  clear write permission in target PTE
  flush TLB for mm + range

fault path:
  verify mm, VA and write fault
  capture PC/FAR/ESR/registers
  restore writable PTE temporarily
  arm thread single-step
  return from abort

single-step path:
  restore protected PTE
  flush TLB
  publish completion event
```

实现时需要为每个受监视页面维护原始 PTE 属性、VMA generation、活动单步线程和待恢复 CPU mask。mmap、munmap、mprotect、fork、COW、THP 拆分和进程退出都要进入状态机。首次实现只覆盖匿名私有普通页，并关闭 THP 影响；稳定后再扩展文件映射和共享页。

多线程并发是主要难点。某线程临时恢复写权限执行一条指令时，其他 CPU 可能在窗口内写入。严格模式需要短暂停其他线程或使用更细粒度的替代机制；非严格模式记录 unprotected_window 统计并允许概率性漏报。

## 13 快照差分与硬件槽虚拟化

### 13.1 快照差分

对未知变化位置，先按页计算快速哈希，再对变化页按 64 字节块和字节定位。快照包含 maps generation 和读取时间，避免把映射变化误判为数据变化。若怀疑 DMA 写，快照差分比 CPU Watchpoint 更合适。

```
scan pass 1: page hash     -> changed pages
scan pass 2: 64-byte hash  -> changed cache-line candidates
scan pass 3: byte diff     -> exact changed ranges
promote: changed range     -> hardware watchpoint
```

### 13.2 槽虚拟化

把多于硬件槽数量的逻辑断点按时间片轮换只适合采样，轮换期间会漏掉事件。协议必须把这类断点标记为 sampled，并公开 active_ratio、last_armed_time 和 missed_window。要求确定性的断点保持 pinned，槽不足时转页保护或返回资源不足。

## 14 CoreSight ETM 联动路线

ETM 记录指令执行路径，适合回答命中点之前经过了哪些分支。推荐使用 perf 的 cs_etm PMU 和 AUX ring。硬件断点事件作为时间锚点，daemon 从循环 AUX 缓冲中截取命中前后窗口，再用 OpenCSD 解码并按 Build-ID 符号化。

```
kernel config baseline:
CONFIG_PERF_EVENTS=y
CONFIG_CORESIGHT=y
CONFIG_CORESIGHT_LINKS_AND_SINKS=y
CONFIG_CORESIGHT_LINK_AND_SINK_TMC=y
CONFIG_CORESIGHT_SOURCE_ETM4X=y

validation:
perf list pmu | grep cs_etm
perf record -e cs_etm//u --per-thread TARGET
perf report --stdio --dump -i perf.data
```

平台 Device Tree、时钟、电源域和 trace sink 决定 ETM 是否可用。首期保持 ETM 为可选能力。生产调试可使用 AUX snapshot 或 pause/resume，把高带宽追踪限制在断点命中附近。事件关联使用 CPU、TID、ContextID、内核时间戳和 trace_id。

## 15 软件断点 uprobe kprobe 与外部调试

### 15.1 BRK 软件断点

对可写代码页可把目标指令替换为 BRK，保存原指令，异常时恢复原指令并单步，再重新写入 BRK。Android W^X、代码签名、共享映射和 JIT 生命周期会增加复杂度，因此普通原生模块优先采用 uprobe，JIT 代码由 agent 协作管理。

### 15.2 uprobe kprobe fprobe

函数入口和返回追踪不需要消耗 BRP。用户 ELF 使用 uprobe/uretprobe，内核符号使用 kprobe、kretprobe 或 fprobe。它们适合执行路径和参数采集，数据访问来源仍交给 Watchpoint 或页保护。

### 15.3 JTAG 外部调试

外部调试覆盖 Bootloader、MMU 启用前、早期内核、死机和调度器失效场景。实施需要板级调试口、SoC CoreSight 拓扑、符号化 vmlinux、加载地址、KASLR 偏移和各 CPU 状态。它与自托管调试共享部分硬件资源，使用前明确谁拥有断点比较器。

## 16 Android ART JIT MTE PAC 与 DMA 特殊处理

| 对象 | 问题 | 处理方案 |
| --- | --- | --- |
| ART Java 对象 | 移动 GC 会改变对象地址 | 通过 JVMTI/ART 事件维护对象身份，GC 后重新解析并安装 |
| JIT 代码 | 代码缓存生成、移动和失效 | 按方法 ID 跟踪 code cache，失效事件删除旧断点 |
| JNI native buffer | 地址通常较稳定 | 首期优先支持，按分配生命周期删除断点 |
| TBI MTE | 指针带 tag，比较地址需要规范化 | 事件同时保存 tagged 与 untagged 地址 |
| PAC | PC LR 可能包含认证相关高位 | 离线符号化前按目标 ABI 规范化 |
| DMA GPU 写入 | CPU 比较器观察不到 | 驱动 tracepoint、SMMU 观测或快照差分 |
| 共享内存 | 多个进程映射同一页 | 按 mm 和 VA 安装；物理来源分析单独关联 inode 或 dma-buf |
| 内核 uaccess | 内核访问用户地址也可能触发 EL0 Watchpoint | 记录 EL 和 uaccess 标志，区分应用访问与内核代访 |

## 17 UAPI 事件格式与控制协议

### 17.1 设备 UAPI

```
#define OPHION_ABI_VERSION 1

enum ophion_bp_type {
    OPHION_BP_EXEC  = 1,
    OPHION_BP_READ  = 2,
    OPHION_BP_WRITE = 4,
};

struct ophion_bp_spec {
    __u32 abi_version;
    __u32 size;
    __u64 session_id;
    __u64 address;
    __u64 user_cookie;
    __s32 pid;
    __s32 tid;
    __u32 type;
    __u32 length;
    __u32 scope;
    __u32 flags;
};

struct ophion_bp_event {
    __u32 abi_version;
    __u32 size;
    __u64 sequence;
    __u64 timestamp_ns;
    __u64 breakpoint_id;
    __u64 requested_address;
    __u64 trigger_address;
    __u64 pc, sp, lr, pstate;
    __u64 regs[31];
    __u32 pid, tid, cpu;
    __u16 access_type, exception_level;
    __u32 flags, map_generation, dropped_before;
};
```

所有结构以 abi_version 和 size 开头，新增字段只追加在尾部。32 位用户态通过显式宽度类型共用 ABI。ioctl 需要 ADD、DELETE、ENABLE、DISABLE、LIST、CAPS、STATS 和 SESSION_RESET。CAPS 返回每类槽数、支持长度、架构、内核版本和可用后端。

### 17.2 daemon 协议

| 方法 | 主要参数 | 结果 |
| --- | --- | --- |
| session.create | package pid mode | session_id 和 capability |
| breakpoint.add | module build_id rva type length scope | logical_id 和 physical slots |
| breakpoint.remove | logical_id | 清理结果 |
| breakpoint.list | session_id | 状态、命中、槽和后端 |
| target.continue | tid 或 thread_group | 运行状态 |
| target.step | tid | 单步完成事件 |
| registers.get | tid | GPR、PC、SP、PSTATE |
| memory.read | address length | 字节与 maps generation |
| events.subscribe | filters | 有序事件流 |

## 18 工程目录 构建与部署

### 18.1 推荐目录

```
kernel/common/
  drivers/misc/ophion_bp/
    Kconfig
    Makefile
    ophion_bp_main.c
    ophion_bp_event.c
    ophion_bp_ring.c
  include/uapi/linux/ophion_bp.h

vendor/ophion/
  daemon/
  cli/
  lib/
  sepolicy/
  init/ophiond.rc
  tests/
```

### 18.2 Kconfig 与 Makefile

```
config OPHION_BP
    tristate "Ophion ARM breakpoint service"
    depends on ARM64 && PERF_EVENTS && HAVE_HW_BREAKPOINT
    default n

obj-$(CONFIG_OPHION_BP) += ophion_bp.o
ophion_bp-y := ophion_bp_main.o ophion_bp_event.o ophion_bp_ring.o
```

### 18.3 构建选择

- GKI vendor module：配置为 m，加入 vendor_dlkm 的模块列表和 modules.load。先检查所需符号是否位于目标 KMI allowlist。
- 内核内建：配置为 y，适合需要修改 hw_breakpoint.c 或早期初始化的设备。
- 内部调试内核：打开 debugfs、KASAN、KCSAN、lockdep 等诊断配置，仅用于验证驱动并发和引用管理。
- 每个目标 ACK 分支维护独立小补丁；UAPI 头和 daemon 协议保持兼容。

### 18.4 部署

```
/vendor_dlkm/lib/modules/ophion_bp.ko
/vendor/bin/ophiond
/vendor/bin/ophion
/vendor/etc/init/ophiond.rc
/vendor/etc/selinux/vendor_file_contexts
/vendor/etc/selinux/vendor_sepolicy.cil
```

## 19 SELinux 与设备访问控制

设备节点只向 ophiond 域开放，CLI 通过受控 Unix socket 访问 daemon。调试构建可由属性或 init service 开关启用。策略按设备节点、进程查询、perf、ptrace 和符号文件分别授权，避免给普通应用直接访问内核设备。

```
type ophiond, domain;
type ophiond_exec, exec_type, vendor_file_type, file_type;
type ophion_bp_device, dev_type;

init_daemon_domain(ophiond)
allow ophiond ophion_bp_device:chr_file { open read write ioctl map poll };
allow ophiond self:unix_stream_socket { create bind listen accept connect read write };

/dev/ophion-bp             u:object_r:ophion_bp_device:s0
/vendor/bin/ophiond        u:object_r:ophiond_exec:s0
```

具体 perf、ptrace 和 /proc 规则根据 Android 版本与目标域拆分。以 audit 日志补最小规则，并在 CI 中执行 sepolicy 编译和 neverallow 检查。设备节点建议通过 ueventd 设置为 0660，由专用组控制。

## 20 测试 验收 性能与稳定性

### 20.1 最小测试程序

```
static volatile uint64_t watched;

int main(void) {
    for (uint64_t i = 1; i <= 1000000; ++i) {
        watched = i;
        asm volatile("" ::: "memory");
    }
    return watched == 1000000 ? 0 : 1;
}
```

### 20.2 测试矩阵

| 类别 | 用例 | 预期结果 |
| --- | --- | --- |
| 基本功能 | 1 2 4 8 字节读写和执行断点 | 类型、地址和 PC 正确 |
| 对齐 | 每种长度的全部合法偏移及跨边界 | 正确拆槽或返回明确错误 |
| 线程 | 100 个线程创建退出并跨 CPU 迁移 | 无残留断点和 task 引用 |
| 生命周期 | fork exec dlopen munmap 进程重启 | 按策略继承、删除或重装 |
| 电源 | CPU hotplug suspend resume | 断点恢复且统计可见 |
| 压力 | 百万次命中和故意塞满 ring | 无锁死，丢包计数准确 |
| 并发 | 同时增加删除读取事件 | 无 UAF、死锁和重复释放 |
| 兼容 | AArch64 AArch32 Thumb | 指令长度和寄存器集正确 |
| 特殊 | MTE tagged pointer、PAC、uaccess | 地址规范化和来源标志正确 |
| 页保护 | COW mprotect THP 多线程写 | PTE 恢复完整，窗口统计准确 |

### 20.3 观测指标

- breakpoint_add_total、breakpoint_add_failed_by_reason、active_physical_slots。
- event_total、event_dropped、ring_high_watermark、callback_cycles。
- stop_latency、single_step_latency、symbolization_latency。
- task_exit_cleanup、cpu_resume_rearm、page_watch_unprotected_window。

### 20.4 发布门槛

发布前要求普通启动、冷启动、热启动、重复附加、目标崩溃、daemon 崩溃、模块卸载和设备休眠均通过。所有失败路径要返回稳定错误码，并能列出剩余断点、槽和引用统计。

## 21 故障恢复 回滚与版本维护

| 故障 | 恢复动作 | 回滚验证 |
| --- | --- | --- |
| daemon 退出 | session fd 关闭触发断点清理 | CAPS/STATS 显示活动槽归零 |
| 目标进程退出 | exit 路径或 fd 生命周期注销事件 | 无 task 引用和旧 PID 绑定 |
| 模块卸载 | 禁止新请求，注销全部 event，等待回调完成 | rmmod 成功且无异常日志 |
| 页保护会话中断 | 恢复原始 PTE 并执行 TLB flush | 页面权限与 maps 一致 |
| CPU resume 失败 | 禁用受影响 CPU 的断点并上报 degraded | 其他 CPU 继续工作且状态可见 |
| 核心补丁回退 | 关闭 CONFIG_OPHION_BP_EXT 并使用原 perf 路线 | 原 ptrace/perf 自测通过 |

版本维护以 capability 为中心。daemon 启动时读取 ABI 版本、字段大小、硬件槽、支持的长度、后端和内核 commit，按能力启用功能。内核补丁尽量只增加静态 tracepoint 或扩展回调，减少跟随 ACK 合并的冲突面积。

## 22 分阶段实施计划

| 阶段 | 周期参考 | 交付内容 | 退出条件 |
| --- | --- | --- | --- |
| P0 能力探测 | 2 至 3 天 | 槽查询、perf/ptrace PoC、设备矩阵 | 确认目标内核和权限路径 |
| P1 Trace MVP | 1 至 2 周 | 写监视点、线程枚举、事件 ring、CLI | 百万次写入对拍通过 |
| P2 稳定模块 | 2 周 | miscdevice、session、统计、SELinux、部署 | 24 小时压力通过 |
| P3 Stop 调试 | 2 至 3 周 | SIGTRAP/ptrace、寄存器、单步、继续 | EXEC 与 WRITE 交互流程通过 |
| P4 核心增强 | 1 至 2 周 | ESR/FAR、访问类型、单步状态事件 | 跨版本回归通过 |
| P5 页保护 | 3 至 5 周 | 匿名私有页、故障状态机、多线程策略 | PTE 恢复和压力通过 |
| P6 ETM 联动 | 按平台 | AUX ring、快照、OpenCSD 解码 | 命中前路径可稳定还原 |
| P7 ART 集成 | 按需求 | 对象重定位和 JIT 地址更新 | GC/JIT 压力下重装正确 |

建议从 P0 和 P1 开始建立真实设备证据。P2 完成后形成可复用平台；P3 之后才把系统作为交互式调试器使用。页保护和 ETM 分别解决容量与历史路径问题，可以并行演进。

## 23 漏洞利用与反调试分析模式

这一模式用于分析带 TracerPid 检查、时序探测、SIGTRAP 争用、代码完整性校验、调试寄存器探测、环境枚举或调试器攻击面的样本。设计目标不是声称观测不可见，而是把可见变化降到可测、可解释、可切换，并确保样本输入不能直接控制内核观测器的关键状态。

### 23.1 先确定可信边界

漏洞所在异常级别决定观测器放置位置。观测器与被分析对象处于同一或更低可信层时，采到的日志、寄存器和内存都可能被篡改。

| 被分析对象 | 默认可信观测层 | 主方案 | 失效时升级 |
| --- | --- | --- | --- |
| 普通应用或 native 库的 EL0 漏洞 | EL1 内核 | 内核硬件监视点、PTE 页监视、内核 tracepoint | ETM、EL2 或外部 JTAG |
| system_server 或高权限 native 服务的 EL0 漏洞 | EL1 内核加独立 daemon | 内核事件环、pstore、ETM | EL2 或外部采集 |
| 内核驱动或系统调用的 EL1 漏洞 | EL2、CoreSight 或外部探针 | ETM、KVM/EL2 监控、JTAG | 板级 trace、硬件逻辑分析 |
| 固件、TrustZone 或启动链问题 | 对应更高安全状态或外部设备 | 平台 trace、JTAG、串口、保留内存 | 芯片厂商调试设施 |

如果目标是 EL1 漏洞，不应把同一内核中的模块日志当作唯一证据。至少同时保留一条目标难以改写的通道，例如 ETM sink、EL2 采集、串口、pstore 保留区或外部探针。

### 23.2 无进程修改观测模式

建立 `OPHION_MODE_PASSIVE`，作为反调试样本的默认入口。该模式具备以下硬约束：

- 不建立 ptrace 父子关系，不向目标注入 so，不在目标地址空间插入 BRK、trampoline 或 inline hook。
- 不改变目标信号处理器、线程名、文件描述符集合和 `/proc/PID/maps`；控制 daemon 独立运行。
- 断点由内核根据 `pidfd + start_boottime + mm` 绑定，事件中的 PID、TID、CPU 和时间戳全部由内核填写。
- 只允许 Trace 行为；需要 Stop 或改单步状态时，显式切换到 `OPHION_MODE_INTRUSIVE` 并在会话记录中产生模式变更事件。
- 目标地址使用 Build-ID 加 RVA 解析；目标重启、exec 或 mm 更换后重新绑定，禁止仅凭复用的 PID 延续会话。
- 控制面只对独立的受信 daemon 开放；目标进程既不能打开设备，也不能 mmap 可写控制页。

建议配置两个设备镜像：`observer-passive` 只启用内核观测和外部导出，`observer-instrumented` 允许 ptrace、停止、单步和进程内探针。相同输入分别在两个镜像运行，用第一次出现差异的位置判断检测链，而不是一次打开全部功能。

### 23.3 常见反调试检测面与对应策略

| 检测面 | 目标常用观测 | 对本体系的影响 | 首选处理 |
| --- | --- | --- | --- |
| ptrace 状态 | `/proc/self/status` 的 TracerPid、`PTRACE_TRACEME` 返回值、父进程关系 | 传统附加立即暴露 | 被动模式不使用 ptrace；ptrace 仅作为对照组 |
| 信号与软件断点 | SIGTRAP handler、BRK 指令、异常次数和返回 PC | BRK、单步和停止改变控制流 | 优先硬件监视点或 ETM；记录原始 ESR、FAR、PC |
| 时序 | `clock_gettime`、`CNTVCT_EL0`、watchdog、线程心跳 | 停车、频繁命中和符号化造成延迟 | 命中路径只写固定事件；离线符号化；统计 P50/P99 延迟 |
| 代码完整性 | `.text` 哈希、函数前导、PLT/GOT 和重定位检查 | inline hook、BRK、uprobe 可能被发现 | 不改代码页；以硬件断点、PTE 或 ETM 替代 |
| 内存映射 | `/proc/self/maps`、匿名可执行页、注入模块 | agent、trampoline 或 JIT hook 可见 | daemon 与目标分离；被动模式不创建目标映射 |
| 进程与线程环境 | 父进程、线程名、socket、端口、已打开 fd | 常见调试器特征可形成 oracle | 使用固定控制 daemon；目标侧零线程、零 socket、零 fd |
| 内核暴露面 | `/proc/modules`、sysfs、debugfs、设备节点、SELinux audit | 可识别模块和控制设备 | 产品化时优先 built-in；不暴露 debugfs；设备节点仅 daemon 可见 |
| 硬件断点资源 | 抢占 WRP/BRP、安装失败、异常时序 | 样本可通过占槽或探测行为推断 | 启动时记录槽基线；预留策略；失败切换 PTE 或 ETM |
| perf 行为 | perf syscall、SIGIO、采样开销 | 用户态 perf 路线更容易留下行为差异 | 由内核控制面创建事件；目标不持有 perf fd |
| seccomp 与 dump 属性 | seccomp、`PR_SET_DUMPABLE`、Yama/LSM 拒绝 | 阻断用户态附加或改变错误码 | 不依赖目标授权的内核后端；完整记录拒绝 oracle |
| ART/JNI 环境 | Debug.isDebuggerConnected、JDWP、JVMTI、JNI 表和 ClassLoader | Java 层先于 native 层退出 | 被动模式禁用 JDWP/JVMTI；从内核侧观察 native 边界 |
| root、模拟器与系统属性 | build tags、su、属性、传感器和硬件特征 | 样本走不同代码路径 | 使用接近目标产品的 user build；记录属性快照作证据 |

处理原则是定位“输入—判定—动作”三段链：样本读取了什么输入，哪个函数把它判定为调试环境，随后发生退出、延时、伪数据还是控制流切换。字符串命中只作为候选，必须用运行时事件、调用栈或分支轨迹验证。

### 23.4 检测链定位流程

每个样本保存 `sample_sha256`、设备型号、boot image 哈希、内核 commit、ABI、SELinux 状态、命令行、输入样例、开始时间和结束时间。按以下顺序运行：

1. **R0 原始基线**：不加载会话，冷启动三次、热启动三次，保存 stdout、logcat、tombstone、网络、耗时和最终状态。
2. **R1 空载观测器**：内核支持存在但不安装断点，验证“仅存在组件”是否触发差异。
3. **R2 单个硬件监视点**：只在已知数据或判定结果上布一个 WRITE/EXEC 点，不停止线程。
4. **R3 ETM 或页监视**：在不改目标代码的前提下补齐命中前路径或扩大范围。
5. **R4 侵入式对照**：启用 ptrace、Stop、BRK 或进程内 agent，故意制造可见差异以确认检测 oracle。
6. **首差异分析**：按时间对齐 R0 至 R4，找最早的寄存器、分支、系统调用、文件读取、信号或输出差异。
7. **最小复现**：只保留导致差异的一项机制，重复冷启动、热启动和边界输入，确认检测链稳定性。

推荐事件关联键为 `session_id + boot_id + pid_start_time + tid + seq`。所有时间源转换为同一单调时钟域；ETM、内核事件、logcat、网络包和 tombstone 都记录同步点。报告中分开写静态事实、运行时观测、推断和未决项。

### 23.5 漏洞利用链的取证点

对漏洞利用分析，不把单个崩溃地址当作完整结论。沿以下阶段设置事件和快照：

| 阶段 | 要抓的事实 | 推荐机制 | 最低事件字段 |
| --- | --- | --- | --- |
| 入口 | 外部输入进入解析器或 ioctl/binder 接口 | tracepoint、uprobe、入口执行断点 | 输入长度、调用者、PC、时间戳 |
| 原语形成 | 越界、UAF、double free、整数溢出等首次发生 | KASAN/KFENCE、页监视、分配器 tracepoint | 对象地址、大小、分配/释放栈、访问类型 |
| 内存破坏 | 关键对象、函数指针、长度或页表被改写 | WRITE watchpoint、PTE 监视、前后快照 | 原值、新值、写入 PC、FAR、ESR、寄存器 |
| 控制流变化 | 间接跳转、返回地址或异常向量出现异常目标 | EXEC breakpoint、BTI/PAC 异常、ETM | 源 PC、目标 PC、LR、SP、PSTATE |
| 权限与后续动作 | cred、SELinux、映射权限、进程生成或文件写入变化 | LSM/调度/exec/mmap tracepoint | 旧值、新值、主体、对象、返回码 |
| 崩溃或重启 | panic、oops、tombstone、watchdog | pstore、ramoops、串口、外部 trace | 最后事件序列、CPU、异常寄存器、构建哈希 |

硬件监视点优先放在“将要被破坏的稳定对象字段”而不是高频入口。若对象地址动态变化，先用分配器 tracepoint 捕获对象实例，再为实例字段安装短生命周期 watchpoint；释放时立即撤销，避免地址复用产生误判。

EL1 漏洞分析建议同步保存 `ESR_EL1`、`FAR_EL1`、`ELR_EL1`、`SPSR_EL1`、`SP_EL0`、当前 task/mm、页表项、分配器元数据和最近 N 条观测事件。若漏洞可能篡改这些值，以 ETM、EL2 或外部记录作为交叉证据。

### 23.6 调试器自身抗攻击设计

漏洞样本可能把控制面当作新的攻击入口。`/dev/ophion-bp` 和 daemon 协议按不可信输入实现，至少满足下列要求：

- UAPI 结构首部固定为 `abi_version`、`struct_size`、`opcode`、`flags`；未知 flag 和不匹配长度直接返回稳定错误码。
- 使用 `copy_struct_from_user` 或等价的定长复制；所有数组数量、偏移、长度和乘法先做上界与溢出检查。
- 用户指针只在系统调用期间复制，禁止跨回调保存裸用户指针；`task_struct`、`mm_struct`、`pid` 和 perf event 使用明确引用计数。
- 地址必须经过 canonical、权限、目标 mm 和溢出验证；内核读目标内存采用受控 helper，禁止直接解引用目标地址。
- 每个 file descriptor 对应独立 session；所有对象使用不可预测的内核分配 ID，不接受用户提供的内核地址或对象句柄。
- 命中回调处于原子上下文：不睡眠、不分配内存、不获取可能递归的锁、不打开文件、不做栈符号化。
- 环形缓冲的数据区对用户态只读，控制页与数据页分离；内核写入单调序号和提交标志，读端可识别半写事件、覆盖和丢包。
- PID、TID、CPU、时间戳、命中 PC 和访问地址由内核生成；用户 cookie 只作为标签，不能覆盖证据字段。
- 设备节点只允许专用 SELinux domain 打开；daemon 的 Unix socket 校验 `SO_PEERCRED`，CLI 只发高层请求。
- 限制每会话断点数、监视页数、事件速率和内存配额；命中风暴触发熔断，保留首批与末批事件并上报 `RATE_LIMITED`。
- daemon 退出、fd 关闭、目标 exec/exit、模块卸载和系统休眠都进入统一清理状态机；PTE 路线必须恢复原权限并完成 TLB shootdown。
- 核心元数据使用独立 slab cache、poison、redzone 和引用审计；可常量化的表采用 `__ro_after_init`，功能开关使用 static key。

内核观测器必须单独接受 syzkaller 或同类 UAPI fuzz。调试构建同时启用 KASAN、KCSAN、UBSAN、KFENCE、lockdep 和 fault injection，覆盖错误长度、并发 close、重复删除、目标退出、PID 复用、CPU 热插拔、休眠恢复以及每个分配失败点。

### 23.7 防止证据被污染

- 原始事件文件采用只追加分段，段首记录 boot ID、内核 build ID、会话配置和上段摘要哈希。
- 高频路径只做序号和边界校验；段落落盘后再计算 SHA-256，避免在异常回调中做重计算。
- 日志至少双写到普通文件与 pstore/ramoops 或外部接收端；EL1 漏洞场景优先外部通道。
- 每次模式、断点、过滤器、页权限或采样率变化都产生控制事件，禁止只写在 daemon 文本日志中。
- 保存原始地址和原始寄存器；符号、函数名和源码行是派生数据，记录符号包 Build-ID 后可重复生成。
- 崩溃后先冻结和复制证据，再做符号化或恢复；恢复动作本身写入新的审计记录。

### 23.8 反调试模式验收矩阵

| 用例 | 预期结果 |
| --- | --- |
| 读取 TracerPid 并调用 PTRACE_TRACEME | 被动模式与 R0 行为一致；侵入式对照出现预期差异 |
| 安装自定义 SIGTRAP handler | 被动 Trace 不劫持 handler；BRK/Stop 模式明确记录冲突 |
| `.text` 周期哈希 | 被动模式哈希不变；软件断点模式能定位首次差异 |
| 高频 CNTVCT/clock_gettime 探测 | 给出相对 R0 的 P50/P99/最大抖动，不隐藏数据 |
| 枚举 maps、fd、线程、socket | 被动模式不在目标进程增加对应对象 |
| 抢占全部硬件断点槽 | 返回稳定资源错误并自动切换到配置的 PTE/ETM 后端 |
| 构造畸形 ioctl 和并发 close | 只返回预期错误；KASAN/KCSAN/lockdep 无报告 |
| 百万次命中风暴 | 熔断生效，序号和丢包计数可解释，系统无活锁 |
| 目标在命中时 exec/exit | 引用安全释放，旧会话不绑定复用 PID |
| EL1 崩溃破坏普通日志 | pstore、ETM 或外部通道仍保留最后证据窗口 |

### 23.9 实施优先级调整

对于当前“漏洞利用加反调试”场景，建议按下面顺序落地：

1. 在 P0 增加 R0/R1 基线运行器、组件暴露面清单和统一证据目录。
2. P1 默认实现 `OPHION_MODE_PASSIVE`，只做内核硬件监视点加固定事件环，不启用 ptrace 和信号停车。
3. P2 先完成控制面 fuzz、会话隔离、事件熔断、pstore 镜像和 daemon 崩溃恢复，再扩展功能。
4. 将 ETM 从 P6 提前为可选 P3，用于反调试分支和命中前路径；原 Stop 调试后移。
5. EL1 漏洞设备同步准备外部或 EL2 证据通道，避免把同一内核日志作为唯一事实来源。
6. 最后加入侵入式调试后端，专用于确认检测 oracle、交互式寄存器修改和最小复现。

该顺序先建立可信、可复现的观测基线，再增加停止和修改能力；每增加一个后端，都必须重新执行 R0 至 R4 对照并记录首个差异。

## 附录 A 代码骨架

### A.1 内核注册与回调

```
struct ophion_bp {
    struct perf_event *event;
    struct task_struct *task;
    u64 id;
    u64 requested_addr;
    u32 type;
    u32 len;
};

static void ophion_hbp_hit(struct perf_event *bp,
                           struct perf_sample_data *data,
                           struct pt_regs *regs)
{
    struct ophion_bp *ctx = bp->overflow_handler_context;
    struct ophion_bp_event *ev;

    ev = ophion_ring_reserve(raw_smp_processor_id());
    if (!ev) {
        ophion_ring_account_drop(raw_smp_processor_id());
        return;
    }

    ev->timestamp_ns = ktime_get_mono_fast_ns();
    ev->breakpoint_id = ctx->id;
    ev->requested_address = ctx->requested_addr;
    ev->pc = instruction_pointer(regs);
    ev->sp = regs->sp;
    ev->lr = regs->regs[30];
    memcpy(ev->regs, regs->regs, sizeof(ev->regs));
    ev->pid = task_tgid_nr(current);
    ev->tid = task_pid_nr(current);
    ev->cpu = raw_smp_processor_id();

    ophion_ring_commit(ev);
}

static int ophion_register_task_bp(struct ophion_bp *ctx,
                                   struct task_struct *task)
{
    struct perf_event_attr attr;

    hw_breakpoint_init(&attr);
    attr.bp_addr = ctx->requested_addr;
    attr.bp_len = ctx->len;
    attr.bp_type = ctx->type;
    attr.exclude_kernel = 1;

    ctx->event = register_user_hw_breakpoint(&attr,
                  ophion_hbp_hit, ctx, task);
    return IS_ERR(ctx->event) ? PTR_ERR(ctx->event) : 0;
}
```

上面是结构骨架。具体目标分支的 perf_event 回调字段、context 访问方式和导出符号需要按对应内核头调整。执行断点的继续和单步应接入第 11 章状态机。

### A.2 init 服务

```
service ophiond /vendor/bin/ophiond
    class late_start
    user root
    group root readproc
    disabled
    oneshot

on property:persist.vendor.ophion.enable=1
    start ophiond

on property:persist.vendor.ophion.enable=0
    stop ophiond
```

### A.3 CLI 示例

```
ophion capability
ophion attach --package com.example.target
ophion maps --session SESSION_ID
ophion watch --session SESSION_ID \
  --module libtarget.so --build-id BUILD_ID \
  --rva 0x18a2c --type write --length 4 --scope process
ophion events --session SESSION_ID --symbols SYMBOL_DIR
ophion break list --session SESSION_ID
ophion detach --session SESSION_ID
```

## 附录 B 验收检查表

□ 目标设备报告 BRP、WRP 数量和支持长度。

□ 同一逻辑范围的跨边界请求能够拆槽并合并事件。

□ 现存线程和新增线程均安装断点。

□ ASLR、dlopen、exec 和应用重启后能够重建地址。

□ 事件包含 sequence、timestamp、PID、TID、CPU、PC、SP、LR 和寄存器。

□ ring 满时 dropped 递增且 daemon 报告缺口。

□ 目标退出、daemon 退出和模块卸载后活动槽归零。

□ 执行断点经过禁用、单步、恢复后只命中一次。

□ CPU hotplug 和 suspend/resume 后断点继续工作。

□ AArch32/Thumb、TBI/MTE、PAC 和 uaccess 场景按设备能力通过。

□ 页保护后端在会话结束时恢复全部 PTE。

□ ETM 输出能够按 TID 和时间与断点事件关联。

□ KASAN、KCSAN、lockdep 调试构建无新增告警。

□ SELinux 策略只开放 ophiond 所需对象和操作。

□ 文档中的 ABI、错误码、capability 和版本策略已固化到测试。

## 附录 C 参考资料

[1] Armv8 A Self hosted debug  [https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Learn%20the%20Architecture/Arm%20V8A%20self-hosted%20debug.pdf](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Learn%20the%20Architecture/Arm%20V8A%20self-hosted%20debug.pdf)

[2] Android Common Kernel ARM64 hardware breakpoint implementation  [https://android.googlesource.com/kernel/common/+/refs/heads/android-mainline/arch/arm64/kernel/hw_breakpoint.c](https://android.googlesource.com/kernel/common/+/refs/heads/android-mainline/arch/arm64/kernel/hw_breakpoint.c)

[3] Linux hardware breakpoint interface header  [https://android.googlesource.com/kernel/common/+/refs/heads/android-mainline/include/linux/hw_breakpoint.h](https://android.googlesource.com/kernel/common/+/refs/heads/android-mainline/include/linux/hw_breakpoint.h)

[4] Linux hardware breakpoint sample  [https://android.googlesource.com/kernel/common/+/refs/heads/android-mainline/samples/hw_breakpoint/data_breakpoint.c](https://android.googlesource.com/kernel/common/+/refs/heads/android-mainline/samples/hw_breakpoint/data_breakpoint.c)

[5] ARM64 ptrace hardware breakpoint regsets  [https://android.googlesource.com/kernel/common/+/refs/heads/android-mainline/arch/arm64/kernel/ptrace.c](https://android.googlesource.com/kernel/common/+/refs/heads/android-mainline/arch/arm64/kernel/ptrace.c)

[6] perf_event_open manual  [https://man7.org/linux/man-pages/man2/perf_event_open.2.html](https://man7.org/linux/man-pages/man2/perf_event_open.2.html)

[7] Linux CoreSight perf documentation  [https://docs.kernel.org/trace/coresight/coresight-perf.html](https://docs.kernel.org/trace/coresight/coresight-perf.html)

[8] Linux perf ring buffer documentation  [https://docs.kernel.org/userspace-api/perf_ring_buffer.html](https://docs.kernel.org/userspace-api/perf_ring_buffer.html)

[9] Android kernel overview and GKI  [https://source.android.com/docs/core/architecture/kernel](https://source.android.com/docs/core/architecture/kernel)

[10] Android GKI debug features  [https://source.android.com/docs/core/architecture/kernel/debugging-with-gki](https://source.android.com/docs/core/architecture/kernel/debugging-with-gki)

[11] Android kernel code and vendor interfaces  [https://source.android.com/docs/core/architecture/kernel/kernel-code](https://source.android.com/docs/core/architecture/kernel/kernel-code)

[12] Android kernel module support  [https://source.android.com/docs/core/architecture/kernel/kernel-module-support](https://source.android.com/docs/core/architecture/kernel/kernel-module-support)

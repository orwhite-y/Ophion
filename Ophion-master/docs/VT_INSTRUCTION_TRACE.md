# Ophion VT 指令 Trace

Ophion 现在提供统一的 Trace Session 接口。调用方用 `scope` 与 `backend`
组合模式，三种直接可用的组合如下：

| CLI 模式 | scope | backend | 行为 |
| --- | --- | --- | --- |
| `r3-ept` | user | EPT | 对目标进程地址范围撤销 EPT-X，逐条记录范围内执行 |
| `r3-hwbp` | user | HWBP | 私有硬断点触发入口，之后用 VMX MTF 连续单步 |
| `r0-ept` | kernel | EPT | 对内核虚拟地址范围撤销 EPT-X，记录 R0 执行 |

另外有 `r3-auto` 和 `r0-auto`。`r3-auto` 优先选择增强 HWBP；只要任一
处理器上四个 DR 槽都已被客户机占用，就回退到 EPT。`r0-auto` 选择 EPT。

## 增强硬件断点

R3 HWBP 模式不把调试断点直接交给客户机管理：

1. 每个 vCPU 选择一个客户机 DR7 中未启用的槽。
2. VMX 打开 MOV-DR exiting，客户机读写 DR0-DR7 时只接触影子副本。
3. 物理 DR 槽叠加 Ophion 的私有执行断点，因此目标清空 DR0-DR7 不会拆掉入口触发器。
4. VMX 拦截 `#DB`，只消费私有槽产生的原因；同一时刻发生的客户机调试原因仍回注。
5. 命中入口后关闭私有槽，用 MTF 每退休一条指令采一条记录，不设置客户机 TF。
6. 停止或关闭 Session 时恢复客户机 DR 值、DR7、异常位图和 MOV-DR 控制位。

这避免了“用假的 DR 值完全替代客户机硬断点”的兼容性问题：原有客户机断点仍保留，
Ophion 只占用一个当时未启用的槽。没有空闲槽时由 `auto` 回退到 EPT。

## 记录格式与生命周期

所有后端写入同一 `OPHION_TRACE_RECORD`：时间戳、CPU、PID、CR3、RIP、RSP、
RFLAGS、全部通用寄存器，以及可选的 8 个栈 qword。Session 生命周期是：

```text
START -> RUNNING -> STOP/COMPLETE -> READ -> CLOSE
```

- 最多同时存在 4 个 Session。
- 每个 Session 保留最近 1024 条记录，`overwritten` 报告覆盖数量。
- EPT 范围最多跨 16 页；TestDriver 在 Session 运行期间锁定对应页。
- `max_steps` 达到后核心将状态改成 `COMPLETE`。
- 目标进程退出、驱动卸载或显式 `close` 都会撤销 EPT 权限和 DR 叠加并解锁 MDL。

## 构建和使用

```bat
cd TestDriver
build_trace_cli.bat
```

直接运行并实时打印寄存器与可选栈：

```text
trace_cli run r3-ept 4242 0x7FF612341000 0x7FF612342000 500 --stack
trace_cli run r3-hwbp 4242 0x7FF612341120 0x7FF612341300 200 --stack
trace_cli run r0-ept 0 0xFFFFF80612341000 0xFFFFF80612342000 500
```

也可以分离控制与读取：

```text
trace_cli start r3-auto 4242 START END 1000 --stack
trace_cli read SESSION_ID NEXT_SEQUENCE 64
trace_cli stop SESSION_ID
trace_cli close SESSION_ID
```

`start` 与 `end` 是半开区间 `[start, end)`。HWBP 模式在 `start` 处触发，并在
RIP 离开范围或达到 `max_steps` 时完成；EPT 模式只记录范围内实际执行的指令。

## 接口

共享 ABI 位于 `include/trace_protocol.h`。TestDriver 提供：

- `IOCTL_HV_TRACE_START`
- `IOCTL_HV_TRACE_STOP`
- `IOCTL_HV_TRACE_READ`
- `IOCTL_HV_TRACE_CLOSE`

底层 VMCALL 为 `0x1A` 到 `0x1D`。读接口采用 `METHOD_OUT_DIRECT`，VMX-root 在
客户机 CR3 映射下写入锁定的输出缓冲区，避免私有 host CR3 看不到后创建的映射。

## 后续值得做

按收益排序：

1. 增加 Intel PT 后端，长时间 trace 用 PT，EPT/MTF 保留给精确短区间。
2. 把全局环改成 per-vCPU ring，读取时按 TSC/sequence 合并，降低多核写竞争。
3. 在 R3 工具接 Zydis，按目标进程内存即时反汇编并输出模块+RVA。
4. 增加 PID/TID、寄存器表达式、命中次数等条件，以及 immediate/buffered 两种 action。
5. 给 EPT trace 增加跨页热区自适应，仅对当前控制流附近的页保持 NX，降低无关进程退出量。

`r3-hwbp` 会跳过目标进程临时进入 ring 0 的中断/系统调用路径；若 MTF
期间已经切换到其他进程，则会以 `OPHION_TRACE_STOP_CONTEXT_EXIT` 结束，避免
把不连续的两段执行流拼成一条伪 trace。

客户机在 trace 期间新启用被占用的 DR 槽时，私有断点会迁移到其他空闲槽；
若四个槽都已占用，则以 `OPHION_TRACE_STOP_HWBP_CONFLICT` 结束并完整恢复客户机
DR 状态。

设计参考：HyperDbg 的事件/动作与 `!monitor`、`!dr` 接口，以及 VivienneVMM 的
debug-register facade；本实现保留客户机 DR 语义，并补上可实际触发的私有硬断点槽。

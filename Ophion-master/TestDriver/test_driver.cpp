/*
*   test_driver.cpp - EPT hook test: hook NtCreateFile via VMCALL
*
*   模仿 UnrealVTDbg/DbgkSysWin10 的方式:
*     参数直接放寄存器（不传指针），DPC 广播 VMCALL。
*/
#include <ntddk.h>
#include <intrin.h>

#define VMCALL_EPT_HOOK       0x00000003
#define VMCALL_EPT_UNHOOK     0x00000004
#define VMCALL_EPT_UNHOOK_ALL 0x00000005
#define OPHION_VMCALL_ID      0x4F5048494F4E4558ULL   // must match Ophion hv_types.h

//
// 汇编: hv_vmcall_ex(rcx, rdx, r8, r9, r10, r11, r12, r13, r14, r15)
// 无签名 — Ophion handler 会检查 r10 不是 'HVFS' 时走 EPT VMCALL hook 路径
// 但我们需要签名才能通过检查。暂时不用签名，改 Ophion handler 用 rcx 判断。
//
// 实际上 UnrealVTDbg 的 __vm_call_ex 也没有签名寄存器，它用不同的 VMCALL handler。
// 我们的方案：用 Ophion 导出的 asm_vmx_vmcall 的方式，但扩展寄存器传参。
//
// 最终方案：不用签名，Ophion 的 VMCALL handler 对 VMCALL_EPT_HOOK 号不检查签名。
// 或者更好：把参数放 rdx/r8/r9 + 栈传 r10(cr3)，签名用 r10/r11/r12 传不了了。
//
// 最简方案：不用 __vm_call_ex，直接在 DPC 里准备好后调 ept_hook_function()。
// 但用户要求 VMCALL 方式。
//
// 折中：VMCALL 只传 4 个寄存器参数 + 签名。
//   rcx = VMCALL_EPT_HOOK
//   rdx = target
//   r8  = proxy
//   r9  = cr3
// origin_function 通过 NonPaged 全局变量共享。
//

extern "C" {
    //
    // 标准签名 VMCALL (和 Ophion 的 asm_vmx_vmcall 一样)
    // rcx=vmcall_num, rdx=param1, r8=param2, r9=param3
    // 内部设置 r10/r11/r12 = 签名
    //
    NTSTATUS hv_vmcall_ex(
        UINT64 vmcall_reason,
        UINT64 param_rdx,
        UINT64 param_r8,
        UINT64 param_r9,
        UINT64 param_r10,
        UINT64 param_r11,
        UINT64 param_r12,
        UINT64 param_r13,
        UINT64 param_r14,
        UINT64 param_r15);

    NTKERNELAPI VOID    KeGenericCallDpc(PKDEFERRED_ROUTINE, PVOID);
    NTKERNELAPI VOID    KeSignalCallDpcDone(PVOID);
    NTKERNELAPI LOGICAL KeSignalCallDpcSynchronize(PVOID);
}

typedef NTSTATUS (NTAPI * fn_NtCreateFile)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
    PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);

// ---- 全局变量 ----

static fn_NtCreateFile g_orig_NtCreateFile = NULL;
static PVOID           g_target            = NULL;

//
// origin_function 通过 NonPaged 全局变量共享
// VMX-root 写入 trampoline 地址，guest 读取
//
static volatile PVOID g_origin_trampoline = NULL;

// ---- hook 参数 (DPC 传递) ----

struct HOOK_DPC_ARGS {
    PVOID   target;
    PVOID   proxy;
    UINT64  cr3;
    volatile LONG success_count;
};

struct UNHOOK_DPC_ARGS {
    PVOID   target;
    UINT64  cr3;
    volatile LONG success_count;
};

// ---- 代理函数 ----

static volatile LONG g_hook_call_count = 0;

static NTSTATUS NTAPI
Hook_NtCreateFile(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    PLARGE_INTEGER     AllocationSize,
    ULONG              FileAttributes,
    ULONG              ShareAccess,
    ULONG              CreateDisposition,
    ULONG              CreateOptions,
    PVOID              EaBuffer,
    ULONG              EaLength)
{
    // 计数，但不打印（避免递归/死锁）
    _InterlockedIncrement(&g_hook_call_count);
    DbgPrintEx(0, 0, "[EPT-TEST] Hook_NtCreateFile\n");
    // 直接调原函数，什么都不做
    if (g_orig_NtCreateFile)
    {
        return g_orig_NtCreateFile(
            FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
            AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
            CreateOptions, EaBuffer, EaLength);
    }

    return STATUS_UNSUCCESSFUL;
}

// ---- DPC 回调 ----

static VOID
DpcHook(PKDPC Dpc, PVOID Ctx, PVOID A1, PVOID A2)
{
    UNREFERENCED_PARAMETER(Dpc);
    HOOK_DPC_ARGS * args = (HOOK_DPC_ARGS *)Ctx;

    //
    // 像 UnrealVTDbg 一样: 参数直接放寄存器
    //   rcx  = VMCALL_EPT_HOOK
    //   rdx  = target
    //   r8   = proxy
    //   r9   = &g_origin_trampoline (origin_function 指针)
    //   r10  = cr3
    //   r11  = hook_type (0 = abs jump)
    //   r12-r15 = 0 (unused)
    //
    // 注意: 不用签名寄存器! Ophion handler 对 EPT_HOOK 单独处理。
    //
    NTSTATUS ret = hv_vmcall_ex(
        VMCALL_EPT_HOOK,
        (UINT64)args->target,           // rdx
        (UINT64)args->proxy,            // r8
        (UINT64)&g_origin_trampoline,   // r9
        args->cr3,                      // r10
        0,                              // r11 = hook_type
        0, 0, 0, 0);

    if (ret == 0)
        InterlockedIncrement(&args->success_count);

    KeSignalCallDpcSynchronize(A2);
    KeSignalCallDpcDone(A1);
}

static VOID
DpcUnhook(PKDPC Dpc, PVOID Ctx, PVOID A1, PVOID A2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNHOOK_DPC_ARGS * args = (UNHOOK_DPC_ARGS *)Ctx;

    NTSTATUS ret = hv_vmcall_ex(
        VMCALL_EPT_UNHOOK,
        (UINT64)args->target,
        0,
        0,
        args->cr3,
        0, 0, 0, 0, 0);

    if (ret == 0)
        InterlockedIncrement(&args->success_count);

    KeSignalCallDpcSynchronize(A2);
    KeSignalCallDpcDone(A1);
}

// ---- 驱动 ----

static VOID
DpcInvept(PKDPC Dpc, PVOID Ctx, PVOID A1, PVOID A2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Ctx);
    // 只做 INVEPT，不操作链表
    hv_vmcall_ex(VMCALL_EPT_UNHOOK_ALL, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    KeSignalCallDpcSynchronize(A2);
    KeSignalCallDpcDone(A1);
}

static VOID
TestUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    if (g_target)
    {
        //
        // 1. 先禁用代理函数 — 即使 hook 还在，代理直接返回不会崩
        //
        g_orig_NtCreateFile = NULL;

        //
        // 2. 等待所有 CPU 上正在执行的 hook 完成
        //
        KeStallExecutionProcessor(100); // 100us

        //
        // 3. unhook: 恢复所有 CPU 的 PTE + 移除链表
        //
        hv_vmcall_ex(VMCALL_EPT_UNHOOK,
            (UINT64)g_target, 0, 0, 0, 0, 0, 0, 0, 0);

        //
        // 4. 广播 INVEPT 刷新所有 CPU 的 TLB
        //
        KeGenericCallDpc(DpcInvept, NULL);

        DbgPrintEx(0, 0, "[EPT-TEST] Unhooked NtCreateFile.\n");
    }

    DbgPrintEx(0, 0, "[EPT-TEST] Unloaded.\n");
}

extern "C"
NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = TestUnload;

    DbgPrintEx(0, 0, "[EPT-TEST] Loading...\n");

    // 1. 获取 NtCreateFile
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"NtCreateFile");
    g_target = MmGetSystemRoutineAddress(&name);
    if (!g_target)
    {
        DbgPrintEx(0, 0, "[EPT-TEST] Cannot resolve NtCreateFile\n");
        return STATUS_NOT_FOUND;
    }
    DbgPrintEx(0, 0, "[EPT-TEST] NtCreateFile = %p\n", g_target);

    // 2. DPC 广播 VMCALL
    HOOK_DPC_ARGS args = {};
    args.target = g_target;
    args.proxy  = (PVOID)Hook_NtCreateFile;
    args.cr3    = __readcr3();

    //
    // 第一步: 当前 CPU 做完整安装 (split + fake page + trampoline + PTE)
    //
    DbgPrintEx(0, 0, "[EPT-TEST] Installing hook on current CPU... cr3=0x%llX\n", args.cr3);
    NTSTATUS ret = hv_vmcall_ex(
        VMCALL_EPT_HOOK,
        (UINT64)args.target,
        (UINT64)args.proxy,
        (UINT64)&g_origin_trampoline,
        args.cr3,
        0,  // hook_type = 0 (abs jump)
        0, 0, 0, 0);

    if (ret != STATUS_SUCCESS)
    {
        //
        // ret = 0xC001XXXX → XXXX = error_code from ept_hook_install
        // 0=not_called 1=no_PA 2=split_fail 3=pml1_null
        // 4=pool_page 5=pool_func 6=pool_tramp 7=pa_fake 0xFF=null_param
        //
        DbgPrintEx(0, 0, "[EPT-TEST] Hook failed! ret=0x%X error=%u\n",
                   ret, ret & 0xFFFF);
        return STATUS_UNSUCCESSFUL;
    }

    _mm_mfence();  // 确保 VMCALL 的内存写入可见
    DbgPrintEx(0, 0, "[EPT-TEST] Hook installed on CPU. trampoline=%p\n", (PVOID)g_origin_trampoline);

    if (!g_origin_trampoline)
    {
        DbgPrintEx(0, 0, "[EPT-TEST] FATAL: trampoline is NULL after successful hook!\n");
        // hook 已安装但没有 trampoline → 必须先 unhook 再退出
        // 否则任何 NtCreateFile 调用都会蓝屏
        hv_vmcall_ex(VMCALL_EPT_UNHOOK, (UINT64)g_target, 0, 0, args.cr3, 0, 0, 0, 0, 0);
        return STATUS_UNSUCCESSFUL;
    }

    g_orig_NtCreateFile = (fn_NtCreateFile)g_origin_trampoline;

    //
    // 暂时不广播 — 只在当前 CPU 测试 hook 是否工作
    // 其他 CPU 调 NtCreateFile 不受影响（EPT 仍是 RWX）
    //
    DbgPrintEx(0, 0, "[EPT-TEST] Single-CPU hook active (no broadcast)\n");

    DbgPrintEx(0, 0, "[EPT-TEST] NtCreateFile hooked!\n");
    DbgPrintEx(0, 0, "[EPT-TEST]   trampoline = %p\n", (PVOID)g_origin_trampoline);
    DbgPrintEx(0, 0, "[EPT-TEST]   orig_func  = %p\n", (PVOID)g_orig_NtCreateFile);

    //
    // 不主动调 NtCreateFile — 等系统自己调到 hook 的 CPU
    // 如果还蓝屏说明 hook 本身（fake page / trampoline）有问题
    // 如果不蓝屏说明 hook 安装成功，问题在代理函数
    //

    return STATUS_SUCCESS;
}

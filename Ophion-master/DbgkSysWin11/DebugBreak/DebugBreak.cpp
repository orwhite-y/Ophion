#include "../Driver.h"
#include "../ntos/inc/ntosdef.h"
#include "../ntos/inc/ketypes.h"
#include "../ntos/inc/amd64.h"
#include "../ntos/inc/extypes.h"
#include "../ntos/inc/mi.h"
#include "../ntos/inc/pstypes.h"
#include "../ntos/inc/obtypes.h"
#include "../ntos/inc/peb_teb.h"
#include "../ntos/inc/mmtypes.h"
#include "../ntos/inc/ntdbg.h"
#include "../List/MyList.h"
#include "../ntos/inc/ntlpcapi.h"
#include "../ntos/inc/ke.h"
#include "../ntos/inc/ki.h"
#include "../ntos/inc/pecoff.h"
#include "../Log/log.h"
#include "../ntos/inc/psp.h"
#include "../Globals.h"
#include "../Encrypt/Blowfish/Blowfish.h"
#include "../Hvm/AsmCallset.h"
#include "../Hvm/vmcall_reason.h"
#include "../../Common/Ring0/Hvm/OphionMemoryBreakpoint.h"
#include "DebugBreak.h"

bool vmcall_internal(PVOID vmcallinfo)
{
    UNREFERENCED_PARAMETER(vmcallinfo);
    // VT_Driver's legacy software-breakpoint commands overlap unrelated
    // Ophion services, so they must never be forwarded verbatim.
    return false;
}

//只会向当前逻辑处理器发送请求
bool current_vmcall(PVOID vmcallinfo)
{
    return vmcall_internal(vmcallinfo);
}

bool AddHardwareBreakpoint(PBREAKPOINT_RECORD Breakpoint)
{
    if (!Breakpoint)
        return false;

    UINT8 access = 0;
    switch (Breakpoint->command)
    {
    case VMCALL_WATCH_READS: access = OPHION_BP_ACCESS_READ; break;
    case VMCALL_WATCH_WRITES: access = OPHION_BP_ACCESS_WRITE; break;
    case VMCALL_WATCH_EXECUTES: access = OPHION_BP_ACCESS_EXECUTE; break;
    default: return false;
    }

    // Ophion compatibility contract: LoopUserMode == 1 selects one-shot;
    // every other value keeps the original permanent-watch behaviour.
    const UINT8 flags = Breakpoint->LoopUserMode == 1
        ? OPHION_BP_FLAG_ONESHOT : 0;
    UINT64 id = 0;
    UINT64 target_cr3 = 0;
    const NTSTATUS status = OphionMemoryBreakpointSet(
        Breakpoint->pid,
        static_cast<UINT64>(Breakpoint->Address),
        static_cast<UINT32>(Breakpoint->length),
        access,
        flags,
        &id,
        &target_cr3);
    if (!NT_SUCCESS(status))
    {
        outLog("Ophion memory breakpoint set failed: 0x%08X", status);
        return false;
    }

    Breakpoint->watchid = static_cast<int>(id);
    Breakpoint->cr3 = target_cr3;
    outLog("Ophion memory breakpoint set: id=%llu access=%u mode=%s",
        id, access, flags ? "once" : "permanent");
    return true;
}

void SetHardwareBreakpoint(IN PUSER_DATA userData, IN PIRP pIrp)
{
    USER_DATA user = GetUserData(userData);

    PBREAKPOINT_RECORD output = (PBREAKPOINT_RECORD)pIrp->AssociatedIrp.SystemBuffer;  //内核的缓冲区，输入输出都用的这个
    RtlZeroMemory(output, sizeof(BREAKPOINT_RECORD));

    //分配明文缓存区
    BYTE* aucPlainText = allocate_pool<BYTE*>(user.uSize);
    DecryptData((PVOID)user.pUserData, aucPlainText);

    // 计算明文缓冲区中的结构体数量
    size_t numElements = user.uSize / sizeof(BREAKPOINT_RECORD);

    // 遍历明文缓冲区中的结构体
    for (size_t i = 0; i < numElements; i++)
    {
        PBREAKPOINT_RECORD pInfo = reinterpret_cast<PBREAKPOINT_RECORD>(aucPlainText + i * sizeof(BREAKPOINT_RECORD));

        if (AddHardwareBreakpoint(pInfo))
        {
            *output = *pInfo;
        }
        break;
    }
    free_pool(aucPlainText);
}

bool DeleteHardwareBreakpoint(PBREAKPOINT_RECORD Breakpoint)
{
    if (!Breakpoint || Breakpoint->watchid <= 0)
        return false;
    const NTSTATUS status = OphionMemoryBreakpointClear(
        static_cast<UINT64>(Breakpoint->watchid));
    if (!NT_SUCCESS(status))
    {
        outLog("Ophion memory breakpoint clear failed: 0x%08X", status);
    }
    return NT_SUCCESS(status);
}

//移除硬件断点
void RemoveHardwareBreakpoint(IN PUSER_DATA userData, IN PIRP pIrp)
{
    USER_DATA user = GetUserData(userData);

    DWORD* output = (DWORD*)pIrp->AssociatedIrp.SystemBuffer;  //内核的缓冲区，输入输出都用的这个
    RtlZeroMemory(output, sizeof(DWORD));

    //分配明文缓存区
    BYTE* aucPlainText = allocate_pool<BYTE*>(user.uSize);
    DecryptData((PVOID)user.pUserData, aucPlainText);

    // 计算明文缓冲区中的结构体数量
    size_t numElements = user.uSize / sizeof(BREAKPOINT_RECORD);

    // 遍历明文缓冲区中的结构体
    for (size_t i = 0; i < numElements; i++)
    {
        PBREAKPOINT_RECORD pInfo = reinterpret_cast<PBREAKPOINT_RECORD>(aucPlainText + i * sizeof(BREAKPOINT_RECORD));

        if (DeleteHardwareBreakpoint(pInfo))
        {
            *output = 1998;  //成功
        }
        else
        {
            *output = 520;   //失败
        }
        break;
    }
    free_pool(aucPlainText);
}

//添加软件断点
bool AddSoftwareBreakpoint(PVT_BREAK_POINT vmcallinfo)
{
    bool boSuccess = false;
    KAPC_STATE ApcState;
    PEPROCESS Process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)vmcallinfo->pid, &Process);
    if (NT_SUCCESS(status))
    {
        __try
        {
            KeStackAttachProcess(Process, &ApcState);
            *(volatile BYTE*)vmcallinfo->VirtualAddress;  //volatile关键字可以不被Release优化
            _disable(); //关中断
            vmcallinfo->cr3 = __readcr3();
            _enable();  //开中断
            boSuccess = current_vmcall(vmcallinfo);
            KeUnstackDetachProcess(&ApcState);
        }
        __except (1)
        {
            outLog("设置软件断点时崩溃了");
        }
        ObDereferenceObject(Process);
    }
    return boSuccess;
}

void SetSoftwareBreakpoint(IN PUSER_DATA userData, IN PIRP pIrp)
{
    USER_DATA user = GetUserData(userData);

    PVT_BREAK_POINT output = (PVT_BREAK_POINT)pIrp->AssociatedIrp.SystemBuffer;  //内核的缓冲区，输入输出都用的这个
    RtlZeroMemory(output, sizeof(VT_BREAK_POINT));

    //分配明文缓存区
    BYTE* aucPlainText = allocate_pool<BYTE*>(user.uSize);
    DecryptData((PVOID)user.pUserData, aucPlainText);

    // 计算明文缓冲区中的结构体数量
    size_t numElements = user.uSize / sizeof(VT_BREAK_POINT);

    // 遍历明文缓冲区中的结构体
    for (size_t i = 0; i < numElements; i++)
    {
        PVT_BREAK_POINT pInfo = reinterpret_cast<PVT_BREAK_POINT>(aucPlainText + i * sizeof(VT_BREAK_POINT));

        if (AddSoftwareBreakpoint(pInfo))
        {
            *output = *pInfo;
        }
        break;
    }
    free_pool(aucPlainText);
}

bool DeleteSoftwareBreakpoint(PVT_BREAK_POINT vmcallinfo)
{
    bool boSuccess = false;
    KAPC_STATE ApcState;
    PEPROCESS Process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)vmcallinfo->pid, &Process);
    if (NT_SUCCESS(status))
    {
        __try
        {
            KeStackAttachProcess(Process, &ApcState);
            *(volatile BYTE*)vmcallinfo->VirtualAddress;  //volatile关键字可以不被Release优化
            _disable(); //关中断
            vmcallinfo->cr3 = __readcr3();
            _enable();  //开中断
            boSuccess = current_vmcall(vmcallinfo);
            KeUnstackDetachProcess(&ApcState);
        }
        __except (1)
        {
            outLog("删除软件断点时崩溃了");
        }
        ObDereferenceObject(Process);
    }
    return boSuccess;
}

//移除软件断点
void RemoveSoftwareBreakpoint(IN PUSER_DATA userData, IN PIRP pIrp)
{
    USER_DATA user = GetUserData(userData);

    DWORD* output = (DWORD*)pIrp->AssociatedIrp.SystemBuffer;  //内核的缓冲区，输入输出都用的这个
    RtlZeroMemory(output, sizeof(DWORD));

    //分配明文缓存区
    BYTE* aucPlainText = allocate_pool<BYTE*>(user.uSize);
    DecryptData((PVOID)user.pUserData, aucPlainText);

    // 计算明文缓冲区中的结构体数量
    size_t numElements = user.uSize / sizeof(VT_BREAK_POINT);

    // 遍历明文缓冲区中的结构体
    for (size_t i = 0; i < numElements; i++)
    {
        PVT_BREAK_POINT pInfo = reinterpret_cast<PVT_BREAK_POINT>(aucPlainText + i * sizeof(VT_BREAK_POINT));

        if (DeleteSoftwareBreakpoint(pInfo))
        {
            *output = 1998;  //成功
        }
        else
        {
            *output = 520;   //失败
        }
        break;
    }
    free_pool(aucPlainText);
}

bool GetSoftwareBreakpoint(PVT_BREAK_POINT vmcallinfo)
{
    bool boSuccess = false;
    KAPC_STATE ApcState;
    PEPROCESS Process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)vmcallinfo->pid, &Process);
    if (NT_SUCCESS(status))
    {
        __try
        {
            KeStackAttachProcess(Process, &ApcState);
            *(volatile BYTE*)vmcallinfo->VirtualAddress;  //volatile关键字可以不被Release优化
            _disable(); //关中断
            vmcallinfo->cr3 = __readcr3();
            _enable();  //开中断
            boSuccess = current_vmcall(vmcallinfo);
            KeUnstackDetachProcess(&ApcState);
        }
        __except (1)
        {
            outLog("读软件断点时崩溃了");
        }
        ObDereferenceObject(Process);
    }
    if (boSuccess)
    {
        vmcallinfo->errorCode = 1998;
    }
    return boSuccess;
}

//读int3断点
void ReadSoftwareBreakpoint(IN PUSER_DATA userData, IN PIRP pIrp)
{
    USER_DATA user = GetUserData(userData);

    PVT_BREAK_POINT output = (PVT_BREAK_POINT)pIrp->AssociatedIrp.SystemBuffer;  //内核的缓冲区，输入输出都用的这个
    RtlZeroMemory(output, sizeof(VT_BREAK_POINT));

    //分配明文缓存区
    BYTE* aucPlainText = allocate_pool<BYTE*>(user.uSize);
    DecryptData((PVOID)user.pUserData, aucPlainText);

    // 计算明文缓冲区中的结构体数量
    size_t numElements = user.uSize / sizeof(VT_BREAK_POINT);

    // 遍历明文缓冲区中的结构体
    for (size_t i = 0; i < numElements; i++)
    {
        PVT_BREAK_POINT pInfo = reinterpret_cast<PVT_BREAK_POINT>(aucPlainText + i * sizeof(VT_BREAK_POINT));

        if (GetSoftwareBreakpoint(pInfo))
        {
            *output = *pInfo;  //成功
        }
        break;
    }
    free_pool(aucPlainText);
}

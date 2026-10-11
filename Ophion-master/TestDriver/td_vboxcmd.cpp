/*
*   td_vboxcmd.cpp - command-page manager for the VirtualBox defeat/v1 EPT
*   runtime control plane (taskbook T2 / review R-01).
*
*   The driver owns one locked, non-paged command page.  Every complex
*   request (CAPS_QUERY, DIAG_WALK, and later BP/TRACE/SPLIT/NX commands) is
*   written into that page and submitted through a single CPL0 VMCALL
*   (EPTHOOK_VMCALL_OP_EXEC_BUFFER).  The VMM copies request/response through
*   guest physical memory and never dereferences guest virtual addresses.
*
*   ABI mirrors include/VBox/vmm/EptHook.h - keep in sync.
*   Serialization: one FAST_MUTEX; a single driver instance must never have
*   two concurrent users of the command page.
*/

#include "td_common.h"

// ---- ABI mirror of include/VBox/vmm/EptHook.h ----
#define VBX_CMD_MAGIC           0x45484331UI64      /* 'EHC1' */
#define VBX_CMD_ABI_MAJOR       1
#define VBX_CMD_ABI_MINOR       0

#define VBX_OP_EXEC_BUFFER      4

#define VBX_CMD_CAPS_QUERY      1
#define VBX_CMD_DIAG_WALK       2

#pragma pack(push, 8)
typedef struct _VBX_CMD_HDR {
    UINT32 u32Magic;
    UINT16 u16AbiMajor;
    UINT16 u16AbiMinor;
    UINT32 cbRequest;
    UINT32 cbResponse;
    UINT32 uOperation;
    INT32  rc;
    UINT64 uRequestId;
    UINT64 uReserved;
} VBX_CMD_HDR;

typedef struct _VBX_CAPS_RESP {
    UINT32 fModes;
    UINT32 fFlags;
    UINT32 cMaxHooks;
    UINT32 cEventsPerCpu;
    UINT32 cbEvent;
    UINT32 uCmdAbiMajor;
    UINT32 uCmdAbiMinor;
    UINT32 u32Reserved;
} VBX_CAPS_RESP;

typedef struct _VBX_DIAG_REQ {
    VBX_CMD_HDR Hdr;
    UINT64 GCPhys;
    UINT32 u32Reserved;
    UINT32 u32Reserved1;
} VBX_DIAG_REQ;

typedef struct _VBX_DIAG_RESP {
    UINT64 auEntry[4];
    UINT32 fPresent;
    UINT32 fLarge;
    INT32  idHook;
    UINT32 uHookState;
    UINT32 uHookMode;
    UINT32 uHookGeneration;
    UINT32 cFires;
    UINT32 u32Reserved;
} VBX_DIAG_RESP;

static_assert(sizeof(VBX_CMD_HDR) == 40, "vbx hdr");
static_assert(sizeof(VBX_CAPS_RESP) == 32, "vbx caps");
static_assert(sizeof(VBX_DIAG_REQ) == 56, "vbx diag req");
static_assert(sizeof(VBX_DIAG_RESP) == 64, "vbx diag resp");
#pragma pack(pop)

static PVOID      g_vbxCmdPage = NULL;
static UINT64     g_vbxCmdGpa = 0;
static FAST_MUTEX g_vbxCmdMutex;
static BOOLEAN    g_vbxCmdInit = FALSE;

//
// Allocates and locks the command page.  Call once from DriverEntry; failure
// only disables the VBox plane features, never the driver.
//
NTSTATUS TdVbxCmdInit(VOID)
{
    if (g_vbxCmdInit)
        return STATUS_SUCCESS;
    ExInitializeFastMutex(&g_vbxCmdMutex);
    g_vbxCmdPage = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'CbxV');
    if (!g_vbxCmdPage)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(g_vbxCmdPage, PAGE_SIZE);
    g_vbxCmdGpa = (UINT64)MmGetPhysicalAddress(g_vbxCmdPage).QuadPart;
    if (!g_vbxCmdGpa || (g_vbxCmdGpa & 0xFFF))
    {
        ExFreePoolWithTag(g_vbxCmdPage, 'CbxV');
        g_vbxCmdPage = NULL;
        return STATUS_UNSUCCESSFUL;
    }
    g_vbxCmdInit = TRUE;
    HYPERPLATFORM_LOG_INFO("[td-vbx] command page at GPA %llx\n", g_vbxCmdGpa);
    return STATUS_SUCCESS;
}

VOID TdVbxCmdFini(VOID)
{
    if (g_vbxCmdPage)
    {
        ExFreePoolWithTag(g_vbxCmdPage, 'CbxV');
        g_vbxCmdPage = NULL;
    }
    g_vbxCmdGpa = 0;
    g_vbxCmdInit = FALSE;
}

BOOLEAN TdVbxCmdReady(VOID)
{
    return g_vbxCmdInit;
}

//
// Submits one command through the command page.  SEH-guarded: an absent or
// non-opted-in VMM answers with #UD, which becomes STATUS_NOT_SUPPORTED.
//
NTSTATUS TdVbxCmdSubmit(UINT32 uOperation, VOID const * payload, UINT32 cbPayload,
                        VOID * resp, UINT32 cbRespMax, UINT32 * pcbResp,
                        UINT32 * puVmmRc)
{
    if (!g_vbxCmdInit)
        return STATUS_DEVICE_NOT_READY;
    if (sizeof(VBX_CMD_HDR) + cbPayload > PAGE_SIZE)
        return STATUS_INVALID_PARAMETER;

    NTSTATUS st;
    UINT64 uReqId;
    static volatile LONG64 s_reqCounter;

    ExAcquireFastMutex(&g_vbxCmdMutex);
    __try {
        RtlZeroMemory(g_vbxCmdPage, PAGE_SIZE);
        VBX_CMD_HDR * pHdr = (VBX_CMD_HDR *)g_vbxCmdPage;
        pHdr->u32Magic   = (UINT32)VBX_CMD_MAGIC;
        pHdr->u16AbiMajor = VBX_CMD_ABI_MAJOR;
        pHdr->u16AbiMinor = VBX_CMD_ABI_MINOR;
        pHdr->cbRequest  = sizeof(VBX_CMD_HDR) + cbPayload;
        pHdr->uOperation = uOperation;
        pHdr->rc         = (INT32)0x7FFFFFFF;   /* VMM overwrites */
        uReqId = (UINT64)InterlockedIncrement64(&s_reqCounter);
        pHdr->uRequestId = uReqId;
        if (payload && cbPayload)
            RtlCopyMemory((UINT8 *)g_vbxCmdPage + sizeof(VBX_CMD_HDR), payload, cbPayload);

        UINT64 raw = 0;
        UINT64 res = 0;
        raw = TdVmcallEptAsm(VBX_OP_EXEC_BUFFER, g_vbxCmdGpa,
                             sizeof(VBX_CMD_HDR) + (UINT64)cbPayload,
                             uReqId, 0, &res);
        if (raw != 0)
        {
            st = STATUS_UNSUCCESSFUL;
            if (puVmmRc)
                *puVmmRc = (UINT32)raw;
        }
        else
        {
            VBX_CMD_HDR const * pOut = (VBX_CMD_HDR const *)g_vbxCmdPage;
            if (pOut->uRequestId != uReqId || pOut->rc != 0)
            {
                st = STATUS_UNSUCCESSFUL;
                if (puVmmRc)
                    *puVmmRc = (UINT32)pOut->rc;
            }
            else
            {
                st = STATUS_SUCCESS;
                UINT32 const cbOut = pOut->cbResponse;
                if (cbOut >= sizeof(VBX_CMD_HDR) && cbOut <= PAGE_SIZE)
                {
                    UINT32 cbPayloadOut = cbOut - sizeof(VBX_CMD_HDR);
                    if (cbPayloadOut > cbRespMax)
                        cbPayloadOut = 0;
                    if (resp && cbPayloadOut)
                        RtlCopyMemory(resp, (UINT8 const *)g_vbxCmdPage + sizeof(VBX_CMD_HDR),
                                      cbPayloadOut);
                    if (pcbResp)
                        *pcbResp = cbPayloadOut;
                }
                else if (pcbResp)
                {
                    *pcbResp = 0;
                }
                if (puVmmRc)
                    *puVmmRc = 0;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        st = STATUS_NOT_SUPPORTED;
        if (puVmmRc)
            *puVmmRc = 0xFFFFFFFF;
    }
    ExReleaseFastMutex(&g_vbxCmdMutex);
    return st;
}

//
// CAPS_QUERY wrapper: returns the VMM's advertised capabilities.
//
NTSTATUS TdVbxCapsQuery(VOID * pCapsRaw)
{
    VBX_CAPS_RESP * pCaps = (VBX_CAPS_RESP *)pCapsRaw;
    UINT32 cb = 0;
    UINT32 vmmRc = 0;
    NTSTATUS st = TdVbxCmdSubmit(VBX_CMD_CAPS_QUERY, NULL, 0,
                                 pCaps, sizeof(*pCaps), &cb, &vmmRc);
    if (NT_SUCCESS(st) && cb < sizeof(*pCaps))
        return STATUS_INVALID_PARAMETER;
    return st;
}

//
// DIAG_WALK wrapper: read-only EPT level walk for one page-aligned GPA.
//
NTSTATUS TdVbxDiagWalk(UINT64 GCPhys, VOID * pDiagRaw)
{
    VBX_DIAG_RESP * pDiag = (VBX_DIAG_RESP *)pDiagRaw;
    VBX_DIAG_REQ req;
    RtlZeroMemory(&req, sizeof(req));
    req.GCPhys = GCPhys;
    UINT32 cb = 0;
    UINT32 vmmRc = 0;
    /* F02: the payload starts AFTER the header on the wire - pass the GCPhys
       field itself, not the struct base (which would copy header bytes). */
    NTSTATUS st = TdVbxCmdSubmit(VBX_CMD_DIAG_WALK,
                                 (UINT8 *)&req + sizeof(VBX_CMD_HDR),
                                 sizeof(req) - sizeof(VBX_CMD_HDR),
                                 pDiag, sizeof(*pDiag), &cb, &vmmRc);
    if (NT_SUCCESS(st) && cb < sizeof(*pDiag))
        return STATUS_INVALID_PARAMETER;
    return st;
}

// =============================================================================
//  JUMP install/remove wrappers + per-process hook registration (T3)
//
//  Every successful INSTALL is registered with the owning PID so process
//  exit and driver unload can sweep leftovers.  Registration is bookkeeping
//  only - the VMM disarms oneshot hooks by itself when they fire.
// =============================================================================

#define VBX_HOOK_REG_MAX 32

typedef struct _VBX_HOOK_REG_ENTRY {
    UINT64 pid;
    UINT64 trig_gpa;
    BOOLEAN active;
} VBX_HOOK_REG_ENTRY;

static VBX_HOOK_REG_ENTRY g_vbxHooks[VBX_HOOK_REG_MAX];
static KSPIN_LOCK g_vbxHookLock;
static BOOLEAN g_vbxHookLockInit;
BOOLEAN g_fUseOphionPlane = FALSE;   /* A/B: default OFF = VBox plane. */

//
// INSTALL_JUMP through the register ABI (op 2 args: rdx=GPA page,
// rbx=GvaTrigger, rsi=cookie, rdi=GvaRedirect).  SEH-guarded.
//
NTSTATUS TdVbxJumpInstall(UINT64 trig_gpa, UINT64 gva_trigger, UINT64 cookie,
                          UINT64 gva_redirect)
{
    UINT64 raw = 0;
    UINT64 res = 0;
    __try {
        raw = TdVmcallEptAsm(1 /* INSTALL_JUMP */, trig_gpa, gva_trigger,
                             cookie, gva_redirect, &res);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_NOT_SUPPORTED;
    }
    return raw == 0 ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

//
// REMOVE_JUMP through the register ABI (op 2).
//
NTSTATUS TdVbxJumpRemove(UINT64 trig_gpa)
{
    UINT64 raw = 0;
    UINT64 res = 0;
    __try {
        raw = TdVmcallEptAsm(2 /* REMOVE_JUMP */, trig_gpa, 0, 0, 0, &res);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_NOT_SUPPORTED;
    }
    return raw == 0 ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

static VOID TdVbxHookLock(VOID)
{
    if (!g_vbxHookLockInit)
    {
        KeInitializeSpinLock(&g_vbxHookLock);
        g_vbxHookLockInit = TRUE;
    }
}

VOID TdVbxHookRegister(UINT64 pid, UINT64 trig_gpa)
{
    KIRQL irql;
    TdVbxHookLock();
    KeAcquireSpinLock(&g_vbxHookLock, &irql);
    for (UINT32 i = 0; i < VBX_HOOK_REG_MAX; i++)
    {
        if (!g_vbxHooks[i].active)
        {
            g_vbxHooks[i].pid = pid;
            g_vbxHooks[i].trig_gpa = trig_gpa;
            g_vbxHooks[i].active = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_vbxHookLock, irql);
}

VOID TdVbxHookUnregister(UINT64 pid, UINT64 trig_gpa)
{
    KIRQL irql;
    TdVbxHookLock();
    KeAcquireSpinLock(&g_vbxHookLock, &irql);
    for (UINT32 i = 0; i < VBX_HOOK_REG_MAX; i++)
    {
        if (g_vbxHooks[i].active && g_vbxHooks[i].pid == pid &&
            g_vbxHooks[i].trig_gpa == trig_gpa)
        {
            g_vbxHooks[i].active = FALSE;
            break;
        }
    }
    KeReleaseSpinLock(&g_vbxHookLock, irql);
}

//
// Sweeps every registered hook of one process (process-exit notification).
// CR3 never participates: this is an explicit REMOVE, not an auto-retire.
//
VOID TdVbxHookRemoveByPid(UINT64 pid)
{
    KIRQL irql;
    TdVbxHookLock();
    KeAcquireSpinLock(&g_vbxHookLock, &irql);
    for (UINT32 i = 0; i < VBX_HOOK_REG_MAX; i++)
    {
        if (g_vbxHooks[i].active && g_vbxHooks[i].pid == pid)
        {
            UINT64 gpa = g_vbxHooks[i].trig_gpa;
            g_vbxHooks[i].active = FALSE;
            KeReleaseSpinLock(&g_vbxHookLock, irql);
            TdVbxJumpRemove(gpa);
            KeAcquireSpinLock(&g_vbxHookLock, &irql);
        }
    }
    KeReleaseSpinLock(&g_vbxHookLock, irql);
}

VOID TdVbxHookRemoveAll(VOID)
{
    KIRQL irql;
    TdVbxHookLock();
    KeAcquireSpinLock(&g_vbxHookLock, &irql);
    for (UINT32 i = 0; i < VBX_HOOK_REG_MAX; i++)
    {
        if (g_vbxHooks[i].active)
        {
            UINT64 gpa = g_vbxHooks[i].trig_gpa;
            g_vbxHooks[i].active = FALSE;
            KeReleaseSpinLock(&g_vbxHookLock, irql);
            TdVbxJumpRemove(gpa);
            KeAcquireSpinLock(&g_vbxHookLock, &irql);
        }
    }
    KeReleaseSpinLock(&g_vbxHookLock, irql);
}

// =============================================================================
//  T4/T5: breakpoints, trace and event rings over the command page.
// =============================================================================

#pragma pack(push, 8)
typedef struct _VBX_BP_REQ {
    VBX_CMD_HDR Hdr;
    UINT64 GCPhys;
    UINT64 uCr3User;
    UINT64 uCr3Kernel;
    UINT32 offHook;
    UINT32 cbHook;
    UINT8  fAccess;
    UINT8  fFlags;
    UINT16 u16Reserved;
    UINT32 u32Reserved;
} VBX_BP_REQ;

typedef struct _VBX_BP_RESP {
    INT32  idHook;
    UINT32 uGeneration;
} VBX_BP_RESP;

typedef struct _VBX_BP_REMOVE_REQ {
    VBX_CMD_HDR Hdr;
    INT32  idHook;
    UINT32 uGeneration;
} VBX_BP_REMOVE_REQ;

typedef struct _VBX_EVENT_READ_REQ {
    VBX_CMD_HDR Hdr;
    UINT32 cMaxEvents;
    UINT32 u32Reserved;
} VBX_EVENT_READ_REQ;

typedef struct _VBX_EVENT_READ_HDR {
    UINT32 cEvents;
    UINT32 cDropped;
    UINT32 cRemaining;
    UINT32 u32Reserved;
} VBX_EVENT_READ_HDR;
#pragma pack(pop)

#define VBX_BP_ACCESS_READ      0x1
#define VBX_BP_ACCESS_WRITE     0x2
#define VBX_BP_ACCESS_EXECUTE   0x4
#define VBX_BP_F_ONESHOT        0x1
#define VBX_CMD_BP_INSTALL      3
#define VBX_CMD_BP_REMOVE       4
#define VBX_CMD_EVENT_READ      5
#define VBX_CMD_TRACE_START     6
#define VBX_CMD_TRACE_STOP      7
#define VBX_CMD_SPLIT_INSTALL   8
#define VBX_CMD_SPLIT_REMOVE    9

NTSTATUS TdVbxBpInstall(UINT64 GCPhysPage, UINT32 off, UINT32 cb, UINT32 access,
                        UINT32 fOneshot, UINT64 target_cr3, INT32 *pidHook, UINT32 *puGen)
{
    VBX_BP_REQ req;
    RtlZeroMemory(&req, sizeof(req));
    req.GCPhys = GCPhysPage;
    req.uCr3User = target_cr3;      /* KPTI: same value filters both views */
    req.uCr3Kernel = target_cr3;
    req.offHook = off;
    req.cbHook = cb;
    req.fAccess = (UINT8)access;
    req.fFlags = (UINT8)(fOneshot ? VBX_BP_F_ONESHOT : 0);

    VBX_BP_RESP resp = {};
    UINT32 cbResp = 0;
    UINT32 vmmRc = 0;
    // Persistent execute-only installs announce as TRACE_START so the VMM
    // marks the EPTHOOKEVENT stream as trace policy (T5).
    UINT32 const uOp = (access == VBX_BP_ACCESS_EXECUTE && !fOneshot)
                     ? VBX_CMD_TRACE_START : VBX_CMD_BP_INSTALL;
    NTSTATUS st = TdVbxCmdSubmit(uOp,
                                 (UINT8 *)&req + sizeof(VBX_CMD_HDR),
                                 sizeof(req) - sizeof(VBX_CMD_HDR),
                                 &resp, sizeof(resp), &cbResp, &vmmRc);
    if (NT_SUCCESS(st))
    {
        if (pidHook) *pidHook = resp.idHook;
        if (puGen) *puGen = resp.uGeneration;
    }
    return st;
}

NTSTATUS TdVbxBpRemove(INT32 idHook, UINT32 uGeneration)
{
    VBX_BP_REMOVE_REQ req;
    RtlZeroMemory(&req, sizeof(req));
    req.idHook = idHook;
    req.uGeneration = uGeneration;
    UINT32 vmmRc = 0;
    return TdVbxCmdSubmit(VBX_CMD_BP_REMOVE,
                          (UINT8 *)&req + sizeof(VBX_CMD_HDR),
                          sizeof(req) - sizeof(VBX_CMD_HDR),
                          NULL, 0, NULL, &vmmRc);
}

//
// Drains the event ring of every processor: pins the current thread to each
// CPU in turn and issues one EVENT_READ per CPU (the ring drains on the
// submitting EMT).  events[] receives packed 64-byte EPTHOOKEVENT records.
//
NTSTATUS TdVbxEventReadAll(UINT64 *pEvents, UINT32 cMaxEvents, UINT32 *pcEvents,
                           UINT32 *pcDropped, UINT32 *pcRemaining)
{
    if (!cMaxEvents) return STATUS_INVALID_PARAMETER;
    NTSTATUS stFinal = STATUS_SUCCESS;
    UINT32 cCopied = 0, cDropped = 0, cRemaining = 0;

    ULONG cCpus = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    for (ULONG idx = 0; idx < cCpus; ++idx)
    {
        GROUP_AFFINITY oldAff = {}, newAff = {}, *pOld = &oldAff;
        newAff.Group = (USHORT)(idx >= 64 ? 1 : 0);
        newAff.Mask = (KAFFINITY)1 << (idx & 63);
        KeSetSystemGroupAffinityThread(&newAff, pOld);

        VBX_EVENT_READ_REQ req;
        RtlZeroMemory(&req, sizeof(req));
        req.cMaxEvents = cMaxEvents - cCopied;

        UINT8 resp[PAGE_SIZE] = {};
        UINT32 cb = 0;
        UINT32 vmmRc = 0;
        NTSTATUS st = TdVbxCmdSubmit(VBX_CMD_EVENT_READ,
                                     (UINT8 *)&req + sizeof(VBX_CMD_HDR),
                                     sizeof(req) - sizeof(VBX_CMD_HDR),
                                     resp, sizeof(resp), &cb, &vmmRc);
        if (NT_SUCCESS(st) && cb >= sizeof(VBX_EVENT_READ_HDR))
        {
            VBX_EVENT_READ_HDR const * pHdr = (VBX_EVENT_READ_HDR const *)resp;
            cDropped += pHdr->cDropped;
            cRemaining += pHdr->cRemaining;
            UINT32 const cGot = pHdr->cEvents;
            /* F13: copy the full 64-byte EPTHOOKEVENT records - the old code
               kept only the sequence qword and dropped every other field. */
            for (UINT32 i = 0; i < cGot && cCopied < cMaxEvents; ++i)
            {
                RtlCopyMemory((UINT8 *)pEvents + (SIZE_T)cCopied * 64,
                              (UINT8 const *)(pHdr + 1) + (SIZE_T)i * 64,
                              64);
                ++cCopied;
            }
        }
        else if (!NT_SUCCESS(st) && NT_SUCCESS(stFinal))
            stFinal = st;

        KeRevertToUserGroupAffinityThread(pOld);
        if (cCopied >= cMaxEvents)
            break;
    }
    if (pcEvents) *pcEvents = cCopied;
    if (pcDropped) *pcDropped = cDropped;
    if (pcRemaining) *pcRemaining = cRemaining;
    return stFinal;
}

// =============================================================================
//  T6: runtime split-view (immutable code pages) over the command page.
// =============================================================================

#pragma pack(push, 8)
typedef struct _VBX_SPLIT_REQ {
    VBX_CMD_HDR Hdr;
    UINT64 GCPhys;
    UINT32 offHook;
    UINT32 cbHook;
    UINT8  abHook[64];
    UINT8  u8Reserved[8];
} VBX_SPLIT_REQ;
#pragma pack(pop)

//
// Installs an immutable split-view byte patch.  Any later guest write to the
// page invalidates the hook on every vCPU (VMM-side contract, R-03).
//
NTSTATUS TdVbxSplitInstall(UINT64 GCPhysPage, UINT32 off,
                           UINT8 const * pbBytes, UINT32 cbBytes,
                           INT32 *pidHook, UINT32 *puGeneration)
{
    if (!cbBytes || cbBytes > 64 || off + cbBytes > PAGE_SIZE)
        return STATUS_INVALID_PARAMETER;
    VBX_SPLIT_REQ req;
    RtlZeroMemory(&req, sizeof(req));
    req.GCPhys = GCPhysPage;
    req.offHook = off;
    req.cbHook = cbBytes;
    RtlCopyMemory(req.abHook, pbBytes, cbBytes);

    VBX_BP_RESP resp = {};
    UINT32 cbResp = 0;
    UINT32 vmmRc = 0;
    NTSTATUS st = TdVbxCmdSubmit(VBX_CMD_SPLIT_INSTALL,
                                 (UINT8 *)&req + sizeof(VBX_CMD_HDR),
                                 sizeof(req) - sizeof(VBX_CMD_HDR),
                                 &resp, sizeof(resp), &cbResp, &vmmRc);
    if (NT_SUCCESS(st))
    {
        if (pidHook) *pidHook = resp.idHook;
        if (puGeneration) *puGeneration = resp.uGeneration;
    }
    return st;
}

NTSTATUS TdVbxSplitRemove(INT32 idHook, UINT32 uGeneration)
{
    VBX_BP_REMOVE_REQ req;
    RtlZeroMemory(&req, sizeof(req));
    req.idHook = idHook;
    req.uGeneration = uGeneration;
    UINT32 vmmRc = 0;
    return TdVbxCmdSubmit(VBX_CMD_SPLIT_REMOVE,
                          (UINT8 *)&req + sizeof(VBX_CMD_HDR),
                          sizeof(req) - sizeof(VBX_CMD_HDR),
                          NULL, 0, NULL, &vmmRc);
}

// =============================================================================
//  T8: NX shadow (guest PTE NX + transient VMM flip on execution).
// =============================================================================

#pragma pack(push, 8)
typedef struct _VBX_NX_PAGE {
    UINT64 Gva;
    UINT64 GpaPte;
} VBX_NX_PAGE;

typedef struct _VBX_NX_REQ {
    VBX_CMD_HDR Hdr;
    UINT64 uCr3User;
    UINT64 uCr3Kernel;
    UINT32 cPages;
    UINT32 u32Reserved;
    VBX_NX_PAGE aPages[32];
} VBX_NX_REQ;

typedef struct _VBX_NX_RESP {
    UINT32 cPages;
    UINT32 fArmed;
    UINT64 cFlips;
} VBX_NX_RESP;
#pragma pack(pop)

#define VBX_CMD_NX_ADD     10
#define VBX_CMD_NX_REMOVE  11
#define VBX_CMD_NX_QUERY   12
#define VBX_NX_MAX_PAGES   32

//
// Arm NX hiding for up to 32 pages of one process.  The driver must supply
// the leaf-PTE guest-physical address of every page (walk the target CR3
// twice: page PTE and its own PTE) and re-arm whenever the process exits or
// the mappings change.
//
NTSTATUS TdVbxNxAdd(UINT64 target_cr3,
                    VBX_NX_PAGE const * pPages, UINT32 cPages,
                    UINT32 * pcArmed)
{
    if (!cPages || cPages > VBX_NX_MAX_PAGES || !pPages)
        return STATUS_INVALID_PARAMETER;
    VBX_NX_REQ req;
    RtlZeroMemory(&req, sizeof(req));
    req.uCr3User = target_cr3;
    req.uCr3Kernel = target_cr3;
    req.cPages = cPages;
    RtlCopyMemory(req.aPages, pPages, sizeof(VBX_NX_PAGE) * cPages);

    VBX_NX_RESP resp = {};
    UINT32 cbResp = 0;
    UINT32 vmmRc = 0;
    NTSTATUS st = TdVbxCmdSubmit(VBX_CMD_NX_ADD,
                                 (UINT8 *)&req + sizeof(VBX_CMD_HDR),
                                 sizeof(req) - sizeof(VBX_CMD_HDR),
                                 &resp, sizeof(resp), &cbResp, &vmmRc);
    if (NT_SUCCESS(st) && pcArmed)
        *pcArmed = resp.cPages;
    return st;
}

NTSTATUS TdVbxNxRemove(UINT32 * pcArmed)
{
    VBX_NX_RESP resp = {};
    UINT32 cbResp = 0;
    UINT32 vmmRc = 0;
    NTSTATUS st = TdVbxCmdSubmit(VBX_CMD_NX_REMOVE, NULL, 0,
                                 &resp, sizeof(resp), &cbResp, &vmmRc);
    if (NT_SUCCESS(st) && pcArmed)
        *pcArmed = resp.cPages;
    return st;
}

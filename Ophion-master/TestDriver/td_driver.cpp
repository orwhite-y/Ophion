#include "td_common.h"

// =========================================================================
//  driver entry / unload
// =========================================================================

PDEVICE_OBJECT g_dev_obj = NULL;
BOOLEAN g_device_hidden = FALSE;
fn_KeResumeThread g_pKeResumeThread = NULL;
fn_PsResumeThread  g_pPsResumeThread  = NULL;
BOOLEAN g_process_notify_registered = FALSE;
BOOLEAN g_process_notify_ex_registered = FALSE;

// ---- CMOS diagnostic readback (survives WHEA instant-kill) ----
// Ophion writes last-position markers to RTC NVRAM (port 0x70/0x71) in
// VMX-root. TestDriver reads them back at next boot to find crash position.
KTIMER          g_diag_timer;
KDPC            g_diag_dpc;
volatile LONG   g_diag_timer_active = 0;


// ---- Liveness check (named event, no vmcall) ----
// Ophion creates + signals this event after VMX init succeeds on all cores.
// TestDriver opens it read-only and checks state before any VMCALL.
// Name looks like a Windows sync primitive (WcsKsSync = a real Windows event).
static PKEVENT  g_alive_evt  = NULL;
static HANDLE   g_alive_h    = NULL;
#define TD_ALIVE_EVT_NAME L"\\BaseNamedObjects\\WcsKsSync"

VOID TdAliveInit(VOID)
{
    UNICODE_STRING nm = RTL_CONSTANT_STRING(TD_ALIVE_EVT_NAME);
    PKEVENT ev = IoCreateNotificationEvent(&nm, &g_alive_h);
    if (ev)
    {
        g_alive_evt = ev;
        // Do NOT signal here -- Ophion owns signaling. We just hold a handle.
        HYPERPLATFORM_LOG_INFO("[td] alive event opened: %p (state=%u)",
            ev, KeReadStateEvent(ev));
    }
    else
    {
        HYPERPLATFORM_LOG_WARN("[td] alive event open failed (Ophion not loaded?)");
    }
}

VOID TdAliveFini(VOID)
{
    if (g_alive_h)
    {
        ZwClose(g_alive_h);
        g_alive_h = NULL;
    }
    g_alive_evt = NULL;
}

BOOLEAN TdOphionAlive(VOID)
{
    // Quick check: if we never opened the event, Ophion is not loaded.
    if (!g_alive_evt)
        return FALSE;
    // KeReadStateEvent returns nonzero when signaled.
    return KeReadStateEvent(g_alive_evt) != 0;
}

// ---- CMOS raw read (no spinlock -- used at boot before VMX) ----
static UCHAR
TdCmosReadByte(UCHAR off)
{
    UCHAR v;
    __outbyte(0x70, (UCHAR)(off | 0x80));   // disable NMI, select offset
    v = __inbyte(0x71);
    __outbyte(0x70, 0x0D);                   // restore NMI
    return v;
}

// ---- DPC timer: poll VMX-root diag state every 500ms ----
// Logs counters to T.log. If WHEA kills the machine, the last few
// entries show the trajectory; CMOS has the exact last position.
static VOID NTAPI
TdDiagDpcRoutine(PKDPC dpc, PVOID deferred, PVOID sys1, PVOID sys2)
{
    UNREFERENCED_PARAMETER(dpc);
    UNREFERENCED_PARAMETER(deferred);
    UNREFERENCED_PARAMETER(sys1);
    UNREFERENCED_PARAMETER(sys2);

    TD_VMX_DIAG_SNAPSHOT snap;
    RtlZeroMemory(&snap, sizeof(snap));

    NTSTATUS st = hv_vmcall_ex(VMCALL_GET_DIAG_STATE,
                               (UINT64)&snap, 0, 0, 0, 0, 0, 0, 0, 0);
    if (NT_SUCCESS(st))
    {
        HYPERPLATFORM_LOG_WARN(
            "[diag] pf=%llu/%llu sw=%llu rej=%llu mid=%llu "
            "code_enter=%llu sync=%llu/%llu nomatch=%llu "
            "stale=%llu already=%llu cmos=0x%02X sp=%llu "
            "exit=0x%X cpu=%u rip=0x%llx",
            snap.pf_seen, snap.pf_allowed, snap.pf_switched,
            snap.pf_reject, snap.pf_midwin,
            snap.code_enter, snap.code_synced, snap.data_synced,
            snap.nomatch, snap.stale_p1, snap.already_on_shadow,
            (UCHAR)snap.cmos_value, snap.stealth_page_count,
            snap.exit_reason, snap.cpu, snap.vmx_rip);
    }
}

VOID TdUnload(PDRIVER_OBJECT drv)
{
    // ---- Stop diag DPC timer ----
    g_diag_timer_active = 0;
    KeCancelTimer(&g_diag_timer);
    KeFlushQueuedDpcs();

    TdAliveFini();
    TdMemCacheFini();

    if (g_process_notify_registered)
    {
        if (g_process_notify_ex_registered)
            PsSetCreateProcessNotifyRoutineEx(TdProcessNotify, TRUE);
        else
            PsSetCreateProcessNotifyRoutine(TdProcessNotifyLegacy, TRUE);
        g_process_notify_registered = FALSE;
        g_process_notify_ex_registered = FALSE;
    }

    // [瀹歌尙顩﹂悽鈺?娑撳秴鍟€闁俺绻?LoadImage 閸ョ偠鐨熷▔銊ュ弳 renderdoc閿涘本鏁兼稉?NtCreateFile hook 鐟欙箑褰?
    //if (g_loadimage_registered)
    //{
    //    PsRemoveLoadImageNotifyRoutine(TdLoadImageNotify);
    //    g_loadimage_registered = FALSE;
    //}

    if (g_hooked_target)
    {
        HYPERPLATFORM_LOG_INFO("[td] Unhooking R0 hook before unload...");
        TdEptUnhookNtCreateFile();
    }

    TdEptUnhookAllR3();

    if (!g_device_hidden)
    {
        UNICODE_STRING sym;
        RtlInitUnicodeString(&sym, TD_SYMLINK_NAME);
        IoDeleteSymbolicLink(&sym);
        if (drv->DeviceObject) IoDeleteDevice(drv->DeviceObject);
    }

    HYPERPLATFORM_LOG_INFO("[td] Unloaded (device_hidden=%u).", g_device_hidden);
    LogTermination();
}

extern "C"
// DKOM: unlink this driver from PsLoadedModuleList so EnumDeviceDrivers /
// NtQuerySystemInformation(SystemModuleInformation) can't enumerate it.
// DriverObject->DriverSection points to the kernel LDR_DATA_TABLE_ENTRY.
// Links are set to self after unlinking so RemoveEntryList on unload is a
// no-op (safe). Must be called AFTER all init (MmGetSystemRoutineAddress,
// IoCreateDevice, etc.) so those APIs find the driver while it's set up.
#ifndef TD_HIDE_DRIVER
#define TD_HIDE_DRIVER 0
#endif
#if TD_HIDE_DRIVER
VOID TdHideFromPsLoadedModuleList(PDRIVER_OBJECT drv)
{
    PTD_LDR_ENTRY ldr = (PTD_LDR_ENTRY)drv->DriverSection;
    if (!ldr) return;
    // PsLoadedModuleList links kernel modules ONLY via InLoadOrderLinks.
    // InMemoryOrderLinks / InInitializationOrderLinks are NOT initialized by
    // MiLoadSystemImage for kernel modules - they hold stale pool data, so
    // unlinking them dereferences garbage and BSODs. Only unlink
    // InLoadOrderLinks, then self-link so RemoveEntryList on unload is a no-op.
    PLIST_ENTRY e = &ldr->InLoadOrderLinks;          // PsLoadedModuleList
    e->Blink->Flink = e->Flink; e->Flink->Blink = e->Blink;
    e->Flink = e; e->Blink = e;
}
#endif

NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg)
{
    UNREFERENCED_PARAMETER(reg);
    KeInitializeSpinLock(&g_shadow_alloc_lock);
    KeInitializeSpinLock(&g_stealth_track_lock);
    KeInitializeSpinLock(&g_inject_target_lock);
    g_inject_target_lock_init = TRUE;
    KeInitializeSpinLock(&g_SelfPeInfoLock);
    g_SelfPeInfoLockInit = TRUE;

    //
    // init log system 闁?file output, truncate on load
    //
    static const wchar_t kLogFilePath[] = L"\\SystemRoot\\T.log";
    auto log_status = LogInitialization(kLogPutLevelWarn, kLogFilePath);
    if (log_status == STATUS_REINITIALIZATION_NEEDED)
        LogRegisterReinitialization(drv);

    UNICODE_STRING fn;
    // try NtCreateThreadEx first (more likely exported), then ZwCreateThreadEx
    RtlInitUnicodeString(&fn, L"NtCreateThreadEx");
    g_pZwCreateThreadEx = (fn_ZwCreateThreadEx)MmGetSystemRoutineAddress(&fn);
    if (!g_pZwCreateThreadEx)
    {
        RtlInitUnicodeString(&fn, L"ZwCreateThreadEx");
        g_pZwCreateThreadEx = (fn_ZwCreateThreadEx)MmGetSystemRoutineAddress(&fn);
    }
    // resolve ZwResumeThread via MmGetSystemRoutineAddress (exported)
    RtlInitUnicodeString(&fn, L"NtResumeThread");
    g_pZwResumeThread = (fn_ZwResumeThread)MmGetSystemRoutineAddress(&fn);
    if (!g_pZwResumeThread)
    {
        RtlInitUnicodeString(&fn, L"ZwResumeThread");
        g_pZwResumeThread = (fn_ZwResumeThread)MmGetSystemRoutineAddress(&fn);
    }
    if (!g_pZwResumeThread)
        g_pZwResumeThread = (fn_ZwResumeThread)TdResolveNtoskrnlExport("NtResumeThread");
    if (!g_pZwResumeThread)
        g_pZwResumeThread = (fn_ZwResumeThread)TdResolveNtoskrnlExport("ZwResumeThread");

    // resolve PsResumeThread and KeResumeThread via ntoskrnl export table walk
    // (Blackbone-style 闁?these are not in MmGetSystemRoutineAddress's table)
    g_pPsResumeThread = (fn_PsResumeThread)TdResolveNtoskrnlExport("PsResumeThread");
    g_pKeResumeThread = (fn_KeResumeThread)TdResolveNtoskrnlExport("KeResumeThread");

    HYPERPLATFORM_LOG_INFO("[td] thread APIs: create=%p zw_resume=%p ps_resume=%p ke_resume=%p",
        g_pZwCreateThreadEx, g_pZwResumeThread, g_pPsResumeThread, g_pKeResumeThread);

    // prefetch read cache (64 KB batch vmcall) - must be ready before IOCTLs
    TdMemCacheInit();

    // Open liveness event + check if Ophion VMX is active.
    // If Ophion is not loaded / VMX not active, refuse to load TestDriver:
    // all memory IOCTLs require VMCALL, so loading without Ophion is useless
    // and risks #UD BSOD (HvlpVtlCallExceptionHandler bypasses SEH on VBS).
    TdAliveInit();
    if (!TdOphionAlive())
    {
        HYPERPLATFORM_LOG_ERROR("[td] Ophion not active -- refusing to load TestDriver");
        TdAliveFini();
        TdMemCacheFini();
        return (NTSTATUS)0xC0000362;  // STATUS_FAILED_DRIVER_ENTRY
    }
    HYPERPLATFORM_LOG_INFO("[td] Ophion alive -- TestDriver loading with VMX support");

    // ---- CMOS crash-position readback ----
    // Ophion writes last VMX-root position to RTC NVRAM before WHEA kills.
    // Read it back here to find where the crash happened.
    {
        UCHAR cm_magic = TdCmosReadByte(0x50);
        UCHAR cm_val   = TdCmosReadByte(0x51);
        UCHAR cm_match = TdCmosReadByte(0x52);
        UCHAR cm_trig  = TdCmosReadByte(0x53);
        UINT32 cm_streak = 0;
        UINT64 cm_reinj_addr = 0;
        for (int i = 0; i < 4; i++)
            cm_streak |= (UINT32)TdCmosReadByte((UCHAR)(0x54 + i)) << (i * 8);
        for (int i = 0; i < 8; i++)
            cm_reinj_addr |= (UINT64)TdCmosReadByte((UCHAR)(0x58 + i)) << (i * 8);

        HYPERPLATFORM_LOG_WARN(
            "[td-cmos] PREV-CRASH: magic=0x%02X val=0x%02X match=%u trig=%u "
            "reinj_streak=%u reinj_addr=0x%llx",
            cm_magic, cm_val, cm_match, cm_trig, cm_streak, cm_reinj_addr);

        // Per-CPU markers (0x60-0x73)
        for (int cpu = 0; cpu < 20; cpu++)
        {
            UCHAR pv = TdCmosReadByte((UCHAR)(0x60 + cpu));
            if (pv)
                HYPERPLATFORM_LOG_WARN("[td-cmos] cpu%d=0x%02X", cpu, pv);
        }

        // Preserved crash marker (0x74-0x7F, saved by Ophion before VMX init)
        UCHAR pm_magic = TdCmosReadByte(0x74);
        UCHAR pm_val   = TdCmosReadByte(0x75);
        if (pm_magic == 0xA5 && pm_val != 0)
        {
            UINT32 pm_streak = 0;
            UINT64 pm_addr = 0;
            for (int i = 0; i < 4; i++)
                pm_streak |= (UINT32)TdCmosReadByte((UCHAR)(0x76 + i)) << (i * 8);
            for (int i = 0; i < 6; i++)
                pm_addr |= (UINT64)TdCmosReadByte((UCHAR)(0x7A + i)) << (i * 8);
            HYPERPLATFORM_LOG_WARN(
                "[td-cmos] PRESERVED-CRASH: val=0x%02X reinj_streak=%u reinj_addr=0x%llx",
                pm_val, pm_streak, pm_addr);
        }
    }

    // ---- DPC timer: poll VMX-root diag state every 500ms ----
    KeInitializeTimer(&g_diag_timer);
    KeInitializeDpc(&g_diag_dpc, TdDiagDpcRoutine, NULL);
    g_diag_timer_active = 1;
    LARGE_INTEGER due;
    due.QuadPart = -500 * 10000LL;   // 500ms relative
    KeSetTimerEx(&g_diag_timer, due, 500, &g_diag_dpc);  // 500ms period
    HYPERPLATFORM_LOG_INFO("[td] diag DPC timer started (500ms period)");


    UNICODE_STRING dev_name, sym_name;
    RtlInitUnicodeString(&dev_name, TD_DEVICE_NAME);
    RtlInitUnicodeString(&sym_name, TD_SYMLINK_NAME);

    PDEVICE_OBJECT dev = NULL;
    NTSTATUS st = IoCreateDevice(drv, 0, &dev_name,
        FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &dev);
    if (!NT_SUCCESS(st)) return st;
    g_dev_obj = dev;

    st = IoCreateSymbolicLink(&sym_name, &dev_name);
    if (!NT_SUCCESS(st)) { IoDeleteDevice(dev); return st; }

    drv->DriverUnload = TdUnload;
    drv->MajorFunction[IRP_MJ_CREATE] = TdCreateClose;
    drv->MajorFunction[IRP_MJ_CLOSE]  = TdCreateClose;
    drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = TdIoControl;

    //
    // register process exit notification for stealth page cleanup.
    // prevents BSOD in MiDeleteFinalPageTables when fake PT is active.
    //
    NTSTATUS notify_st = PsSetCreateProcessNotifyRoutineEx(TdProcessNotify, FALSE);
    if (NT_SUCCESS(notify_st))
    {
        g_process_notify_registered = TRUE;
        g_process_notify_ex_registered = TRUE;
        HYPERPLATFORM_LOG_INFO("[td] Process notify callback registered (Ex).");
    }
    else
    {
        HYPERPLATFORM_LOG_WARN("[td] PsSetCreateProcessNotifyRoutineEx failed: 0x%08X", notify_st);
        NTSTATUS legacy_st = PsSetCreateProcessNotifyRoutine(TdProcessNotifyLegacy, FALSE);
        if (NT_SUCCESS(legacy_st))
        {
            g_process_notify_registered = TRUE;
            g_process_notify_ex_registered = FALSE;
            HYPERPLATFORM_LOG_INFO("[td] Process notify callback registered (legacy).");
        }
        else
        {
            HYPERPLATFORM_LOG_ERROR("[td] PsSetCreateProcessNotifyRoutine legacy failed: 0x%08X", legacy_st);
        }
    }

    // [瀹稿弶鏁為柌濂?娑撳秴鍟€娴ｈ法鏁?LoadImage 闁氨鐓″▔銊ュ弳 renderdoc閿涘本鏁兼稉?HookedNtCreateFile 鐟欙箑褰?
    //if (g_process_notify_registered)
    //{
    //    NTSTATUS li_st = PsSetLoadImageNotifyRoutine(TdLoadImageNotify);
    //    if (NT_SUCCESS(li_st))
    //    {
    //        g_loadimage_registered = TRUE;
    //        HYPERPLATFORM_LOG_INFO("[td] LoadImage notify registered (driver-side injection armed).");
    //    }
    //}

    // 閼奉亜濮╃€瑰顥?NtCreateFile EPT hook閿涘牅绗夐崘宥勭贩鐠?Injector 閸?IOCTL閿?
    //{
    //    //NTSTATUS hook_st = TdEptHookNtCreateFile();
    //    if (NT_SUCCESS(hook_st))
    //        HYPERPLATFORM_LOG_INFO("[td] NtCreateFile EPT hook installed (CreateFile(\"test\") triggers renderdoc inject).");
    //    else
    //        HYPERPLATFORM_LOG_WARN("[td] NtCreateFile EPT hook failed: 0x%08X (manual IOCTL may be needed)", hook_st);
    //}
    //    NTSTATUS li_st = PsSetLoadImageNotifyRoutine(TdLoadImageNotify);
    //    if (NT_SUCCESS(li_st))
    //    {
    //        g_loadimage_registered = TRUE;
    //        HYPERPLATFORM_LOG_INFO("[td] LoadImage notify registered (driver-side injection armed).");
    //    }
    //}


#if TD_HIDE_DRIVER
    // DKOM: hide this driver from PsLoadedModuleList (after all init).
    TdHideFromPsLoadedModuleList(drv);
#endif

    HYPERPLATFORM_LOG_INFO("[td] Loaded. Device: %wZ", &sym_name);
    return STATUS_SUCCESS;
}

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

VOID TdUnload(PDRIVER_OBJECT drv)
{
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
    auto log_status = LogInitialization(kLogPutLevelDebug, kLogFilePath);
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

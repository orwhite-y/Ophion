/*
*   driver.c - Ophion hypervisor kernel driver
*   pure hypervisor — no IOCTL, no device object.
*   all communication via VMCALL from other kernel drivers.
*/
#include "hv.h"
#include "log.h"

VOID
DriverUnload(_In_ PDRIVER_OBJECT driver_obj)
{
    UNREFERENCED_PARAMETER(driver_obj);
    HYPERPLATFORM_LOG_INFO("[hv] Unloading hypervisor driver...");

    ept_stealth_free_all_broadcast();
    ept_stealth_region_destroy();
    broadcast_terminate_all();
    vmx_terminate();

    HYPERPLATFORM_LOG_INFO("[hv] Driver unloaded.");
    LogTermination();
}

// DKOM: unlink this driver from PsLoadedModuleList (same technique as
// test_driver's TdHideFromPsLoadedModuleList, with a local minimal LDR struct).
#ifndef HV_HIDE_DRIVER
#define HV_HIDE_DRIVER 1
#endif
#if HV_HIDE_DRIVER
typedef struct _HV_LDR_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
} HV_LDR_ENTRY;

static VOID HvHideFromPsLoadedModuleList(PDRIVER_OBJECT drv)
{
    HV_LDR_ENTRY* ldr = (HV_LDR_ENTRY*)drv->DriverSection;
    if (!ldr) return;
    // PsLoadedModuleList links kernel modules ONLY via InLoadOrderLinks.
    // InMemoryOrderLinks / InInitializationOrderLinks are NOT initialized by
    // MiLoadSystemImage for kernel modules - they contain stale pool data
    // (freelist pointers), so unlinking them dereferences garbage and BSODs
    // (seen: InMemoryOrderLinks.Blink == 0x720 -> AV write at +0).
    // Only unlink InLoadOrderLinks, then self-link it so a later
    // RemoveEntryList (e.g. on unload) is a no-op.
    PLIST_ENTRY e = &ldr->InLoadOrderLinks;
    e->Blink->Flink = e->Flink; e->Flink->Blink = e->Blink;
    e->Flink = e; e->Blink = e;
}
#endif

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  driver_obj,
    _In_ PUNICODE_STRING registry_path)
{
    UNREFERENCED_PARAMETER(registry_path);

    //
    // init log system — buffer-based, safe for VMX-root via _SAFE macros
    //
    static const wchar_t kLogFilePath[] = L"\\SystemRoot\\O.log";
    auto log_status = LogInitialization(kLogPutLevelDebug, kLogFilePath);
    BOOLEAN log_reinit_needed = FALSE;
    if (log_status == STATUS_REINITIALIZATION_NEEDED)
        log_reinit_needed = TRUE;
    else if (!NT_SUCCESS(log_status))
        return log_status;

    HYPERPLATFORM_LOG_INFO("[hv] Ophion initializing...");

    driver_obj->DriverUnload = DriverUnload;

    if (!vmx_init())
    {
        HYPERPLATFORM_LOG_ERROR("[hv] VMX initialization FAILED!");
        broadcast_terminate_all();
        vmx_terminate();
        LogTermination();
        return STATUS_HV_OPERATION_FAILED;
    }

    if (ept_stealth_region_init())
        HYPERPLATFORM_LOG_INFO("[hv] Stealth region initialized.");
    else
        HYPERPLATFORM_LOG_WARN("[hv] Stealth region init failed (stealth features disabled).");

    if (log_reinit_needed)
        LogRegisterReinitialization(driver_obj);

#if HV_HIDE_DRIVER
    // DKOM: hide this driver from PsLoadedModuleList (after all init).
    HvHideFromPsLoadedModuleList(driver_obj);
#endif

    HYPERPLATFORM_LOG_INFO("[hv] Hypervisor loaded and active on all cores!");
    return STATUS_SUCCESS;
}

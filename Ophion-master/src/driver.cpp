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

    HYPERPLATFORM_LOG_INFO("[hv] Hypervisor loaded and active on all cores!");
    return STATUS_SUCCESS;
}

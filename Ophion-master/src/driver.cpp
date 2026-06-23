/*
*   driver.c - Ophion hypervisor kernel driver
*   pure hypervisor — no IOCTL, no device object.
*   all communication via VMCALL from other kernel drivers.
*/
#include "hv.h"

VOID
DriverUnload(_In_ PDRIVER_OBJECT driver_obj)
{
    UNREFERENCED_PARAMETER(driver_obj);
    DbgPrintEx(0, 0, "[hv] Unloading hypervisor driver...\n");

    ept_stealth_free_all_broadcast();
    ept_stealth_region_destroy();
    broadcast_terminate_all();
    vmx_terminate();

    DbgPrintEx(0, 0, "[hv] Driver unloaded.\n");
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  driver_obj,
    _In_ PUNICODE_STRING registry_path)
{
    UNREFERENCED_PARAMETER(registry_path);
    DbgPrintEx(0, 0, "[hv] Ophion initializing...\n");

    driver_obj->DriverUnload = DriverUnload;

    if (!vmx_init())
    {
        DbgPrintEx(0, 0, "[hv] VMX initialization FAILED!\n");
        vmx_terminate();
        return STATUS_HV_OPERATION_FAILED;
    }

    if (ept_stealth_region_init())
        DbgPrintEx(0, 0, "[hv] Stealth region initialized.\n");
    else
        DbgPrintEx(0, 0, "[hv] Stealth region init failed (stealth features disabled).\n");

    DbgPrintEx(0, 0, "[hv] Hypervisor loaded and active on all cores!\n");
    return STATUS_SUCCESS;
}

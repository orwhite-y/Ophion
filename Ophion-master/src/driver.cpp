/*
*   driver.c - Ophion hypervisor kernel driver
*   pure hypervisor — no IOCTL, no device object.
*   all communication via VMCALL from other kernel drivers.
*/
#include "hv.h"
#include "log.h"
#include <ntstrsafe.h>

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
#define HV_HIDE_DRIVER 0
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

// Write the WEDGE readback string to \SystemRoot\W.log via direct file I/O.
// (Bypasses the log system + DbgPrint: the RAM log buffer is lost on reset, and
//  DbgPrint is intercepted in this env.) Returns TRUE on success so the caller
// clears the CMOS marker only after the write lands - a write failure preserves
// the marker for the next boot's retry.
static BOOLEAN wedge_write_wlog(const char *buf, SIZE_T len)
{
    UNICODE_STRING path = RTL_CONSTANT_STRING(L"\\SystemRoot\\W.log");
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &path,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    IO_STATUS_BLOCK iosb = {};
    HANDLE h = NULL;
    NTSTATUS st = ZwCreateFile(&h, FILE_GENERIC_WRITE, &oa, &iosb,
        NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
    if (!NT_SUCCESS(st) || !h)
        return FALSE;
    LARGE_INTEGER off = { 0 };
    NTSTATUS wst = ZwWriteFile(h, NULL, NULL, NULL, &iosb, (PVOID)buf, (ULONG)len, &off, NULL);
    ZwClose(h);
    return NT_SUCCESS(wst);
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

    //
    // WEDGE readback: if the previous boot ended in a triple-fault reset during
    // wedge investigation, the CMOS marker (set by wedge_cmos_mark at each WEDGE
    // point in the post-trigger VT path) holds the LAST point reached before the
    // reset. This is the only signal that survives a reset (the RAM log buffer is
    // lost). Write it to \SystemRoot\W.log via direct file I/O (bypasses the log
    // system + DbgPrint, both unusable here), then clear the marker. Runs before
    // vmx_init so it executes even when VMX fails. At PASSIVE -> ZwWriteFile safe.
    //
    {
        UCHAR wm = 0, wv = 0;
        wedge_cmos_read(&wm, &wv);
        UCHAR wms = wedge_cmos_read_match_seen();  // sticky: did a stealth match happen this run?
        UCHAR wts = wedge_cmos_read_trig_seen();   // sticky: did the injection trigger fire this run?
        UINT32 wrc = 0; UINT64 wra = 0;
        wedge_cmos_read_reinj(&wrc, &wra);  // reinject livelock probe (streak + fault VA)

        // per-CPU last-VM-exit bytes (0x60..0x7F). Show which handler each CPU was
        // last in, breaking the #PF-storm masking that made the single global marker
        // always read 0x0d (last #PF). Non-zero per-CPU on a wedge boot = fresh data
        // (HV ran + handled VM-exits); all-zero = no VM-exits (clean boot, game didn't
        // run, or VMX didn't init). boot counter removed: 0x40-0x43 is BIOS-used.
        char pbuf[160];
        pbuf[0] = 0;
        for (UINT32 i = 0; i < 32; i++)
        {
            char b[8];
            RtlStringCbPrintfA(b, sizeof(b), "%02x ", wedge_cmos_read_percpu(i));
            RtlStringCbCatA(pbuf, sizeof(pbuf), b);
        }

        char wbuf[512];
        if (wm == WEDGE_CMOS_MAGIC)
        {
            static const char *wn[] = {
                /*00*/ "(none)", "A-trig-fire", "B-pf-entry", "C-heal-enter",
                /*04*/ "D-post-enter-cr3", "E-pre-walk", "E2-post-walk", "(rsv7)",
                /*08*/ "(rsv8)", "(rsv9)", "B0-pre-lookup", "B1-match",
                /*0C*/ "B2-pre-heal", "BN-nomatch", "REINJ", "TF-guest-loop",
                /*10*/ "S1-pre-vmxinit", "S2-vmx-on", "S3-ept-done", "S4-ready",
                /*14*/ "(rsv14)", "(rsv15)", "(rsv16)", "(rsv17)",
                /*18*/ "(rsv18)", "(rsv19)", "(rsv1A)", "(rsv1B)",
                /*1C*/ "(rsv1C)", "(rsv1D)", "S-ept-fail", "S-vmx-fail"
            };
            const char *nm = (wv < sizeof(wn)/sizeof(wn[0])) ? wn[wv] : "(unknown)";
            RtlStringCbPrintfA(wbuf, sizeof(wbuf),
                "[WEDGE-LAST] marker=0x%02x -> %s match_seen=%d trig_seen=%d reinj_streak=%lu reinj_addr=0x%I64x\r\n"
                "[WEDGE-PERCPU] %s(cpu0..cpu31 | 8E=#PF 8D=#GP 86=#UD | +0x40=stuck-in-handler | VMCALL-only: E0=hook E1=stealth E2=CPL E3=switch | else=completed)\r\n",
                (ULONG)wv, nm, (ULONG)wms, (ULONG)wts, (ULONG)wrc, wra, pbuf);
        }
        else
        {
            RtlStringCbPrintfA(wbuf, sizeof(wbuf),
                "[WEDGE-LAST] no marker (magic=0x%02x) match_seen=%d trig_seen=%d reinj_streak=%lu reinj_addr=0x%I64x\r\n"
                "[WEDGE-PERCPU] %s(cpu0..cpu31 | 8E=#PF 8D=#GP 86=#UD | +0x40=stuck-in-handler | VMCALL-only: E0=hook E1=stealth E2=CPL E3=switch | else=completed)\r\n",
                (ULONG)wm, (ULONG)wms, (ULONG)wts, (ULONG)wrc, wra, pbuf);
        }
        // Write W.log FIRST; clear the CMOS only after a successful write, so a write
        // failure (rare) preserves the data for the next boot's retry. Always clear on
        // success (incl. reinj probe + per-CPU) so each boot starts fresh.
        if (wedge_write_wlog(wbuf, strlen(wbuf)))
            wedge_cmos_clear();
    }

    // WEDGE setup-phase marks (0x10..0x13, +0x1E/0x1F failures). Pins down WHERE a
    // freeze happens when no VM-exit is recorded (per-CPU all-00 + magic=0x00 meant
    // no wedge_cmos_mark ever ran -- couldn't tell "VMX never came up" from "VMX up
    // but hung in setup before any VM-exit"). wedge_cmos_mark sets magic too, so after
    // the first phase mark the readback takes the marker= branch instead of no-marker.
    //   0x10 about-to-vmx_init | 0x11 VMX-on | 0x12 EPT-done | 0x13 ready
    //   0x1E EPT-fail(non-fatal) | 0x1F vmx_init FAILED
    wedge_cmos_mark(0x10);

    if (!vmx_init())
    {
        HYPERPLATFORM_LOG_ERROR("[hv] VMX initialization FAILED!");
        wedge_cmos_mark(0x1F);
        broadcast_terminate_all();
        vmx_terminate();
        LogTermination();
        return STATUS_HV_OPERATION_FAILED;
    }

    wedge_cmos_mark(0x11);  // VMX is ON

    if (ept_stealth_region_init())
    {
        HYPERPLATFORM_LOG_INFO("[hv] Stealth region initialized.");
        wedge_cmos_mark(0x12);
    }
    else
    {
        HYPERPLATFORM_LOG_WARN("[hv] Stealth region init failed (stealth features disabled).");
        wedge_cmos_mark(0x1E);
    }

    if (log_reinit_needed)
        LogRegisterReinitialization(driver_obj);

#if HV_HIDE_DRIVER
    // DKOM: hide this driver from PsLoadedModuleList (after all init).
    HvHideFromPsLoadedModuleList(driver_obj);
#endif

    wedge_cmos_mark(0x13);  // HV fully ready

    HYPERPLATFORM_LOG_INFO("[hv] Hypervisor loaded and active on all cores!");
    return STATUS_SUCCESS;
}

/*
*   driver.c - Ophion hypervisor kernel driver
*   pure hypervisor 闂?no IOCTL, no device object.
*   all communication via VMCALL from other kernel drivers.
*/
#include "hv.h"
#include "log.h"
#include <ntstrsafe.h>

//
// PID -> kernel CR3 cache. populated by PsSetCreateProcessNotifyRoutine +
// initial enumeration at DriverEntry. read lock-free from VMX-root (kernel
// space, mapped under the private host CR3). writes are spinlocked (R0 only).
//
// EPROCESS.DirectoryTableBase = kernel CR3 (full mapping incl. user half).
// stable at 0x28 on Win10/11 x64.
//
#define EPROCESS_DIRTABLEBASE  0x28
#define HV_PID_CR3_MAX         4096
#define HV_MAX_CPUS            256
#define HV_SCRATCH_SIZE        HV_R3_MEM_MAX   // 4096 (must match VMCALL_MEM_REQUEST.data)

#ifndef STATUS_SOME_NOT_MAPPED
#define STATUS_SOME_NOT_MAPPED ((NTSTATUS)0x00000107L)
#endif

typedef struct _HV_PID_CR3_ENTRY {
    volatile HANDLE  pid;
    volatile UINT64  cr3;
} HV_PID_CR3_ENTRY;

static HV_PID_CR3_ENTRY g_pid_cr3_table[HV_PID_CR3_MAX];
static KSPIN_LOCK       g_pid_cr3_lock;
static PUCHAR           g_scratch[HV_MAX_CPUS];
static BOOLEAN          g_vmx_active = FALSE;

// self-map index: PML4[S] points to PML4 itself. found at PASSIVE_LEVEL by
// scanning the System PML4 for a self-referencing entry. used by hv_walk_va
// in VMX-root to read PTEs through the self-map (lock-free, no pa_to_va).
volatile UINT32         g_self_map_index = 0xFFFFFFFF;  // invalid until init

// forward declarations (defined after wedge_write_wlog, used in DriverUnload)
static NTSTATUS hv_pid_cr3_init(VOID);
static VOID     hv_pid_cr3_fini(VOID);
static NTSTATUS hv_scratch_init(VOID);
static VOID     hv_scratch_fini(VOID);
// ---------------------------------------------------------------------------
//  Liveness signal: named notification event signaled while VMX is active on
//  all cores.  Other kernel drivers (TestDriver) read its state WITHOUT a
//  vmcall, so they never VMCALL into a CPU where VMX is off (which #UDs ->
//  BSOD on VBS systems via HvlpVtlCallExceptionHandler, which bypasses SEH).
//  Set after vmx_init() succeeds, cleared at the very start of DriverUnload
//  (before broadcast_terminate_all) so clients stop vmcalling during teardown.
// ---------------------------------------------------------------------------
#define HV_ALIVE_EVT_NAME L"\\BaseNamedObjects\\WcsKsSync"
static PKEVENT  g_alive_evt = NULL;
static HANDLE   g_alive_h   = NULL;

static VOID hv_alive_set(VOID)
{
    UNICODE_STRING nm = RTL_CONSTANT_STRING(HV_ALIVE_EVT_NAME);
    PKEVENT ev = IoCreateNotificationEvent(&nm, &g_alive_h);
    if (ev)
    {
        g_alive_evt = ev;
        KeClearEvent(g_alive_evt);
        KeSetEvent(g_alive_evt, IO_NO_INCREMENT, FALSE);
        HYPERPLATFORM_LOG_INFO("[hv] alive event signaled (VMX active)");
    }
    else
    {
        HYPERPLATFORM_LOG_ERROR("[hv] alive event create failed");
    }
}

static VOID hv_alive_clear(VOID)
{
    if (g_alive_evt)
    {
        KeClearEvent(g_alive_evt);
        g_alive_evt = NULL;
        HYPERPLATFORM_LOG_INFO("[hv] alive event cleared (VMX tearing down)");
    }
    if (g_alive_h)
    {
        ZwClose(g_alive_h);
        g_alive_h = NULL;
    }
}
VOID
DriverUnload(_In_ PDRIVER_OBJECT driver_obj)
{
    UNREFERENCED_PARAMETER(driver_obj);
    HYPERPLATFORM_LOG_INFO("[hv] Unloading hypervisor driver...");

    g_vmx_active = FALSE;
    hv_alive_clear();          // tell clients to stop vmcalling BEFORE VMX goes off

    ept_stealth_free_all_broadcast();
    ept_stealth_region_destroy();
    hv_pid_cr3_fini();
    hv_scratch_fini();
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

//
// PID -> CR3 cache management. writes are spinlocked (R0, PASSIVE/APC).
// reads (hv_pid_to_cr3) are lock-free, called from VMX-root: the table is in
// kernel space (NonPagedPool / static BSS), mapped under the private host CR3.
// stale reads (process just died) are safe: hv_walk_va returns FALSE -> abort.
//
static void hv_pid_cr3_insert(HANDLE pid, UINT64 cr3)
{
    if (!pid || !cr3) return;
    KIRQL irql;
    KeAcquireSpinLock(&g_pid_cr3_lock, &irql);
    for (UINT32 i = 0; i < HV_PID_CR3_MAX; i++)
    {
        if (g_pid_cr3_table[i].pid == pid)
        {
            g_pid_cr3_table[i].cr3 = cr3;
            KeReleaseSpinLock(&g_pid_cr3_lock, irql);
            return;
        }
    }
    for (UINT32 i = 0; i < HV_PID_CR3_MAX; i++)
    {
        if (g_pid_cr3_table[i].pid == 0)
        {
            g_pid_cr3_table[i].cr3 = cr3;
            _mm_mfence();
            g_pid_cr3_table[i].pid = pid;
            break;
        }
    }
    KeReleaseSpinLock(&g_pid_cr3_lock, irql);
}

static void hv_pid_cr3_remove(HANDLE pid)
{
    if (!pid) return;
    KIRQL irql;
    KeAcquireSpinLock(&g_pid_cr3_lock, &irql);
    for (UINT32 i = 0; i < HV_PID_CR3_MAX; i++)
    {
        if (g_pid_cr3_table[i].pid == pid)
        {
            g_pid_cr3_table[i].pid = 0;
            g_pid_cr3_table[i].cr3 = 0;
            break;
        }
    }
    KeReleaseSpinLock(&g_pid_cr3_lock, irql);
}

// lock-free lookup, callable from VMX-root.
UINT64 hv_pid_to_cr3(HANDLE pid)
{
    if (!pid) return 0;
    for (UINT32 i = 0; i < HV_PID_CR3_MAX; i++)
    {
        if (g_pid_cr3_table[i].pid == pid)
            return g_pid_cr3_table[i].cr3;
    }
    return 0;
}

// Find the PML4 self-map index by scanning for a self-referencing entry.
// Must run at PASSIVE_LEVEL (uses pa_to_va which acquires PFN DB lock).
// The self-map index is the same for all processes (kernel-space constant).
static NTSTATUS hv_selfmap_init(VOID)
{
    UINT64 sys_cr3 = get_system_cr3();
    UINT64 pml4_pa = sys_cr3 & 0x000FFFFFFFFFF000ULL;
    HYPERPLATFORM_LOG_INFO("[hv] selfmap_init: sys_cr3=%llx pml4_pa=%llx", sys_cr3, pml4_pa);

    // Try multiple methods to map the PML4 physical page and scan for
    // a self-referencing entry (PML4[S] & PFN_MASK == pml4_pa && present).
    PUINT64 pml4 = NULL;
    BOOLEAN mapped_iospace = FALSE;

    // Method A: MmGetVirtualForPhysical (pa_to_va). Works on some builds.
    pml4 = (PUINT64)pa_to_va(pml4_pa);
    if (pml4)
    {
        HYPERPLATFORM_LOG_INFO("[hv] selfmap: pa_to_va ok pml4=%p", pml4);
    }
    else
    {
        // Method B: MmMapIoSpace with MmCached
        PHYSICAL_ADDRESS _phys; _phys.QuadPart = (LONGLONG)pml4_pa;
        pml4 = (PUINT64)MmMapIoSpace(_phys, 0x1000, MmCached);
        if (pml4)
        {
            mapped_iospace = TRUE;
            HYPERPLATFORM_LOG_INFO("[hv] selfmap: MmMapIoSpace(MmCached) ok pml4=%p", pml4);
        }
        else
        {
            // Method C: MmMapIoSpace with MmNonCached
            pml4 = (PUINT64)MmMapIoSpace(_phys, 0x1000, MmNonCached);
            if (pml4)
            {
                mapped_iospace = TRUE;
                HYPERPLATFORM_LOG_INFO("[hv] selfmap: MmMapIoSpace(MmNonCached) ok pml4=%p", pml4);
            }
            else
            {
                HYPERPLATFORM_LOG_ERROR("[hv] selfmap: ALL mapping methods failed");
            }
        }
    }

    if (pml4)
    {
        // Scan for self-referencing entry
        UINT32 sm_found = 0xFFFFFFFF;
        UINT64 sm_entry = 0;
        for (UINT32 i = 0; i < 512; i++)
        {
            if ((pml4[i] & 0x000FFFFFFFFFF000ULL) == pml4_pa && (pml4[i] & 1))
            {
                sm_found = i;
                sm_entry = pml4[i];
                break;
            }
        }

        // Log first 8 entries for diagnostics if not found
        if (sm_found == 0xFFFFFFFF)
        {
            HYPERPLATFORM_LOG_ERROR("[hv] selfmap: no self-ref found. PML4[0..7]:",
                pml4[0], pml4[1], pml4[2], pml4[3],
                pml4[4], pml4[5], pml4[6], pml4[7]);
        }

        if (mapped_iospace) MmUnmapIoSpace(pml4, 0x1000);

        if (sm_found != 0xFFFFFFFF)
        {
            g_self_map_index = sm_found;
            HYPERPLATFORM_LOG_INFO("[hv] self-map index = 0x%x (PML4[%x]=%llx)",
                sm_found, sm_found, sm_entry);
            return STATUS_SUCCESS;
        }
    }

    HYPERPLATFORM_LOG_ERROR("[hv] selfmap init: FAILED - R3 mem VMCALL will zero-fill");
    return STATUS_NOT_FOUND;
}

// per-CPU scratch buffer for R3 memory copy (kernel VA, valid under any CR3).
PUCHAR hv_get_scratch(VOID)
{
    ULONG cpu = KeGetCurrentProcessorNumberEx(NULL);
    if (cpu < HV_MAX_CPUS && g_scratch[cpu])
        return g_scratch[cpu];
    return NULL;
}

static VOID hv_proc_notify(
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create)
{
    UNREFERENCED_PARAMETER(ParentId);
    if (Create)
    {
        PEPROCESS eproc = NULL;
        if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &eproc)) && eproc)
        {
            UINT64 cr3 = *(UINT64 *)((PUCHAR)eproc + EPROCESS_DIRTABLEBASE);
            ObDereferenceObject(eproc);
            hv_pid_cr3_insert(ProcessId, cr3);
        }
    }
    else
    {
        hv_pid_cr3_remove(ProcessId);
    }
}

// enumerate all existing processes at init (before hostcr3_build).
static NTSTATUS hv_pid_cr3_init(VOID)
{
    KeInitializeSpinLock(&g_pid_cr3_lock);
    RtlZeroMemory(g_pid_cr3_table, sizeof(g_pid_cr3_table));

    for (ULONG pid = 0; pid <= 0xFFFF; pid++)
    {
        PEPROCESS eproc = NULL;
        if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &eproc)) && eproc)
        {
            UINT64 cr3 = *(UINT64 *)((PUCHAR)eproc + EPROCESS_DIRTABLEBASE);
            ObDereferenceObject(eproc);
            hv_pid_cr3_insert((HANDLE)(ULONG_PTR)pid, cr3);
        }
    }

    NTSTATUS st = PsSetCreateProcessNotifyRoutine(hv_proc_notify, FALSE);
    if (!NT_SUCCESS(st))
    {
        HYPERPLATFORM_LOG_ERROR("[hv] PsSetCreateProcessNotifyRoutine failed: 0x%x", st);
        return st;
    }
    HYPERPLATFORM_LOG_INFO("[hv] PID->CR3 cache initialized (%u entries max).", HV_PID_CR3_MAX);
    return STATUS_SUCCESS;
}

static VOID hv_pid_cr3_fini(VOID)
{
    PsSetCreateProcessNotifyRoutine(hv_proc_notify, TRUE);
}

static NTSTATUS hv_scratch_init(VOID)
{
    ULONG n = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (n > HV_MAX_CPUS) n = HV_MAX_CPUS;
    for (ULONG i = 0; i < n; i++)
    {
        g_scratch[i] = (PUCHAR)ExAllocatePoolWithTag(
            NonPagedPool, HV_SCRATCH_SIZE, 'OscH');
        if (!g_scratch[i])
        {
            HYPERPLATFORM_LOG_ERROR("[hv] scratch alloc failed for CPU %u", i);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    HYPERPLATFORM_LOG_INFO("[hv] Scratch buffers allocated for %u CPUs.", n);
    return STATUS_SUCCESS;
}

static VOID hv_scratch_fini(VOID)
{
    for (ULONG i = 0; i < HV_MAX_CPUS; i++)
    {
        if (g_scratch[i])
        {
            ExFreePoolWithTag(g_scratch[i], 'OscH');
            g_scratch[i] = NULL;
        }
    }
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  driver_obj,
    _In_ PUNICODE_STRING registry_path)
{
    UNREFERENCED_PARAMETER(registry_path);

    //
    // init log system 闂?buffer-based, safe for VMX-root via _SAFE macros
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
    //
    // PID->CR3 cache + scratch buffers MUST be allocated before vmx_init()
    // (which calls hostcr3_build): NonPagedPool allocs after hostcr3_build are
    // not mapped in the private host CR3 and would fault in VMX-root.
    //
    {
        NTSTATUS _cr3st = hv_pid_cr3_init();
        if (!NT_SUCCESS(_cr3st))
        {
            LogTermination();
            return _cr3st;
        }
        NTSTATUS _scst = hv_scratch_init();
        if (!NT_SUCCESS(_scst))
        {
            hv_pid_cr3_fini();
            LogTermination();
            return _scst;
        }
    }

    // find PML4 self-map index (must be before vmx_init / hostcr3_build).
    // used by hv_walk_va in VMX-root to read PTEs without pa_to_va (deadlock-safe).
    {
        NTSTATUS _smst = hv_selfmap_init();
        if (!NT_SUCCESS(_smst))
        {
            HYPERPLATFORM_LOG_ERROR("[hv] self-map init FAILED - R3 mem VMCALL disabled");
            // non-fatal: hv_walk_va will return FALSE if index is invalid
        }
    }

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
    g_vmx_active = TRUE;
    hv_alive_set();           // signal VMX active to all kernel clients

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

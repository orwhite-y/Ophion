/*
*   breadcrumb.cpp - ring buffer allocation, flush worker thread, CMOS globals
*
*   Ring buffer: pre-allocated NonPagedPool (before hostcr3_build so it is
*   mapped in the private host CR3). Written from VMX-root via hv_breadcrumb()
*   (interlocked + memory write only). Flushed to \SystemRoot\BC.log by a
*   PASSIVE_LEVEL worker thread every 500ms.
*
*   CMOS globals: g_cmos_lock (spinlock), g_cmos_percpu_cache (throttle cache).
*/
#include "hv.h"
#include "log.h"
#include <ntstrsafe.h>

// CMOS globals (referenced by inline functions in breadcrumb.h)
volatile LONG g_cmos_lock = 0;
volatile UCHAR g_cmos_percpu_cache[64] = {0};

// Ring buffer global
BC_RING *g_bc_ring = NULL;

// Self-map walk safe range (set by ept_stealth init, read by asm_host_pf_handler).
// When g_pf_safe_start != 0, a host #PF with RIP in [start,end) recovers
// (RAX=0, skip 3 bytes) instead of BSOD. 0 = unset -> all host #PF BSOD.
UINT64 g_pf_safe_start = 0;
UINT64 g_pf_safe_end = 0;
volatile LONG g_pf_recovery_count = 0;
volatile LONG g_dbg_a2_walk_fallback = 0;

// Worker thread state
static HANDLE g_bc_thread_handle = NULL;
static PKTHREAD g_bc_thread_obj = NULL;
static volatile BOOLEAN g_bc_thread_run = FALSE;
static KEVENT g_bc_flush_event;

#define BC_LOG_PATH L"\\SystemRoot\\BC.log"
#define BC_MAGIC_INIT 0xBCBC0001

// Allocate ring buffer. Must be called at PASSIVE_LEVEL BEFORE vmx_init
// (so the allocation is mapped in the private host CR3).
NTSTATUS hv_breadcrumb_init(VOID)
{
    SIZE_T size = sizeof(BC_RING);
    g_bc_ring = (BC_RING *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, size, 'bcHO');
    if (!g_bc_ring)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(g_bc_ring, size);
    g_bc_ring->write_idx = 0;
    g_bc_ring->seq_counter = 0;
    _mm_sfence();
    g_bc_ring->magic = BC_MAGIC_INIT;

    KeInitializeEvent(&g_bc_flush_event, NotificationEvent, FALSE);
    return STATUS_SUCCESS;
}

// Write the ring buffer contents to BC.log as text.
// Called at PASSIVE_LEVEL from the worker thread.
static NTSTATUS hv_breadcrumb_write_log(VOID)
{
    if (!g_bc_ring || g_bc_ring->magic != BC_MAGIC_INIT)
        return STATUS_NOT_FOUND;

    UNICODE_STRING path = RTL_CONSTANT_STRING(BC_LOG_PATH);
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &path,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    IO_STATUS_BLOCK iosb = {};
    HANDLE h = NULL;
    NTSTATUS st = ZwCreateFile(&h, FILE_GENERIC_WRITE, &oa, &iosb,
        NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE | FILE_WRITE_THROUGH, NULL, 0);
    /* FILE_WRITE_THROUGH: every write is flushed to disk before completing, so BC.log
     * survives a hard reset (triple-fault) up to the last 500ms flush cycle. */
    if (!NT_SUCCESS(st) || !h)
    {
        static volatile LONG _bc_log_fail_logged = 0;
        if (_InterlockedCompareExchange(&_bc_log_fail_logged, 1, 0) == 0)
            HYPERPLATFORM_LOG_ERROR("[hv] BC.log ZwCreateFile FAILED st=0x%lx", (ULONG)st);
        return st;
    }

    // Write header
    char hdr[128];
    LARGE_INTEGER off = { 0 };
    int hl = 0;
    // Read the current write position atomically (add 0 = read without modify)
    LONG cur_write = _InterlockedExchangeAdd(&g_bc_ring->write_idx, 0);
    if (NT_SUCCESS(RtlStringCbPrintfA(hdr, sizeof(hdr),
            "=== BC.log ring dump === write_idx=%ld seq=%ld\r\n",
            cur_write, (LONG)g_bc_ring->seq_counter)))
        hl = (int)strlen(hdr);
    if (hl > 0)
        ZwWriteFile(h, NULL, NULL, NULL, &iosb, hdr, (ULONG)hl, &off, NULL);
    off.QuadPart += hl;

    // Dump all entries (newest first = reverse from write_idx)
    // We dump the full ring; entries with seq=0 are empty/never written.
    char line[160];
    for (LONG i = 0; i < BC_RING_ENTRIES; i++)
    {
        LONG idx = (cur_write - 1 - i) & (BC_RING_ENTRIES - 1);
        BC_ENTRY *e = &g_bc_ring->entries[idx];
        UINT32 seq = e->seq;
        if (seq == 0)
            continue;  // empty slot
        // Re-read to check consistency (seq might have changed if overwritten)
        _mm_lfence();
        UINT16 eid = e->event_id;
        UINT8 cpu = e->cpu;
        UINT8 flg = e->flags;
        UINT64 dat = e->data;
        _mm_lfence();
        if (e->seq != seq)
            continue;  // entry was overwritten during read, skip

        int ll = 0;
        if (NT_SUCCESS(RtlStringCbPrintfA(line, sizeof(line),
                "[%6lu] cpu=%-2u evt=0x%04x data=0x%016I64x flg=%u\r\n",
                (unsigned long)seq, (unsigned)cpu, (unsigned)eid, dat, (unsigned)flg)))
            ll = (int)strlen(line);
        if (ll > 0)
            ZwWriteFile(h, NULL, NULL, NULL, &iosb, line, (ULONG)ll, &off, NULL);
        off.QuadPart += ll;
    }

    ZwClose(h);
    return STATUS_SUCCESS;
}

// Immediate flush (PASSIVE_LEVEL). Can be called from IOCTL handler.
VOID hv_breadcrumb_flush_now(VOID)
{
    hv_breadcrumb_write_log();
}

// Worker thread: flush ring buffer to BC.log every 500ms.
static VOID bc_worker_thread(PVOID context)
{
    UNREFERENCED_PARAMETER(context);
    LARGE_INTEGER timeout;
    timeout.QuadPart = -5000000LL;  // 500ms in 100ns units (relative)

    // Set priority to low to avoid interfering with system
    KeSetPriorityThread(KeGetCurrentThread(), LOW_REALTIME_PRIORITY);

    while (g_bc_thread_run)
    {
        // Wait for timeout or explicit flush signal
        KeWaitForSingleObject(&g_bc_flush_event, Executive, KernelMode,
                              FALSE, &timeout);
        KeClearEvent(&g_bc_flush_event);

        if (!g_bc_thread_run)
            break;

        hv_breadcrumb_write_log();
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

// Start the BC.log flush worker thread. Must be called at PASSIVE_LEVEL.
VOID hv_breadcrumb_start_flush(VOID)
{
    if (g_bc_thread_handle)
        return;

    g_bc_thread_run = TRUE;
    KeInitializeEvent(&g_bc_flush_event, NotificationEvent, FALSE);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, NULL,
        OBJ_KERNEL_HANDLE, NULL, NULL);
    NTSTATUS st = PsCreateSystemThread(
        &g_bc_thread_handle, THREAD_ALL_ACCESS, &oa,
        NULL, NULL, bc_worker_thread, NULL);
    if (!NT_SUCCESS(st))
    {
        g_bc_thread_run = FALSE;
        g_bc_thread_handle = NULL;
        return;
    }

    // Get thread object for waiting on stop
    ObReferenceObjectByHandle(g_bc_thread_handle,
        THREAD_ALL_ACCESS, *PsThreadType, KernelMode,
        (PVOID *)&g_bc_thread_obj, NULL);
    ZwClose(g_bc_thread_handle);
    g_bc_thread_handle = NULL;

    /* Create BC.log immediately (don't wait 500ms) so we can confirm the worker
     * is functional even if the system crashes within the first flush window. */
    hv_breadcrumb_flush_now();
}

// Stop the BC.log flush worker thread. Must be called at PASSIVE_LEVEL.
VOID hv_breadcrumb_stop_flush(VOID)
{
    if (!g_bc_thread_obj)
        return;

    g_bc_thread_run = FALSE;
    KeSetEvent(&g_bc_flush_event, IO_NO_INCREMENT, FALSE);

    LARGE_INTEGER timeout;
    timeout.QuadPart = -10000000LL;  // 1 second timeout
    KeWaitForSingleObject(g_bc_thread_obj, Executive,
        KernelMode, FALSE, &timeout);

    ObDereferenceObject(g_bc_thread_obj);
    g_bc_thread_obj = NULL;
}

/* =======================================================================
 *  Panic API -- converts fatal VMX-root conditions into analyzable BSODs.
 *  KeBugCheckEx(0xDEADC0DE, code, a1, a2, a3). The 4 args survive in every
 *  dump type (even small minidumps). Combined with a kernel dump the ring
 *  buffer trail is also recoverable:  dq poi(g_bc_ring) L1000
 * ======================================================================= */

/* hv_host_pf_panic is defined in hostidt.cpp (with CMOS NVRAM stamping for
 * triple-fault-resilient crash recording). It is NOT defined here to avoid
 * a duplicate-symbol linker error. The asm_host_pf_handler in AsmHostIdt.asm
 * calls it via C linkage (extern "C"). */

/* General VMX-root panic (called from C vmexit handlers on the full host
 * stack). Stamps a final HOST_CRASH breadcrumb (VMX-root safe: g_bc_ring is
 * non-paged and mapped in the private host CR3) then KeBugCheckEx. */
__declspec(noinline) VOID
hv_panic(UINT64 code, UINT64 a1, UINT64 a2, UINT64 a3)
{
    hv_breadcrumb_cpu(BC_EVT_HOST_CRASH, 0xFF, code);
    _mm_sfence();
    KeBugCheckEx(0xDEADC0DE, (ULONG_PTR)code,
                 (ULONG_PTR)a1, (ULONG_PTR)a2, (ULONG_PTR)a3);
}
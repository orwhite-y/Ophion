/*
*   breadcrumb.h - VMX-root safe crash diagnostic system
*
*   Three layers of crash-surviving diagnostics:
*   A) Ring buffer (in-memory, high detail, flushed to BC.log by worker thread)
*   B) CMOS NVRAM (survives triple-fault hard reboot, minimal but crucial data)
*   C) Per-step injector disk log (reads BC.log after each IOCTL step)
*
*   VMX-root safety: NO API calls, NO file I/O, NO DbgPrint, NO MmGetVirtualForPhysical.
*   Only interlocked ops, memory writes, and port I/O (__outbyte/__inbyte).
*
*   CMOS safety: Port 0x70/0x71 is shared globally across all CPUs.
*   A spinlock (interlocked test-and-set) serializes the 2-port CMOS protocol.
*   Bounded spin (1024 iterations) prevents deadlock if lock holder crashes.
*   Bit 7 of port 0x70 masks NMI -- always cleared on index write.
*/
#pragma once

#include <ntddk.h>
#include <intrin.h>

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
*  CMOS NVRAM diagnostic layout (battery-backed, survives triple-fault)
* =========================================================================
*
*  0x50: Magic (0xA5 = valid data written this boot)
*  0x51: Last global event marker (see WEDGE event table below)
*  0x52: Sticky "match seen" flag (stealth page matched at least once)
*  0x53: Sticky "trigger seen" flag (injection trigger fired at least once)
*  0x54-0x5B: Last #PF fault VA (8 bytes, little-endian)
*  0x5C-0x5F: Last #PF error code (4 bytes)
*  0x60-0x7F: Per-CPU last event byte (32 CPUs max)
*
*  WEDGE event table (value -> meaning):
*  0x00 (none)          0x01 A-trig-fire       0x02 B-pf-entry
*  0x03 C-heal-enter    0x04 D-post-enter-cr3  0x05 E-pre-walk
*  0x06 E2-post-walk    0x0B B1-match          0x0C B2-pre-heal
*  0x0D BN-nomatch      0x0E REINJ             0x0F TF-guest-loop
*  0x10 S1-pre-vmxinit  0x11 S2-vmx-on         0x12 S3-ept-done
*  0x13 S4-ready        0x1E S-ept-fail        0x1F S-vmx-fail
*  0x20 INJECT_START    0x21 INJECT_SHADOW_CR3 0x22 INJECT_STEALTH
*  0x23 INJECT_HOOK     0x24 INJECT_RESUME     0x25 INJECT_DLLMAIN
*  0x26 INJECT_TRIGGER  0x27 INJECT_UNHOOK     0x28 INJECT_DONE
*  0x30 PF_SHADOW_OPEN  0x31 PF_SHADOW_SWAP    0x32 PF_A2_HEAL
*  0x33 PF_A2_BAIL      0x34 PF_ABORT          0x35 PF_ABORT_REINJ
*  0x36 PF_WIDEN        0x37 PF_NARROW
*  0x40 MTF_ENTRY       0x41 MTF_RESTORE       0x42 MTF_WP_RESYNC
*  0x50 CR3_LOAD_EXIT   0x51 CR3_STORE_EXIT    0x52 SHADOW_PENDING
*  0x53 SHADOW_REACTIVATE 0x54 ALREADY_ON_SHADOW
*  0x60 EPT_VIOLATION   0x61 EPT_VIOLATION_PT
*  0x70 VMCALL_HOOK     0x71 VMCALL_STEALTH    0x72 VMCALL_INJECT
*  0x73 VMCALL_ABORT    0x74 VMCALL_DUMP_BC
*  0x99 TRIPLE_FAULT    0xFF HOST_CRASH
*/

#define WEDGE_CMOS_MAGIC_OFF     0x50
#define WEDGE_CMOS_VALUE_OFF     0x51
#define WEDGE_CMOS_MAGIC         0xA5
#define WEDGE_CMOS_MATCH_OFF     0x52
#define WEDGE_CMOS_TRIG_OFF      0x53
#define WEDGE_CMOS_PF_VA_OFF     0x54   /* 8 bytes (0x54-0x5B) */
#define WEDGE_CMOS_PF_ERR_OFF    0x5C   /* 4 bytes (0x5C-0x5F) */
#define WEDGE_CMOS_PERCPU_BASE   0x60   /* 32 bytes (0x60-0x7F) */

/* =========================================================================
*  CMOS spinlock + safe port I/O (VMX-root safe)
* ========================================================================= */

extern volatile LONG g_cmos_lock;
extern volatile UCHAR g_cmos_percpu_cache[64];

/* VMX-root safe CMOS byte write (spinlock + NMI-safe index) */
static __forceinline VOID
cmos_write_byte(UCHAR index, UCHAR data)
{
    LONG spins = 0;
    while (_InterlockedCompareExchange(&g_cmos_lock, 1, 0) != 0)
    {
        if (++spins > 1024) return;   /* give up, don't hang */
        _mm_pause();
    }
    __outbyte(0x70, index & 0x7F);    /* bit7=0 -> NMI not masked */
    __outbyte(0x71, data);
    __outbyte(0x70, 0x0D);            /* restore: clear NMI disable */
    _InterlockedExchange(&g_cmos_lock, 0);
}

/* VMX-root safe CMOS byte read */
static __forceinline UCHAR
cmos_read_byte(UCHAR index)
{
    LONG spins = 0;
    while (_InterlockedCompareExchange(&g_cmos_lock, 1, 0) != 0)
    {
        if (++spins > 1024) return 0;
        _mm_pause();
    }
    __outbyte(0x70, index & 0x7F);
    UCHAR val = __inbyte(0x71);
    __outbyte(0x70, 0x0D);
    _InterlockedExchange(&g_cmos_lock, 0);
    return val;
}

static __forceinline VOID
cmos_write_qword(UCHAR index, UINT64 val)
{
    for (UINT32 i = 0; i < 8; i++)
        cmos_write_byte((UCHAR)(index + i), (UCHAR)(val >> (i * 8)));
}

static __forceinline UINT64
cmos_read_qword(UCHAR index)
{
    UINT64 val = 0;
    for (UINT32 i = 0; i < 8; i++)
        val |= ((UINT64)cmos_read_byte((UCHAR)(index + i))) << (i * 8);
    return val;
}

static __forceinline VOID
cmos_write_dword(UCHAR index, UINT32 val)
{
    for (UINT32 i = 0; i < 4; i++)
        cmos_write_byte((UCHAR)(index + i), (UCHAR)(val >> (i * 8)));
}

static __forceinline UINT32
cmos_read_dword(UCHAR index)
{
    UINT32 val = 0;
    for (UINT32 i = 0; i < 4; i++)
        val |= ((UINT32)cmos_read_byte((UCHAR)(index + i))) << (i * 8);
    return val;
}

/* =========================================================================
*  WEDGE marker API (throttled per-CPU + global)
* ========================================================================= */

/* Write a WEDGE progress marker.
   Throttled: skips CMOS write if value unchanged for this CPU (hot-path safe). */
static __forceinline VOID
wedge_cmos_mark(UCHAR v)
{
    ULONG cpu = KeGetCurrentProcessorNumberEx(NULL);
    UCHAR c = (UCHAR)(cpu & 0x3F);
    if (g_cmos_percpu_cache[c] == v)
        return;
    cmos_write_byte((UCHAR)(WEDGE_CMOS_PERCPU_BASE + (cpu & 0x1F)), v);
    g_cmos_percpu_cache[c] = v;
    cmos_write_byte(WEDGE_CMOS_MAGIC_OFF, WEDGE_CMOS_MAGIC);
    cmos_write_byte(WEDGE_CMOS_VALUE_OFF, v);
}

/* Write a WEDGE marker with explicit CPU number (for VMX-root where vcpu->core_id is known) */
static __forceinline VOID
wedge_cmos_mark_cpu(UINT32 cpu, UCHAR v)
{
    UCHAR c = (UCHAR)(cpu & 0x3F);
    if (g_cmos_percpu_cache[c] == v)
        return;
    cmos_write_byte((UCHAR)(WEDGE_CMOS_PERCPU_BASE + (cpu & 0x1F)), v);
    g_cmos_percpu_cache[c] = v;
    cmos_write_byte(WEDGE_CMOS_MAGIC_OFF, WEDGE_CMOS_MAGIC);
    cmos_write_byte(WEDGE_CMOS_VALUE_OFF, v);
}

static __forceinline VOID
wedge_cmos_read(UCHAR *magic, UCHAR *val)
{
    if (magic) *magic = cmos_read_byte(WEDGE_CMOS_MAGIC_OFF);
    if (val)   *val   = cmos_read_byte(WEDGE_CMOS_VALUE_OFF);
}

static __forceinline VOID
wedge_cmos_clear(VOID)
{
    cmos_write_byte(WEDGE_CMOS_MAGIC_OFF, 0);
    cmos_write_byte(WEDGE_CMOS_VALUE_OFF, 0);
    cmos_write_byte(WEDGE_CMOS_MATCH_OFF, 0);
    cmos_write_byte(WEDGE_CMOS_TRIG_OFF, 0);
    cmos_write_qword(WEDGE_CMOS_PF_VA_OFF, 0);
    cmos_write_dword(WEDGE_CMOS_PF_ERR_OFF, 0);
    for (UINT32 i = 0; i < 32; i++)
        cmos_write_byte((UCHAR)(WEDGE_CMOS_PERCPU_BASE + i), 0);
    for (UINT32 i = 0; i < 64; i++)
        g_cmos_percpu_cache[i] = 0;
}

static __forceinline VOID
wedge_cmos_set_match_seen(VOID)
{
    cmos_write_byte(WEDGE_CMOS_MATCH_OFF, 1);
}

static __forceinline UCHAR
wedge_cmos_read_match_seen(VOID)
{
    return cmos_read_byte(WEDGE_CMOS_MATCH_OFF);
}

static __forceinline VOID
wedge_cmos_set_trig_seen(VOID)
{
    cmos_write_byte(WEDGE_CMOS_TRIG_OFF, 1);
}

static __forceinline UCHAR
wedge_cmos_read_trig_seen(VOID)
{
    return cmos_read_byte(WEDGE_CMOS_TRIG_OFF);
}

/* Snap last #PF fault VA + error code to CMOS (survives triple-fault) */
static __forceinline VOID
wedge_cmos_snap_pf(UINT64 fault_va, UINT32 error_code)
{
    cmos_write_qword(WEDGE_CMOS_PF_VA_OFF, fault_va);
    cmos_write_dword(WEDGE_CMOS_PF_ERR_OFF, error_code);
}

static __forceinline VOID
wedge_cmos_read_pf(UINT64 *fault_va, UINT32 *error_code)
{
    if (fault_va)    *fault_va    = cmos_read_qword(WEDGE_CMOS_PF_VA_OFF);
    if (error_code)  *error_code  = cmos_read_dword(WEDGE_CMOS_PF_ERR_OFF);
}

static __forceinline UCHAR
wedge_cmos_read_percpu(UINT32 cpu)
{
    if (cpu >= 32) return 0;
    return cmos_read_byte((UCHAR)(WEDGE_CMOS_PERCPU_BASE + cpu));
}

/* =========================================================================
*  Ring buffer (in-memory, high-detail, flushed to BC.log)
* ========================================================================= */

#define BC_RING_ENTRIES  2048
#define BC_ENTRY_SIZE    16

typedef struct DECLSPEC_ALIGN(16) _BC_ENTRY {
    volatile UINT32 seq;     /* 0 = empty; non-zero = valid (written LAST) */
    UINT16 event_id;         /* BC_EVT_* */
    UINT8  cpu;              /* CPU number */
    UINT8  flags;            /* extra info */
    UINT64 data;             /* event-specific data (VA, PFN, error code, etc.) */
} BC_ENTRY;

typedef struct DECLSPEC_ALIGN(64) _BC_RING {
    BC_ENTRY entries[BC_RING_ENTRIES];
    volatile LONG write_idx;    /* next slot (InterlockedIncrement, wraps) */
    volatile LONG seq_counter;  /* global monotonic sequence */
    UINT32 magic;               /* 0xBCBC0001 = initialized */
} BC_RING;

/* Ring buffer event IDs */
#define BC_EVT_NONE              0
#define BC_EVT_HV_INIT_START     1
#define BC_EVT_HV_INIT_VMXON     2
#define BC_EVT_HV_INIT_EPT       3
#define BC_EVT_HV_INIT_READY     4
#define BC_EVT_INJECT_START      10
#define BC_EVT_INJECT_SHADOW_CR3 11
#define BC_EVT_INJECT_STEALTH    12
#define BC_EVT_INJECT_HOOK       13
#define BC_EVT_INJECT_RESUME     14
#define BC_EVT_INJECT_DLLMAIN    15
#define BC_EVT_INJECT_TRIGGER    16
#define BC_EVT_INJECT_UNHOOK     17
#define BC_EVT_INJECT_DONE       18
#define BC_EVT_PF_ENTRY          20
#define BC_EVT_PF_SHADOW_OPEN    21
#define BC_EVT_PF_SHADOW_SWAP    22
#define BC_EVT_PF_A2_HEAL        23
#define BC_EVT_PF_A2_BAIL        24
#define BC_EVT_PF_ABORT          25
#define BC_EVT_PF_ABORT_REINJ    26
#define BC_EVT_PF_WIDEN          27
#define BC_EVT_PF_NARROW         28
#define BC_EVT_MTF_ENTRY         30
#define BC_EVT_MTF_RESTORE       31
#define BC_EVT_MTF_WP_RESYNC     32
#define BC_EVT_CR3_LOAD_EXIT     40
#define BC_EVT_CR3_STORE_EXIT    41
#define BC_EVT_SHADOW_PENDING    42
#define BC_EVT_SHADOW_REACTIVATE 43
#define BC_EVT_ALREADY_ON_SHADOW 44
#define BC_EVT_EPT_VIOLATION     50
#define BC_EVT_EPT_VIOLATION_PT  51
#define BC_EVT_VMCALL            60
#define BC_EVT_TRIPLE_FAULT      99
#define BC_EVT_HOST_CRASH        0xFF

/* Ring buffer API (implemented in breadcrumb.cpp) */
extern BC_RING *g_bc_ring;

/* VMX-root safe: write a breadcrumb entry (interlocked + memory write only) */
static __forceinline VOID
hv_breadcrumb(UINT16 event_id, UINT64 data)
{
    BC_RING *r = g_bc_ring;
    if (!r || r->magic != 0xBCBC0001) return;
    LONG idx = _InterlockedIncrement(&r->write_idx) - 1;
    idx &= (BC_RING_ENTRIES - 1);
    BC_ENTRY *e = &r->entries[idx];
    e->event_id = event_id;
    e->cpu = (UINT8)(KeGetCurrentProcessorNumberEx(NULL) & 0xFF);
    e->flags = 0;
    e->data = data;
    _mm_sfence();
    e->seq = (UINT32)_InterlockedIncrement(&r->seq_counter);
}

/* VMX-root safe: breadcrumb with explicit CPU */
static __forceinline VOID
hv_breadcrumb_cpu(UINT16 event_id, UINT32 cpu, UINT64 data)
{
    BC_RING *r = g_bc_ring;
    if (!r || r->magic != 0xBCBC0001) return;
    LONG idx = _InterlockedIncrement(&r->write_idx) - 1;
    idx &= (BC_RING_ENTRIES - 1);
    BC_ENTRY *e = &r->entries[idx];
    e->event_id = event_id;
    e->cpu = (UINT8)(cpu & 0xFF);
    e->flags = 0;
    e->data = data;
    _mm_sfence();
    e->seq = (UINT32)_InterlockedIncrement(&r->seq_counter);
}

/* PASSIVE_LEVEL API (breadcrumb.cpp) */
NTSTATUS hv_breadcrumb_init(VOID);           /* allocate ring buffer (before vmx_init) */
VOID     hv_breadcrumb_start_flush(VOID);     /* start BC.log flush worker thread */
VOID     hv_breadcrumb_stop_flush(VOID);      /* stop worker thread (DriverUnload) */
VOID     hv_breadcrumb_flush_now(VOID);       /* immediate flush (called from PASSIVE) */

/* -----------------------------------------------------------------------
 *  Panic API (VMX-root safe -> KeBugCheckEx with rich args)
 *  Converts fatal VMX-root conditions (unmapped-page #PF, guest triple-fault,
 *  EPT misconfig, unhandled exit) into an analyzable BSOD whose bugcheck args
 *  carry the fault VA / RIP / CR3 / exit-reason. The minidump bugcheck args
 *  survive in EVERY dump type (even small). With a kernel dump, the ring
 *  buffer is also captured (dump via: dq poi(g_bc_ring) L1000).
 * ----------------------------------------------------------------------- */
#define HV_PANIC_HOST_PF        0x01    /* VMX-root #PF: P2=cr2(faultVA) P3=rip P4=err(#PF ec) */
#define HV_PANIC_TRIPLE_FAULT   0x02    /* guest triple-fault: a1=rip a2=core a3=exit_reason */
#define HV_PANIC_EPT_MISCONFIG  0x03    /* EPT misconfig: a1=guest_rip a2=exit_qual a3=core */
#define HV_PANIC_UNHANDLED_EXIT 0x04    /* unhandled VM-exit: a1=exit_reason a2=guest_rip a3=core */
#define HV_PANIC_ENTRY_FAILURE  0x05    /* VM-entry failure: a1=exit_reason a2=instr_err a3=core */

/* Called from asm_host_pf_handler (IDT #PF). Does NOT touch the ring buffer
 * (the #PF may have been caused by a ring access), just KeBugCheckEx. */
VOID hv_host_pf_panic(UINT64 cr2, UINT64 rip, UINT64 err, UINT64 cr3);

/* Host #PF recovery: safe walk range for stealth_walk_pte_selfmap / stealth_walk_pt_page_selfmap.
 * When a #PF hits a "mov rax,[rax]" (48 8B 00) inside this range, the asm host #PF
 * handler recovers by setting RAX=0 (not-present) and advancing RIP by 3. */
extern UINT64 g_pf_safe_start;
extern UINT64 g_pf_safe_end;
void ept_stealth_init_pf_safe_range(void);
extern volatile LONG g_pf_recovery_count;
extern volatile LONG g_dbg_a2_walk_fallback;

/* General VMX-root panic (called from C vmexit handlers, full host stack).
 * Stamps a final HOST_CRASH breadcrumb then KeBugCheckEx. */
VOID hv_panic(UINT64 code, UINT64 a1, UINT64 a2, UINT64 a3);

#ifdef __cplusplus
}
#endif


/* =========================================================================
*  Backward-compatible reinject probe wrappers
*  (old callers use wedge_cmos_snap_reinj/read_reinj; data stored in PF fields)
* ========================================================================= */

/* Snap reinject livelock data (streak + fault addr) to CMOS PF fields.
   Stored as: pf_va = addr, pf_err = streak.
   On readback, high streak = livelock on that addr. */
static __forceinline VOID
wedge_cmos_snap_reinj(UINT32 streak, UINT64 addr)
{
    cmos_write_qword(WEDGE_CMOS_PF_VA_OFF, addr);
    cmos_write_dword(WEDGE_CMOS_PF_ERR_OFF, streak);
}

static __forceinline VOID
wedge_cmos_read_reinj(UINT32 *streak, UINT64 *addr)
{
    if (addr)   *addr   = cmos_read_qword(WEDGE_CMOS_PF_VA_OFF);
    if (streak) *streak = cmos_read_dword(WEDGE_CMOS_PF_ERR_OFF);
}

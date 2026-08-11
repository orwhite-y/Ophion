/*
*   hostidt.c - private host IDT for VMX-root mode
*   prevents NMI hijacking where guest corrupts OS IDT and triggers
*   NMI while in host mode to execute attacker code in ring 0
*/
#include "hv.h"

extern VOID asm_host_nmi_handler(VOID);
extern VOID asm_host_df_handler(VOID);
extern VOID asm_host_gp_handler(VOID);
extern VOID asm_host_default_handler(VOID);
extern VOID asm_host_pf_handler(VOID);

static VOID
hostidt_set_gate(
    PIDT_GATE_DESCRIPTOR_64 gate,
    UINT64                  handler,
    UINT16                  selector,
    UINT8                   type,
    UINT8                   ist
)
{
    gate->OffsetLow  = (UINT16)(handler & 0xFFFF);
    gate->OffsetMid  = (UINT16)((handler >> 16) & 0xFFFF);
    gate->OffsetHigh = (UINT32)(handler >> 32);
    gate->Selector   = selector;
    gate->Ist        = ist;
    gate->Reserved0  = 0;
    gate->Type       = type;
    gate->Zero       = 0;
    gate->Dpl        = 0;
    gate->Present    = 1;
    gate->Reserved1  = 0;
}

BOOLEAN
hostidt_build(VOID)
{
    UINT16 cs;

    if (g_host_idt.initialized)
        return TRUE;

    cs = asm_get_cs() & 0xF8;

    g_host_idt.original_idt_base = asm_get_idt_base();

    //
    // default handler halts cpu �?anything unexpected is a bug
    //
    for (UINT32 i = 0; i < IDT_NUM_ENTRIES; i++)
        hostidt_set_gate(&g_host_idt.idt[i], (UINT64)asm_host_default_handler, cs, IDT_TYPE_INTERRUPT_GATE, 0);

    //
    // NMI: sets pending flag, vmexit handler injects to guest
    //
    hostidt_set_gate(&g_host_idt.idt[IDT_VECTOR_NMI], (UINT64)asm_host_nmi_handler, cs, IDT_TYPE_INTERRUPT_GATE, 0);

    //
    // #DF/#GP: unrecoverable in host mode, halt
    //
    hostidt_set_gate(&g_host_idt.idt[IDT_VECTOR_DF], (UINT64)asm_host_df_handler, cs, IDT_TYPE_INTERRUPT_GATE, 0);
    hostidt_set_gate(&g_host_idt.idt[IDT_VECTOR_GP], (UINT64)asm_host_gp_handler, cs, IDT_TYPE_INTERRUPT_GATE, 0);

    //
    // #PF: advance RIP instead of halting. A #PF in VMX-root means we accessed
    // a page not mapped in the private host CR3. Halting causes CLOCK_WATCHDOG_TIMEOUT.
    // Advancing RIP lets the CPU continue (skips the faulting instruction).
    //
    hostidt_set_gate(&g_host_idt.idt[IDT_VECTOR_PF], (UINT64)asm_host_pf_handler, cs, IDT_TYPE_INTERRUPT_GATE, 0);

    g_host_idt.initialized = TRUE;
    return TRUE;
}

UINT64
hostidt_get_base(VOID)
{
    return (UINT64)&g_host_idt.idt[0];
}

VOID
hostidt_destroy(VOID)
{
    g_host_idt.initialized = FALSE;
}

/* ===========================================================================
 *  VMX-root fatal-exception panic  ("BSOD even in VMX" mechanism)
 * ===========================================================================
 *  Old host handlers: #PF did "add [rsp+8],1" (advances 1 byte -> lands
 *  mid-instruction -> #UD -> default handler -> cli;hlt -> silent freeze,
 *  the "only mouse moves" symptom). #DF/#GP/default just cli;hlt. Neither
 *  produced any diagnostic.
 *
 *  New path (called from AsmHostIdt.asm):
 *    1. Stamp crash data into CMOS NVRAM (port 0x70/0x71, battery-backed).
 *       CMOS survives even a triple-fault hard reset, so the record is always
 *       recoverable after reboot -- the "record even if VMX dies" guarantee.
 *    2. KeBugCheckEx(0xDEADC0DE,...). The private host CR3 (hostcr3_build)
 *       deep-copies the full system PML4 (entries 256..511), so ntoskrnl and
 *       KeBugCheckEx are mapped in VMX-root -> real minidump with CR2/RIP/err
 *       in the 4 bugcheck parameters.
 *
 *  CMOS crash layout (read after reboot, bytes 0x50..0x6F):
 *    0x50 magic 0xA5   0x51 type(1=#PF,2=#exc)   0x52 vector   0x53 rsv
 *    0x54..0x5B fault VA (CR2)    0x5C..0x63 faulting RIP
 *    0x64..0x67 error code        0x68..0x6F active CR3
 * ======================================================================== */

#define HV_BUGCHECK_CODE      0xDEADC0DE
#define HV_PANIC_HOST_PF      0xFF01u
#define HV_PANIC_HOST_EXC     0xFF02u

#define W_CMOS_MAGIC_OFF      0x50
#define W_CMOS_MAGIC          0xA5
#define W_CMOS_TYPE_OFF       0x51
#define W_CMOS_VEC_OFF        0x52
#define W_CMOS_VA_OFF         0x54    /* 8 bytes */
#define W_CMOS_RIP_OFF        0x5C    /* 8 bytes */
#define W_CMOS_ERR_OFF        0x64    /* 4 bytes */
#define W_CMOS_CR3_OFF        0x68    /* 8 bytes */

static volatile LONG g_host_panic_fired = 0;

/* VMX-root safe CMOS writes (port I/O only, no API, no lock). Crash path only:
 * guarded by g_host_panic_fired so at most one CPU writes CMOS per boot. */
static void w_cmos_byte(UCHAR idx, UCHAR data)
{
    __outbyte(0x70, idx & 0x7F);    /* bit7=0 -> do not mask NMI */
    __outbyte(0x71, data);
    __outbyte(0x70, 0x0D);          /* restore index, keep NMI enabled */
}
static void w_cmos_qword(UCHAR idx, UINT64 val)
{
    for (int i = 0; i < 8; i++)
        w_cmos_byte((UCHAR)(idx + i), (UCHAR)(val >> (i * 8)));
}
static void w_cmos_dword(UCHAR idx, UINT32 val)
{
    for (int i = 0; i < 4; i++)
        w_cmos_byte((UCHAR)(idx + i), (UCHAR)(val >> (i * 8)));
}

/* Called from asm_host_pf_handler (host IDT #PF). Never returns. */
extern "C" __declspec(noinline) VOID
hv_host_pf_panic(UINT64 cr2, UINT64 rip, UINT64 err, UINT64 cr3)
{
    if (_InterlockedCompareExchange(&g_host_panic_fired, 1, 0) == 0)
    {
        w_cmos_byte(W_CMOS_MAGIC_OFF, W_CMOS_MAGIC);
        w_cmos_byte(W_CMOS_TYPE_OFF, 1);
        w_cmos_byte(W_CMOS_VEC_OFF, 0x0E);
        w_cmos_qword(W_CMOS_VA_OFF, cr2);
        w_cmos_qword(W_CMOS_RIP_OFF, rip);
        w_cmos_dword(W_CMOS_ERR_OFF, (UINT32)err);
        w_cmos_qword(W_CMOS_CR3_OFF, cr3);
    }
    KeBugCheckEx(HV_BUGCHECK_CODE, (ULONG_PTR)HV_PANIC_HOST_PF,
                 (ULONG_PTR)cr2, (ULONG_PTR)rip, (ULONG_PTR)err);
    _disable();
    for (;;) { __halt(); }
}

/* Called from asm_host_df/gp/default_handler. Never returns. */
extern "C" __declspec(noinline) VOID
hv_host_exc_panic(UINT64 vector, UINT64 rip, UINT64 err)
{
    UINT64 cr3 = __readcr3();
    if (_InterlockedCompareExchange(&g_host_panic_fired, 1, 0) == 0)
    {
        w_cmos_byte(W_CMOS_MAGIC_OFF, W_CMOS_MAGIC);
        w_cmos_byte(W_CMOS_TYPE_OFF, 2);
        w_cmos_byte(W_CMOS_VEC_OFF, (UCHAR)(vector & 0xFF));
        w_cmos_qword(W_CMOS_RIP_OFF, rip);
        w_cmos_dword(W_CMOS_ERR_OFF, (UINT32)err);
        w_cmos_qword(W_CMOS_CR3_OFF, cr3);
    }
    KeBugCheckEx(HV_BUGCHECK_CODE, (ULONG_PTR)HV_PANIC_HOST_EXC,
                 (ULONG_PTR)vector, (ULONG_PTR)rip, (ULONG_PTR)err);
    _disable();
    for (;;) { __halt(); }
}
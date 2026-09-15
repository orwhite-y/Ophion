/*
*   ept_hook.cpp - EPT hook engine (split-TLB / dual-page)
*
*   architecture:
*     caller (any kernel driver) fills EPT_HOOK_VMCALL_PARAM at PASSIVE_LEVEL,
*     DPC-broadcasts VMCALL(VMCALL_EPT_HOOK, &param) to every CPU.
*     VMX-root handler:
*       1. switches CR3 to guest CR3 (access guest memory safely)
*       2. splits 2MB page from pre-allocated pool
*       3. copies target page → fake page, runs LDE, builds trampoline
*       4. writes hook payload, modifies EPT PTE
*       5. restores host CR3, INVEPT
*/
#include "hv.h"
#include "log.h"

// Forward declaration: secondary CPU hook installation (EPT-only, no allocation)
BOOLEAN ept_hook_install_secondary_cpu(
    VIRTUAL_MACHINE_STATE * vcpu,
    PEPT_HOOK_VMCALL_PARAM req,
    UINT64 target_pfn,
    UINT64 phys_addr);

#define PFN_MASK  0x000FFFFFFFFFF000ULL
#define POOL_TAG_SPLIT       0
#define POOL_TAG_HOOKED_PAGE 1
#define POOL_TAG_HOOKED_FUNC 2
#define POOL_TAG_TRAMPOLINE  3

#define EPT_PML1_PAGE_OFFSET(_a) (((UINT64)(_a)) & 0xFFF)

// mask PCID and no-flush bit from CR3, keep only PML4 physical address
#define CR3_ADDR_MASK  0x000FFFFFFFFFF000ULL

#ifndef INT32_MIN
#define INT32_MIN (-2147483647 - 1)
#define INT32_MAX 2147483647
#endif
#ifndef INT8_MIN
#define INT8_MIN (-128)
#define INT8_MAX 127
#endif

//
// spinlock for serializing the "new page" full install path in ept_hook_install.
// the DPC broadcast VMCALL handler uses InterlockedCompareExchange on the shared
// req->installed field, but the OPHION_VMCALL_ID path builds per-CPU local_req,
// so this lock provides defense-in-depth for all VMCALL dispatch paths.
//
static volatile LONG g_hook_list_lock = 0;

// Diagnostic: last failure point in ept_hook_install (0=success, 1+=failure code)
volatile UINT64 g_ept_hook_diag = 0;
volatile UINT64 g_ept_hook_diag2 = 0;  // sub-diagnostic (LDE length, instruction bytes)
#define HOOK_DIAG_NO_EPT       1
#define HOOK_DIAG_NO_PHYS      2
#define HOOK_DIAG_TRAMP_SAME   3
#define HOOK_DIAG_POOL_FUNC_S  4
#define HOOK_DIAG_POOL_TRMP_S  5
#define HOOK_DIAG_TRAMP_NEWF   6
#define HOOK_DIAG_SPLIT_FAIL   7
#define HOOK_DIAG_NO_PML1      8
#define HOOK_DIAG_POOL_PAGE    9
#define HOOK_DIAG_POOL_FUNC_N  10
#define HOOK_DIAG_POOL_TRMP_N  11
#define HOOK_DIAG_STEALTH_REG  12
#define HOOK_DIAG_TRAMP_NEWP   13
#define HOOK_DIAG_INVALID_CR3  14  // CR3 validation failed (NULL, unaligned, or out of range)
#define HOOK_DIAG_CR3_FAULT    15  // CR3 switch caused #PF (process exited or CR3 invalid)
#define HOOK_DIAG_SECONDARY_NO_PAGE  16  // Secondary CPU: HOOKED_PAGE_INFO not found
#define HOOK_DIAG_SECONDARY_SPLIT    17  // Secondary CPU: split large page failed
#define HOOK_DIAG_SECONDARY_NO_PML1  18  // Secondary CPU: PML1 entry not found
#define HOOK_DIAG_INVALID_HOOK_TYPE 19
#define HOOK_DIAG_LDE_FAILED       20
#define HOOK_DIAG_CROSS_PAGE       21
#define HOOK_DIAG_HOOK_OVERLAP     22
#define HOOK_DIAG_TRAMP_SIZE       23
#define HOOK_DIAG_CR3_CONFLICT     24
#define HOOK_DIAG_PAGE_RACE        25

static __forceinline VOID
hook_lock_acquire(VOID)
{
    unsigned int wait = 1;
    while (_InterlockedCompareExchange(&g_hook_list_lock, 1, 0) != 0)
    {
        for (unsigned int i = 0; i < wait; i++)
            _mm_pause();
        if (wait < 4096)
            wait <<= 1;
    }
}

//
// DIAG: track which EPT-hooked R3 functions (VMCALL type-1) actually fire a
// redirect to the renderdoc proxy, and how often. Answers:
//   - do CreateDXGIFactory1 / D3D12CreateDevice fire at init?  => creation hooked, factory+device wrapped
//   - does any hooked export fire per-frame?                   => wrapper still active
// Correlate va/proxy against T.log "[td-r3] target=... proxy=..." install lines.
// Bounded, lock-free, best-effort (diagnostic only).
//
#define HOOK_FIRE_SLOTS 32
static volatile UINT64 g_hook_fire_va[HOOK_FIRE_SLOTS];
static volatile UINT64 g_hook_fire_proxy[HOOK_FIRE_SLOTS];
static volatile LONG   g_hook_fire_count[HOOK_FIRE_SLOTS];
static volatile LONG   g_hook_fire_total = 0;

static void
ept_hook_fire_record(UINT64 va, UINT64 proxy)
{
    if (!va) return;

    BOOLEAN found = FALSE;
    for (UINT32 i = 0; i < HOOK_FIRE_SLOTS; i++)
    {
        if (g_hook_fire_va[i] == va)
        {
            _InterlockedIncrement(&g_hook_fire_count[i]);
            found = TRUE;
            break;
        }
    }

    if (!found)
    {
        for (UINT32 i = 0; i < HOOK_FIRE_SLOTS; i++)
        {
            if (g_hook_fire_va[i] == 0)
            {
                g_hook_fire_va[i] = va;                 // x64: aligned 64-bit store is atomic
                g_hook_fire_proxy[i] = proxy;
                _InterlockedExchange(&g_hook_fire_count[i], 1);
                HYPERPLATFORM_LOG_WARN_SAFE("[hook-fire] FIRST va=%llx proxy=%llx", va, proxy);
                found = TRUE;
                break;
            }
        }
    }

    if ((_InterlockedIncrement(&g_hook_fire_total) & 4095) == 0)
    {
        for (UINT32 i = 0; i < HOOK_FIRE_SLOTS; i++)
        {
            if (g_hook_fire_va[i])
                HYPERPLATFORM_LOG_WARN_SAFE("[hook-fire] va=%llx proxy=%llx count=%llu",
                    g_hook_fire_va[i], g_hook_fire_proxy[i], (UINT64)g_hook_fire_count[i]);
        }
    }
}

// ---- helpers ----

static VOID
hook_write_absolute_jump(PUINT8 buf, UINT64 dst)
{
    buf[0] = 0x68;
    *(PUINT32)(&buf[1]) = (UINT32)dst;
    buf[5] = 0xC7; buf[6] = 0x44; buf[7] = 0x24; buf[8] = 0x04;
    *(PUINT32)(&buf[9]) = (UINT32)(dst >> 32);
    buf[13] = 0xC3;
}

// The trampoline may live far away from the hooked image.  Copying an x64
// instruction byte-for-byte is therefore not sufficient: RIP-relative
// operands and relative branches retain the old instruction address.  Fix the
// common encodings used by PE export thunks/prologues while the bytes are
// still in the guest address space.
static BOOLEAN
hook_relocate_instruction(PUINT8 src, PUINT8 dst, SIZE_T len,
                          UINT64 src_va, UINT64 dst_va)
{
    if (!src || !dst || !len) return FALSE;
    RtlCopyMemory(dst, src, len);

    UCHAR op = src[0];
    SIZE_T prefix = 0;
    while (prefix < len && (src[prefix] == 0x40 || src[prefix] == 0x41 ||
                            src[prefix] == 0x42 || src[prefix] == 0x43 ||
                            src[prefix] == 0x44 || src[prefix] == 0x45 ||
                            src[prefix] == 0x46 || src[prefix] == 0x47 ||
                            src[prefix] == 0x66 || src[prefix] == 0x67))
        prefix++;
    if (prefix >= len) return TRUE;
    op = src[prefix++];

    // CALL/JMP rel32 and short JMP.
    if ((op == 0xE8 || op == 0xE9) && len >= prefix + 4)
    {
        INT32 old_disp = *(INT32 *)(src + prefix);
        UINT64 target = src_va + len + (INT64)old_disp;
        INT64 new_disp = (INT64)target - (INT64)(dst_va + len);

        if (new_disp < INT32_MIN || new_disp > INT32_MAX)
        {
            //
            // Distance exceeds ±2GB → convert to absolute jump/call
            // This eliminates the need for near-trampoline allocation
            //
            // E8 (call rel32) → FF 15 00 00 00 00 + 8-byte target (14 bytes)
            // E9 (jmp  rel32) → FF 25 00 00 00 00 + 8-byte target (14 bytes)
            //
            if (len < 14)
            {
                // Not enough space for absolute jump (need 14 bytes)
                g_ept_hook_diag2 = (1ULL<<48)|((UINT64)new_disp & 0xFFFFFFFFFFFFULL);
                return FALSE;
            }

            // Build absolute jump/call
            dst[0] = 0xFF;                      // call/jmp [rip+0]
            dst[1] = (op == 0xE8) ? 0x15 : 0x25;  // ModRM: call=0x15, jmp=0x25
            *(UINT32 *)&dst[2] = 0x00000000;    // disp32 = 0
            *(UINT64 *)&dst[6] = target;        // 64-bit target address

            // Fill remaining bytes with NOP
            for (SIZE_T i = 14; i < len; i++)
                dst[i] = 0x90;

            return TRUE;
        }

        *(INT32 *)(dst + prefix) = (INT32)new_disp;
        return TRUE;
    }
    if (op == 0xEB && len >= prefix + 1)
    {
        INT8 old_disp = *(INT8 *)(src + prefix);
        UINT64 target = src_va + len + (INT64)old_disp;
        INT64 new_disp = (INT64)target - (INT64)(dst_va + len);
        if (new_disp < INT8_MIN || new_disp > INT8_MAX) { g_ept_hook_diag2 = (2ULL<<48)|((UINT64)new_disp & 0xFFFFFFFFFFFFULL); return FALSE; }
        *(INT8 *)(dst + prefix) = (INT8)new_disp;
        return TRUE;
    }

    // Most RIP-relative instructions have a ModRM byte with mod=00,r/m=101.
    // Handle the common one-byte opcode forms and 0F 8x conditional branches.
    if (op == 0x0F && prefix < len && (src[prefix] & 0xF0) == 0x80)
    {
        if (len < prefix + 5) return TRUE;
        INT32 old_disp = *(INT32 *)(src + prefix + 1);
        UINT64 target = src_va + len + (INT64)old_disp;
        INT64 new_disp = (INT64)target - (INT64)(dst_va + len);
        if (new_disp < INT32_MIN || new_disp > INT32_MAX) { g_ept_hook_diag2 = (3ULL<<48)|((UINT64)new_disp & 0xFFFFFFFFFFFFULL); return FALSE; }
        *(INT32 *)(dst + prefix + 1) = (INT32)new_disp;
        return TRUE;
    }

    const BOOLEAN has_modrm = (op == 0x88 || op == 0x89 || op == 0x8A ||
                               op == 0x8B || op == 0x8D || op == 0x8F ||
                               op == 0x03 || op == 0x0B || op == 0x2B ||
                               op == 0x33 || op == 0x3B || op == 0x39 ||
                               op == 0x3A || op == 0x85 || op == 0x84 ||
                               op == 0xC6 || op == 0xC7 || op == 0xFF);
    if (has_modrm && prefix < len)
    {
        UCHAR modrm = src[prefix];
        if ((modrm & 0xC7) == 0x05 && len >= prefix + 5)
        {
            INT32 old_disp = *(INT32 *)(src + prefix + 1);
            UINT64 target = src_va + len + (INT64)old_disp;
            INT64 new_disp = (INT64)target - (INT64)(dst_va + len);

            if (new_disp < INT32_MIN || new_disp > INT32_MAX)
            {
                //
                // RIP-relative operand exceeds ±2GB
                // Cannot easily convert to absolute (requires full instruction rewriting)
                // This is rare in practice - most RIP-relative operands stay within range
                //
                g_ept_hook_diag2 = (4ULL<<48)|((UINT64)new_disp & 0xFFFFFFFFFFFFULL);
                return FALSE;
            }

            *(INT32 *)(dst + prefix + 1) = (INT32)new_disp;
        }
    }
    return TRUE;
}

static BOOLEAN
hook_calculate_patch_size(PVOID target_function, UINT32 hook_type, SIZE_T *out_size)
{
    if (!target_function || !out_size)
        return FALSE;

    if (hook_type > 2)
    {
        g_ept_hook_diag = HOOK_DIAG_INVALID_HOOK_TYPE;
        return FALSE;
    }

    SIZE_T minimum = (hook_type == 1) ? 3 : (hook_type == 2) ? 1 : 14;
    SIZE_T page_offset = (UINT64)target_function & 0xfff;
    SIZE_T size = 0;

    while (size < minimum)
    {
        if (page_offset + size >= PAGE_SIZE)
        {
            g_ept_hook_diag = HOOK_DIAG_CROSS_PAGE;
            g_ept_hook_diag2 = (UINT64)page_offset | ((UINT64)size << 32);
            return FALSE;
        }

        SIZE_T instruction_size = LDE((PUINT8)target_function + size, 64);
        if (!instruction_size || instruction_size > 64)
        {
            g_ept_hook_diag = HOOK_DIAG_LDE_FAILED;
            g_ept_hook_diag2 = (UINT64)size | ((UINT64)instruction_size << 32);
            return FALSE;
        }

        if (page_offset + size + instruction_size > PAGE_SIZE)
        {
            g_ept_hook_diag = HOOK_DIAG_CROSS_PAGE;
            g_ept_hook_diag2 = (UINT64)page_offset | ((UINT64)size << 16) | ((UINT64)instruction_size << 32);
            return FALSE;
        }

        size += instruction_size;
    }

    if (size > 114)
    {
        g_ept_hook_diag = HOOK_DIAG_TRAMP_SIZE;
        g_ept_hook_diag2 = (UINT64)size;
        return FALSE;
    }

    *out_size = size;
    return TRUE;
}

static BOOLEAN
hook_ranges_overlap(PVOID a, SIZE_T a_size, PVOID b, SIZE_T b_size)
{
    if (!a || !b || !a_size || !b_size)
        return TRUE;

    UINT64 a_start = (UINT64)a;
    UINT64 b_start = (UINT64)b;

    return a_start < b_start + b_size &&
           b_start < a_start + a_size;
}

static BOOLEAN
hook_build_trampoline(PUINT8 src, PUINT8 dst, SIZE_T hook_size,
                       UINT64 src_va, UINT64 dst_va)
{
    SIZE_T off = 0;
    while (off < hook_size)
    {
        SIZE_T insn = LDE(src + off, 64);
        if (!insn || off + insn > hook_size)
        {
            g_ept_hook_diag2 = ((UINT64)off << 32) | (insn & 0xFFFFFFFF);
            return FALSE;
        }
        if (!hook_relocate_instruction(src + off, dst + off, insn,
                                       src_va + off, dst_va + off))
            return FALSE;
        off += insn;
    }
    return TRUE;
}

static VOID
ept_swap_page(PEPT_PML1_ENTRY entry, EPT_PML1_ENTRY value, EPT_POINTER eptp)
{
    entry->AsUInt = value.AsUInt;
    _mm_mfence();
    INVEPT_DESCRIPTOR desc = {0};
    desc.EptPointer = eptp;
    asm_invept(InveptSingleContext, &desc);
}

//
// split 2MB 鈫?4KB using pool manager (safe in VMX-root, no ExAllocatePool)
//
//
// split 2MB 鈫?4KB using pool manager (safe in VMX-root)
// returns the split buffer so caller can access PML1 entries directly
// (avoids pa_to_va/MmGetVirtualForPhysical which may not work in VMX-root)
//
// PITFALL #6: Split buffer must be page-aligned. FIX: Pool uses MmAllocateContiguousMemory instead of ExAllocatePool2.
// NOT static 鈥?also used by ept_stealth.cpp (VMX-root safe split)
PVMM_EPT_DYNAMIC_SPLIT
ept_split_large_page_pool(PVMM_EPT_PAGE_TABLE page_table, SIZE_T phys_addr)
{
    PEPT_PML2_ENTRY target = ept_get_pml2(page_table, phys_addr);
    if (!target || !target->LargePage)
        return NULL;

    PVMM_EPT_DYNAMIC_SPLIT new_split = (PVMM_EPT_DYNAMIC_SPLIT)
        pool_manager_request(POOL_TAG_SPLIT, sizeof(VMM_EPT_DYNAMIC_SPLIT));
    if (!new_split)
        return NULL;

    RtlZeroMemory(new_split, sizeof(VMM_EPT_DYNAMIC_SPLIT));
    new_split->u.Entry = target;

    EPT_PML1_ENTRY tmpl;
    tmpl.AsUInt        = 0;
    tmpl.ReadAccess    = 1;
    tmpl.WriteAccess   = 1;
    tmpl.ExecuteAccess = 1;
    __stosq((SIZE_T *)&new_split->PML1[0], tmpl.AsUInt, VMM_EPT_PML1E_COUNT);

    for (SIZE_T i = 0; i < VMM_EPT_PML1E_COUNT; i++)
    {
        new_split->PML1[i].PageFrameNumber =
            ((target->PageFrameNumber * SIZE_2_MB) / PAGE_SIZE) + i;
        new_split->PML1[i].MemoryType =
            ept_get_memory_type(new_split->PML1[i].PageFrameNumber, FALSE);
    }

    EPT_PML2_POINTER new_ptr;
    new_ptr.AsUInt          = 0;
    new_ptr.ReadAccess      = 1;
    new_ptr.WriteAccess     = 1;
    new_ptr.ExecuteAccess   = 1;
    // PITFALL #7: Don't call MmGetPhysicalAddress in VMX-root.
    // FIX: pool_manager_get_physical() returns PA pre-computed at PASSIVE_LEVEL during init.
    new_ptr.PageFrameNumber = pool_manager_get_physical(new_split) / PAGE_SIZE;

    RtlCopyMemory(target, &new_ptr, sizeof(new_ptr));
    return new_split;
}

// =========================================================================
//  VMX-root: ept_hook_install 鈥?called from VMCALL handler per-CPU
//  caller must switch CR3 to caller_cr3 BEFORE calling this.
//
//  first CPU (InterlockedCmpExchg installed 0鈫?):
//    full install: alloc, copy page, LDE, trampoline, fake page, list add
//  other CPUs:
//    just split their own EPT page + modify PTE + invept
// =========================================================================

//
// ept_hook_install 鈥?鍦?VMX-root 涓嬭繍琛?
// 鏀寔 private host CR3: 璋冪敤鏂?(VMCALL handler) 宸茬粡 vmx_enter_guest_cr3()
// 鍒囨崲鍒?system CR3銆傚浜?R3 hook 浼氶澶栧垏鍒?caller_cr3 璁块棶鐢ㄦ埛鎬?VA銆?
//
// R3 hook (target_cr3 != 0):
//   - 鍒囨崲鍒?caller_cr3 璁块棶鐢ㄦ埛鎬佺洰鏍?VA (MmGetPhysicalAddress, RtlCopyMemory, LDE)
//   - 浣跨敤 caller 鎻愪緵鐨?user_trampoline (R3 鍙墽琛屽唴瀛? 浠ｆ浛 kernel pool
//   - violation handler 鎸?CR3 杩囨护: 鍙湁鐩爣杩涚▼鐪嬪埌 hook锛屽叾浠栬繘绋嬮€忎紶
BOOLEAN
ept_hook_install(VIRTUAL_MACHINE_STATE * vcpu, PEPT_HOOK_VMCALL_PARAM req)
{
    if (!vcpu->ept_page_table || !req->target_function)
    {
        g_ept_hook_diag = HOOK_DIAG_NO_EPT;
        return FALSE;
    }

    //
    // is_r3: need CR3 switch to access user-mode target VA.
    // triggered when target_cr3 is set (per-process hook) OR when
    // user_trampoline is provided (shellcode inject with target_cr3=0).
    //
    // target_cr3 controls EPT violation per-process CR3 filtering (separate).
    //
    BOOLEAN is_r3 = (req->target_cr3 != 0 || req->user_trampoline != NULL);

    //
    // R3 hook / inject: switch to caller_cr3 (target process) for user-mode VA access.
    // system CR3 doesn't map user-mode VAs of other processes.
    // kernel VAs (pool, EPT tables, VMM stack) are mapped in all CR3s.
    //
    UINT64 pre_cr3 = 0;
    UINT64 pre_rflags = 0;
    if (is_r3 && req->caller_cr3)
    {
        //
        // CRITICAL: Validate CR3 before switching
        // Invalid CR3 causes Triple Fault → instant reboot
        //
        // Basic validation:
        // 1. CR3 must be page-aligned (bits 0-11 must be 0, except PCID in bits 0-11 if CR4.PCIDE=1)
        // 2. CR3 PFN must be reasonable (not NULL, not kernel space)
        // 3. Ideally: verify PML4 is accessible
        //
        UINT64 cr3_pfn = (req->caller_cr3 & PFN_MASK) >> 12;

        // Check 1: NULL CR3
        if (cr3_pfn == 0)
        {
            g_ept_hook_diag = HOOK_DIAG_INVALID_CR3;
            return FALSE;
        }

        // Check 2: Page alignment (allow PCID bits 0-11)
        // PFN_MASK already clears low 12 bits, so if result is 0 → invalid
        if ((req->caller_cr3 & PFN_MASK) == 0)
        {
            g_ept_hook_diag = HOOK_DIAG_INVALID_CR3;
            return FALSE;
        }

        // Check 3: Unreasonable PFN (too high, likely corrupted)
        // On x64, physical memory typically < 256TB (PFN < 0x1000000000)
        if (cr3_pfn > 0x1000000000ULL)
        {
            g_ept_hook_diag = HOOK_DIAG_INVALID_CR3;
            g_ept_hook_diag2 = req->caller_cr3;
            return FALSE;
        }

        pre_cr3 = __readcr3();
        __writecr3(req->caller_cr3);
        //
        // SMAP: VM exit sets RFLAGS to 0x2 (AC=0). with CR4.SMAP=1,
        // supervisor access to user pages (U/S=1) causes #PF.
        // set AC=1 to allow user page access in VMX-root.
        // (STAC/CLAC may #UD on older CPUs, so use direct RFLAGS write)
        //
        pre_rflags = __readeflags();
        __writeeflags(pre_rflags | (1ULL << 18));  // set AC flag
        _mm_mfence();

        //
        // Verify CR3 switch was safe by attempting to read target VA
        // If CR3 is truly invalid, this will #PF and we catch it below
        //
        __try
        {
            // Probe read: touch first byte of target function
            volatile UINT8 probe = *(volatile UINT8 *)req->target_function;
            (void)probe;  // Suppress unused warning
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            // CR3 switch caused fault → restore and fail
            _mm_mfence();
            __writeeflags(pre_rflags);
            __writecr3(pre_cr3);

            g_ept_hook_diag = HOOK_DIAG_CR3_FAULT;
            g_ept_hook_diag2 = req->caller_cr3;
            return FALSE;
        }
    }

    //
    // macro to restore CR3 + RFLAGS on early return (R3 mode only)
    //
    #define HOOK_RESTORE_CR3_AND_RETURN(val) do { \
        if (is_r3 && pre_cr3) { \
            _mm_mfence(); \
            __writeeflags(pre_rflags); \
            __writecr3(pre_cr3); \
        } \
        return (val); \
    } while(0)

    UINT64 phys_addr = MmGetPhysicalAddress(req->target_function).QuadPart;
    if (!phys_addr)
    {
        g_ept_hook_diag = HOOK_DIAG_NO_PHYS;
        HOOK_RESTORE_CR3_AND_RETURN(FALSE);
    }

    UINT64 target_pfn = phys_addr >> 12;

    //
    // OPTIMIZATION: Secondary CPU fast path
    // If is_primary_cpu == FALSE, skip resource allocation and only modify EPT
    // This eliminates race conditions and pool waste from concurrent installations
    //
    if (req->is_primary_cpu == FALSE)
    {
        BOOLEAN ok = ept_hook_install_secondary_cpu(vcpu, req, target_pfn, phys_addr);
        HOOK_RESTORE_CR3_AND_RETURN(ok);
    }

    //
    // PRIMARY CPU path: full installation (resource allocation + EPT)
    //

    // 妫€鏌ユ槸鍚﹀凡 hook 杩囪繖涓〉闈?
    SIZE_T requested_size = 0;
    UINT64 requested_cr3 = req->target_cr3 & CR3_ADDR_MASK;
    if (!hook_calculate_patch_size(req->target_function,
                                   req->hook_type,
                                   &requested_size))
    {
        HOOK_RESTORE_CR3_AND_RETURN(FALSE);
    }

    hook_lock_acquire();

    struct _LIST_ENTRY * hcur;
    for (hcur = g_ept->hooked_pages.Flink; hcur != &g_ept->hooked_pages; hcur = hcur->Flink)
    {
        PEPT_HOOKED_PAGE_INFO existing = CONTAINING_RECORD(hcur, EPT_HOOKED_PAGE_INFO, hooked_page_list);
        if (existing->pfn_of_hooked_page == target_pfn)
        {
            if ((existing->target_cr3 & CR3_ADDR_MASK) != requested_cr3)
            {
                g_ept_hook_diag = HOOK_DIAG_CR3_CONFLICT;
                g_ept_hook_diag2 = existing->target_cr3;
                _InterlockedExchange(&g_hook_list_lock, 0);
                HOOK_RESTORE_CR3_AND_RETURN(FALSE);
            }

            PEPT_HOOKED_FUNCTION_INFO exact_function = NULL;
            for (PLIST_ENTRY fc = existing->hooked_functions_list.Flink;
                 fc != &existing->hooked_functions_list; fc = fc->Flink)
            {
                PEPT_HOOKED_FUNCTION_INFO efi = CONTAINING_RECORD(
                    fc, EPT_HOOKED_FUNCTION_INFO, hooked_function_list);

                if (efi->virtual_address == req->target_function)
                {
                    exact_function = efi;
                }
                else if (hook_ranges_overlap(efi->virtual_address,
                                             efi->hook_size,
                                             req->target_function,
                                             requested_size))
                {
                    g_ept_hook_diag = HOOK_DIAG_HOOK_OVERLAP;
                    g_ept_hook_diag2 = (UINT64)efi->virtual_address;
                    _InterlockedExchange(&g_hook_list_lock, 0);
                    HOOK_RESTORE_CR3_AND_RETURN(FALSE);
                }
            }

            if (exact_function)
            {
                PUINT8 trampoline = NULL;
                BOOLEAN user_trampoline = FALSE;

                if (is_r3 && req->user_trampoline)
                {
                    trampoline = (PUINT8)req->user_trampoline;
                    user_trampoline = TRUE;
                }
                else if (!exact_function->user_trampoline)
                {
                    trampoline = exact_function->first_trampoline_address;
                    user_trampoline = FALSE;
                }

                if (!trampoline)
                {
                    g_ept_hook_diag = HOOK_DIAG_TRAMP_NEWF;
                    _InterlockedExchange(&g_hook_list_lock, 0);
                    HOOK_RESTORE_CR3_AND_RETURN(FALSE);
                }

                if (!hook_build_trampoline((PUINT8)req->target_function,
                                           trampoline,
                                           requested_size,
                                           (UINT64)req->target_function,
                                           (UINT64)trampoline))
                {
                    g_ept_hook_diag = HOOK_DIAG_TRAMP_NEWF;
                    _InterlockedExchange(&g_hook_list_lock, 0);
                    HOOK_RESTORE_CR3_AND_RETURN(FALSE);
                }
                hook_write_absolute_jump(&trampoline[requested_size],
                                         (UINT64)req->target_function + requested_size);

                UINT64 off = EPT_PML1_PAGE_OFFSET(req->target_function);
                PUINT8 fake = &existing->fake_page_va[off];
                switch (req->hook_type) {
                case 0: hook_write_absolute_jump(fake, (UINT64)req->proxy_function); break;
                case 1: fake[0]=0x0F; fake[1]=0x01; fake[2]=0xC1; break;
                case 2: fake[0]=0xCC; break;
                }

                _InterlockedExchange(&exact_function->retiring, 0);
                _InterlockedExchange(&exact_function->oneshot_fired, 0);
                exact_function->handler_function = req->proxy_function;
                exact_function->oneshot = req->oneshot;
                exact_function->expected_tid = req->expected_tid;
                exact_function->hook_type = req->hook_type;
                exact_function->external_fired = req->external_fired;
                exact_function->first_trampoline_address = trampoline;
                exact_function->hook_size = requested_size;
                exact_function->user_trampoline = user_trampoline;

                if (req->origin_function)
                    *req->origin_function = trampoline;
            }
            else
            {
                PEPT_HOOKED_FUNCTION_INFO fi = (PEPT_HOOKED_FUNCTION_INFO)
                    pool_manager_request(POOL_TAG_HOOKED_FUNC, sizeof(EPT_HOOKED_FUNCTION_INFO));
                if (!fi)
                {
                    g_ept_hook_diag = HOOK_DIAG_POOL_FUNC_S;
                    _InterlockedExchange(&g_hook_list_lock, 0);
                    HOOK_RESTORE_CR3_AND_RETURN(FALSE);
                }
                RtlZeroMemory(fi, sizeof(*fi));

                if (is_r3 && req->user_trampoline)
                {
                    fi->first_trampoline_address = (PUINT8)req->user_trampoline;
                    fi->user_trampoline = TRUE;
                }
                else
                {
                    fi->first_trampoline_address = (PUINT8)pool_manager_request(POOL_TAG_TRAMPOLINE, 128);
                    fi->user_trampoline = FALSE;
                }
                if (!fi->first_trampoline_address)
                {
                    g_ept_hook_diag = HOOK_DIAG_POOL_TRMP_S;
                    pool_manager_release(fi);
                    _InterlockedExchange(&g_hook_list_lock, 0);
                    HOOK_RESTORE_CR3_AND_RETURN(FALSE);
                }

                fi->virtual_address    = req->target_function;
                fi->fake_page_contents = existing->fake_page_va;
                fi->handler_function   = req->proxy_function;
                fi->oneshot            = req->oneshot;
                fi->expected_tid       = req->expected_tid;
                fi->hook_type          = req->hook_type;
                fi->external_fired     = req->external_fired;
                fi->hook_size          = requested_size;

                if (!hook_build_trampoline((PUINT8)req->target_function,
                                           fi->first_trampoline_address,
                                           requested_size,
                                           (UINT64)req->target_function,
                                           (UINT64)fi->first_trampoline_address))
                {
                    if (!fi->user_trampoline)
                        pool_manager_release(fi->first_trampoline_address);
                    pool_manager_release(fi);
                    g_ept_hook_diag = HOOK_DIAG_TRAMP_NEWF;
                    _InterlockedExchange(&g_hook_list_lock, 0);
                    HOOK_RESTORE_CR3_AND_RETURN(FALSE);
                }
                hook_write_absolute_jump(&fi->first_trampoline_address[requested_size],
                                         (UINT64)req->target_function + requested_size);

                if (req->origin_function)
                    *req->origin_function = fi->first_trampoline_address;

                UINT64 off = EPT_PML1_PAGE_OFFSET(req->target_function);
                PUINT8 fake = &existing->fake_page_va[off];
                switch (req->hook_type) {
                case 0: hook_write_absolute_jump(fake, (UINT64)req->proxy_function); break;
                case 1: fake[0]=0x0F; fake[1]=0x01; fake[2]=0xC1; break;
                case 2: fake[0]=0xCC; break;
                }

                InsertHeadList(&existing->hooked_functions_list, &fi->hooked_function_list);
            }

            {
                PEPT_PML2_ENTRY p2 = ept_get_pml2(vcpu->ept_page_table, (SIZE_T)phys_addr);
                if (p2 && p2->LargePage)
                    ept_split_large_page_pool(vcpu->ept_page_table, (SIZE_T)phys_addr);

                PEPT_PML1_ENTRY p1 = ept_get_pml1(vcpu->ept_page_table, (SIZE_T)phys_addr);
                if (p1)
                {
                    p1->ExecuteAccess = 0;
                    p1->ReadAccess    = 1;
                    p1->WriteAccess   = 1;
                }
            }
            {
                SIZE_T fake_phys = (SIZE_T)(existing->pfn_of_fake_page_contents << 12);
                PEPT_PML2_ENTRY fp2 = ept_get_pml2(vcpu->ept_page_table, fake_phys);
                if (fp2 && fp2->LargePage)
                    ept_split_large_page_pool(vcpu->ept_page_table, fake_phys);
                PEPT_PML1_ENTRY fp1 = ept_get_pml1(vcpu->ept_page_table, fake_phys);
                if (fp1)
                {
                    fp1->ReadAccess = 0;
                    fp1->WriteAccess = 0;
                    fp1->ExecuteAccess = 1;
                }
            }

            _mm_mfence();
            ept_invept_single(vcpu->ept_pointer);
            _InterlockedExchange(&g_hook_list_lock, 0);
            HOOK_RESTORE_CR3_AND_RETURN(TRUE);
        }
    }

    //
    // page not found: the hook-list lock is already held.
    //

    // split 2MB 鈫?4KB
    PVMM_EPT_DYNAMIC_SPLIT split = NULL;
    PEPT_PML1_ENTRY pte = NULL;

    PEPT_PML2_ENTRY pml2 = ept_get_pml2(vcpu->ept_page_table, (SIZE_T)phys_addr);
    if (pml2 && pml2->LargePage)
    {
        split = ept_split_large_page_pool(vcpu->ept_page_table, (SIZE_T)phys_addr);
        if (!split) { g_ept_hook_diag = HOOK_DIAG_SPLIT_FAIL; _InterlockedExchange(&g_hook_list_lock, 0); HOOK_RESTORE_CR3_AND_RETURN(FALSE); }
        pte = &split->PML1[ADDRMASK_EPT_PML1_INDEX(phys_addr)];
    }
    else
    {
        pte = ept_get_pml1(vcpu->ept_page_table, (SIZE_T)phys_addr);
    }
    if (!pte) { g_ept_hook_diag = HOOK_DIAG_NO_PML1; _InterlockedExchange(&g_hook_list_lock, 0); HOOK_RESTORE_CR3_AND_RETURN(FALSE); }

    // 鍒嗛厤璺熻釜缁撴瀯
    PEPT_HOOKED_PAGE_INFO hp = (PEPT_HOOKED_PAGE_INFO)
        pool_manager_request(POOL_TAG_HOOKED_PAGE, sizeof(EPT_HOOKED_PAGE_INFO));
    if (!hp) { g_ept_hook_diag = HOOK_DIAG_POOL_PAGE; _InterlockedExchange(&g_hook_list_lock, 0); HOOK_RESTORE_CR3_AND_RETURN(FALSE); }
    RtlZeroMemory(hp, sizeof(*hp));
    InitializeListHead(&hp->hooked_functions_list);

    PEPT_HOOKED_FUNCTION_INFO fi = (PEPT_HOOKED_FUNCTION_INFO)
        pool_manager_request(POOL_TAG_HOOKED_FUNC, sizeof(EPT_HOOKED_FUNCTION_INFO));
    if (!fi) { g_ept_hook_diag = HOOK_DIAG_POOL_FUNC_N; pool_manager_release(hp); _InterlockedExchange(&g_hook_list_lock, 0); HOOK_RESTORE_CR3_AND_RETURN(FALSE); }
    RtlZeroMemory(fi, sizeof(*fi));

    //
    // trampoline: R3 hook 鐢?caller 鎻愪緵鐨勭敤鎴锋€佸彲鎵ц鍐呭瓨, R0 hook 鐢?kernel pool
    //
    if (is_r3 && req->user_trampoline)
    {
        fi->first_trampoline_address = (PUINT8)req->user_trampoline;
        fi->user_trampoline = TRUE;
    }
    else
    {
        fi->first_trampoline_address = (PUINT8)pool_manager_request(POOL_TAG_TRAMPOLINE, 128);
        fi->user_trampoline = FALSE;
    }
    if (!fi->first_trampoline_address) { g_ept_hook_diag = HOOK_DIAG_POOL_TRMP_N; pool_manager_release(fi); pool_manager_release(hp); _InterlockedExchange(&g_hook_list_lock, 0); HOOK_RESTORE_CR3_AND_RETURN(FALSE); }

    // 璁剧疆 hooked page 鈥?fake page in stealth region (EPT X-only)
    hp->pfn_of_hooked_page = target_pfn;
    {
        UINT64 fake_pfn = 0;
        hp->fake_page_va = stealth_region_alloc_page(&fake_pfn);
        if (!hp->fake_page_va)
        {
            g_ept_hook_diag = HOOK_DIAG_STEALTH_REG;
            if (!fi->user_trampoline && fi->first_trampoline_address)
                pool_manager_release(fi->first_trampoline_address);
            pool_manager_release(fi);
            pool_manager_release(hp);
            _InterlockedExchange(&g_hook_list_lock, 0);
            HOOK_RESTORE_CR3_AND_RETURN(FALSE);
        }
        hp->pfn_of_fake_page_contents = fake_pfn;
    }
    hp->entry_address = pte;
    hp->target_cr3 = req->target_cr3 & CR3_ADDR_MASK;

    // 鎷疯礉鍘熷椤甸潰鍒?fake page (stealth region)
    RtlCopyMemory(hp->fake_page_va, PAGE_ALIGN(req->target_function), PAGE_SIZE);

    // LDE + 鏋勫缓 trampoline
    fi->virtual_address    = req->target_function;
    fi->fake_page_contents = hp->fake_page_va;
    fi->handler_function   = req->proxy_function;
    fi->oneshot            = req->oneshot;
    fi->expected_tid       = req->expected_tid;
    fi->hook_type          = req->hook_type;
    fi->external_fired     = req->external_fired;

    UINT64 off   = EPT_PML1_PAGE_OFFSET(req->target_function);
    PUINT8 fake  = &hp->fake_page_va[off];
    fi->hook_size = requested_size;

    if (!hook_build_trampoline((PUINT8)req->target_function,
                               fi->first_trampoline_address, requested_size,
                               (UINT64)req->target_function,
                               (UINT64)fi->first_trampoline_address))
    {
        if (!fi->user_trampoline)
            pool_manager_release(fi->first_trampoline_address);
        pool_manager_release(fi);
        pool_manager_release(hp);
        g_ept_hook_diag = HOOK_DIAG_TRAMP_NEWP;
        _InterlockedExchange(&g_hook_list_lock, 0);
        HOOK_RESTORE_CR3_AND_RETURN(FALSE);
    }
    hook_write_absolute_jump(&fi->first_trampoline_address[requested_size],
                             (UINT64)req->target_function + requested_size);

    if (req->origin_function)
        *req->origin_function = fi->first_trampoline_address;

    // 鍐?hook payload
    switch (req->hook_type) {
    case 0: hook_write_absolute_jump(fake, (UINT64)req->proxy_function); break;
    case 1: fake[0]=0x0F; fake[1]=0x01; fake[2]=0xC1; break;
    case 2: fake[0]=0xCC; break;
    }

    // PTE 鏉冮檺
    hp->original_entry = *pte;
    hp->original_entry.ExecuteAccess = 0;
    hp->original_entry.ReadAccess    = 1;
    hp->original_entry.WriteAccess   = 1;

    hp->changed_entry = hp->original_entry;
    hp->changed_entry.ReadAccess       = (g_ept->execute_only_supported && !req->force_read_access) ? 0 : 1;
    hp->changed_entry.WriteAccess      = 0;
    hp->changed_entry.ExecuteAccess    = 1;
    hp->changed_entry.PageFrameNumber  = hp->pfn_of_fake_page_contents;

    hp->Options = EPTO_HOOK_FUNCTION;
    InsertHeadList(&hp->hooked_functions_list, &fi->hooked_function_list);
    InsertHeadList(&g_ept->hooked_pages, &hp->hooked_page_list);

    _InterlockedExchange(&g_hook_list_lock, 0);

    //
    // R3 hook: 鍒囧洖 system CR3 (绂诲紑 caller_cr3)
    // 鍚庣画 PTE 淇敼鍜?INVEPT 涓嶉渶瑕佺敤鎴锋€?VA 璁块棶
    //
    if (is_r3 && pre_cr3)
    {
        _mm_mfence();
        __writeeflags(pre_rflags);  // restore RFLAGS (clear AC / SMAP)
        __writecr3(pre_cr3);
        pre_cr3 = 0;   // prevent double-restore in macro
    }

    pte->ExecuteAccess = 0;
    pte->ReadAccess    = 1;
    pte->WriteAccess   = 1;

    // EPT X-only on fake page physical page (stealth region)
    {
        SIZE_T fake_phys = (SIZE_T)(hp->pfn_of_fake_page_contents << 12);
        PEPT_PML2_ENTRY fp2 = ept_get_pml2(vcpu->ept_page_table, fake_phys);
        if (fp2 && fp2->LargePage)
            ept_split_large_page_pool(vcpu->ept_page_table, fake_phys);
        PEPT_PML1_ENTRY fp1 = ept_get_pml1(vcpu->ept_page_table, fake_phys);
        if (fp1) { fp1->ReadAccess = 0; fp1->WriteAccess = 0; fp1->ExecuteAccess = 1; }
    }

    g_ept_hook_diag = 0;
    _mm_mfence();
    ept_invept_single(vcpu->ept_pointer);
    return TRUE;

    #undef HOOK_RESTORE_CR3_AND_RETURN
}

//
// VMX-root: unhook 鈥?first CPU does list removal, all CPUs restore PTE
//
static BOOLEAN
ept_hook_page_has_active_function(PEPT_HOOKED_PAGE_INFO hp)
{
    PLIST_ENTRY fc = hp->hooked_functions_list.Flink;
    while (fc != &hp->hooked_functions_list)
    {
        PEPT_HOOKED_FUNCTION_INFO fn = CONTAINING_RECORD(fc, EPT_HOOKED_FUNCTION_INFO, hooked_function_list);
        if (!fn->retiring)
            return TRUE;
        fc = fc->Flink;
    }
    return FALSE;
}

static VOID
ept_hook_restore_current_vcpu(VIRTUAL_MACHINE_STATE * vcpu, PEPT_HOOKED_PAGE_INFO hp)
{
    PEPT_PML1_ENTRY p = ept_get_pml1(vcpu->ept_page_table, (SIZE_T)(hp->pfn_of_hooked_page << 12));
    if (!p)
        return;

    EPT_PML1_ENTRY passthrough = hp->original_entry;
    passthrough.ReadAccess = 1;
    passthrough.WriteAccess = 1;
    passthrough.ExecuteAccess = 1;
    passthrough.PageFrameNumber = hp->pfn_of_hooked_page;
    p->AsUInt = passthrough.AsUInt;
    _mm_mfence();
    ept_invept_single(vcpu->ept_pointer);
}

BOOLEAN
ept_unhook_install(VIRTUAL_MACHINE_STATE * vcpu, PEPT_UNHOOK_VMCALL_PARAM req)
{
    if (!g_ept || !req->target_function) return FALSE;

    UINT64 phys_addr  = MmGetPhysicalAddress(req->target_function).QuadPart;
    UINT64 target_pfn = phys_addr >> 12;

    PLIST_ENTRY cur = g_ept->hooked_pages.Flink;
    while (cur != &g_ept->hooked_pages)
    {
        PEPT_HOOKED_PAGE_INFO hp = CONTAINING_RECORD(cur, EPT_HOOKED_PAGE_INFO, hooked_page_list);
        cur = cur->Flink;
        if (hp->pfn_of_hooked_page != target_pfn) continue;

        PLIST_ENTRY fc = hp->hooked_functions_list.Flink;
        while (fc != &hp->hooked_functions_list)
        {
            PEPT_HOOKED_FUNCTION_INFO fn = CONTAINING_RECORD(fc, EPT_HOOKED_FUNCTION_INFO, hooked_function_list);
            fc = fc->Flink;
            if (fn->virtual_address == req->target_function)
            {
                if (fn->fake_page_contents && fn->first_trampoline_address && fn->hook_size)
                {
                    UINT64 off = EPT_PML1_PAGE_OFFSET(fn->virtual_address);
                    RtlCopyMemory(&fn->fake_page_contents[off],
                                  fn->first_trampoline_address,
                                  fn->hook_size);
                }
                _InterlockedExchange(&fn->retiring, 1);
                req->result = TRUE;
                break;
            }
        }

        if (req->result)
        {
            if (!ept_hook_page_has_active_function(hp))
                ept_hook_restore_current_vcpu(vcpu, hp);
            return TRUE;
        }
    }

    //
    // 鎭㈠鎵€鏈?CPU 鐨?PTE 鍒?RWX
    // (涓嶈兘鍙仮澶嶅綋鍓?CPU锛屽叾浠?CPU 鐨?EPT PTE 涔熼渶瑕佹仮澶?
    //
    return FALSE;
}

//
// unhook all 鈥?only restore PTEs and free memory.
// does NOT call INVEPT 鈥?caller is responsible for TLB invalidation.
// this is safe to call after VMXOFF (vmx_terminate path).
//
VOID
ept_unhook_all(VOID)
{
    if (!g_ept) return;
    while (!IsListEmpty(&g_ept->hooked_pages))
    {
        PLIST_ENTRY item = RemoveHeadList(&g_ept->hooked_pages);
        PEPT_HOOKED_PAGE_INFO hp = CONTAINING_RECORD(item, EPT_HOOKED_PAGE_INFO, hooked_page_list);
        while (!IsListEmpty(&hp->hooked_functions_list))
        {
            PLIST_ENTRY fi = RemoveHeadList(&hp->hooked_functions_list);
            PEPT_HOOKED_FUNCTION_INFO fn = CONTAINING_RECORD(fi, EPT_HOOKED_FUNCTION_INFO, hooked_function_list);
            if (fn->first_trampoline_address && !fn->user_trampoline)
                pool_manager_release(fn->first_trampoline_address);
            pool_manager_release(fn);
        }
        if (hp->entry_address)
        {
            hp->entry_address->ReadAccess      = 1;
            hp->entry_address->WriteAccess     = 1;
            hp->entry_address->ExecuteAccess   = 1;
            hp->entry_address->PageFrameNumber = hp->pfn_of_hooked_page;
        }
        pool_manager_release(hp);
    }
    // PITFALL #11: No INVEPT here - may be called after VMXOFF when INVEPT would cause #UD.
}

// =========================================================================
//  VMX-root: retire (passthrough) every R3 hook whose page targets a given
//  CR3. Used at process exit to neutralize stale hooks left on the shared
//  d3d12/dxgi pages so the NEXT process is never dispatched to THIS process's
//  (soon-freed) proxy. Sets fi->retiring=TRUE and restores this vCPU's EPT to
//  the original page (RWX); a DPC broadcast runs it on every vCPU. No CR3
//  switch and no user-VA resolution, so it is safe from the process-exit
//  notify callback (unlike VMCALL_EPT_UNHOOK, which loads the dying CR3 on
//  every CPU and deadlocks there).
// =========================================================================
VOID
ept_unhook_by_cr3(VIRTUAL_MACHINE_STATE * vcpu, UINT64 target_cr3)
{
    if (!g_ept || !target_cr3)
        return;

    PLIST_ENTRY cur = g_ept->hooked_pages.Flink;
    while (cur != &g_ept->hooked_pages)
    {
        PEPT_HOOKED_PAGE_INFO hp = CONTAINING_RECORD(cur, EPT_HOOKED_PAGE_INFO, hooked_page_list);
        cur = cur->Flink;

        if ((hp->target_cr3 & CR3_ADDR_MASK) != (target_cr3 & CR3_ADDR_MASK))
            continue;

        // retire every function on this page so both the violation handler
        // (ept_hook_page_has_active_function -> restore) and the VMCALL
        // dispatch (fi->retiring -> restore) pass through to the original
        // code instead of redirecting to this process's proxy.
        PLIST_ENTRY fc = hp->hooked_functions_list.Flink;
        while (fc != &hp->hooked_functions_list)
        {
            PEPT_HOOKED_FUNCTION_INFO fi = CONTAINING_RECORD(fc, EPT_HOOKED_FUNCTION_INFO, hooked_function_list);
            fc = fc->Flink;
            _InterlockedExchange(&fi->retiring, 1);
        }

        // restore THIS vCPU's EPT to the original page (RWX). the DPC broadcast
        // runs this on every vCPU, so all vCPUs drop the hook. target_cr3 is
        // left as-is so non-target processes still take the cheap non-target
        // pass-through in ept_handle_violation without a VMCALL.
        if (!ept_hook_page_has_active_function(hp))
            ept_hook_restore_current_vcpu(vcpu, hp);
    }
}

// =========================================================================
//  VMX-root: EPT violation / MTF / VMCALL-hook handlers
// =========================================================================

BOOLEAN
ept_handle_violation(VIRTUAL_MACHINE_STATE * vcpu, UINT64 guest_phys, UINT64 exit_qual)
{
    VMX_EXIT_QUALIFICATION_EPT_VIOLATION viol;
    viol.AsUInt = exit_qual;
    UINT64 pfn = guest_phys >> 12;

    PLIST_ENTRY cur = g_ept->hooked_pages.Flink;
    while (cur != &g_ept->hooked_pages)
    {
        PEPT_HOOKED_PAGE_INFO hp = CONTAINING_RECORD(cur, EPT_HOOKED_PAGE_INFO, hooked_page_list);
        cur = cur->Flink;
        if (hp->pfn_of_hooked_page != pfn && hp->pfn_of_fake_page_contents != pfn) continue;

        //
        // fake page physical page scan protection:
        // if anti-cheat maps pfn_of_fake_page_contents directly (MmMapIoSpace etc.),
        // EPT X-only 鈫?violation here. swap to hooked page PFN (zeroed) temporarily
        // so the read sees zeros, then MTF swaps back to X-only.
        //
        if (pfn == hp->pfn_of_fake_page_contents && pfn != hp->pfn_of_hooked_page)
        {
            if (viol.ReadAccess || viol.WriteAccess)
            {
                PEPT_PML1_ENTRY fake_pte = ept_get_pml1(vcpu->ept_page_table,
                    (SIZE_T)(hp->pfn_of_fake_page_contents << 12));
                if (fake_pte)
                {
                    // temporarily point to the hooked page (zeroed) for reads
                    EPT_PML1_ENTRY tmp = *fake_pte;
                    tmp.ReadAccess = 1; tmp.WriteAccess = 0; tmp.ExecuteAccess = 0;
                    tmp.PageFrameNumber = hp->pfn_of_hooked_page;  // zeroed page
                    fake_pte->AsUInt = tmp.AsUInt;
                    _mm_mfence();
                    ept_invept_single(vcpu->ept_pointer);

                    vcpu->mtf_restore_page = hp;
                    SIZE_T pc = 0;
                    __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &pc);
                    pc |= (SIZE_T)CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG;
                    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, pc);
                }
                return TRUE;
            }
            continue;
        }

        if (!ept_hook_page_has_active_function(hp))
        {
            ept_hook_restore_current_vcpu(vcpu, hp);
            return TRUE;
        }

        PEPT_PML1_ENTRY my_pte = ept_get_pml1(vcpu->ept_page_table, (SIZE_T)(hp->pfn_of_hooked_page << 12));
        if (!my_pte) continue;

        if (viol.ReadAccess || viol.WriteAccess)
        {
            EPT_PML1_ENTRY orig = hp->original_entry;
            ept_swap_page(my_pte, orig, vcpu->ept_pointer);
            vcpu->mtf_restore_page = hp;
            SIZE_T pc = 0;
            __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &pc);
            pc |= (SIZE_T)CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG;
            __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, pc);
            return TRUE;
        }
        if (viol.ExecuteAccess)
        {
            //
            // R3 hook: per-process filtering.
            // only the target process (matching CR3) sees the fake page (hook).
            // other processes get a temporary RWX pass-through via MTF single-step,
            // executing original code transparently.
            //
            if (hp->target_cr3 != 0)
            {
                UINT64 guest_cr3 = 0;
                __vmx_vmread(VMCS_GUEST_CR3, &guest_cr3);

                if ((guest_cr3 & CR3_ADDR_MASK) != hp->target_cr3)
                {
                    // non-target process: pass through with temporary RWX
                    EPT_PML1_ENTRY passthrough = hp->original_entry;
                    passthrough.ExecuteAccess = 1;
                    ept_swap_page(my_pte, passthrough, vcpu->ept_pointer);
                    vcpu->mtf_restore_page = hp;
                    SIZE_T pc = 0;
                    __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &pc);
                    pc |= (SIZE_T)CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG;
                        __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, pc);
                    return TRUE;
                }
            }

            //
            // TID-filtered oneshot: decide as early as possible.
            // if a non-target thread is executing the hooked entry VA,
            // keep it on the original page here and avoid exposing the
            // fake page / VMCALL path at all.
            //
            UINT64 rip = vcpu->vmexit_rip;
            PLIST_ENTRY fc = hp->hooked_functions_list.Flink;
            while (fc != &hp->hooked_functions_list)
            {
                PEPT_HOOKED_FUNCTION_INFO fi =
                    CONTAINING_RECORD(fc, EPT_HOOKED_FUNCTION_INFO, hooked_function_list);
                fc = fc->Flink;

                if ((UINT64)fi->virtual_address != rip)
                    continue;

                if (fi->expected_tid)
                {
                    UINT64 current_tid = (UINT64)(ULONG_PTR)PsGetCurrentThreadId();
                    if (current_tid != fi->expected_tid)
                    {
                        EPT_PML1_ENTRY passthrough = hp->original_entry;
                        passthrough.ExecuteAccess = 1;
                        ept_swap_page(my_pte, passthrough, vcpu->ept_pointer);
                        vcpu->mtf_restore_page = hp;

                        SIZE_T pc = 0;
                        __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &pc);
                        pc |= (SIZE_T)CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG;
                        __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, pc);
                        return TRUE;
                    }
                }

                break;
            }

            // target process (or R0 hook): swap to fake page (hook visible)
            ept_swap_page(my_pte, hp->changed_entry, vcpu->ept_pointer);
            return TRUE;
        }
    }
    return FALSE;
}

VOID
ept_handle_mtf(VIRTUAL_MACHINE_STATE * vcpu)
{
    SIZE_T pc = 0;
    __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &pc);
    pc &= ~(SIZE_T)CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG;
    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, pc);

    //
    // Shadow-CR3 restore must run first. The same MTF exit can also carry
    // other restore state, and we do not want a prior branch to skip this one.
    //
    if (vcpu->nx_timer_restore)
    {
        //
        // restore the real guest CR3 unconditionally. the shadow window is opened
        // only by us and only for one instruction (MTF), so by the time MTF fires
        // we are on shadow and nx_timer_real_cr3 holds the real CR3. the old code
        // gated the restore on (current_pfn == shadow_pfn) and then cleared the slot
        // regardless - if the compare failed (nested/mismatched shadow) the real CR3
        // was lost and the guest was stranded on shadow, running many instructions
        // on stale shadow tables -> 0x1A. restore whenever a real CR3 is saved;
        // writing it back while already real is a harmless no-op.
        //
        if (vcpu->nx_timer_real_cr3)
            __vmx_vmwrite(VMCS_GUEST_CR3, vcpu->nx_timer_real_cr3);

        vcpu->nx_timer_restore  = NULL;
        vcpu->nx_timer_real_cr3 = 0;

        // restore the NX-fetch-only #PF intercept that the shadow swap widened to
        // "all" for the duration of the window.
        ept_update_pf_intercept(vcpu);
    }

    if (vcpu->mtf_restore_page)
    {
        PEPT_HOOKED_PAGE_INFO hp = vcpu->mtf_restore_page;

        if (!ept_hook_page_has_active_function(hp))
        {
            ept_hook_restore_current_vcpu(vcpu, hp);
            vcpu->mtf_restore_page = NULL;
            return;
        }

        // restore target page EPT
        PEPT_PML1_ENTRY my_pte = ept_get_pml1(vcpu->ept_page_table,
            (SIZE_T)(hp->pfn_of_hooked_page << 12));
        if (my_pte)
        {
            if (hp->fake_pt)
                ept_swap_page(my_pte, hp->changed_entry, vcpu->ept_pointer);
            else
                ept_swap_page(my_pte, hp->original_entry, vcpu->ept_pointer);
        }

        // restore fake page EPT to X-only (in case it was opened for phys scan read)
        if (hp->fake_page_va)
        {
            PEPT_PML1_ENTRY fake_pte = ept_get_pml1(vcpu->ept_page_table,
                (SIZE_T)(hp->pfn_of_fake_page_contents << 12));
            if (fake_pte && fake_pte->ReadAccess)
            {
                fake_pte->ReadAccess = 0; fake_pte->WriteAccess = 0; fake_pte->ExecuteAccess = 1;
                fake_pte->PageFrameNumber = hp->pfn_of_fake_page_contents;
                _mm_mfence();
                ept_invept_single(vcpu->ept_pointer);
            }
        }

        vcpu->mtf_restore_page = NULL;
    }

    //
    // stealth target page MTF: swap back to read-only view (no execute)
    //
    else if (vcpu->mtf_restore_stealth)
    {
        PEPT_STEALTH_PAGE_INFO sp = vcpu->mtf_restore_stealth;
        PEPT_PML1_ENTRY my_pte = ept_get_pml1(vcpu->ept_page_table,
            (SIZE_T)(sp->pfn_of_target << 12));
        if (my_pte)
        {
            my_pte->AsUInt = sp->original_entry.AsUInt;
            _mm_mfence();
            ept_invept_single(vcpu->ept_pointer);
        }
        vcpu->mtf_restore_stealth = NULL;
    }

    //
    // stealth shared fake PT page MTF: resync from real PT page, swap back
    // fires after OS writes a PTE in the same PT page (page in/out, A/D bits)
    //
    else if (vcpu->mtf_restore_fake_pt)
    {
        PSTEALTH_FAKE_PT fpt = vcpu->mtf_restore_fake_pt;

        //
        // resync fake PT page from real PT page BEFORE swapping back.
        // fpt->real_page_va is a system VA from MmGetVirtualForPhysical.
        // it's valid under system CR3, NOT under private host CR3.
        // switch to system CR3 to read, then switch back.
        //
        // copies all 512 PTEs from real 鈫?fake, then re-applies NX=1
        // for every stealth/hooked entry that uses this fake PT.
        // this prevents stale A/D bits and stale PFN mappings from causing
        // MEMORY_MANAGEMENT BSOD when the CPU walks the fake PT page for
        // non-hooked PTEs in the same page.
        //
        {
            UINT64 saved_cr3 = vmx_enter_guest_cr3();
            stealth_fake_pt_resync(fpt);
            vmx_leave_guest_cr3(saved_cr3);
        }

        // swap PT page EPT back to fake view
        PEPT_PML1_ENTRY pt_pte = ept_get_pml1(vcpu->ept_page_table,
            (SIZE_T)(fpt->pt_page_pfn << 12));
        if (pt_pte)
        {
            pt_pte->AsUInt = fpt->pt_fake_entry.AsUInt;
            _mm_mfence();
            ept_invept_single(vcpu->ept_pointer);
        }

        vcpu->mtf_restore_fake_pt = NULL;
    }

    //
    // inject hook #PF recovery: fake PT had NX temporarily cleared (NX=0)
    // so CPU could build a TLB entry. now RESTORE NX=1 in the fake PT.
    //
    // CRITICAL: do NOT call INVEPT 鈥?preserve the target VA's TLB entry!
    // the TLB has NX=0 cached 鈫?CPU continues executing 鈫?native speed.
    // anti-cheat reading the PTE 鈫?fake PT 鈫?sees NX=1 鈫?clean.
    //
    else if (vcpu->stealth_pf_swapped_hook)
    {
        PEPT_HOOKED_PAGE_INFO hp = vcpu->stealth_pf_swapped_hook;

        // swap PT page EPT from exec PT (NX=0) back to fake PT (NX=1)
        if (hp->fake_pt)
        {
            // re-apply NX=1 in fake page (Windows may have cleared it via A/D management)
            stealth_fake_pt_set_nx(hp->fake_pt, hp->pt_pte_index);

            PEPT_PML1_ENTRY pt_pte = ept_get_pml1(vcpu->ept_page_table,
                (SIZE_T)(hp->fake_pt->pt_page_pfn << 12));
            if (pt_pte)
            {
                pt_pte->AsUInt = hp->fake_pt->pt_fake_entry.AsUInt;
                _mm_mfence();
                // NO INVEPT 鈥?preserve target VA's TLB entry (NX=0 cached)!
            }
        }

        vcpu->stealth_pf_swapped_hook = NULL;
    }

    //
    // stealth #PF recovery: PT page was swapped to real view (NX=0) so CPU
    // could build a TLB entry. now swap it BACK to fake view (NX=1).
    //
    // CRITICAL: do NOT flush the stealth VA's TLB entry!
    // the TLB has NX=0 cached 鈫?CPU continues executing from TLB 鈫?native speed.
    // anti-cheat reading the PTE 鈫?fake PT 鈫?sees NX=1 鈫?clean.
    //
    else if (vcpu->stealth_pf_swapped)
    {
        PEPT_STEALTH_PAGE_INFO sp = vcpu->stealth_pf_swapped;

        //
        // swap PT page EPT back to fake view (NX=1 visible to PTE scanners)
        //
        // CRITICAL: do NOT call INVEPT or INVVPID here!
        //
        // INVEPT (even single-context) flushes ALL combined mappings
        // (guest-linear 鈫?host-physical) for this EPTP. this would destroy
        // the stealth VA's TLB entry, forcing a page walk on the next
        // instruction fetch 鈫?fake PT 鈫?NX=1 鈫?#PF again 鈫?infinite loop.
        //
        // instead: just write the EPT PTE directly. the old EPT entry
        // (pointing to real PT page) may be cached in EPT TLB, but that's
        // actually beneficial 鈥?if the CPU uses the cached EPT entry for
        // a guest page walk, it sees the real PT (NX=0), which is what we
        // want. the fake PT is only for anti-cheat reads, which go through
        // a different EPT violation path (write-protected PT page).
        //
        // the stale EPT TLB entry will eventually be evicted naturally,
        // at which point the new PTE (fake view) takes effect.
        //
        if (sp->fake_pt)
        {
            // fake PT mode: swap EPT back to fake view (NX=1 visible to scanners)
            PEPT_PML1_ENTRY pt_pte = ept_get_pml1(vcpu->ept_page_table,
                (SIZE_T)(sp->fake_pt->pt_page_pfn << 12));
            if (pt_pte)
            {
                pt_pte->AsUInt = sp->fake_pt->pt_fake_entry.AsUInt;
                _mm_mfence();
                // NO INVEPT 鈥?preserve stealth VA's TLB entry!
            }
        }
        // NX cycle mode uses preemption timer, not MTF 鈥?nothing to do here.

        // for resident: target page stays in execute view 鈫?code continues from TLB

        vcpu->stealth_pf_swapped = NULL;
    }
}

// =========================================================================
//  VMX-root: #PF handler for inject hooks with fake PT (NX hiding)
//
//  when an inject hook page is executed, the CPU page walker reads the
//  fake PT page (NX=1) and generates #PF with error code bit 4 set.
//
//  approach: temporarily clear NX in the fake PT page itself, let CPU
//  re-walk and build a TLB entry (NX=0), then restore NX=1 via MTF.
//
//  this avoids swapping to real PT (Windows can restore NX=1 in real PTE
//  at any time, making the real PT unreliable).
// =========================================================================

// debug counters 鈥?safe in VMX-root (no OS API calls, just atomic increment)
volatile LONG g_dbg_pf_called = 0;    // ept_hook_handle_pf was called
volatile LONG g_dbg_pf_matched = 0;   // fault VA matched a hooked page
volatile LONG g_dbg_pf_skipped = 0;   // skipped (no fake_pt/exec_pt)

BOOLEAN
ept_hook_handle_pf(VIRTUAL_MACHINE_STATE * vcpu, UINT64 fault_addr, UINT32 error_code)
{
    if (!g_ept || IsListEmpty(&g_ept->hooked_pages)) return FALSE;

    //
    // ONLY handle NX violations: P=1 (page present) + I/D=1 (instruction fetch).
    // P=0 means demand paging 鈥?must re-inject to guest so Windows pages it in.
    // error_code bit 0 = P (present), bit 4 = I/D (instruction fetch).
    //
    _InterlockedIncrement(&g_dbg_pf_called);

    if (!(error_code & 0x01))
        return FALSE;  // page not present 鈫?demand paging, let guest handle

    UINT64 fault_page = fault_addr & ~0xFFFULL;

    PLIST_ENTRY cur = g_ept->hooked_pages.Flink;
    while (cur != &g_ept->hooked_pages)
    {
        PEPT_HOOKED_PAGE_INFO hp = CONTAINING_RECORD(cur, EPT_HOOKED_PAGE_INFO, hooked_page_list);
        cur = cur->Flink;

        if (!hp->fake_pt || !hp->exec_pt_page)
        {
            _InterlockedIncrement(&g_dbg_pf_skipped);
            continue;
        }

        PLIST_ENTRY fc = hp->hooked_functions_list.Flink;
        while (fc != &hp->hooked_functions_list)
        {
            PEPT_HOOKED_FUNCTION_INFO fi = CONTAINING_RECORD(fc, EPT_HOOKED_FUNCTION_INFO, hooked_function_list);
            fc = fc->Flink;

            if (((UINT64)fi->virtual_address & ~0xFFFULL) == fault_page)
            {
                _InterlockedIncrement(&g_dbg_pf_matched);

                // 1. resync exec PT from fake PT (fake page is "live" 鈥?gets all writes)
                //    then force NX=0 for our entry so CPU page walk succeeds
                if (hp->exec_pt_page)
                {
                    RtlCopyMemory(hp->exec_pt_page, hp->fake_pt->fake_page_va, PAGE_SIZE);
                    PUINT64 exec_pte = (PUINT64)hp->exec_pt_page;
                    exec_pte[hp->pt_pte_index] &= ~(1ULL << 63);  // NX=0
                }

                // 2. lazy split PT page EPT (2MB 鈫?4KB) if needed, then swap to exec view
                {
                    UINT64 pt_phys = hp->fake_pt->pt_page_pfn << 12;
                    PEPT_PML2_ENTRY pt_p2 = ept_get_pml2(vcpu->ept_page_table, (SIZE_T)pt_phys);
                    if (pt_p2 && pt_p2->LargePage)
                        ept_split_large_page_pool(vcpu->ept_page_table, (SIZE_T)pt_phys);
                }
                PEPT_PML1_ENTRY pt_pte = ept_get_pml1(vcpu->ept_page_table,
                    (SIZE_T)(hp->fake_pt->pt_page_pfn << 12));
                if (pt_pte) pt_pte->AsUInt = hp->pt_exec_entry.AsUInt;

                // 2. record for MTF restore (swap back to fake PT after one instruction)
                vcpu->stealth_pf_swapped_hook = hp;

                // 3. arm MTF 鈥?after one instruction, MTF handler restores fake PT (NX=1)
                {
                    SIZE_T pc = 0;
                    __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &pc);
                    pc |= (SIZE_T)CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG;
                    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, pc);
                }

                _mm_mfence();
                ept_invept_single(vcpu->ept_pointer);

                // flush guest TLB for fault VA so CPU re-walks with NX=0
                INVVPID_DESCRIPTOR desc = {0};
                desc.Vpid = VPID_TAG;
                if (g_ept->invvpid_individual_addr)
                {
                    desc.LinearAddress = fault_addr;
                    asm_invvpid(InvvpidIndividualAddress, &desc);
                }
                else
                    asm_invvpid(InvvpidSingleContext, &desc);

                return TRUE;
            }
        }
    }
    return FALSE;
}

BOOLEAN
ept_handle_vmcall_hook(VIRTUAL_MACHINE_STATE * vcpu)
{
    UINT64 rip = vcpu->vmexit_rip;
    PLIST_ENTRY cur = g_ept->hooked_pages.Flink;
    while (cur != &g_ept->hooked_pages)
    {
        PEPT_HOOKED_PAGE_INFO hp = CONTAINING_RECORD(cur, EPT_HOOKED_PAGE_INFO, hooked_page_list);
        cur = cur->Flink;

        //
        // R3 hook: only dispatch VMCALL for the target process.
        // non-target processes should never reach here (violation handler
        // gives them original code), but check CR3 as safety net.
        //
        if (hp->target_cr3 != 0)
        {
            UINT64 guest_cr3 = 0;
            __vmx_vmread(VMCS_GUEST_CR3, &guest_cr3);
            if ((guest_cr3 & CR3_ADDR_MASK) != hp->target_cr3)
                continue;
        }

        PLIST_ENTRY fc = hp->hooked_functions_list.Flink;
        while (fc != &hp->hooked_functions_list)
        {
            PEPT_HOOKED_FUNCTION_INFO fi = CONTAINING_RECORD(fc, EPT_HOOKED_FUNCTION_INFO, hooked_function_list);
            fc = fc->Flink;
            if ((UINT64)fi->virtual_address == rip)
            {
                if (fi->retiring)
                {
                    ept_hook_restore_current_vcpu(vcpu, hp);
                    return TRUE;
                }

                //
                // oneshot: first trigger 鈫?redirect to handler (shellcode).
                // subsequent triggers 鈫?pass through to original function.
                //
                // can't use fi->first_trampoline_address for R3 hooks because
                // it's in kernel pool (R3 can't execute kernel addresses 鈫?crash).
                //
                // instead: temporarily swap EPT to original view (real code),
                // let CPU re-execute from the real function, arm MTF to swap back.
                // same technique as ept_handle_violation for non-target CR3.
                //
                UINT64 current_tid = (UINT64)(ULONG_PTR)PsGetCurrentThreadId();
                if (fi->expected_tid && current_tid != fi->expected_tid)
                {
                    PEPT_PML1_ENTRY my_pte = ept_get_pml1(vcpu->ept_page_table,
                        (SIZE_T)(hp->pfn_of_hooked_page << 12));
                    if (my_pte)
                    {
                        EPT_PML1_ENTRY passthrough = hp->original_entry;
                        passthrough.ExecuteAccess = 1;
                        ept_swap_page(my_pte, passthrough, vcpu->ept_pointer);
                        vcpu->mtf_restore_page = hp;
                        SIZE_T pc = 0;
                        __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &pc);
                        pc |= (SIZE_T)CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG;
                        __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, pc);
                    }
                    return TRUE;
                }

                if (fi->oneshot)
                {
                    if (_InterlockedCompareExchange(&fi->oneshot_fired, 1, 0) == 0)
                    {
                        _InterlockedExchange(&fi->retiring, 1);
                        if (fi->external_fired)
                            _InterlockedExchange(fi->external_fired, 1);
                        ept_hook_fire_record((UINT64)fi->virtual_address, (UINT64)fi->handler_function);
                        __vmx_vmwrite(VMCS_GUEST_RIP, (UINT64)fi->handler_function);
                        wedge_cmos_mark(0x01);  // WEDGE-A (trigger fired -> redirected RIP to handler)
                        wedge_cmos_set_trig_seen();  // sticky: the injection trigger fired this run
                        return TRUE;
                    }

                    PEPT_PML1_ENTRY my_pte = ept_get_pml1(vcpu->ept_page_table,
                        (SIZE_T)(hp->pfn_of_hooked_page << 12));
                    if (my_pte)
                    {
                        EPT_PML1_ENTRY passthrough = hp->original_entry;
                        passthrough.ExecuteAccess = 1;
                        ept_swap_page(my_pte, passthrough, vcpu->ept_pointer);
                        vcpu->mtf_restore_page = hp;
                        SIZE_T pc = 0;
                        __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &pc);
                        pc |= (SIZE_T)CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG;
                        __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, pc);
                    }
                    // don't change RIP 鈥?CPU re-executes same VA from original code
                    return TRUE;
                }
                ept_hook_fire_record((UINT64)fi->virtual_address, (UINT64)fi->handler_function);
                __vmx_vmwrite(VMCS_GUEST_RIP, (UINT64)fi->handler_function);
                return TRUE;
            }
        }
    }
    return FALSE;
}

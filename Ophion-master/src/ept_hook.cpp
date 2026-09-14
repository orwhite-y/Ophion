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
#define HOOK_DIAG_PAGE_POLICY_MISMATCH 19 // Same page has a different read-access policy

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


#define EPT_HOOK_MAX_ORIGINAL_BYTES 32

static PEPT_HOOKED_PAGE_INFO
ept_hook_dispatch_page(PEPT_HOOKED_PAGE_INFO hp)
{
    return (hp && hp->is_secondary_hook_page && hp->primary_hook_page)
        ? hp->primary_hook_page
        : hp;
}

static BOOLEAN
ept_hook_calculate_overwrite_size(PUINT8 target, UINT32 hook_type, SIZE_T *hook_size)
{
    SIZE_T minimum_size = (hook_type == 1) ? 3 : (hook_type == 2) ? 1 : 14;
    SIZE_T size = 0;

    while (size < minimum_size)
    {
        SIZE_T instruction_size = LDE(target + size, 64);
        if (!instruction_size || size + instruction_size > EPT_HOOK_MAX_ORIGINAL_BYTES)
        {
            g_ept_hook_diag2 = ((UINT64)size << 32) | (instruction_size & 0xFFFFFFFFULL);
            return FALSE;
        }
        size += instruction_size;
    }

    *hook_size = size;
    return TRUE;
}

static VOID
ept_hook_build_payload(UINT8 payload[16], SIZE_T *payload_size,
                       UINT32 hook_type, UINT64 proxy_function)
{
    RtlZeroMemory(payload, 16);
    switch (hook_type)
    {
    case 0:
        hook_write_absolute_jump(payload, proxy_function);
        *payload_size = 14;
        break;
    case 1:
        payload[0] = 0x0F;
        payload[1] = 0x01;
        payload[2] = 0xC1;
        *payload_size = 3;
        break;
    case 2:
    default:
        payload[0] = 0xCC;
        *payload_size = 1;
        break;
    }
}

static VOID
ept_hook_write_payload_split(PEPT_HOOKED_PAGE_INFO primary,
                             PEPT_HOOKED_PAGE_INFO secondary,
                             PVOID target_function,
                             UINT32 hook_type,
                             UINT64 proxy_function)
{
    UINT8 payload[16];
    SIZE_T payload_size = 0;
    SIZE_T offset = EPT_PML1_PAGE_OFFSET(target_function);
    SIZE_T primary_length = PAGE_SIZE - offset;
    if (primary_length > sizeof(payload))
        primary_length = sizeof(payload);

    ept_hook_build_payload(payload, &payload_size, hook_type, proxy_function);
    if (primary_length > payload_size)
        primary_length = payload_size;

    RtlCopyMemory(&primary->fake_page_va[offset], payload, primary_length);
    if (secondary && payload_size > primary_length)
    {
        RtlCopyMemory(&secondary->fake_page_va[0],
                      payload + primary_length,
                      payload_size - primary_length);
    }
}

static PEPT_PML1_ENTRY
ept_hook_prepare_target_pte(VIRTUAL_MACHINE_STATE *vcpu, UINT64 phys_addr,
                            PEPT_HOOKED_PAGE_INFO hp, UINT64 fake_pfn,
                            UINT64 target_cr3, BOOLEAN force_read_access,
                            BOOLEAN initialize_entries)
{
    PEPT_PML2_ENTRY pml2 = ept_get_pml2(vcpu->ept_page_table, (SIZE_T)phys_addr);
    if (pml2 && pml2->LargePage)
    {
        if (!ept_split_large_page_pool(vcpu->ept_page_table, (SIZE_T)phys_addr))
            return NULL;
    }

    PEPT_PML1_ENTRY pte = ept_get_pml1(vcpu->ept_page_table, (SIZE_T)phys_addr);
    if (!pte)
        return NULL;

    hp->pfn_of_hooked_page = phys_addr >> 12;
    hp->entry_address = pte;
    hp->target_cr3 = target_cr3 & CR3_ADDR_MASK;

    if (!initialize_entries)
    {
        // An installed target PTE may currently point at its fake page. Never
        // re-baseline original_entry from a transient EPT state.
        hp->changed_entry.ReadAccess =
            (g_ept->execute_only_supported && !hp->force_read_access) ? 0 : 1;
        return pte;
    }

    hp->original_entry = *pte;
    hp->original_entry.ExecuteAccess = 0;
    hp->original_entry.ReadAccess = 1;
    hp->original_entry.WriteAccess = 1;

    hp->changed_entry = hp->original_entry;
    hp->changed_entry.ReadAccess =
        (g_ept->execute_only_supported && !force_read_access) ? 0 : 1;
    hp->changed_entry.WriteAccess = 0;
    hp->changed_entry.ExecuteAccess = 1;
    hp->changed_entry.PageFrameNumber = fake_pfn;
    return pte;
}

static VOID
ept_hook_pair_swap(VIRTUAL_MACHINE_STATE *vcpu, PEPT_HOOKED_PAGE_INFO primary,
                   EPT_PML1_ENTRY primary_entry, EPT_PML1_ENTRY secondary_entry)
{
    PEPT_PML1_ENTRY pte = ept_get_pml1(vcpu->ept_page_table,
        (SIZE_T)(primary->pfn_of_hooked_page << 12));
    if (pte)
        ept_swap_page(pte, primary_entry, vcpu->ept_pointer);

    PEPT_HOOKED_PAGE_INFO secondary = primary->secondary_hook_page;
    if (secondary)
    {
        pte = ept_get_pml1(vcpu->ept_page_table,
            (SIZE_T)(secondary->pfn_of_hooked_page << 12));
        if (pte)
            ept_swap_page(pte, secondary_entry, vcpu->ept_pointer);
    }
}

static EPT_PML1_ENTRY
ept_hook_passthrough_entry(PEPT_HOOKED_PAGE_INFO hp)
{
    EPT_PML1_ENTRY entry = hp->original_entry;
    entry.ReadAccess = 1;
    entry.WriteAccess = 1;
    entry.ExecuteAccess = 1;
    entry.PageFrameNumber = hp->pfn_of_hooked_page;
    return entry;
}

static VOID
ept_hook_restore_pair(VIRTUAL_MACHINE_STATE *vcpu, PEPT_HOOKED_PAGE_INFO hp)
{
    PEPT_HOOKED_PAGE_INFO primary = ept_hook_dispatch_page(hp);
    if (!primary)
        return;

    EPT_PML1_ENTRY primary_passthrough = ept_hook_passthrough_entry(primary);
    EPT_PML1_ENTRY secondary_passthrough = primary_passthrough;
    if (primary->secondary_hook_page)
        secondary_passthrough = ept_hook_passthrough_entry(primary->secondary_hook_page);

    ept_hook_pair_swap(vcpu, primary, primary_passthrough, secondary_passthrough);
}
static PEPT_HOOKED_PAGE_INFO
ept_hook_create_secondary_page(VIRTUAL_MACHINE_STATE *vcpu,
                               PEPT_HOOKED_PAGE_INFO primary,
                               PVOID target_function,
                               UINT64 next_phys,
                               BOOLEAN force_read_access)
{
    PEPT_HOOKED_PAGE_INFO secondary = (PEPT_HOOKED_PAGE_INFO)
        pool_manager_request(POOL_TAG_HOOKED_PAGE, sizeof(EPT_HOOKED_PAGE_INFO));
    if (!secondary)
        return NULL;

    RtlZeroMemory(secondary, sizeof(*secondary));
    InitializeListHead(&secondary->hooked_functions_list);

    UINT64 fake_pfn = 0;
    secondary->fake_page_va = stealth_region_alloc_page(&fake_pfn);
    if (!secondary->fake_page_va)
    {
        pool_manager_release(secondary);
        return NULL;
    }
    secondary->pfn_of_fake_page_contents = fake_pfn;

    PUINT8 next_va = (PUINT8)PAGE_ALIGN(target_function) + PAGE_SIZE;
    RtlCopyMemory(secondary->fake_page_va, next_va, PAGE_SIZE);

    if (!ept_hook_prepare_target_pte(vcpu, next_phys, secondary, fake_pfn,
                                     primary->target_cr3, force_read_access, TRUE))
    {
        pool_manager_release(secondary);
        return NULL;
    }

    secondary->Options = EPTO_HOOK_FUNCTION;
    secondary->force_read_access = force_read_access;
    secondary->is_secondary_hook_page = TRUE;
    secondary->primary_hook_page = primary;
    primary->secondary_hook_page = secondary;
    InsertHeadList(&g_ept->hooked_pages, &secondary->hooked_page_list);
    return secondary;
}

static PEPT_HOOKED_PAGE_INFO
ept_hook_ensure_secondary_page(VIRTUAL_MACHINE_STATE *vcpu,
                               PEPT_HOOKED_PAGE_INFO primary,
                               PVOID target_function,
                               UINT64 next_phys,
                               SIZE_T hook_size,
                               BOOLEAN force_read_access)
{
    SIZE_T offset = EPT_PML1_PAGE_OFFSET(target_function);
    if (offset + hook_size <= PAGE_SIZE)
        return NULL;

    if (primary->secondary_hook_page)
    {
        if (primary->secondary_hook_page->pfn_of_hooked_page != (next_phys >> 12))
            return NULL;
        return primary->secondary_hook_page;
    }

    for (PLIST_ENTRY cur = g_ept->hooked_pages.Flink;
         cur != &g_ept->hooked_pages; cur = cur->Flink)
    {
        PEPT_HOOKED_PAGE_INFO existing = CONTAINING_RECORD(
            cur, EPT_HOOKED_PAGE_INFO, hooked_page_list);
        if (existing->pfn_of_hooked_page == (next_phys >> 12))
            return NULL;
    }

    return ept_hook_create_secondary_page(vcpu, primary, target_function,
                                          next_phys, force_read_access);
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

    BOOLEAN is_r3 = (req->target_cr3 != 0 || req->user_trampoline != NULL);
    UINT64 pre_cr3 = 0;
    UINT64 pre_rflags = 0;

    if (is_r3 && req->caller_cr3)
    {
        UINT64 cr3_pfn = (req->caller_cr3 & PFN_MASK) >> 12;
        if (!cr3_pfn || !(req->caller_cr3 & PFN_MASK) || cr3_pfn > 0x1000000000ULL)
        {
            g_ept_hook_diag = HOOK_DIAG_INVALID_CR3;
            g_ept_hook_diag2 = req->caller_cr3;
            return FALSE;
        }

        pre_cr3 = __readcr3();
        __writecr3(req->caller_cr3);
        pre_rflags = __readeflags();
        __writeeflags(pre_rflags | (1ULL << 18));
        _mm_mfence();

        __try
        {
            volatile UINT8 probe = *(volatile UINT8 *)req->target_function;
            (void)probe;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            _mm_mfence();
            __writeeflags(pre_rflags);
            __writecr3(pre_cr3);
            g_ept_hook_diag = HOOK_DIAG_CR3_FAULT;
            g_ept_hook_diag2 = req->caller_cr3;
            return FALSE;
        }
    }

#define HOOK_RESTORE_CR3_AND_RETURN(val) do { \
    if (is_r3 && pre_cr3) { \
        _mm_mfence(); \
        __writeeflags(pre_rflags); \
        __writecr3(pre_cr3); \
    } \
    return (val); \
} while (0)

    UINT64 phys_addr = MmGetPhysicalAddress(req->target_function).QuadPart;
    if (!phys_addr)
    {
        g_ept_hook_diag = HOOK_DIAG_NO_PHYS;
        HOOK_RESTORE_CR3_AND_RETURN(FALSE);
    }

    UINT64 target_pfn = phys_addr >> 12;
    SIZE_T target_offset = EPT_PML1_PAGE_OFFSET(req->target_function);
    SIZE_T hook_size = 0;

    // Conservatively validate the possible next page before LDE can read into it.
    if (target_offset + EPT_HOOK_MAX_ORIGINAL_BYTES > PAGE_SIZE)
    {
        PUINT8 next_va = (PUINT8)PAGE_ALIGN(req->target_function) + PAGE_SIZE;
        UINT64 next_phys = MmGetPhysicalAddress(next_va).QuadPart;
        if (!next_phys)
        {
            g_ept_hook_diag = HOOK_DIAG_NO_PHYS;
            g_ept_hook_diag2 = (UINT64)next_va;
            HOOK_RESTORE_CR3_AND_RETURN(FALSE);
        }
    }

    if (!ept_hook_calculate_overwrite_size((PUINT8)req->target_function,
                                            req->hook_type, &hook_size))
    {
        g_ept_hook_diag = HOOK_DIAG_TRAMP_NEWP;
        HOOK_RESTORE_CR3_AND_RETURN(FALSE);
    }

    BOOLEAN crosses_page = (target_offset + hook_size > PAGE_SIZE);
    UINT64 next_phys = 0;
    PUINT8 next_va = NULL;
    if (crosses_page)
    {
        next_va = (PUINT8)PAGE_ALIGN(req->target_function) + PAGE_SIZE;
        next_phys = MmGetPhysicalAddress(next_va).QuadPart;
        if (!next_phys)
        {
            g_ept_hook_diag = HOOK_DIAG_NO_PHYS;
            g_ept_hook_diag2 = (UINT64)next_va;
            HOOK_RESTORE_CR3_AND_RETURN(FALSE);
        }
    }

    if (req->is_primary_cpu == FALSE)
    {
        BOOLEAN ok = ept_hook_install_secondary_cpu(vcpu, req, target_pfn, phys_addr);
        HOOK_RESTORE_CR3_AND_RETURN(ok);
    }

    hook_lock_acquire();

    PEPT_HOOKED_PAGE_INFO primary = NULL;
    for (PLIST_ENTRY cur = g_ept->hooked_pages.Flink;
         cur != &g_ept->hooked_pages; cur = cur->Flink)
    {
        PEPT_HOOKED_PAGE_INFO existing = CONTAINING_RECORD(
            cur, EPT_HOOKED_PAGE_INFO, hooked_page_list);
        if (existing->pfn_of_hooked_page == target_pfn)
        {
            if (existing->is_secondary_hook_page)
            {
                _InterlockedExchange(&g_hook_list_lock, 0);
                g_ept_hook_diag = HOOK_DIAG_SECONDARY_SPLIT;
                g_ept_hook_diag2 = target_pfn;
                HOOK_RESTORE_CR3_AND_RETURN(FALSE);
            }
            primary = existing;
            break;
        }
    }

    PEPT_HOOKED_FUNCTION_INFO fi = NULL;
    BOOLEAN existing_function = FALSE;
    PUINT8 old_trampoline = NULL;
    BOOLEAN old_user_trampoline = FALSE;
    PEPT_HOOKED_PAGE_INFO secondary = NULL;

    if (primary)
    {
        for (PLIST_ENTRY cur = primary->hooked_functions_list.Flink;
             cur != &primary->hooked_functions_list; cur = cur->Flink)
        {
            PEPT_HOOKED_FUNCTION_INFO existing = CONTAINING_RECORD(
                cur, EPT_HOOKED_FUNCTION_INFO, hooked_function_list);
            if (existing->virtual_address == req->target_function)
            {
                fi = existing;
                existing_function = TRUE;
                old_trampoline = fi->first_trampoline_address;
                old_user_trampoline = fi->user_trampoline;
                break;
            }
        }
    }

    if (!fi)
    {
        fi = (PEPT_HOOKED_FUNCTION_INFO)
            pool_manager_request(POOL_TAG_HOOKED_FUNC, sizeof(EPT_HOOKED_FUNCTION_INFO));
        if (!fi)
        {
            _InterlockedExchange(&g_hook_list_lock, 0);
            g_ept_hook_diag = primary ? HOOK_DIAG_POOL_FUNC_S : HOOK_DIAG_POOL_FUNC_N;
            HOOK_RESTORE_CR3_AND_RETURN(FALSE);
        }
        RtlZeroMemory(fi, sizeof(*fi));
    }

    PUINT8 trampoline = NULL;
    BOOLEAN allocated_trampoline = FALSE;
    BOOLEAN new_user_trampoline = FALSE;
    BOOLEAN restore_trampoline = FALSE;
    UINT8 trampoline_backup[128];

    if (is_r3 && req->user_trampoline)
    {
        trampoline = (PUINT8)req->user_trampoline;
        new_user_trampoline = TRUE;
    }
    else
    {
        if (existing_function && old_user_trampoline)
        {
            trampoline = (PUINT8)pool_manager_request(POOL_TAG_TRAMPOLINE, 128);
            allocated_trampoline = TRUE;
        }
        else if (existing_function && old_trampoline)
        {
            trampoline = old_trampoline;
        }
        else
        {
            trampoline = (PUINT8)pool_manager_request(POOL_TAG_TRAMPOLINE, 128);
            allocated_trampoline = TRUE;
        }
    }

    if (!trampoline)
    {
        if (!existing_function)
            pool_manager_release(fi);
        _InterlockedExchange(&g_hook_list_lock, 0);
        g_ept_hook_diag = primary ? HOOK_DIAG_POOL_TRMP_S : HOOK_DIAG_POOL_TRMP_N;
        HOOK_RESTORE_CR3_AND_RETURN(FALSE);
    }

    if (existing_function && trampoline == old_trampoline)
    {
        RtlCopyMemory(trampoline_backup, trampoline, sizeof(trampoline_backup));
        restore_trampoline = TRUE;
    }

    if (!hook_build_trampoline((PUINT8)req->target_function, trampoline, hook_size,
                               (UINT64)req->target_function, (UINT64)trampoline))
    {
        if (restore_trampoline)
            RtlCopyMemory(trampoline, trampoline_backup, sizeof(trampoline_backup));
        if (allocated_trampoline)
            pool_manager_release(trampoline);
        if (!existing_function)
            pool_manager_release(fi);
        _InterlockedExchange(&g_hook_list_lock, 0);
        g_ept_hook_diag = primary ? HOOK_DIAG_TRAMP_NEWF : HOOK_DIAG_TRAMP_NEWP;
        HOOK_RESTORE_CR3_AND_RETURN(FALSE);
    }

    UINT8 original_bytes[32];
    RtlCopyMemory(original_bytes, req->target_function, hook_size);

    if (!primary)
    {
        primary = (PEPT_HOOKED_PAGE_INFO)
            pool_manager_request(POOL_TAG_HOOKED_PAGE, sizeof(EPT_HOOKED_PAGE_INFO));
        if (!primary)
        {
            if (restore_trampoline)
                RtlCopyMemory(trampoline, trampoline_backup, sizeof(trampoline_backup));
            if (allocated_trampoline)
                pool_manager_release(trampoline);
            if (!existing_function)
                pool_manager_release(fi);
            _InterlockedExchange(&g_hook_list_lock, 0);
            g_ept_hook_diag = HOOK_DIAG_POOL_PAGE;
            HOOK_RESTORE_CR3_AND_RETURN(FALSE);
        }

        RtlZeroMemory(primary, sizeof(*primary));
        InitializeListHead(&primary->hooked_functions_list);

        UINT64 fake_pfn = 0;
        primary->fake_page_va = stealth_region_alloc_page(&fake_pfn);
        if (!primary->fake_page_va)
        {
            pool_manager_release(primary);
            if (restore_trampoline)
                RtlCopyMemory(trampoline, trampoline_backup, sizeof(trampoline_backup));
            if (allocated_trampoline)
                pool_manager_release(trampoline);
            if (!existing_function)
                pool_manager_release(fi);
            _InterlockedExchange(&g_hook_list_lock, 0);
            g_ept_hook_diag = HOOK_DIAG_STEALTH_REG;
            HOOK_RESTORE_CR3_AND_RETURN(FALSE);
        }
        primary->pfn_of_fake_page_contents = fake_pfn;
        RtlCopyMemory(primary->fake_page_va, PAGE_ALIGN(req->target_function), PAGE_SIZE);

        if (!ept_hook_prepare_target_pte(
                vcpu, phys_addr, primary, fake_pfn, req->target_cr3,
                req->force_read_access, TRUE))
        {
            pool_manager_release(primary);
            if (restore_trampoline)
                RtlCopyMemory(trampoline, trampoline_backup, sizeof(trampoline_backup));
            if (allocated_trampoline)
                pool_manager_release(trampoline);
            if (!existing_function)
                pool_manager_release(fi);
            _InterlockedExchange(&g_hook_list_lock, 0);
            g_ept_hook_diag = HOOK_DIAG_NO_PML1;
            HOOK_RESTORE_CR3_AND_RETURN(FALSE);
        }

        if (crosses_page)
        {
            secondary = ept_hook_create_secondary_page(
                vcpu, primary, req->target_function, next_phys,
                req->force_read_access);
            if (!secondary)
            {
                pool_manager_release(primary);
                if (restore_trampoline)
                    RtlCopyMemory(trampoline, trampoline_backup, sizeof(trampoline_backup));
                if (allocated_trampoline)
                    pool_manager_release(trampoline);
                if (!existing_function)
                    pool_manager_release(fi);
                _InterlockedExchange(&g_hook_list_lock, 0);
                g_ept_hook_diag = HOOK_DIAG_STEALTH_REG;
                g_ept_hook_diag2 = next_phys;
                HOOK_RESTORE_CR3_AND_RETURN(FALSE);
            }
        }

        primary->Options = EPTO_HOOK_FUNCTION;
        primary->force_read_access = req->force_read_access;
        InsertHeadList(&g_ept->hooked_pages, &primary->hooked_page_list);
    }
    else
    {
        // Read access is an EPT page-wide property.  A later hook must not
        // silently switch it while earlier hooks on the same page are active.
        if (primary->force_read_access != req->force_read_access)
        {
            if (restore_trampoline)
                RtlCopyMemory(trampoline, trampoline_backup, sizeof(trampoline_backup));
            if (allocated_trampoline)
                pool_manager_release(trampoline);
            if (!existing_function)
                pool_manager_release(fi);
            _InterlockedExchange(&g_hook_list_lock, 0);
            g_ept_hook_diag = HOOK_DIAG_PAGE_POLICY_MISMATCH;
            g_ept_hook_diag2 = primary->pfn_of_hooked_page;
            HOOK_RESTORE_CR3_AND_RETURN(FALSE);
        }

        secondary = primary->secondary_hook_page;
        if (crosses_page)
        {
            // Reuse the page pair when another function on this primary page
            // already owns it.  Otherwise create it before any metadata commit.
            secondary = ept_hook_ensure_secondary_page(
                vcpu, primary, req->target_function, next_phys,
                hook_size, req->force_read_access);
            if (!secondary)
            {
                if (restore_trampoline)
                    RtlCopyMemory(trampoline, trampoline_backup, sizeof(trampoline_backup));
                if (allocated_trampoline)
                    pool_manager_release(trampoline);
                if (!existing_function)
                    pool_manager_release(fi);
                _InterlockedExchange(&g_hook_list_lock, 0);
                g_ept_hook_diag = HOOK_DIAG_STEALTH_REG;
                g_ept_hook_diag2 = next_phys;
                HOOK_RESTORE_CR3_AND_RETURN(FALSE);
            }
        }

        if (!ept_hook_prepare_target_pte(
                vcpu, phys_addr, primary, primary->pfn_of_fake_page_contents,
                req->target_cr3, req->force_read_access, FALSE))
        {
            if (restore_trampoline)
                RtlCopyMemory(trampoline, trampoline_backup, sizeof(trampoline_backup));
            if (allocated_trampoline)
                pool_manager_release(trampoline);
            if (!existing_function)
                pool_manager_release(fi);
            _InterlockedExchange(&g_hook_list_lock, 0);
            g_ept_hook_diag = HOOK_DIAG_NO_PML1;
            HOOK_RESTORE_CR3_AND_RETURN(FALSE);
        }

        // ensure_secondary_page() initializes a newly created secondary page.
        // An already-linked secondary page has valid EPT state and only needs
        // its read-permission policy refreshed for this request.
        if (secondary)
            secondary->changed_entry.ReadAccess =
                (g_ept->execute_only_supported && !secondary->force_read_access) ? 0 : 1;
    }

    if (existing_function && old_trampoline && !old_user_trampoline &&
        old_trampoline != trampoline)
    {
        pool_manager_release(old_trampoline);
    }

    fi->virtual_address = req->target_function;
    fi->handler_function = req->proxy_function;
    fi->first_trampoline_address = trampoline;
    fi->fake_page_contents = primary->fake_page_va;
    RtlCopyMemory(fi->original_bytes, original_bytes, hook_size);
    fi->hook_size = hook_size;
    fi->hook_type = req->hook_type;
    fi->user_trampoline = new_user_trampoline;
    fi->oneshot = req->oneshot;
    fi->expected_tid = req->expected_tid;
    fi->external_fired = req->external_fired;
    fi->retiring = FALSE;
    fi->oneshot_fired = 0;

    if (!existing_function)
        InsertHeadList(&primary->hooked_functions_list, &fi->hooked_function_list);

    ept_hook_write_payload_split(primary, secondary, req->target_function,
                                 req->hook_type, (UINT64)req->proxy_function);
    if (req->origin_function)
        *req->origin_function = fi->first_trampoline_address;

    _InterlockedExchange(&g_hook_list_lock, 0);

    if (is_r3 && pre_cr3)
    {
        _mm_mfence();
        __writeeflags(pre_rflags);
        __writecr3(pre_cr3);
        pre_cr3 = 0;
    }

    // Target pages remain non-executable; execute violations dispatch the hook.
    {
        PEPT_PML1_ENTRY pte = ept_get_pml1(vcpu->ept_page_table, (SIZE_T)phys_addr);
        if (pte)
        {
            pte->AsUInt = primary->original_entry.AsUInt;
        }
        if (secondary)
        {
            PEPT_PML1_ENTRY next_pte = ept_get_pml1(
                vcpu->ept_page_table, (SIZE_T)next_phys);
            if (next_pte)
                next_pte->AsUInt = secondary->original_entry.AsUInt;
        }
    }

    // Fake pages are execute-only (or R+X when execute-only is unsupported).
    {
        UINT64 pages[2];
        pages[0] = primary->pfn_of_fake_page_contents;
        pages[1] = secondary ? secondary->pfn_of_fake_page_contents : 0;
        for (UINT32 i = 0; i < 2; i++)
        {
            if (!pages[i])
                continue;
            UINT64 fake_phys = pages[i] << 12;
            PEPT_PML2_ENTRY fp2 = ept_get_pml2(vcpu->ept_page_table, (SIZE_T)fake_phys);
            if (fp2 && fp2->LargePage)
                ept_split_large_page_pool(vcpu->ept_page_table, (SIZE_T)fake_phys);
            PEPT_PML1_ENTRY fp1 = ept_get_pml1(vcpu->ept_page_table, (SIZE_T)fake_phys);
            if (fp1)
            {
                BOOLEAN allow_read = (i == 0)
                    ? primary->force_read_access
                    : secondary->force_read_access;
                fp1->ReadAccess =
                    (g_ept->execute_only_supported && !allow_read) ? 0 : 1;
                fp1->WriteAccess = 0;
                fp1->ExecuteAccess = 1;
                fp1->PageFrameNumber = pages[i];
            }
        }
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
ept_hook_restore_current_vcpu(VIRTUAL_MACHINE_STATE *vcpu, PEPT_HOOKED_PAGE_INFO hp)
{
    ept_hook_restore_pair(vcpu, hp);
}

BOOLEAN
ept_unhook_install(VIRTUAL_MACHINE_STATE *vcpu, PEPT_UNHOOK_VMCALL_PARAM req)
{
    if (!g_ept || !req->target_function)
        return FALSE;

    UINT64 phys_addr = MmGetPhysicalAddress(req->target_function).QuadPart;
    UINT64 target_pfn = phys_addr >> 12;

    PLIST_ENTRY cur = g_ept->hooked_pages.Flink;
    while (cur != &g_ept->hooked_pages)
    {
        PEPT_HOOKED_PAGE_INFO listed = CONTAINING_RECORD(cur, EPT_HOOKED_PAGE_INFO, hooked_page_list);
        cur = cur->Flink;
        if (listed->pfn_of_hooked_page != target_pfn)
            continue;

        PEPT_HOOKED_PAGE_INFO hp = ept_hook_dispatch_page(listed);
        if (!hp)
            continue;

        PLIST_ENTRY fc = hp->hooked_functions_list.Flink;
        while (fc != &hp->hooked_functions_list)
        {
            PEPT_HOOKED_FUNCTION_INFO fn = CONTAINING_RECORD(fc, EPT_HOOKED_FUNCTION_INFO, hooked_function_list);
            fc = fc->Flink;
            if (fn->virtual_address != req->target_function)
                continue;

            UINT64 offset = EPT_PML1_PAGE_OFFSET(fn->virtual_address);
            SIZE_T primary_length = PAGE_SIZE - offset;
            if (primary_length > fn->hook_size)
                primary_length = fn->hook_size;

            if (hp->fake_page_va)
            {
                RtlCopyMemory(&hp->fake_page_va[offset],
                              fn->original_bytes,
                              primary_length);
            }

            PEPT_HOOKED_PAGE_INFO secondary = hp->secondary_hook_page;
            if (secondary && secondary->fake_page_va && fn->hook_size > primary_length)
            {
                RtlCopyMemory(&secondary->fake_page_va[0],
                              fn->original_bytes + primary_length,
                              fn->hook_size - primary_length);
            }

            fn->retiring = TRUE;
            req->result = TRUE;
            break;
        }

        if (req->result)
        {
            if (!ept_hook_page_has_active_function(hp))
                ept_hook_restore_current_vcpu(vcpu, hp);
            return TRUE;
        }
    }

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
    if (!g_ept)
        return;

    while (!IsListEmpty(&g_ept->hooked_pages))
    {
        PLIST_ENTRY item = RemoveHeadList(&g_ept->hooked_pages);
        PEPT_HOOKED_PAGE_INFO hp = CONTAINING_RECORD(item, EPT_HOOKED_PAGE_INFO, hooked_page_list);

        PEPT_HOOKED_PAGE_INFO primary = hp->primary_hook_page;
        PEPT_HOOKED_PAGE_INFO secondary = hp->secondary_hook_page;
        if (primary)
            primary->secondary_hook_page = NULL;
        if (secondary)
            secondary->primary_hook_page = NULL;
        hp->primary_hook_page = NULL;
        hp->secondary_hook_page = NULL;

        if (!hp->is_secondary_hook_page)
        {
            while (!IsListEmpty(&hp->hooked_functions_list))
            {
                PLIST_ENTRY fi = RemoveHeadList(&hp->hooked_functions_list);
                PEPT_HOOKED_FUNCTION_INFO fn = CONTAINING_RECORD(
                    fi, EPT_HOOKED_FUNCTION_INFO, hooked_function_list);
                if (fn->first_trampoline_address && !fn->user_trampoline)
                    pool_manager_release(fn->first_trampoline_address);
                pool_manager_release(fn);
            }
        }

        if (hp->entry_address)
        {
            hp->entry_address->ReadAccess = 1;
            hp->entry_address->WriteAccess = 1;
            hp->entry_address->ExecuteAccess = 1;
            hp->entry_address->PageFrameNumber = hp->pfn_of_hooked_page;
        }
        pool_manager_release(hp);
    }
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
ept_unhook_by_cr3(VIRTUAL_MACHINE_STATE *vcpu, UINT64 target_cr3)
{
    if (!g_ept || !target_cr3)
        return;

    PLIST_ENTRY cur = g_ept->hooked_pages.Flink;
    while (cur != &g_ept->hooked_pages)
    {
        PEPT_HOOKED_PAGE_INFO listed = CONTAINING_RECORD(cur, EPT_HOOKED_PAGE_INFO, hooked_page_list);
        cur = cur->Flink;
        if (listed->is_secondary_hook_page)
            continue;

        PEPT_HOOKED_PAGE_INFO hp = ept_hook_dispatch_page(listed);
        if (!hp || (hp->target_cr3 & CR3_ADDR_MASK) != (target_cr3 & CR3_ADDR_MASK))
            continue;

        PLIST_ENTRY fc = hp->hooked_functions_list.Flink;
        while (fc != &hp->hooked_functions_list)
        {
            PEPT_HOOKED_FUNCTION_INFO fi = CONTAINING_RECORD(
                fc, EPT_HOOKED_FUNCTION_INFO, hooked_function_list);
            fc = fc->Flink;
            fi->retiring = TRUE;
        }

        if (!ept_hook_page_has_active_function(hp))
            ept_hook_restore_pair(vcpu, hp);
    }
}
// =========================================================================
//  VMX-root: EPT violation / MTF / VMCALL-hook handlers
// =========================================================================

BOOLEAN
ept_handle_violation(VIRTUAL_MACHINE_STATE *vcpu, UINT64 guest_phys, UINT64 exit_qual)
{
    VMX_EXIT_QUALIFICATION_EPT_VIOLATION viol;
    viol.AsUInt = exit_qual;
    UINT64 pfn = guest_phys >> 12;

    PLIST_ENTRY cur = g_ept->hooked_pages.Flink;
    while (cur != &g_ept->hooked_pages)
    {
        PEPT_HOOKED_PAGE_INFO listed = CONTAINING_RECORD(cur, EPT_HOOKED_PAGE_INFO, hooked_page_list);
        cur = cur->Flink;

        PEPT_HOOKED_PAGE_INFO hp = ept_hook_dispatch_page(listed);
        PEPT_HOOKED_PAGE_INFO secondary = hp ? hp->secondary_hook_page : NULL;
        if (!hp)
            continue;
        if (hp->pfn_of_hooked_page != pfn &&
            hp->pfn_of_fake_page_contents != pfn &&
            (!secondary ||
             (secondary->pfn_of_hooked_page != pfn &&
              secondary->pfn_of_fake_page_contents != pfn)))
        {
            continue;
        }

        // Physical scans of either fake page are given a temporary data view.
        if (pfn == hp->pfn_of_fake_page_contents ||
            (secondary && pfn == secondary->pfn_of_fake_page_contents))
        {
            if (viol.ReadAccess || viol.WriteAccess)
            {
                PEPT_HOOKED_PAGE_INFO fake_owner =
                    (secondary && pfn == secondary->pfn_of_fake_page_contents)
                        ? secondary : hp;

                PEPT_PML1_ENTRY fake_pte = ept_get_pml1(
                    vcpu->ept_page_table,
                    (SIZE_T)(fake_owner->pfn_of_fake_page_contents << 12));
                if (fake_pte)
                {
                    EPT_PML1_ENTRY temporary = *fake_pte;
                    temporary.ReadAccess = 1;
                    temporary.WriteAccess = 0;
                    temporary.ExecuteAccess = 0;
                    temporary.PageFrameNumber = fake_owner->pfn_of_hooked_page;
                    fake_pte->AsUInt = temporary.AsUInt;
                    _mm_mfence();
                    ept_invept_single(vcpu->ept_pointer);

                    vcpu->mtf_restore_page = hp;
                    vcpu->mtf_restore_hook_view = FALSE;
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
            ept_hook_restore_pair(vcpu, hp);
            return TRUE;
        }

        if (viol.ReadAccess || viol.WriteAccess)
        {
            ept_hook_pair_swap(vcpu, hp, hp->original_entry,
                               secondary ? secondary->original_entry : hp->original_entry);
            vcpu->mtf_restore_page = hp;
            vcpu->mtf_restore_hook_view = TRUE;
            SIZE_T pc = 0;
            __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &pc);
            pc |= (SIZE_T)CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG;
            __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, pc);
            return TRUE;
        }

        if (viol.ExecuteAccess)
        {
            EPT_PML1_ENTRY passthrough = hp->original_entry;
            passthrough.ExecuteAccess = 1;

            if (hp->target_cr3 != 0)
            {
                UINT64 guest_cr3 = 0;
                __vmx_vmread(VMCS_GUEST_CR3, &guest_cr3);
                if ((guest_cr3 & CR3_ADDR_MASK) != hp->target_cr3)
                {
                    ept_hook_pair_swap(vcpu, hp, passthrough,
                                       secondary ? ept_hook_passthrough_entry(secondary) : passthrough);
                    vcpu->mtf_restore_page = hp;
                    vcpu->mtf_restore_hook_view = FALSE;
                    SIZE_T pc = 0;
                    __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &pc);
                    pc |= (SIZE_T)CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG;
                    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, pc);
                    return TRUE;
                }
            }

            UINT64 rip = vcpu->vmexit_rip;
            for (PLIST_ENTRY fc = hp->hooked_functions_list.Flink;
                 fc != &hp->hooked_functions_list; fc = fc->Flink)
            {
                PEPT_HOOKED_FUNCTION_INFO fi = CONTAINING_RECORD(
                    fc, EPT_HOOKED_FUNCTION_INFO, hooked_function_list);
                if ((UINT64)fi->virtual_address != rip)
                    continue;

                if (fi->expected_tid)
                {
                    UINT64 current_tid = (UINT64)(ULONG_PTR)PsGetCurrentThreadId();
                    if (current_tid != fi->expected_tid)
                    {
                        ept_hook_pair_swap(vcpu, hp, passthrough,
                                           secondary ? ept_hook_passthrough_entry(secondary) : passthrough);
                        vcpu->mtf_restore_page = hp;
                        vcpu->mtf_restore_hook_view = FALSE;
                        SIZE_T pc = 0;
                        __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &pc);
                        pc |= (SIZE_T)CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG;
                        __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, pc);
                        return TRUE;
                    }
                }
                break;
            }

            ept_hook_pair_swap(vcpu, hp, hp->changed_entry,
                               secondary ? secondary->changed_entry : hp->changed_entry);
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
        PEPT_HOOKED_PAGE_INFO hp = ept_hook_dispatch_page(vcpu->mtf_restore_page);
        PEPT_HOOKED_PAGE_INFO secondary = hp ? hp->secondary_hook_page : NULL;

        if (!hp)
        {
            vcpu->mtf_restore_page = NULL;
            vcpu->mtf_restore_hook_view = FALSE;
        }
        else
        {
            if (!ept_hook_page_has_active_function(hp))
            {
                ept_hook_restore_pair(vcpu, hp);
            }
            else
            {
                EPT_PML1_ENTRY restore_entry =
                    (vcpu->mtf_restore_hook_view || hp->fake_pt)
                        ? hp->changed_entry : hp->original_entry;
                EPT_PML1_ENTRY secondary_restore =
                    secondary ? ((vcpu->mtf_restore_hook_view || hp->fake_pt)
                        ? secondary->changed_entry : secondary->original_entry)
                      : restore_entry;
                ept_hook_pair_swap(vcpu, hp, restore_entry, secondary_restore);
            }

            // Restore both fake pages to their execute-only hook view.
            PEPT_HOOKED_PAGE_INFO fake_pages[2];
            fake_pages[0] = hp;
            fake_pages[1] = secondary;
            for (UINT32 i = 0; i < 2; i++)
            {
                if (!fake_pages[i] || !fake_pages[i]->fake_page_va)
                    continue;
                PEPT_PML1_ENTRY fake_pte = ept_get_pml1(
                    vcpu->ept_page_table,
                    (SIZE_T)(fake_pages[i]->pfn_of_fake_page_contents << 12));
                if (fake_pte)
                {
                    fake_pte->ReadAccess = fake_pages[i]->changed_entry.ReadAccess ? 1 : 0;
                    fake_pte->WriteAccess = 0;
                    fake_pte->ExecuteAccess = 1;
                    fake_pte->PageFrameNumber = fake_pages[i]->pfn_of_fake_page_contents;
                }
            }
            _mm_mfence();
            ept_invept_single(vcpu->ept_pointer);

            vcpu->mtf_restore_page = NULL;
            vcpu->mtf_restore_hook_view = FALSE;
        }
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
        PEPT_HOOKED_PAGE_INFO listed = CONTAINING_RECORD(cur, EPT_HOOKED_PAGE_INFO, hooked_page_list);
        cur = cur->Flink;
        if (listed->is_secondary_hook_page)
            continue;

        PEPT_HOOKED_PAGE_INFO hp = listed;
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
                    EPT_PML1_ENTRY passthrough = hp->original_entry;
                    passthrough.ExecuteAccess = 1;
                    ept_hook_pair_swap(vcpu, hp, passthrough,
                        hp->secondary_hook_page ? ept_hook_passthrough_entry(hp->secondary_hook_page) : passthrough);
                    vcpu->mtf_restore_page = hp;
                    vcpu->mtf_restore_hook_view = FALSE;
                    SIZE_T pc = 0;
                    __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &pc);
                    pc |= (SIZE_T)CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG;
                    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, pc);
                    return TRUE;
                }

                if (fi->oneshot)
                {
                    if (_InterlockedCompareExchange(&fi->oneshot_fired, 1, 0) == 0)
                    {
                        fi->retiring = TRUE;
                        if (fi->external_fired)
                            _InterlockedExchange(fi->external_fired, 1);
                        ept_hook_fire_record((UINT64)fi->virtual_address, (UINT64)fi->handler_function);
                        __vmx_vmwrite(VMCS_GUEST_RIP, (UINT64)fi->handler_function);
                        wedge_cmos_mark(0x01);  // WEDGE-A (trigger fired -> redirected RIP to handler)
                        wedge_cmos_set_trig_seen();  // sticky: the injection trigger fired this run
                        return TRUE;
                    }

                    EPT_PML1_ENTRY passthrough = hp->original_entry;
                    passthrough.ExecuteAccess = 1;
                    ept_hook_pair_swap(vcpu, hp, passthrough,
                        hp->secondary_hook_page ? ept_hook_passthrough_entry(hp->secondary_hook_page) : passthrough);
                    vcpu->mtf_restore_page = hp;
                    vcpu->mtf_restore_hook_view = FALSE;
                    SIZE_T pc = 0;
                    __vmx_vmread(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, &pc);
                    pc |= (SIZE_T)CPU_BASED_VM_EXEC_CTRL_MONITOR_TRAP_FLAG;
                    __vmx_vmwrite(VMCS_CTRL_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, pc);
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

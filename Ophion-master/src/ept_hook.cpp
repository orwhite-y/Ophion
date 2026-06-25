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

#define POOL_TAG_SPLIT       0
#define POOL_TAG_HOOKED_PAGE 1
#define POOL_TAG_HOOKED_FUNC 2
#define POOL_TAG_TRAMPOLINE  3

#define EPT_PML1_PAGE_OFFSET(_a) (((UINT64)(_a)) & 0xFFF)

// mask PCID and no-flush bit from CR3, keep only PML4 physical address
#define CR3_ADDR_MASK  0x000FFFFFFFFFF000ULL

//
// spinlock for serializing the "new page" full install path in ept_hook_install.
// the DPC broadcast VMCALL handler uses InterlockedCompareExchange on the shared
// req->installed field, but the OPHION_VMCALL_ID path builds per-CPU local_req,
// so this lock provides defense-in-depth for all VMCALL dispatch paths.
//
static volatile LONG g_hook_list_lock = 0;

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
// split 2MB → 4KB using pool manager (safe in VMX-root, no ExAllocatePool)
//
//
// split 2MB → 4KB using pool manager (safe in VMX-root)
// returns the split buffer so caller can access PML1 entries directly
// (avoids pa_to_va/MmGetVirtualForPhysical which may not work in VMX-root)
//
// PITFALL #6: Split buffer must be page-aligned. FIX: Pool uses MmAllocateContiguousMemory instead of ExAllocatePool2.
// NOT static — also used by ept_stealth.cpp (VMX-root safe split)
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
//  VMX-root: ept_hook_install — called from VMCALL handler per-CPU
//  caller must switch CR3 to caller_cr3 BEFORE calling this.
//
//  first CPU (InterlockedCmpExchg installed 0→1):
//    full install: alloc, copy page, LDE, trampoline, fake page, list add
//  other CPUs:
//    just split their own EPT page + modify PTE + invept
// =========================================================================

//
// ept_hook_install — 在 VMX-root 下运行
// 支持 private host CR3: 调用方 (VMCALL handler) 已经 vmx_enter_guest_cr3()
// 切换到 system CR3。对于 R3 hook 会额外切到 caller_cr3 访问用户态 VA。
//
// R3 hook (target_cr3 != 0):
//   - 切换到 caller_cr3 访问用户态目标 VA (MmGetPhysicalAddress, RtlCopyMemory, LDE)
//   - 使用 caller 提供的 user_trampoline (R3 可执行内存) 代替 kernel pool
//   - violation handler 按 CR3 过滤: 只有目标进程看到 hook，其他进程透传
BOOLEAN
ept_hook_install(VIRTUAL_MACHINE_STATE * vcpu, PEPT_HOOK_VMCALL_PARAM req)
{
    if (!vcpu->ept_page_table || !req->target_function)
        return FALSE;

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
        HOOK_RESTORE_CR3_AND_RETURN(FALSE);

    UINT64 target_pfn = phys_addr >> 12;

    // 检查是否已 hook 过这个页面
    struct _LIST_ENTRY * hcur;
    for (hcur = g_ept->hooked_pages.Flink; hcur != &g_ept->hooked_pages; hcur = hcur->Flink)
    {
        PEPT_HOOKED_PAGE_INFO existing = CONTAINING_RECORD(hcur, EPT_HOOKED_PAGE_INFO, hooked_page_list);
        if (existing->pfn_of_hooked_page == target_pfn)
        {
            //
            // 页面已 hook — 检查这个具体函数是否已经 hook
            //
            BOOLEAN func_exists = FALSE;
            PLIST_ENTRY fc = existing->hooked_functions_list.Flink;
            while (fc != &existing->hooked_functions_list)
            {
                PEPT_HOOKED_FUNCTION_INFO efi = CONTAINING_RECORD(fc, EPT_HOOKED_FUNCTION_INFO, hooked_function_list);
                if (efi->virtual_address == req->target_function)
                {
                    func_exists = TRUE;
                    break;
                }
                fc = fc->Flink;
            }

            if (func_exists)
            {
                // 这个函数已经 hook 了 (其他 CPU 的重复调用)
                // 只做 split + PTE + invept
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
                _mm_mfence();
                ept_invept_single(vcpu->ept_pointer);
                HOOK_RESTORE_CR3_AND_RETURN(TRUE);
            }

            //
            // 同页面不同函数 — 添加新 hook 到已有的 fake page
            // lock protects concurrent InsertHeadList on the per-page function list
            //
            hook_lock_acquire();

            PEPT_HOOKED_FUNCTION_INFO fi = (PEPT_HOOKED_FUNCTION_INFO)
                pool_manager_request(POOL_TAG_HOOKED_FUNC, sizeof(EPT_HOOKED_FUNCTION_INFO));
            if (!fi) { _InterlockedExchange(&g_hook_list_lock, 0); HOOK_RESTORE_CR3_AND_RETURN(FALSE); }
            RtlZeroMemory(fi, sizeof(*fi));

            //
            // trampoline: R3 hook 用 caller 提供的用户态可执行内存, R0 hook 用 kernel pool
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
            if (!fi->first_trampoline_address) { pool_manager_release(fi); _InterlockedExchange(&g_hook_list_lock, 0); HOOK_RESTORE_CR3_AND_RETURN(FALSE); }

            fi->virtual_address    = req->target_function;
            fi->fake_page_contents = existing->fake_page_va;
            fi->handler_function   = req->proxy_function;

            UINT64 off   = EPT_PML1_PAGE_OFFSET(req->target_function);
            PUINT8 fake  = &existing->fake_page_va[off];
            SIZE_T min_sz = (req->hook_type == 1) ? 3 : (req->hook_type == 2) ? 1 : 14;
            SIZE_T ow = 0;
            while (ow < min_sz) ow += LDE((PUINT8)req->target_function + ow, 64);
            fi->hook_size = ow;
            fi->protect_dll_base = req->protect_dll_base;

            RtlCopyMemory(fi->first_trampoline_address, req->target_function, ow);
            hook_write_absolute_jump(&fi->first_trampoline_address[ow],
                                     (UINT64)req->target_function + ow);

            if (req->origin_function)
                *req->origin_function = fi->first_trampoline_address;

            switch (req->hook_type) {
            case 0: hook_write_absolute_jump(fake, (UINT64)req->proxy_function); break;
            case 1: fake[0]=0x0F; fake[1]=0x01; fake[2]=0xC1; break;
            case 2: fake[0]=0xCC; break;
            }

            InsertHeadList(&existing->hooked_functions_list, &fi->hooked_function_list);
            _InterlockedExchange(&g_hook_list_lock, 0);

            _mm_mfence();
            ept_invept_single(vcpu->ept_pointer);
            HOOK_RESTORE_CR3_AND_RETURN(TRUE);
        }
    }

    //
    // page not found — need full install. acquire lock to prevent
    // concurrent InsertHeadList corruption from multiple CPUs.
    //
    hook_lock_acquire();

    //
    // double-check after lock: another CPU may have installed while we waited
    //
    for (hcur = g_ept->hooked_pages.Flink; hcur != &g_ept->hooked_pages; hcur = hcur->Flink)
    {
        PEPT_HOOKED_PAGE_INFO existing2 = CONTAINING_RECORD(hcur, EPT_HOOKED_PAGE_INFO, hooked_page_list);
        if (existing2->pfn_of_hooked_page == target_pfn)
        {
            _InterlockedExchange(&g_hook_list_lock, 0);

            // found after lock — lightweight path (split + PTE + INVEPT)
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
            _mm_mfence();
            ept_invept_single(vcpu->ept_pointer);
            HOOK_RESTORE_CR3_AND_RETURN(TRUE);
        }
    }

    // split 2MB → 4KB
    PVMM_EPT_DYNAMIC_SPLIT split = NULL;
    PEPT_PML1_ENTRY pte = NULL;

    PEPT_PML2_ENTRY pml2 = ept_get_pml2(vcpu->ept_page_table, (SIZE_T)phys_addr);
    if (pml2 && pml2->LargePage)
    {
        split = ept_split_large_page_pool(vcpu->ept_page_table, (SIZE_T)phys_addr);
        if (!split) { _InterlockedExchange(&g_hook_list_lock, 0); HOOK_RESTORE_CR3_AND_RETURN(FALSE); }
        pte = &split->PML1[ADDRMASK_EPT_PML1_INDEX(phys_addr)];
    }
    else
    {
        pte = ept_get_pml1(vcpu->ept_page_table, (SIZE_T)phys_addr);
    }
    if (!pte) { _InterlockedExchange(&g_hook_list_lock, 0); HOOK_RESTORE_CR3_AND_RETURN(FALSE); }

    // 分配跟踪结构
    PEPT_HOOKED_PAGE_INFO hp = (PEPT_HOOKED_PAGE_INFO)
        pool_manager_request(POOL_TAG_HOOKED_PAGE, sizeof(EPT_HOOKED_PAGE_INFO));
    if (!hp) { _InterlockedExchange(&g_hook_list_lock, 0); HOOK_RESTORE_CR3_AND_RETURN(FALSE); }
    RtlZeroMemory(hp, sizeof(*hp));
    InitializeListHead(&hp->hooked_functions_list);

    PEPT_HOOKED_FUNCTION_INFO fi = (PEPT_HOOKED_FUNCTION_INFO)
        pool_manager_request(POOL_TAG_HOOKED_FUNC, sizeof(EPT_HOOKED_FUNCTION_INFO));
    if (!fi) { pool_manager_release(hp); _InterlockedExchange(&g_hook_list_lock, 0); HOOK_RESTORE_CR3_AND_RETURN(FALSE); }
    RtlZeroMemory(fi, sizeof(*fi));

    //
    // trampoline: R3 hook 用 caller 提供的用户态可执行内存, R0 hook 用 kernel pool
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
    if (!fi->first_trampoline_address) { pool_manager_release(fi); pool_manager_release(hp); _InterlockedExchange(&g_hook_list_lock, 0); HOOK_RESTORE_CR3_AND_RETURN(FALSE); }

    // 设置 hooked page — fake page in stealth region (EPT X-only)
    hp->pfn_of_hooked_page = target_pfn;
    {
        UINT64 fake_pfn = 0;
        hp->fake_page_va = stealth_region_alloc_page(&fake_pfn);
        if (!hp->fake_page_va) { pool_manager_release(fi); pool_manager_release(hp); _InterlockedExchange(&g_hook_list_lock, 0); HOOK_RESTORE_CR3_AND_RETURN(FALSE); }
        hp->pfn_of_fake_page_contents = fake_pfn;
    }
    hp->entry_address = pte;
    hp->target_cr3 = req->target_cr3 & CR3_ADDR_MASK;

    // 拷贝原始页面到 fake page (stealth region)
    RtlCopyMemory(hp->fake_page_va, PAGE_ALIGN(req->target_function), PAGE_SIZE);

    // LDE + 构建 trampoline
    fi->virtual_address    = req->target_function;
    fi->fake_page_contents = hp->fake_page_va;
    fi->handler_function   = req->proxy_function;

    UINT64 off   = EPT_PML1_PAGE_OFFSET(req->target_function);
    PUINT8 fake  = &hp->fake_page_va[off];
    SIZE_T min_sz = (req->hook_type == 1) ? 3 : (req->hook_type == 2) ? 1 : 14;
    SIZE_T ow = 0;
    while (ow < min_sz) ow += LDE((PUINT8)req->target_function + ow, 64);
    fi->hook_size = ow;
    fi->protect_dll_base = req->protect_dll_base;

    RtlCopyMemory(fi->first_trampoline_address, req->target_function, ow);
    hook_write_absolute_jump(&fi->first_trampoline_address[ow],
                             (UINT64)req->target_function + ow);

    if (req->origin_function)
        *req->origin_function = fi->first_trampoline_address;

    // 写 hook payload
    switch (req->hook_type) {
    case 0: hook_write_absolute_jump(fake, (UINT64)req->proxy_function); break;
    case 1: fake[0]=0x0F; fake[1]=0x01; fake[2]=0xC1; break;
    case 2: fake[0]=0xCC; break;
    }

    // PTE 权限
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
    // R3 hook: 切回 system CR3 (离开 caller_cr3)
    // 后续 PTE 修改和 INVEPT 不需要用户态 VA 访问
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

    _mm_mfence();
    ept_invept_single(vcpu->ept_pointer);
    return TRUE;

    #undef HOOK_RESTORE_CR3_AND_RETURN
}

//
// VMX-root: unhook — first CPU does list removal, all CPUs restore PTE
//
BOOLEAN
ept_unhook_install(VIRTUAL_MACHINE_STATE * vcpu, PEPT_UNHOOK_VMCALL_PARAM req)
{
    if (!g_ept || !req->target_function) return FALSE;

    UINT64 phys_addr  = MmGetPhysicalAddress(req->target_function).QuadPart;
    UINT64 target_pfn = phys_addr >> 12;

    // first CPU only: remove from lists and free
    if (_InterlockedCompareExchange(&req->unhooked, 1, 0) == 0)
    {
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
                    RemoveEntryList(&fn->hooked_function_list);
                    if (fn->first_trampoline_address && !fn->user_trampoline) pool_manager_release(fn->first_trampoline_address);
                    pool_manager_release(fn);
                    break;
                }
            }
            if (IsListEmpty(&hp->hooked_functions_list))
            {
                RemoveEntryList(&hp->hooked_page_list);
                pool_manager_release(hp);
            }
            req->result = TRUE;
            break;
        }
    }

    //
    // 恢复所有 CPU 的 PTE 到 RWX
    // (不能只恢复当前 CPU，其他 CPU 的 EPT PTE 也需要恢复)
    //
    for (UINT32 i = 0; i < g_cpu_count; i++)
    {
        if (!g_vcpu[i].ept_page_table) continue;
        PEPT_PML1_ENTRY p = ept_get_pml1(g_vcpu[i].ept_page_table, (SIZE_T)phys_addr);
        if (p)
        {
            p->ReadAccess      = 1;
            p->WriteAccess     = 1;
            p->ExecuteAccess   = 1;
            p->PageFrameNumber = target_pfn;
        }
    }
    _mm_mfence();
    ept_invept_single(vcpu->ept_pointer);
    return TRUE;
}

//
// unhook all — only restore PTEs and free memory.
// does NOT call INVEPT — caller is responsible for TLB invalidation.
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
            if (fn->first_trampoline_address) pool_manager_release(fn->first_trampoline_address);
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
        // EPT X-only → violation here. swap to hooked page PFN (zeroed) temporarily
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

    if (vcpu->mtf_restore_page)
    {
        PEPT_HOOKED_PAGE_INFO hp = vcpu->mtf_restore_page;

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
        // copies all 512 PTEs from real → fake, then re-applies NX=1
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
    // CRITICAL: do NOT call INVEPT — preserve the target VA's TLB entry!
    // the TLB has NX=0 cached → CPU continues executing → native speed.
    // anti-cheat reading the PTE → fake PT → sees NX=1 → clean.
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
                // NO INVEPT — preserve target VA's TLB entry (NX=0 cached)!
            }
        }

        vcpu->stealth_pf_swapped_hook = NULL;
    }

    //
    // stealth #PF recovery: PT page was swapped to real view (NX=0) so CPU
    // could build a TLB entry. now swap it BACK to fake view (NX=1).
    //
    // CRITICAL: do NOT flush the stealth VA's TLB entry!
    // the TLB has NX=0 cached → CPU continues executing from TLB → native speed.
    // anti-cheat reading the PTE → fake PT → sees NX=1 → clean.
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
        // (guest-linear → host-physical) for this EPTP. this would destroy
        // the stealth VA's TLB entry, forcing a page walk on the next
        // instruction fetch → fake PT → NX=1 → #PF again → infinite loop.
        //
        // instead: just write the EPT PTE directly. the old EPT entry
        // (pointing to real PT page) may be cached in EPT TLB, but that's
        // actually beneficial — if the CPU uses the cached EPT entry for
        // a guest page walk, it sees the real PT (NX=0), which is what we
        // want. the fake PT is only for anti-cheat reads, which go through
        // a different EPT violation path (write-protected PT page).
        //
        // the stale EPT TLB entry will eventually be evicted naturally,
        // at which point the new PTE (fake view) takes effect.
        //
        if (sp->fake_pt)
        {
            PEPT_PML1_ENTRY pt_pte = ept_get_pml1(vcpu->ept_page_table,
                (SIZE_T)(sp->fake_pt->pt_page_pfn << 12));
            if (pt_pte)
            {
                pt_pte->AsUInt = sp->fake_pt->pt_fake_entry.AsUInt;
                _mm_mfence();
                // NO INVEPT — preserve stealth VA's TLB entry!
            }
        }

        // keep execute view — shellcode reads its own data from the same page
        if (0 && !sp->resident)
        {
            PEPT_PML1_ENTRY target_pte = ept_get_pml1(vcpu->ept_page_table,
                (SIZE_T)(sp->pfn_of_target << 12));
            if (target_pte)
            {
                target_pte->AsUInt = sp->original_entry.AsUInt;
                _mm_mfence();
                // NO INVEPT here either for oneshot — let stale TLB be
            }
        }
        // for resident: target page stays in execute view → code continues from TLB

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

// debug counters — safe in VMX-root (no OS API calls, just atomic increment)
volatile LONG g_dbg_pf_called = 0;    // ept_hook_handle_pf was called
volatile LONG g_dbg_pf_matched = 0;   // fault VA matched a hooked page
volatile LONG g_dbg_pf_skipped = 0;   // skipped (no fake_pt/exec_pt)

BOOLEAN
ept_hook_handle_pf(VIRTUAL_MACHINE_STATE * vcpu, UINT64 fault_addr, UINT32 error_code)
{
    if (!g_ept || IsListEmpty(&g_ept->hooked_pages)) return FALSE;

    //
    // ONLY handle NX violations: P=1 (page present) + I/D=1 (instruction fetch).
    // P=0 means demand paging — must re-inject to guest so Windows pages it in.
    // error_code bit 0 = P (present), bit 4 = I/D (instruction fetch).
    //
    _InterlockedIncrement(&g_dbg_pf_called);

    if (!(error_code & 0x01))
        return FALSE;  // page not present → demand paging, let guest handle

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

                // 1. resync exec PT from fake PT (fake page is "live" — gets all writes)
                //    then force NX=0 for our entry so CPU page walk succeeds
                if (hp->exec_pt_page)
                {
                    RtlCopyMemory(hp->exec_pt_page, hp->fake_pt->fake_page_va, PAGE_SIZE);
                    PUINT64 exec_pte = (PUINT64)hp->exec_pt_page;
                    exec_pte[hp->pt_pte_index] &= ~(1ULL << 63);  // NX=0
                }

                // 2. lazy split PT page EPT (2MB → 4KB) if needed, then swap to exec view
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

                // 3. arm MTF — after one instruction, MTF handler restores fake PT (NX=1)
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
                //
                // DLL protection filter: if protect_dll_base is set,
                // check guest RCX (DllHandle arg of LdrUnloadDll).
                // match → return STATUS_SUCCESS without unloading.
                // no match → redirect to original (trampoline).
                //
                if (fi->protect_dll_base != 0)
                {
                    UINT64 guest_rcx = vcpu->regs->rcx;
                    if (guest_rcx == fi->protect_dll_base)
                    {
                        // block unload: set rax = 0 (STATUS_SUCCESS),
                        // pop return address from stack, skip the function entirely.
                        vcpu->regs->rax = 0;
                        UINT64 guest_rsp = 0;
                        __vmx_vmread(VMCS_GUEST_RSP, &guest_rsp);

                        // read return address from [RSP] (need guest CR3 for user stack)
                        UINT64 saved_cr3 = vmx_enter_guest_cr3();
                        UINT64 guest_cr3 = 0;
                        __vmx_vmread(VMCS_GUEST_CR3, &guest_cr3);
                        UINT64 prev_cr3 = __readcr3();
                        __writecr3(guest_cr3);
                        UINT64 prev_flags = __readeflags();
                        __writeeflags(prev_flags | (1ULL << 18));  // SMAP bypass

                        UINT64 ret_addr = *(PUINT64)guest_rsp;

                        __writeeflags(prev_flags);
                        __writecr3(prev_cr3);
                        vmx_leave_guest_cr3(saved_cr3);

                        // set RIP = return address, RSP += 8 (pop)
                        __vmx_vmwrite(VMCS_GUEST_RIP, ret_addr);
                        __vmx_vmwrite(VMCS_GUEST_RSP, guest_rsp + 8);
                        return TRUE;
                    }
                    // not our DLL — redirect to trampoline (original function)
                    __vmx_vmwrite(VMCS_GUEST_RIP, (UINT64)fi->first_trampoline_address);
                    return TRUE;
                }

                __vmx_vmwrite(VMCS_GUEST_RIP, (UINT64)fi->handler_function);
                return TRUE;
            }
        }
    }
    return FALSE;
}

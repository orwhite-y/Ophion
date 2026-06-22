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

#define POOL_TAG_SPLIT       0
#define POOL_TAG_HOOKED_PAGE 1
#define POOL_TAG_HOOKED_FUNC 2
#define POOL_TAG_TRAMPOLINE  3

#define EPT_PML1_PAGE_OFFSET(_a) (((UINT64)(_a)) & 0xFFF)

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
static PVMM_EPT_DYNAMIC_SPLIT
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
    // 用预计算的物理地址，不在 VMX-root 调 MmGetPhysicalAddress
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
// ept_hook_install — 在 VMX-root 下运行 (HOST_CR3 = system CR3)
// 不用 private host CR3 → 所有内核内存直接可访问，和 VT_Driver 一样简单。
//
BOOLEAN
ept_hook_install(VIRTUAL_MACHINE_STATE * vcpu, PEPT_HOOK_VMCALL_PARAM req)
{
    if (!vcpu->ept_page_table || !req->target_function)
        return FALSE;

    UINT64 phys_addr = MmGetPhysicalAddress(req->target_function).QuadPart;
    if (!phys_addr)
        return FALSE;

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
                return TRUE;
            }

            //
            // 同页面不同函数 — 添加新 hook 到已有的 fake page
            //
            PEPT_HOOKED_FUNCTION_INFO fi = (PEPT_HOOKED_FUNCTION_INFO)
                pool_manager_request(POOL_TAG_HOOKED_FUNC, sizeof(EPT_HOOKED_FUNCTION_INFO));
            if (!fi) return FALSE;
            RtlZeroMemory(fi, sizeof(*fi));

            fi->first_trampoline_address = (PUINT8)pool_manager_request(POOL_TAG_TRAMPOLINE, 128);
            if (!fi->first_trampoline_address) { pool_manager_release(fi); return FALSE; }

            fi->virtual_address    = req->target_function;
            fi->fake_page_contents = existing->fake_page_contents;
            fi->handler_function   = req->proxy_function;

            UINT64 off   = EPT_PML1_PAGE_OFFSET(req->target_function);
            PUINT8 fake  = &existing->fake_page_contents[off];
            SIZE_T min_sz = (req->hook_type == 1) ? 3 : (req->hook_type == 2) ? 1 : 14;
            SIZE_T ow = 0;
            while (ow < min_sz) ow += LDE((PUINT8)req->target_function + ow, 64);
            fi->hook_size = ow;

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

            _mm_mfence();
            ept_invept_single(vcpu->ept_pointer);
            return TRUE;
        }
    }

    // split 2MB → 4KB
    PVMM_EPT_DYNAMIC_SPLIT split = NULL;
    PEPT_PML1_ENTRY pte = NULL;

    PEPT_PML2_ENTRY pml2 = ept_get_pml2(vcpu->ept_page_table, (SIZE_T)phys_addr);
    if (pml2 && pml2->LargePage)
    {
        split = ept_split_large_page_pool(vcpu->ept_page_table, (SIZE_T)phys_addr);
        if (!split) return FALSE;
        pte = &split->PML1[ADDRMASK_EPT_PML1_INDEX(phys_addr)];
    }
    else
    {
        pte = ept_get_pml1(vcpu->ept_page_table, (SIZE_T)phys_addr);
    }
    if (!pte) return FALSE;

    // 分配跟踪结构
    PEPT_HOOKED_PAGE_INFO hp = (PEPT_HOOKED_PAGE_INFO)
        pool_manager_request(POOL_TAG_HOOKED_PAGE, sizeof(EPT_HOOKED_PAGE_INFO));
    if (!hp) return FALSE;
    RtlZeroMemory(hp, sizeof(*hp));
    InitializeListHead(&hp->hooked_functions_list);

    PEPT_HOOKED_FUNCTION_INFO fi = (PEPT_HOOKED_FUNCTION_INFO)
        pool_manager_request(POOL_TAG_HOOKED_FUNC, sizeof(EPT_HOOKED_FUNCTION_INFO));
    if (!fi) { pool_manager_release(hp); return FALSE; }
    RtlZeroMemory(fi, sizeof(*fi));

    fi->first_trampoline_address = (PUINT8)pool_manager_request(POOL_TAG_TRAMPOLINE, 128);
    if (!fi->first_trampoline_address) { pool_manager_release(fi); pool_manager_release(hp); return FALSE; }

    // 设置 hooked page
    hp->pfn_of_hooked_page = target_pfn;
    // fake_page_contents 在 hooked_page 结构体里（pool 分配），
    // 物理地址 = pool 基地址 + 结构体内偏移
    UINT64 hp_pa = pool_manager_get_physical(hp);
    UINT64 fake_offset = (UINT64)hp->fake_page_contents - (UINT64)hp;
    hp->pfn_of_fake_page_contents = (hp_pa + fake_offset) >> 12;
    hp->entry_address = pte;

    // 拷贝原始页面到 fake page
    RtlCopyMemory(hp->fake_page_contents, PAGE_ALIGN(req->target_function), PAGE_SIZE);

    // LDE + 构建 trampoline
    fi->virtual_address    = req->target_function;
    fi->fake_page_contents = hp->fake_page_contents;
    fi->handler_function   = req->proxy_function;

    UINT64 off   = EPT_PML1_PAGE_OFFSET(req->target_function);
    PUINT8 fake  = &hp->fake_page_contents[off];
    SIZE_T min_sz = (req->hook_type == 1) ? 3 : (req->hook_type == 2) ? 1 : 14;
    SIZE_T ow = 0;
    while (ow < min_sz) ow += LDE((PUINT8)req->target_function + ow, 64);
    fi->hook_size = ow;

    RtlCopyMemory(fi->first_trampoline_address, req->target_function, ow);
    hook_write_absolute_jump(&fi->first_trampoline_address[ow],
                             (UINT64)req->target_function + ow);

    // 写 origin_function (如果提供了)
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
    hp->changed_entry.ReadAccess       = g_ept->execute_only_supported ? 0 : 1;
    hp->changed_entry.WriteAccess      = 0;
    hp->changed_entry.ExecuteAccess    = 1;
    hp->changed_entry.PageFrameNumber  = hp->pfn_of_fake_page_contents;

    hp->Options = EPTO_HOOK_FUNCTION;
    InsertHeadList(&hp->hooked_functions_list, &fi->hooked_function_list);
    InsertHeadList(&g_ept->hooked_pages, &hp->hooked_page_list);

    pte->ExecuteAccess = 0;
    pte->ReadAccess    = 1;
    pte->WriteAccess   = 1;

    _mm_mfence();
    ept_invept_single(vcpu->ept_pointer);
    return TRUE;
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
                    if (fn->first_trampoline_address) pool_manager_release(fn->first_trampoline_address);
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
    // no INVEPT here — VMX may already be off (VMXOFF done before this call)
}

VOID ept_unhook_all_broadcast(VOID) { ept_unhook_all(); }

// =========================================================================
//  PASSIVE_LEVEL wrapper (for Ophion's own IOCTL path)
// =========================================================================

extern "C" {
    NTKERNELAPI VOID    KeGenericCallDpc(PKDEFERRED_ROUTINE, PVOID);
    NTKERNELAPI VOID    KeSignalCallDpcDone(PVOID);
    NTKERNELAPI LOGICAL KeSignalCallDpcSynchronize(PVOID);
}

static VOID dpc_hook(PKDPC Dpc, PVOID Ctx, PVOID A1, PVOID A2)
{
    UNREFERENCED_PARAMETER(Dpc);
    PEPT_HOOK_VMCALL_PARAM req = (PEPT_HOOK_VMCALL_PARAM)Ctx;
    asm_vmx_vmcall(VMCALL_EPT_HOOK, (UINT64)req, req->caller_cr3, 0);
    KeSignalCallDpcSynchronize(A2);
    KeSignalCallDpcDone(A1);
}

static VOID dpc_unhook(PKDPC Dpc, PVOID Ctx, PVOID A1, PVOID A2)
{
    UNREFERENCED_PARAMETER(Dpc);
    PEPT_UNHOOK_VMCALL_PARAM req = (PEPT_UNHOOK_VMCALL_PARAM)Ctx;
    asm_vmx_vmcall(VMCALL_EPT_UNHOOK, (UINT64)req, req->caller_cr3, 0);
    KeSignalCallDpcSynchronize(A2);
    KeSignalCallDpcDone(A1);
}

BOOLEAN
ept_hook_function(PVOID target, PVOID proxy, PVOID * original, UINT32 hook_type)
{
    EPT_HOOK_VMCALL_PARAM req = {};
    req.caller_cr3      = __readcr3();
    req.target_function = target;
    req.proxy_function  = proxy;
    req.origin_function = original;
    req.hook_type       = hook_type;
    KeGenericCallDpc(dpc_hook, &req);
    return req.result;
}

BOOLEAN
ept_unhook_function(PVOID target)
{
    EPT_UNHOOK_VMCALL_PARAM req = {};
    req.caller_cr3      = __readcr3();
    req.target_function = target;
    KeGenericCallDpc(dpc_unhook, &req);
    return req.result;
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
        PEPT_PML1_ENTRY my_pte = ept_get_pml1(vcpu->ept_page_table,
            (SIZE_T)(hp->pfn_of_hooked_page << 12));
        if (my_pte) ept_swap_page(my_pte, hp->original_entry, vcpu->ept_pointer);
        vcpu->mtf_restore_page = NULL;
    }
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
        PLIST_ENTRY fc = hp->hooked_functions_list.Flink;
        while (fc != &hp->hooked_functions_list)
        {
            PEPT_HOOKED_FUNCTION_INFO fi = CONTAINING_RECORD(fc, EPT_HOOKED_FUNCTION_INFO, hooked_function_list);
            fc = fc->Flink;
            if ((UINT64)fi->virtual_address == rip)
            {
                __vmx_vmwrite(VMCS_GUEST_RIP, (UINT64)fi->handler_function);
                return TRUE;
            }
        }
    }
    return FALSE;
}

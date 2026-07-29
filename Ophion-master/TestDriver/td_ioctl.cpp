#include "td_common.h"

// =========================================================================
//  IOCTL handler
// =========================================================================

NTSTATUS TdCreateClose(PDEVICE_OBJECT, PIRP irp)
{
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS TdIoControl(PDEVICE_OBJECT, PIRP irp)
{
    NTSTATUS st = STATUS_SUCCESS;
    PIO_STACK_LOCATION io = IoGetCurrentIrpStackLocation(irp);
    irp->IoStatus.Information = 0;

    HYPERPLATFORM_LOG_INFO("[td-ioctl] enter: code=0x%08X in=%u out=%u",
        io->Parameters.DeviceIoControl.IoControlCode,
        io->Parameters.DeviceIoControl.InputBufferLength,
        io->Parameters.DeviceIoControl.OutputBufferLength);

    switch (io->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_INJECT:
    {
        //
        // EPT hook-based shellcode injection 閳?ALL pre-built at PASSIVE_LEVEL.
        // VMX-root only does EPT manipulation, NEVER touches user VA (SMAP safe).
        //
        // flow:
        //   1. alloc PAGE_READWRITE in target (NX=1 in PTE, clean VAD)
        //   2. build shellcode, copy to kernel buffer, patch VMCALL at entry
        //   3. build trampoline at PASSIVE_LEVEL: [saved bytes] + [abs jmp back]
        //   4. zero original page (COW may change PA), walk PT AFTER zero
        //   5. copy PT page to buffer, force NX=0 in buffer (NOT real PTE)
        //   6. VMCALL_EPT_HOOK_INJECT: EPT split + fake PT(NX=1) + exec PT(NX=0)
        //   7. create thread 閳?#PF(NX) 閳?HV swaps to exec PT 閳?TLB(NX=0) 閳?executes
        //
        if (io->Parameters.DeviceIoControl.InputBufferLength < sizeof(TD_INJECT_PARAMS) ||
            io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(TD_INJECT_PARAMS))
        { st = STATUS_BUFFER_TOO_SMALL; break; }

        TD_INJECT_PARAMS * p = (TD_INJECT_PARAMS *)irp->AssociatedIrp.SystemBuffer;

        PEPROCESS proc = NULL;
        st = PsLookupProcessByProcessId((HANDLE)p->target_pid, &proc);
        if (!NT_SUCCESS(st)) break;

        KAPC_STATE apc_state;
        KeStackAttachProcess(proc, &apc_state);

        ULONG gap_offset = 0, gap_avail = 0;

        //
        // try section tail padding first 閳?shellcode goes into the zero-padded
        // tail of a section's last page. no new allocation, no new VAD.
        // original page content preserved (real DLL code stays in front).
        //
        PVOID base = TdFindGapInProcess(g_shellcode_pic_size + 32, &gap_offset, &gap_avail);
        if (base)
        {
            HYPERPLATFORM_LOG_INFO("[td] inject: section padding VA=%p+0x%X avail=0x%X pid=%llu",
                       base, gap_offset, gap_avail, p->target_pid);
        }

        if (!base)
        {
            //
            // no gap found 閳?refuse to inject. never allocate new memory
            // (VirtualAlloc creates a visible VAD that anti-cheat can scan).
            //
            HYPERPLATFORM_LOG_ERROR("[td] inject: no section gap found, aborting (no VirtualAlloc fallback)");
            KeUnstackDetachProcess(&apc_state);
            ObDereferenceObject(proc);
            st = STATUS_NOT_FOUND;
            break;
        }

        HYPERPLATFORM_LOG_INFO("[td] inject: VA=%p offset=0x%X pid=%llu (gap mode)",
                   base, gap_offset, p->target_pid);

        UINT64 caller_cr3 = __readcr3();

        //
        // shellcode entry VA = base + gap_offset.
        // for gap mode: inside DLL section padding.
        // for fallback: at page start (gap_offset = 0).
        //
        PVOID entry_va = (PUINT8)base + gap_offset;

        // --- step 3: build fake_buf (shadow page content) ---
        //
        // gap mode:  copy original page (preserving DLL code) 閳?write shellcode at gap_offset
        // fallback:  page starts empty 閳?write shellcode at offset 0
        // original page is NOT zeroed in gap mode 閳?DLL code stays intact.
        //
        PVOID fake_buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'kjnI');
        if (!fake_buf)
        {
            KeUnstackDetachProcess(&apc_state);
            ObDereferenceObject(proc);
            st = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        //
        // trigger COW to get a private physical page for this process.
        // the shared DLL page PA is used by ALL processes 閳?EPT hooking
        // the shared PA would affect every process.
        //
        // direct PTE manipulation: set Write bit in PTE 閳?write byte 閳?COW.
        // no ZwProtectVirtualMemory call (AC can monitor that API).
        // user-visible page protection stays unchanged.
        //
        // COW: get a private physical page for this process
        {
            UINT64 pa_before = MmGetPhysicalAddress(base).QuadPart;

            //
            // walk guest page table to find PTE, set Write bit directly.
            // caller_cr3 is the target process CR3 (we're attached).
            //
            UINT64 cow_cr3 = __readcr3();
            UINT64 cow_va  = (UINT64)base;
            PHYSICAL_ADDRESS cow_pa;
            BOOLEAN cow_done = FALSE;

            // PML4
            cow_pa.QuadPart = (LONGLONG)((cow_cr3 & ~0xFFFULL) + ((cow_va >> 39) & 0x1FF) * 8);
            PUINT64 pml4e = (PUINT64)MmGetVirtualForPhysical(cow_pa);
            if (pml4e && (*pml4e & 1))
            {
                // PDPT
                cow_pa.QuadPart = (LONGLONG)((*pml4e & 0x000FFFFFFFFFF000ULL) + ((cow_va >> 30) & 0x1FF) * 8);
                PUINT64 pdpe = (PUINT64)MmGetVirtualForPhysical(cow_pa);
                if (pdpe && (*pdpe & 1) && !(*pdpe & (1ULL << 7)))
                {
                    // PD
                    cow_pa.QuadPart = (LONGLONG)((*pdpe & 0x000FFFFFFFFFF000ULL) + ((cow_va >> 21) & 0x1FF) * 8);
                    PUINT64 pde = (PUINT64)MmGetVirtualForPhysical(cow_pa);
                    if (pde && (*pde & 1) && !(*pde & (1ULL << 7)))
                    {
                        // PT 閳?PTE
                        cow_pa.QuadPart = (LONGLONG)((*pde & 0x000FFFFFFFFFF000ULL) + ((cow_va >> 12) & 0x1FF) * 8);
                        PUINT64 pte = (PUINT64)MmGetVirtualForPhysical(cow_pa);
                        if (pte && (*pte & 1))
                        {
                            // set Write bit, write, restore
                            UINT64 orig_pte = *pte;
                            *pte = orig_pte | (1ULL << 1);  // set W bit
                            __invlpg((PVOID)cow_va);         // flush TLB for this VA

                            // write to padding 閳?triggers COW
                            ((volatile UINT8 *)base)[gap_offset] = 0x01;
                            ((volatile UINT8 *)base)[gap_offset] = 0x00;

                            // restore PTE (COW already happened, PTE now points to private page)
                            // re-read PTE since COW may have changed it
                            // just clear W bit if it was originally clear
                            if (!(orig_pte & (1ULL << 1)))
                            {
                                UINT64 new_pte = *pte;
                                *pte = new_pte & ~(1ULL << 1);
                                __invlpg((PVOID)cow_va);
                            }
                            cow_done = TRUE;
                        }
                    }
                }
            }

            UINT64 pa_after = MmGetPhysicalAddress(base).QuadPart;
            HYPERPLATFORM_LOG_INFO("[td] inject: COW %s (PA %llx -> %llx) pte_method=%d",
                       (pa_before != pa_after) ? "OK" : "SAME", pa_before, pa_after, cow_done);
        }

        // copy original page content (DLL code in front, zeros in padding)
        RtlCopyMemory(fake_buf, base, PAGE_SIZE);

        // build PIC shellcode at gap_offset inside fake_buf
        if (!TdBuildShellcodePIC((PUINT8)fake_buf + gap_offset, PAGE_SIZE - gap_offset))
        {
            RtlSecureZeroMemory(fake_buf, PAGE_SIZE);
            ExFreePoolWithTag(fake_buf, 'kjnI');
            KeUnstackDetachProcess(&apc_state);
            ObDereferenceObject(proc);
            st = STATUS_UNSUCCESSFUL;
            HYPERPLATFORM_LOG_ERROR("[td] inject: PIC shellcode build failed");
            break;
        }
        // gap mode: original page untouched 閳?DLL code + zero padding stays

        UINT64 base_phys = MmGetPhysicalAddress(base).QuadPart;
        HYPERPLATFORM_LOG_INFO("[td] inject: PA=%llx entry=%p", base_phys, entry_va);

        if (!base_phys)
        {
            RtlSecureZeroMemory(fake_buf, PAGE_SIZE);
            ExFreePoolWithTag(fake_buf, 'kjnI');
            KeUnstackDetachProcess(&apc_state);
            ObDereferenceObject(proc);
            st = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        // --- step 4: build trampoline + patch VMCALL in fake_buf ---
        //
        // VMCALL at shellcode entry (gap_offset in shadow page).
        // trampoline at shadow offset 0xF00.
        // HV intercepts VMCALL 閳?set RIP = base+0xF00 閳?trampoline 閳?jmp back.
        //
        UINT32 hook_size = 4;  // sub rsp, 28h = 48 83 EC 28

        // trampoline at 0xF00: [saved shellcode entry bytes] + [abs jmp entry+4]
        RtlCopyMemory((PUINT8)fake_buf + 0xF00, (PUINT8)fake_buf + gap_offset, hook_size);
        {
            PUINT8 t = (PUINT8)fake_buf + 0xF00 + hook_size;
            UINT64 dst = (UINT64)entry_va + hook_size;
            t[0] = 0x68;
            *(PUINT32)(t + 1) = (UINT32)dst;
            t[5] = 0xC7; t[6] = 0x44; t[7] = 0x24; t[8] = 0x04;
            *(PUINT32)(t + 9) = (UINT32)(dst >> 32);
            t[13] = 0xC3;
        }

        // patch VMCALL at shellcode entry in shadow
        ((PUINT8)fake_buf)[gap_offset + 0] = 0x0F;
        ((PUINT8)fake_buf)[gap_offset + 1] = 0x01;
        ((PUINT8)fake_buf)[gap_offset + 2] = 0xC1;

        HYPERPLATFORM_LOG_INFO("[td] inject: trampoline at shadow+0xF00, entry at +0x%X", gap_offset);

        // --- step 5b: pre-compute PT page info for fake PT / NX hiding ---
        //
        // walk guest page tables AFTER zeroing (COW may have changed PTE/PA).
        // NEVER clear NX in real PTE 閳?Windows' MiAgeWorkingSet restores it.
        // instead: copy PT page to kernel buffer, force NX=0 in the COPY.
        // VMX-root builds exec PT from this copy (NX=0), fake PT gets NX=1.
        //
        UINT64 pt_pfn = 0;
        UINT32 pt_idx = 0;
        PVOID  pt_page_buf = NULL;

        PVOID pt_real_va = NULL;  // system VA of real PT page (for VMX-root resync)

        //
        // DISABLED fake PT for gap mode 閳?the #PF + MTF single-step conflicts
        // with the VMCALL at shellcode entry (MTF fires before VMCALL executes,
        // restoring fake PT NX=1, causing infinite #PF loop).
        //
        // gap mode uses EPT X=0 path instead: EPT violation 閳?shadow 閳?VMCALL.
        // PTE NX bit is already 0 (PAGE_EXECUTE_READ .text section), no fake PT needed.
        //
        // TODO: fix #PF handler to not arm MTF for inject hook pages, then re-enable.
        //
        //
        // fake PT disabled for gap mode 閳?the #PF + MTF single-step conflicts
        // with the VMCALL at shellcode entry. gap mode uses EPT X=0 path instead.
        // PTE NX bit is already 0 (PAGE_EXECUTE_READ .text section), no fake PT needed.
        //

        // --- step 6: VMCALL to set up EPT (kernel buffers only, no user VA in VMX-root) ---
        TD_HOOK_INJECT_PARAM inj_req = {};
        inj_req.target_va        = (UINT64)entry_va;
        inj_req.target_phys      = base_phys;
        inj_req.handler_va       = (UINT64)base + 0xF00;  // trampoline in shadow page
        inj_req.fake_page_buffer = fake_buf;
        inj_req.hook_size        = hook_size;
        inj_req.force_read_access = FALSE;  // execute-only: reads 閳?original page (zeros)
        inj_req.pt_page_pfn      = pt_pfn;
        inj_req.pt_pte_index     = pt_idx;
        inj_req.pt_page_copy     = pt_page_buf;
        inj_req.pt_page_va       = pt_real_va;

        KeGenericCallDpc([](PKDPC, PVOID Ctx, PVOID A1, PVOID A2) {
            hv_vmcall_simple(VMCALL_EPT_HOOK_INJECT, (UINT64)Ctx, 0, 0);
            KeSignalCallDpcSynchronize(A2);
            KeSignalCallDpcDone(A1);
        }, &inj_req);

        RtlSecureZeroMemory(fake_buf, PAGE_SIZE);
        ExFreePoolWithTag(fake_buf, 'kjnI');
        if (pt_page_buf) { RtlSecureZeroMemory(pt_page_buf, PAGE_SIZE); ExFreePoolWithTag(pt_page_buf, 'kjnI'); }

        if (inj_req.result)
        {
            // original page already zeroed (step 3, before PA read + EPT install).
            // EPT binds to the zeroed page's PA. reads 閳?zeros. execute 閳?fake page.

            HYPERPLATFORM_LOG_INFO("[td] inject: EPT hook OK, fake_pt=%s",
                       inj_req.fake_pt_ok ? "YES" : "NO");

            // track for cleanup (no MDL 閳?page is one-shot inject, not persistent)
            R3_HOOK_ENTRY * he = R3HookFindFree();
            if (he)
            {
                he->active          = TRUE;
                he->target_pid      = p->target_pid;
                he->target_va       = base;
                he->trampoline_va   = NULL;
                he->trampoline_size = 0;
                he->target_mdl      = NULL;
                he->target_cr3      = caller_cr3;
            }

            p->shellcode_va = (UINT64)entry_va;
            p->actual_size  = PAGE_SIZE;
            irp->IoStatus.Information = sizeof(TD_INJECT_PARAMS);
            HYPERPLATFORM_LOG_INFO("[td] inject: EPT hook OK");
        }
        else
        {
            HYPERPLATFORM_LOG_ERROR("[td] inject: EPT hook FAILED");
            st = STATUS_UNSUCCESSFUL;
        }

        //
        // --- step 7: resolve trigger function (valid CFG target) ---
        //
        // gap address is NOT in CFG bitmap 閳?can't create thread there directly.
        // instead: EPT hook a legit function 閳?redirect to entry_va (gap shellcode).
        // thread entry = trigger function (in CFG bitmap) 閳?EPT hook 閳?shellcode.
        //
        // NtYieldExecution: cold function, rarely monitored by anti-cheat.
        // takes no params, returns immediately 閳?perfect as thread entry stub.
        // (NtTestAlert is a well-known injection vector and heavily monitored.)
        //
        PVOID trigger_fn = (PVOID)p->trigger_va;

        // resolve trigger from target process's ntdll via PEB walk
        if (!trigger_fn && NT_SUCCESS(st))
        {
            // try NtYieldExecution first, fall back to RtlSetCurrentTransaction
            static const char * trigger_candidates[] = {
                "NtYieldExecution",
                "RtlSetCurrentTransaction",
                "NtTestAlert",
                NULL
            };

            PPEB peb = PsGetProcessPeb(proc);
            if (peb)
            {
                __try {
                    TD_PEB_LDR_DATA * ldr = *(TD_PEB_LDR_DATA **)((PUINT8)peb + 0x18);
                    if (ldr)
                    {
                        PLIST_ENTRY ldr_head = &ldr->InMemoryOrderModuleList;
                        PLIST_ENTRY ldr_cur = ldr_head->Flink;
                        while (ldr_cur != ldr_head)
                        {
                            TD_LDR_ENTRY * ldr_e = CONTAINING_RECORD(ldr_cur, TD_LDR_ENTRY, InMemoryOrderLinks);
                            if (ldr_e->BaseDllName.Buffer &&
                                TdMatchDllName(ldr_e->BaseDllName.Buffer, ldr_e->BaseDllName.Length,
                                               g_ntdll_name, 9))
                            {
                                PIMAGE_DOS_HEADER dos_h = (PIMAGE_DOS_HEADER)ldr_e->DllBase;
                                PIMAGE_NT_HEADERS64 nt_h = (PIMAGE_NT_HEADERS64)((PUINT8)ldr_e->DllBase + dos_h->e_lfanew);
                                ULONG exp_rva = nt_h->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                                PIMAGE_EXPORT_DIRECTORY exp_d = (PIMAGE_EXPORT_DIRECTORY)((PUINT8)ldr_e->DllBase + exp_rva);
                                PULONG names = (PULONG)((PUINT8)ldr_e->DllBase + exp_d->AddressOfNames);
                                PUSHORT ords = (PUSHORT)((PUINT8)ldr_e->DllBase + exp_d->AddressOfNameOrdinals);
                                PULONG funcs = (PULONG)((PUINT8)ldr_e->DllBase + exp_d->AddressOfFunctions);

                                for (const char ** cand = trigger_candidates; *cand && !trigger_fn; cand++)
                                {
                                    for (ULONG ei = 0; ei < exp_d->NumberOfNames; ei++)
                                    {
                                        const char * fn = (const char *)((PUINT8)ldr_e->DllBase + names[ei]);
                                        if (strcmp(fn, *cand) == 0)
                                        {
                                            trigger_fn = (PUINT8)ldr_e->DllBase + funcs[ords[ei]];
                                            HYPERPLATFORM_LOG_INFO("[td] inject: trigger=%s at %p", *cand, trigger_fn);
                                            break;
                                        }
                                    }
                                }
                                break;
                            }
                            ldr_cur = ldr_cur->Flink;
                        }
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    HYPERPLATFORM_LOG_WARN("[td] inject: trigger resolve exception");
                }
            }
        }

        if (!trigger_fn && NT_SUCCESS(st))
        {
            HYPERPLATFORM_LOG_ERROR("[td] inject: cannot resolve trigger function");
            st = STATUS_NOT_FOUND;
        }

        //
        // --- step 8: EPT hook trigger 閳?entry_va (single VMCALL, CPU 0) ---
        //
        NTSTATUS hook_st = STATUS_UNSUCCESSFUL;
        if (NT_SUCCESS(st))
        {
            KAFFINITY old_aff = KeSetSystemAffinityThreadEx((KAFFINITY)1);  // CPU 0

            PVOID dummy_origin = NULL;
            hook_st = hv_vmcall_ex(
                VMCALL_EPT_HOOK,
                (UINT64)trigger_fn,         // target: NtYieldExecution
                (UINT64)entry_va,           // proxy: shellcode in gap
                (UINT64)&dummy_origin,      // origin (unused)
                caller_cr3,                 // caller CR3
                1,                          // hook_type = VMCALL (0F 01 C1)
                caller_cr3,                 // target_cr3 (per-process filter)
                0, 0, 2);                   // no user trampoline, flags bit1 = oneshot

            KeRevertToUserAffinityThreadEx(old_aff);

            HYPERPLATFORM_LOG_INFO("[td] inject: trigger hook %s (trigger=%p -> entry=%p st=0x%08X)",
                       NT_SUCCESS(hook_st) ? "OK" : "FAILED", trigger_fn, entry_va, hook_st);
        }

        if (!NT_SUCCESS(hook_st))
            st = hook_st;

        KeUnstackDetachProcess(&apc_state);

        //
        // --- step 9: create thread at trigger, pin to CPU 0 ---
        //
        // trigger hook only on CPU 0's EPT 閳?thread MUST run on CPU 0.
        // SUSPENDED 閳?set affinity 閳?resume.
        // keep thread handle for async cleanup.
        //
        HANDLE cleanup_thr_h = NULL;
        if (NT_SUCCESS(st) && p->shellcode_va)
        {
            if (g_pZwCreateThreadEx)
            {
                HANDLE thr_proc_h = NULL;
                NTSTATUS oh_st = ObOpenObjectByPointer(
                    proc, OBJ_KERNEL_HANDLE, NULL,
                    PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &thr_proc_h);

                if (NT_SUCCESS(oh_st))
                {
                    HANDLE thr_h = NULL;
                    NTSTATUS thr_st = g_pZwCreateThreadEx(
                        &thr_h, THREAD_ALL_ACCESS, NULL, thr_proc_h,
                        trigger_fn, NULL,
                        THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
                        0, 0, 0, NULL);

                    if (NT_SUCCESS(thr_st) && thr_h)
                    {
                        KAFFINITY cpu0 = (KAFFINITY)1;
                        ZwSetInformationThread(thr_h, ThreadAffinityMask, &cpu0, sizeof(cpu0));

                        ULONG prev = 0;
                        NTSTATUS resume_st = TdResumeThreadHandle(thr_h, &prev);
                        if (NT_SUCCESS(resume_st))
                        {
                            HYPERPLATFORM_LOG_INFO("[td] inject: thread SUSPENDED+CPU0+RESUMED trigger=%p", trigger_fn);
                            cleanup_thr_h = thr_h;  // keep for async cleanup (don't close yet)
                        }
                        else
                        {
                            HYPERPLATFORM_LOG_ERROR("[td] inject: thread resume failed: 0x%08X", resume_st);
                            TdCloseCreatedThreadHandle(thr_h, FALSE);
                            TdUnhookTriggerAllCpus(trigger_fn, caller_cr3);
                            st = resume_st;
                        }
                    }
                    else
                        HYPERPLATFORM_LOG_ERROR("[td] inject: ZwCreateThreadEx failed: 0x%08X", thr_st);
                    ZwClose(thr_proc_h);
                }
            }
            else
            {
                // fallback: RtlCreateUserThread
                KAFFINITY old_aff = KeSetSystemAffinityThreadEx((KAFFINITY)1);
                KAPC_STATE thr_apc;
                KeStackAttachProcess(proc, &thr_apc);

                HANDLE thr_h = NULL;
                CLIENT_ID cid = {};
                NTSTATUS thr_st = RtlCreateUserThread(
                    ZwCurrentProcess(), NULL, FALSE, 0, 0, 0,
                    trigger_fn, NULL, &thr_h, &cid);

                if (NT_SUCCESS(thr_st) && thr_h)
                {
                    KAFFINITY cpu0 = (KAFFINITY)1;
                    ZwSetInformationThread(thr_h, ThreadAffinityMask, &cpu0, sizeof(cpu0));
                    cleanup_thr_h = thr_h;
                }

                KeUnstackDetachProcess(&thr_apc);
                KeRevertToUserAffinityThreadEx(old_aff);
                HYPERPLATFORM_LOG_INFO("[td] inject: fallback RtlCreateUserThread trigger=%p st=0x%08X", trigger_fn, thr_st);
            }
        }

        //
        // --- step 10: async cleanup 閳?unhook trigger ASAP, inject stays resident ---
        //
        // trigger hook only needed for first thread creation 閳?shellcode entry.
        // once thread is running, unhook trigger immediately to minimize
        // EPT violation exposure on NtYieldExecution.
        // inject page EPT stealth stays permanently 閳?shellcode runs forever.
        //
        if (cleanup_thr_h && NT_SUCCESS(st))
        {
            // allocate cleanup context
            struct _INJECT_CLEANUP_CTX {
                HANDLE          thread_handle;
                PVOID           trigger_fn;
                PVOID           inject_entry;
                UINT64          target_cr3;
                UINT64          target_pid;
                PIO_WORKITEM    work_item;
            };

            PIO_WORKITEM wi = IoAllocateWorkItem(IoGetCurrentIrpStackLocation(irp)->DeviceObject);
            if (wi)
            {
                auto * ctx = (struct _INJECT_CLEANUP_CTX *)
                    ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(struct _INJECT_CLEANUP_CTX), 'nlcI');

                if (ctx)
                {
                    ctx->thread_handle = cleanup_thr_h;
                    ctx->trigger_fn    = trigger_fn;
                    ctx->inject_entry  = entry_va;
                    ctx->target_cr3    = caller_cr3;
                    ctx->target_pid    = p->target_pid;
                    ctx->work_item     = wi;

                    IoQueueWorkItem(wi, [](PDEVICE_OBJECT, PVOID context) {
                        auto * c = (struct _INJECT_CLEANUP_CTX *)context;

                        // short delay 閳?let thread start executing (trigger fires once)
                        LARGE_INTEGER delay;
                        delay.QuadPart = -5LL * 10000000LL;  // 5 sec
                        KeDelayExecutionThread(KernelMode, FALSE, &delay);

                        // thread handle kept open but not waited on (thread runs forever)
                        TdCloseCreatedThreadHandle(c->thread_handle, TRUE);

                        HYPERPLATFORM_LOG_INFO("[td] cleanup: unhooking trigger, inject stays resident");

                        // unhook trigger only 閳?inject page stays
                        PEPROCESS proc2 = NULL;
                        if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)c->target_pid, &proc2)))
                        {
                            KAPC_STATE apc2;
                            KeStackAttachProcess(proc2, &apc2);

                            KAFFINITY old = KeSetSystemAffinityThreadEx((KAFFINITY)1);

                            // unhook trigger (NtYieldExecution) 閳?no longer needed
                            hv_vmcall_ex(VMCALL_EPT_UNHOOK,
                                (UINT64)c->trigger_fn, 0, 0,
                                c->target_cr3, 0, 0, 0, 0, 0);

                            // inject page EPT stealth KEPT 閳?shellcode runs permanently
                            // read view  = original DLL code (anti-cheat sees clean page)
                            // exec view  = shadow page (shellcode loop)

                            KeRevertToUserAffinityThreadEx(old);
                            KeUnstackDetachProcess(&apc2);
                            ObDereferenceObject(proc2);

                            HYPERPLATFORM_LOG_INFO("[td] cleanup: trigger unhook=%p, inject RESIDENT=%p",
                                       c->trigger_fn, c->inject_entry);
                        }

                        IoFreeWorkItem(c->work_item);
                        ExFreePoolWithTag(c, 'nlcI');
                    }, DelayedWorkQueue, ctx);

                    cleanup_thr_h = NULL;  // ownership transferred to work item
                }
                else
                {
                    IoFreeWorkItem(wi);
                }
            }

            // if work item failed, close thread handle directly
            if (cleanup_thr_h)
            {
                TdCloseCreatedThreadHandle(cleanup_thr_h, TRUE);
                TdUnhookTriggerAllCpus(trigger_fn, caller_cr3);
            }
        }

        ObDereferenceObject(proc);
        break;
    }

    case IOCTL_EPT_HOOK:
    {
        st = TdEptHookNtCreateFile();
        break;
    }

    case IOCTL_EPT_UNHOOK:
    {
        st = TdEptUnhookNtCreateFile();
        break;
    }

    case IOCTL_EPT_HOOK_R3:
    {
        if (io->Parameters.DeviceIoControl.InputBufferLength < sizeof(TD_R3_HOOK_PARAMS) ||
            io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(TD_R3_HOOK_PARAMS))
        { st = STATUS_BUFFER_TOO_SMALL; break; }

        TD_R3_HOOK_PARAMS * p = (TD_R3_HOOK_PARAMS *)irp->AssociatedIrp.SystemBuffer;

        PVOID tramp = NULL;
        st = TdEptHookR3(
            p->target_pid,
            (PVOID)p->target_function_va,
            (PVOID)p->proxy_function_va,
            (UINT32)p->hook_type,
            &tramp);

        p->trampoline_va = (UINT64)tramp;
        p->status        = (UINT64)st;
        irp->IoStatus.Information = sizeof(TD_R3_HOOK_PARAMS);
        break;
    }

    case IOCTL_EPT_UNHOOK_R3:
    {
        if (io->Parameters.DeviceIoControl.InputBufferLength < sizeof(TD_R3_UNHOOK_PARAMS) ||
            io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(TD_R3_UNHOOK_PARAMS))
        { st = STATUS_BUFFER_TOO_SMALL; break; }

        TD_R3_UNHOOK_PARAMS * p = (TD_R3_UNHOOK_PARAMS *)irp->AssociatedIrp.SystemBuffer;

        st = TdEptUnhookR3(p->target_pid, (PVOID)p->target_function_va);
        p->status = (UINT64)st;
        irp->IoStatus.Information = sizeof(TD_R3_UNHOOK_PARAMS);
        break;
    }

    case IOCTL_INJECT_DLL:
    {
        //
        // manual-map DLL injection 閳?zero R3 API calls.
        // buffer layout: [TD_INJECT_DLL_PARAMS header] [raw DLL bytes]
        //
        ULONG in_len  = io->Parameters.DeviceIoControl.InputBufferLength;
        ULONG out_len = io->Parameters.DeviceIoControl.OutputBufferLength;

        if (in_len < sizeof(TD_INJECT_DLL_PARAMS) || out_len < sizeof(TD_INJECT_DLL_PARAMS))
        { st = STATUS_BUFFER_TOO_SMALL; break; }

        TD_INJECT_DLL_PARAMS * p = (TD_INJECT_DLL_PARAMS *)irp->AssociatedIrp.SystemBuffer;

        if (p->dll_offset < sizeof(TD_INJECT_DLL_PARAMS) ||
            p->dll_size == 0 ||
            (UINT64)p->dll_offset + p->dll_size > in_len)
        {
            HYPERPLATFORM_LOG_ERROR("[td-map] invalid DLL params: offset=%u size=%u in_len=%u",
                       p->dll_offset, p->dll_size, in_len);
            st = STATUS_INVALID_PARAMETER;
            break;
        }

        PUINT8 raw_dll = (PUINT8)p + p->dll_offset;

        HYPERPLATFORM_LOG_INFO("[td-map] IOCTL_INJECT_DLL: pid=%llu dll_size=%u",
                   p->target_pid, p->dll_size);

        // look up target process
        PEPROCESS proc = NULL;
        st = PsLookupProcessByProcessId((HANDLE)p->target_pid, &proc);
        if (!NT_SUCCESS(st))
        {
            HYPERPLATFORM_LOG_ERROR("[td-map] PsLookupProcessByProcessId failed: 0x%08X", st);
            break;
        }

        KAPC_STATE apc_state;
        KeStackAttachProcess(proc, &apc_state);

        PVOID image_base  = NULL;
        PVOID image_entry = NULL;

        st = TdManualMapInProcess(proc, raw_dll, (SIZE_T)p->dll_size, &image_base, &image_entry);

        if (NT_SUCCESS(st) && image_entry)
        {
            HYPERPLATFORM_LOG_INFO("[td-map] mapped OK: base=%p entry=%p", image_base, image_entry);

            // fill output
            PIMAGE_DOS_HEADER raw_dos = (PIMAGE_DOS_HEADER)raw_dll;
            PIMAGE_NT_HEADERS64 raw_nt = (PIMAGE_NT_HEADERS64)(raw_dll + raw_dos->e_lfanew);
            p->out_base  = (UINT64)image_base;
            p->out_entry = (UINT64)image_entry;
            p->out_size  = raw_nt->OptionalHeader.SizeOfImage;
            irp->IoStatus.Information = sizeof(TD_INJECT_DLL_PARAMS);

            //
            // resolve trigger from ntdll (prefer cold functions that are not hot scheduler paths)
            //
            PVOID trigger_fn = NULL;
            {
                static const char * trigger_candidates[] = {
                    "NtTestAlert", "RtlSetCurrentTransaction", NULL
                };
                PPEB peb = PsGetProcessPeb(proc);
                if (peb)
                {
                    __try {
                        TD_PEB_LDR_DATA * ldr = *(TD_PEB_LDR_DATA **)((PUINT8)peb + 0x18);
                        if (ldr)
                        {
                            PLIST_ENTRY ldr_head = &ldr->InMemoryOrderModuleList;
                            PLIST_ENTRY ldr_cur = ldr_head->Flink;
                            while (ldr_cur != ldr_head)
                            {
                                TD_LDR_ENTRY * ldr_e = CONTAINING_RECORD(ldr_cur, TD_LDR_ENTRY, InMemoryOrderLinks);
                                if (ldr_e->BaseDllName.Buffer &&
                                    TdMatchDllName(ldr_e->BaseDllName.Buffer, ldr_e->BaseDllName.Length,
                                                   g_ntdll_name, 9))
                                {
                                    for (const char ** c = trigger_candidates; *c && !trigger_fn; c++)
                                    {
                                        trigger_fn = TdFindExportByName(ldr_e->DllBase, *c);
                                        if (trigger_fn)
                                            HYPERPLATFORM_LOG_INFO("[td-map] trigger=%s at %p", *c, trigger_fn);
                                    }
                                    break;
                                }
                                ldr_cur = ldr_cur->Flink;
                            }
                        }
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        HYPERPLATFORM_LOG_WARN("[td-map] exception resolving trigger");
                    }
                }
            }

            if (!trigger_fn)
            {
                HYPERPLATFORM_LOG_ERROR("[td-map] cannot resolve trigger function");
                st = STATUS_NOT_FOUND;
            }

            //
            // EPT hook trigger 閳?stub (oneshot, per-process CR3 filter)
            //
            UINT64 caller_cr3 = __readcr3();
            NTSTATUS hook_st = STATUS_UNSUCCESSFUL;

            if (NT_SUCCESS(st))
            {
                KAFFINITY old_aff = KeSetSystemAffinityThreadEx((KAFFINITY)1);  // CPU 0

                PVOID dummy_origin = NULL;
                hook_st = hv_vmcall_ex(
                    VMCALL_EPT_HOOK,
                    (UINT64)trigger_fn,          // target: trigger function
                    (UINT64)image_entry,         // proxy: DllMain stub
                    (UINT64)&dummy_origin,       // origin (unused)
                    caller_cr3,                  // caller CR3
                    1,                           // hook_type = VMCALL (0F 01 C1)
                    caller_cr3,                  // target_cr3 (per-process filter)
                    0, 0, 2);                    // no user trampoline, flags bit1 = oneshot

                KeRevertToUserAffinityThreadEx(old_aff);

                HYPERPLATFORM_LOG_INFO("[td-map] trigger hook %s (trigger=%p -> entry=%p st=0x%08X)",
                           NT_SUCCESS(hook_st) ? "OK" : "FAILED", trigger_fn, image_entry, hook_st);

                if (!NT_SUCCESS(hook_st))
                    st = hook_st;
            }

            KeUnstackDetachProcess(&apc_state);

            //
            // create thread at trigger 閳?EPT hook 閳?DllMain stub
            //
            if (NT_SUCCESS(st))
            {
                if (g_pZwCreateThreadEx)
                {
                    HANDLE thr_proc_h = NULL;
                    NTSTATUS oh_st = ObOpenObjectByPointer(
                        proc, OBJ_KERNEL_HANDLE, NULL,
                        PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &thr_proc_h);

                    if (NT_SUCCESS(oh_st))
                    {
                        HANDLE thr_h = NULL;
                        NTSTATUS thr_st = g_pZwCreateThreadEx(
                            &thr_h, THREAD_ALL_ACCESS, NULL, thr_proc_h,
                            trigger_fn, NULL,
                            THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
                            0, 0, 0, NULL);

                        if (NT_SUCCESS(thr_st) && thr_h)
                        {
                            KAFFINITY cpu0 = (KAFFINITY)1;
                            ZwSetInformationThread(thr_h, ThreadAffinityMask, &cpu0, sizeof(cpu0));

                            ULONG prev = 0;
                            NTSTATUS resume_st = TdResumeThreadHandle(thr_h, &prev);
                            if (NT_SUCCESS(resume_st))
                            {
                                HYPERPLATFORM_LOG_INFO("[td-map] thread SUSPENDED+CPU0+RESUMED trigger=%p", trigger_fn);
                                TdCloseCreatedThreadHandle(thr_h, TRUE);
                            }
                            else
                            {
                                HYPERPLATFORM_LOG_ERROR("[td-map] thread resume failed: 0x%08X", resume_st);
                                TdCloseCreatedThreadHandle(thr_h, FALSE);
                                TdUnhookTriggerAllCpus(trigger_fn, caller_cr3);
                                st = resume_st;
                            }
                        }
                        else
                            HYPERPLATFORM_LOG_ERROR("[td-map] ZwCreateThreadEx failed: 0x%08X", thr_st);
                        ZwClose(thr_proc_h);
                    }
                }
                else
                {
                    // fallback: RtlCreateUserThread
                    KAFFINITY old_aff = KeSetSystemAffinityThreadEx((KAFFINITY)1);
                    KAPC_STATE thr_apc;
                    KeStackAttachProcess(proc, &thr_apc);

                    HANDLE thr_h = NULL;
                    CLIENT_ID cid = {};
                    NTSTATUS thr_st = RtlCreateUserThread(
                        ZwCurrentProcess(), NULL, FALSE, 0, 0, 0,
                        trigger_fn, NULL, &thr_h, &cid);

                    if (NT_SUCCESS(thr_st) && thr_h)
                    {
                        KAFFINITY cpu0 = (KAFFINITY)1;
                        ZwSetInformationThread(thr_h, ThreadAffinityMask, &cpu0, sizeof(cpu0));
                        ZwClose(thr_h);
                    }

                    KeUnstackDetachProcess(&thr_apc);
                    KeRevertToUserAffinityThreadEx(old_aff);
                    HYPERPLATFORM_LOG_INFO("[td-map] fallback RtlCreateUserThread trigger=%p st=0x%08X",
                               trigger_fn, thr_st);
                }
            }
        }
        else
        {
            HYPERPLATFORM_LOG_ERROR("[td-map] TdManualMapInProcess failed: 0x%08X", st);
            KeUnstackDetachProcess(&apc_state);
        }

        ObDereferenceObject(proc);
        break;
    }

    case IOCTL_INJECT_RW:
    case IOCTL_INJECT_RW_SHADOW:
    {
        //
        // RW-alloc + EPT stealth + trigger hook injection.
        //
        // flow:
        //   1. attach to target process
        //   2. ZwAllocateVirtualMemory(PAGE_READWRITE) 閳?own VAD, NX=1 in PTE
        //   3. build PIC shellcode into the page
        //   4. EPT stealth: shadow page = shellcode (execute view),
        //      original page zeroed (read view = clean for anti-cheat)
        //      NX handled by HV #PF cycle (no PTE/fake PT manipulation)
        //   5. EPT hook trigger function 閳?redirect to shellcode VA
        //   6. create thread at trigger 閳?EPT hook fires 閳?#PF 閳?NX cycle 閳?executes
        //   7. async cleanup: unhook trigger after delay, inject stays resident
        //
        if (io->Parameters.DeviceIoControl.InputBufferLength < sizeof(TD_INJECT_RW_PARAMS) ||
            io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(TD_INJECT_RW_PARAMS))
        { st = STATUS_BUFFER_TOO_SMALL; break; }

        TD_INJECT_RW_PARAMS * p = (TD_INJECT_RW_PARAMS *)irp->AssociatedIrp.SystemBuffer;
        BOOLEAN shadow_only = (io->Parameters.DeviceIoControl.IoControlCode == IOCTL_INJECT_RW_SHADOW);
        UINT64 r3_shellcode_size64 = p->shellcode_size;
        UINT32 r3_shellcode_size = (UINT32)r3_shellcode_size64;
        PUINT8 r3_shellcode = (PUINT8)(p + 1);
        ULONG alloc_protect = (ULONG)(p->alloc_protect ? p->alloc_protect : PAGE_READWRITE);

        if (shadow_only && !g_process_notify_registered)
        {
            HYPERPLATFORM_LOG_ERROR("[td-rw-shadow] process notify unavailable; refusing persistent shadow injection");
            st = STATUS_DEVICE_NOT_READY;
            break;
        }

        if (!r3_shellcode_size64 ||
            r3_shellcode_size64 > TD_MAX_INJECT_RW_SIZE ||
            r3_shellcode_size64 > 0xFFFFFFFFULL ||
            r3_shellcode_size64 > (0xFFFFFFFFULL - sizeof(TD_INJECT_RW_PARAMS)) ||
            io->Parameters.DeviceIoControl.InputBufferLength < sizeof(TD_INJECT_RW_PARAMS) + (ULONG)r3_shellcode_size64)
        {
            HYPERPLATFORM_LOG_ERROR("[td-rw] invalid R3 shellcode size=%llu input=%u",
                       r3_shellcode_size64, io->Parameters.DeviceIoControl.InputBufferLength);
            st = STATUS_INVALID_PARAMETER;
            break;
        }

        if (alloc_protect != PAGE_READWRITE && alloc_protect != PAGE_WRITECOPY)
        {
            HYPERPLATFORM_LOG_ERROR("[td-rw] invalid allocation protect=0x%X", alloc_protect);
            st = STATUS_INVALID_PARAMETER;
            break;
        }

        PEPROCESS proc = NULL;
        st = PsLookupProcessByProcessId((HANDLE)p->target_pid, &proc);
        if (!NT_SUCCESS(st)) break;

        KAPC_STATE apc_state;
        KeStackAttachProcess(proc, &apc_state);

        //
        // step 1: allocate PAGE_READWRITE in target process
        //
        SIZE_T alloc_size = (r3_shellcode_size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
        PVOID  alloc_base = NULL;
        BOOLEAN stealth_tracked = FALSE;
        BOOLEAN thread_started = FALSE;
        BOOLEAN trigger_hooked = FALSE;
        SIZE_T pages_installed = 0;

        st = ZwAllocateVirtualMemory(
            ZwCurrentProcess(), &alloc_base, 0, &alloc_size,
            MEM_COMMIT | MEM_RESERVE, alloc_protect);

        if (!NT_SUCCESS(st) || !alloc_base)
        {
            HYPERPLATFORM_LOG_ERROR("[td-rw] ZwAllocateVirtualMemory failed: 0x%08X", st);
            KeUnstackDetachProcess(&apc_state);
            ObDereferenceObject(proc);
            break;
        }

        HYPERPLATFORM_LOG_INFO("[td-rw%s] allocated RW page: VA=%p size=0x%llX pid=%llu",
                   shadow_only ? "-shadow" : "", alloc_base, (UINT64)alloc_size, p->target_pid);

        //
        // step 2: copy R3-provided shellcode directly into the allocated page
        //
        RtlZeroMemory(alloc_base, alloc_size);
        RtlCopyMemory(alloc_base, r3_shellcode, r3_shellcode_size);
        HYPERPLATFORM_LOG_INFO("[td-rw%s] copied R3 shellcode: VA=%p sc_size=0x%X alloc=0x%llX",
                   shadow_only ? "-shadow" : "", alloc_base, r3_shellcode_size, (UINT64)alloc_size);

        //
        // NO PTE NX clear needed here 閳?HV handles NX via #PF cycle:
        //   #PF (NX=1) 閳?VMX-root clears NX 閳?MTF restores NX 閳?TLB keeps NX=0
        //   PTE always shows NX=1 to scanners. TLB eviction 閳?#PF 閳?repeat.
        //

        //
        // step 4: EPT stealth 閳?shadow page gets shellcode, original page zeroed
        //
        // use resident mode: shellcode_buffer = NULL 閳?HV copies from
        // target_page_copy (kernel NonPaged buffer, safe on any CPU).
        // the shellcode is already written in the page, so target_page_copy
        // contains the shellcode content 閳?shadow page gets it.
        // EPT: execute 閳?shadow (shellcode), read/write 閳?original (zeros).
        //
        UINT64 caller_cr3 = __readcr3();

        // build shadow CR3: copies page tables with NX=0 for shellcode page.
        // never modifies real PTEs 閳?no conflict with MiAgeWorkingSet.
        UINT64 existing = TdStealthFindShadowCr3ForPid(p->target_pid);
        UINT64 shadow_cr3 = existing ? TdExtendShadowCR3(existing, caller_cr3, (UINT64)alloc_base, alloc_size)
                                      : TdBuildShadowCR3(caller_cr3, (UINT64)alloc_base, alloc_size);
        if (!shadow_cr3)
        {
            HYPERPLATFORM_LOG_ERROR("[td-rw] shadow CR3 build failed");
            ZwFreeVirtualMemory(ZwCurrentProcess(), &alloc_base, &alloc_size, MEM_RELEASE);
            KeUnstackDetachProcess(&apc_state);
            ObDereferenceObject(proc);
            st = STATUS_UNSUCCESSFUL;
            break;
        }

        NTSTATUS stealth_st = STATUS_SUCCESS;
        for (SIZE_T off = 0; off < alloc_size; off += PAGE_SIZE)
        {
            PVOID page_va = (PUINT8)alloc_base + off;
            UINT64 page_phys = MmGetPhysicalAddress(page_va).QuadPart;
            UINT64 pt_pfn = 0;
            UINT32 pt_idx = 0;

            if (!page_phys || !TdResolveGuestPT(caller_cr3, (UINT64)page_va, &pt_pfn, &pt_idx))
            {
                HYPERPLATFORM_LOG_ERROR("[td-rw%s] PT/PA resolve failed VA=%p PA=0x%llX",
                    shadow_only ? "-shadow" : "", page_va, page_phys);
                stealth_st = STATUS_UNSUCCESSFUL;
                break;
            }

            stealth_st = TdStealthAllocPage(
                caller_cr3,
                page_va,
                page_phys,
                NULL,
                0,
                TRUE,
                pt_pfn,
                pt_idx,
                FALSE,
                shadow_cr3,
                shadow_only,
                FALSE);

            if (!NT_SUCCESS(stealth_st))
            {
                HYPERPLATFORM_LOG_ERROR("[td-rw%s] stealth setup failed VA=%p st=0x%08X",
                    shadow_only ? "-shadow" : "", page_va, stealth_st);
                break;
            }

            pages_installed++;
        }

        if (!NT_SUCCESS(stealth_st))
        {
            if (stealth_st != STATUS_IO_TIMEOUT)
            {
                for (SIZE_T i = 0; i < pages_installed; i++)
                    TdStealthFreePage((PUINT8)alloc_base + (i * PAGE_SIZE));
                if (!existing)
                    TdShadowFreeCr3(shadow_cr3);
                ZwFreeVirtualMemory(ZwCurrentProcess(), &alloc_base, &alloc_size, MEM_RELEASE);
            }
            KeUnstackDetachProcess(&apc_state);
            ObDereferenceObject(proc);
            st = stealth_st;
            break;
        }

        HYPERPLATFORM_LOG_INFO("[td-rw%s] stealth setup OK pages=%llu shadow_cr3=0x%llX",
            shadow_only ? "-shadow" : "", (UINT64)pages_installed, shadow_cr3);

        //
        // step 5: zero the original page 閳?read view is now clean
        // EPT stealth is already active, so execute view (shadow) is untouched.
        //
        if (!shadow_only)
        {
            RtlZeroMemory(alloc_base, alloc_size);
            HYPERPLATFORM_LOG_INFO("[td-rw] EPT stealth OK, original page zeroed");
        }
        else
        {
            HYPERPLATFORM_LOG_INFO("[td-rw-shadow] shadow CR3 NX bypass OK, target EPT unchanged");
        }

        // track for process exit cleanup (fake PT removal)
        if (!TdStealthTrackAdd(p->target_pid, alloc_base, alloc_size, shadow_cr3))
        {
            HYPERPLATFORM_LOG_ERROR("[td-rw] stealth track table full");
            for (SIZE_T i = 0; i < pages_installed; i++)
                TdStealthFreePage((PUINT8)alloc_base + (i * PAGE_SIZE));
            if (!existing)
                TdShadowFreeCr3(shadow_cr3);
            ZwFreeVirtualMemory(ZwCurrentProcess(), &alloc_base, &alloc_size, MEM_RELEASE);
            KeUnstackDetachProcess(&apc_state);
            ObDereferenceObject(proc);
            st = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        stealth_tracked = TRUE;

        //
        // step 7: resolve trigger function from ntdll
        //
        PVOID trigger_fn = (PVOID)p->trigger_va;
        if (!trigger_fn)
        {
            static const char * trigger_candidates[] = {
                "NtTestAlert", "RtlSetCurrentTransaction", NULL
            };
            PPEB peb = PsGetProcessPeb(proc);
            if (peb)
            {
                __try {
                    TD_PEB_LDR_DATA * ldr = *(TD_PEB_LDR_DATA **)((PUINT8)peb + 0x18);
                    if (ldr)
                    {
                        PLIST_ENTRY ldr_head = &ldr->InMemoryOrderModuleList;
                        PLIST_ENTRY ldr_cur = ldr_head->Flink;
                        while (ldr_cur != ldr_head)
                        {
                            TD_LDR_ENTRY * ldr_e = CONTAINING_RECORD(ldr_cur, TD_LDR_ENTRY, InMemoryOrderLinks);
                            if (ldr_e->BaseDllName.Buffer &&
                                TdMatchDllName(ldr_e->BaseDllName.Buffer, ldr_e->BaseDllName.Length,
                                               g_ntdll_name, 9))
                            {
                                for (const char ** c = trigger_candidates; *c && !trigger_fn; c++)
                                {
                                    trigger_fn = TdFindExportByName(ldr_e->DllBase, *c);
                                    if (trigger_fn)
                                        HYPERPLATFORM_LOG_INFO("[td-rw] trigger=%s at %p", *c, trigger_fn);
                                }
                                break;
                            }
                            ldr_cur = ldr_cur->Flink;
                        }
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    HYPERPLATFORM_LOG_WARN("[td-rw] exception resolving trigger");
                }
            }
        }

        if (!trigger_fn)
        {
            HYPERPLATFORM_LOG_ERROR("[td-rw] cannot resolve trigger function");
            st = STATUS_NOT_FOUND;
        }

        //
        // step 8: create thread at trigger (SUSPENDED) 閳?before hook, no race
        //
        HANDLE cleanup_thr_h = NULL;
        UINT64 expected_tid = 0;
        if (NT_SUCCESS(st))
        {
            if (g_pZwCreateThreadEx)
            {
                HANDLE thr_proc_h = NULL;
                NTSTATUS oh_st = ObOpenObjectByPointer(
                    proc, OBJ_KERNEL_HANDLE, NULL,
                    PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &thr_proc_h);

                if (NT_SUCCESS(oh_st))
                {
                    HANDLE thr_h = NULL;
                    NTSTATUS thr_st = g_pZwCreateThreadEx(
                        &thr_h, THREAD_ALL_ACCESS, NULL, thr_proc_h,
                        trigger_fn, NULL,
                        THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
                        0, 0, 0, NULL);

                    if (NT_SUCCESS(thr_st) && thr_h)
                    {
                        HANDLE kernel_thr_h = NULL;
                        NTSTATUS kh_st = TdMakeKernelThreadHandle(thr_h, &kernel_thr_h, &expected_tid);
                        ZwClose(thr_h);

                        if (!NT_SUCCESS(kh_st) || !kernel_thr_h || !expected_tid)
                        {
                            HYPERPLATFORM_LOG_ERROR("[td-rw] cannot convert created thread handle: st=0x%08X tid=%llu",
                                kh_st, expected_tid);
                            if (kernel_thr_h)
                                ZwClose(kernel_thr_h);
                            st = NT_SUCCESS(kh_st) ? STATUS_UNSUCCESSFUL : kh_st;
                        }
                        else
                        {
                            cleanup_thr_h = kernel_thr_h;
                            HYPERPLATFORM_LOG_INFO("[td-rw] thread SUSPENDED trigger=%p tid=%llu", trigger_fn, expected_tid);
                        }
                    }
                    else
                    {
                        HYPERPLATFORM_LOG_ERROR("[td-rw] ZwCreateThreadEx failed: 0x%08X", thr_st);
                        st = thr_st;
                    }
                    ZwClose(thr_proc_h);
                }
                else
                {
                    HYPERPLATFORM_LOG_ERROR("[td-rw] ObOpenObjectByPointer failed: 0x%08X", oh_st);
                    st = oh_st;
                }
            }
            else
            {
                // fallback: RtlCreateUserThread (suspended)
                KAPC_STATE thr_apc;
                KeStackAttachProcess(proc, &thr_apc);

                HANDLE thr_h = NULL;
                CLIENT_ID cid = {};
                NTSTATUS thr_st = RtlCreateUserThread(
                    ZwCurrentProcess(), NULL, TRUE, 0, 0, 0,
                    trigger_fn, NULL, &thr_h, &cid);

                if (NT_SUCCESS(thr_st) && thr_h)
                {
                    expected_tid = (UINT64)(ULONG_PTR)cid.UniqueThread;

                    HANDLE kernel_thr_h = NULL;
                    UINT64 resolved_tid = expected_tid;
                    NTSTATUS kh_st = TdMakeKernelThreadHandle(thr_h, &kernel_thr_h, &resolved_tid);
                    ZwClose(thr_h);
                    if (!expected_tid)
                        expected_tid = resolved_tid;

                    if (!NT_SUCCESS(kh_st) || !kernel_thr_h || !expected_tid)
                    {
                        HYPERPLATFORM_LOG_ERROR("[td-rw] cannot convert fallback thread handle: st=0x%08X tid=%llu",
                            kh_st, expected_tid);
                        if (kernel_thr_h)
                            ZwClose(kernel_thr_h);
                        st = !expected_tid ? STATUS_UNSUCCESSFUL : kh_st;
                    }
                    else
                    {
                        cleanup_thr_h = kernel_thr_h;
                    }
                }
                else
                {
                    st = thr_st;
                }

                KeUnstackDetachProcess(&thr_apc);
                HYPERPLATFORM_LOG_INFO("[td-rw] fallback RtlCreateUserThread trigger=%p tid=%llu st=0x%08X",
                           trigger_fn, expected_tid, thr_st);
            }
        }

        //
        // step 9: prepare cleanup ctx before resume so we can signal immediate unhook
        //
        struct _RW_CLEANUP_CTX {
            HANDLE          thread_handle;
            PVOID           trigger_fn;
            PVOID           shellcode_va;
            UINT64          target_cr3;
            UINT64          target_pid;
            PIO_WORKITEM    work_item;
            volatile LONG   fired_signal;
        };

        PIO_WORKITEM wi = NULL;
        struct _RW_CLEANUP_CTX * cleanup_ctx = NULL;

        if (cleanup_thr_h && NT_SUCCESS(st))
        {
            wi = IoAllocateWorkItem(IoGetCurrentIrpStackLocation(irp)->DeviceObject);
            if (wi)
            {
                cleanup_ctx = (struct _RW_CLEANUP_CTX *)
                    ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(struct _RW_CLEANUP_CTX), 'wRcI');
            }
        }

        if (cleanup_ctx)
        {
            cleanup_ctx->thread_handle = cleanup_thr_h;
            cleanup_ctx->trigger_fn    = trigger_fn;
            cleanup_ctx->shellcode_va  = alloc_base;
            cleanup_ctx->target_cr3    = caller_cr3;
            cleanup_ctx->target_pid    = p->target_pid;
            cleanup_ctx->work_item     = wi;
            cleanup_ctx->fired_signal  = 0;
        }
        else if (cleanup_thr_h && NT_SUCCESS(st))
        {
            st = STATUS_INSUFFICIENT_RESOURCES;
            TdCloseCreatedThreadHandle(cleanup_thr_h, FALSE);
            cleanup_thr_h = NULL;
            if (wi)
            {
                IoFreeWorkItem(wi);
                wi = NULL;
            }
        }

        //
        // step 10: EPT hook trigger 閳?shellcode VA (TID-filtered, oneshot)
        //
        if (NT_SUCCESS(st) && expected_tid)
        {
            PVOID dummy_origin = NULL;
            volatile LONG * fired_ptr = cleanup_ctx ? &cleanup_ctx->fired_signal : NULL;
            NTSTATUS hook_st = TdInstallTriggerHookAllCpus(
                trigger_fn, alloc_base, caller_cr3, 2, expected_tid, &dummy_origin, fired_ptr);

            HYPERPLATFORM_LOG_INFO("[td-rw] trigger hook %s trigger=%p sc=%p tid=%llu st=0x%08X",
                       NT_SUCCESS(hook_st) ? "OK" : "FAILED", trigger_fn, alloc_base, expected_tid, hook_st);

            if (!NT_SUCCESS(hook_st))
                st = hook_st;
            else
                trigger_hooked = TRUE;
        }

        KeUnstackDetachProcess(&apc_state);

        //
        // step 11: resume thread (now hook is active with correct TID)
        //
        if (NT_SUCCESS(st) && cleanup_thr_h)
        {
            ULONG prev_count = 0;
            NTSTATUS resume_st = TdResumeThreadHandle(cleanup_thr_h, &prev_count);
            if (NT_SUCCESS(resume_st))
            {
                HYPERPLATFORM_LOG_INFO("[td-rw] thread RESUMED trigger=%p tid=%llu prev=%u",
                    trigger_fn, expected_tid, prev_count);
                thread_started = TRUE;
            }
            else
            {
                HYPERPLATFORM_LOG_ERROR("[td-rw] thread resume failed: 0x%08X", resume_st);
                st = resume_st;
                TdCloseCreatedThreadHandle(cleanup_thr_h, FALSE);
                cleanup_thr_h = NULL;
                if (cleanup_ctx)
                {
                    cleanup_ctx->fired_signal = 1;
                    cleanup_ctx->thread_handle = NULL;
                }
            }
        }

        //
        // step 12: async cleanup 閳?unhook trigger immediately after first hit
        //
        if (cleanup_ctx && NT_SUCCESS(st) && thread_started)
        {
            IoQueueWorkItem(wi, [](PDEVICE_OBJECT, PVOID context) {
                auto * c = (struct _RW_CLEANUP_CTX *)context;

                LARGE_INTEGER poll_interval;
                poll_interval.QuadPart = -1LL * 10000LL;

                for (ULONG i = 0; i < 10000 && c->fired_signal == 0; i++)
                {
                    if (KeDelayExecutionThread(KernelMode, FALSE, &poll_interval) != STATUS_SUCCESS)
                        break;
                }

                if (c->thread_handle)
                    TdCloseCreatedThreadHandle(c->thread_handle, TRUE);

                HYPERPLATFORM_LOG_INFO("[td-rw] cleanup: unhooking trigger (fired=%ld), inject stays resident",
                    c->fired_signal);

                PEPROCESS proc2 = NULL;
                if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)c->target_pid, &proc2)))
                {
                    KAPC_STATE apc2;
                    KeStackAttachProcess(proc2, &apc2);

                    TdUnhookTriggerAllCpus(c->trigger_fn, c->target_cr3);
                    KeUnstackDetachProcess(&apc2);
                    ObDereferenceObject(proc2);

                    HYPERPLATFORM_LOG_INFO("[td-rw] cleanup: trigger unhook=%p, inject RESIDENT=%p",
                        c->trigger_fn, c->shellcode_va);
                }

                IoFreeWorkItem(c->work_item);
                ExFreePoolWithTag(c, 'wRcI');
            }, DelayedWorkQueue, cleanup_ctx);

            cleanup_thr_h = NULL;
        }
        else
        {
            if (cleanup_ctx)
            {
                if (cleanup_ctx->thread_handle)
                    TdCloseCreatedThreadHandle(cleanup_ctx->thread_handle, thread_started ? TRUE : FALSE);
                ExFreePoolWithTag(cleanup_ctx, 'wRcI');
                cleanup_ctx = NULL;
                cleanup_thr_h = NULL;
            }
            if (wi)
            {
                IoFreeWorkItem(wi);
                wi = NULL;
            }
        }

        if (cleanup_thr_h)
            TdCloseCreatedThreadHandle(cleanup_thr_h, thread_started ? TRUE : FALSE);

        if (NT_SUCCESS(st) && !thread_started)
            st = STATUS_UNSUCCESSFUL;

        if (!NT_SUCCESS(st) && stealth_tracked && !thread_started)
        {
            KAPC_STATE cleanup_apc;
            KeStackAttachProcess(proc, &cleanup_apc);
            if (trigger_hooked)
                TdUnhookTriggerAllCpus(trigger_fn, caller_cr3);
            UINT64 cleanup_shadow_cr3 = TdStealthTrackRemove(p->target_pid, alloc_base);
            for (SIZE_T i = 0; i < pages_installed; i++)
                TdStealthFreePage((PUINT8)alloc_base + (i * PAGE_SIZE));
            if (cleanup_shadow_cr3)
                TdShadowFreeCr3(cleanup_shadow_cr3);
            ZwFreeVirtualMemory(ZwCurrentProcess(), &alloc_base, &alloc_size, MEM_RELEASE);
            KeUnstackDetachProcess(&cleanup_apc);
            stealth_tracked = FALSE;
        }

        if (NT_SUCCESS(st))
        {
            p->shellcode_va = (UINT64)alloc_base;
            p->alloc_size   = alloc_size;
            irp->IoStatus.Information = sizeof(TD_INJECT_RW_PARAMS);
        }

        ObDereferenceObject(proc);
        break;
    }

    case IOCTL_ALLOC_SHADOW_MEMORY:
    {
        if (io->Parameters.DeviceIoControl.InputBufferLength < sizeof(TD_ALLOC_SHADOW_MEMORY_PARAMS) ||
            io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(TD_ALLOC_SHADOW_MEMORY_PARAMS))
        { st = STATUS_BUFFER_TOO_SMALL; break; }

        TD_ALLOC_SHADOW_MEMORY_PARAMS * p =
            (TD_ALLOC_SHADOW_MEMORY_PARAMS *)irp->AssociatedIrp.SystemBuffer;

        HYPERPLATFORM_LOG_INFO("[td-alloc] ENTER: pid=%llu size=%llu exec=%u prot=0x%llX",
            p->target_pid, p->size, p->need_execute, p->alloc_protect);

        p->base_va = 0;
        p->shadow_cr3 = 0;

        if (!p->target_pid || !p->size)
        {
            st = STATUS_INVALID_PARAMETER;
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_ALLOC_SHADOW_MEMORY_PARAMS);
            break;
        }

        if (p->size > (MAXSIZE_T - (PAGE_SIZE - 1)))
        {
            st = STATUS_INTEGER_OVERFLOW;
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_ALLOC_SHADOW_MEMORY_PARAMS);
            break;
        }

        SIZE_T alloc_size = (SIZE_T)((p->size + PAGE_SIZE - 1) & ~(UINT64)(PAGE_SIZE - 1));
        BOOLEAN need_execute = (p->need_execute != 0);
        ULONG alloc_protect = (ULONG)(p->alloc_protect ? p->alloc_protect : PAGE_READWRITE);
        PEPROCESS proc = NULL;

        if (need_execute && !g_process_notify_registered)
        {
            HYPERPLATFORM_LOG_ERROR("[td-alloc] process notify unavailable; refusing persistent shadow allocation");
            st = STATUS_DEVICE_NOT_READY;
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_ALLOC_SHADOW_MEMORY_PARAMS);
            break;
        }

        if (alloc_protect != PAGE_READWRITE && alloc_protect != PAGE_WRITECOPY)
        {
            HYPERPLATFORM_LOG_ERROR("[td-alloc] invalid allocation protect=0x%X", alloc_protect);
            st = STATUS_INVALID_PARAMETER;
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_ALLOC_SHADOW_MEMORY_PARAMS);
            break;
        }

        st = PsLookupProcessByProcessId((HANDLE)p->target_pid, &proc);
        if (!NT_SUCCESS(st))
        {
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_ALLOC_SHADOW_MEMORY_PARAMS);
            break;
        }

        KAPC_STATE apc_state;
        KeStackAttachProcess(proc, &apc_state);

        PVOID alloc_base = NULL;
        UINT64 shadow_cr3 = 0;
        SIZE_T pages_installed = 0;
        BOOLEAN timeout_seen = FALSE;

        st = ZwAllocateVirtualMemory(
            ZwCurrentProcess(), &alloc_base, 0, &alloc_size,
            MEM_COMMIT | MEM_RESERVE, alloc_protect);

        if (NT_SUCCESS(st) && alloc_base)
        {
            RtlZeroMemory(alloc_base, alloc_size);
            HYPERPLATFORM_LOG_INFO("[td-alloc] allocation: pid=%llu VA=%p size=0x%llX exec=%u protect=0x%X",
                       p->target_pid, alloc_base, (UINT64)alloc_size, need_execute, alloc_protect);
        }

        UINT64 existing = 0;
        if (NT_SUCCESS(st) && need_execute)
        {
            UINT64 caller_cr3 = __readcr3();
            existing = TdStealthFindShadowCr3ForPid(p->target_pid);
            if (existing)
                shadow_cr3 = TdExtendShadowCR3(existing, caller_cr3, (UINT64)alloc_base, alloc_size);
            else
                shadow_cr3 = TdBuildShadowCR3(caller_cr3, (UINT64)alloc_base, alloc_size);
            if (!shadow_cr3)
            {
                HYPERPLATFORM_LOG_ERROR("[td-alloc] shadow CR3 build failed VA=%p size=0x%llX",
                           alloc_base, (UINT64)alloc_size);
                st = STATUS_UNSUCCESSFUL;
            }

            for (SIZE_T off = 0; NT_SUCCESS(st) && off < alloc_size; off += PAGE_SIZE)
            {
                PVOID page_va = (PUINT8)alloc_base + off;
                UINT64 page_phys = MmGetPhysicalAddress(page_va).QuadPart;
                UINT64 pt_pfn = 0;
                UINT32 pt_idx = 0;

                if (!page_phys || !TdResolveGuestPT(caller_cr3, (UINT64)page_va, &pt_pfn, &pt_idx))
                {
                    HYPERPLATFORM_LOG_ERROR("[td-alloc] PT/PA resolve failed VA=%p PA=0x%llX",
                               page_va, page_phys);
                    st = STATUS_UNSUCCESSFUL;
                    break;
                }

                NTSTATUS stealth_st = TdStealthAllocPage(
                    caller_cr3,
                    page_va,
                    page_phys,
                    NULL,
                    0,
                    TRUE,
                    pt_pfn,
                    pt_idx,
                    FALSE,
                    shadow_cr3,
                    TRUE,
                    FALSE);

                if (!NT_SUCCESS(stealth_st))
                {
                    HYPERPLATFORM_LOG_ERROR("[td-alloc] shadow-only stealth failed VA=%p st=0x%08X",
                               page_va, stealth_st);
                    st = stealth_st;
                    if (stealth_st == STATUS_IO_TIMEOUT)
                        timeout_seen = TRUE;
                    break;
                }

                pages_installed++;
            }

            if (NT_SUCCESS(st))
            {
                if (!TdStealthTrackAdd(p->target_pid, alloc_base, alloc_size, shadow_cr3))
                {
                    HYPERPLATFORM_LOG_ERROR("[td-alloc] stealth track table full");
                    st = STATUS_INSUFFICIENT_RESOURCES;
                }
            }
        }

        if (!NT_SUCCESS(st) && alloc_base && !timeout_seen)
        {
            for (SIZE_T i = 0; i < pages_installed; i++)
                TdStealthFreePage((PUINT8)alloc_base + (i * PAGE_SIZE));
            if (shadow_cr3 && !existing)
                TdShadowFreeCr3(shadow_cr3);
            ZwFreeVirtualMemory(ZwCurrentProcess(), &alloc_base, &alloc_size, MEM_RELEASE);
            alloc_base = NULL;
            shadow_cr3 = 0;
        }

        p->base_va = (UINT64)alloc_base;
        p->size = (UINT64)alloc_size;
        p->alloc_protect = alloc_protect;
        p->shadow_cr3 = shadow_cr3;
        p->status = (UINT64)(ULONG)st;
        irp->IoStatus.Information = sizeof(TD_ALLOC_SHADOW_MEMORY_PARAMS);

        KeUnstackDetachProcess(&apc_state);
        ObDereferenceObject(proc);
        break;
    }

    case IOCTL_FREE_SHADOW_MEMORY:
    {
        if (io->Parameters.DeviceIoControl.InputBufferLength < sizeof(TD_ALLOC_SHADOW_MEMORY_PARAMS) ||
            io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(TD_ALLOC_SHADOW_MEMORY_PARAMS))
        { st = STATUS_BUFFER_TOO_SMALL; break; }

        TD_ALLOC_SHADOW_MEMORY_PARAMS * p =
            (TD_ALLOC_SHADOW_MEMORY_PARAMS *)irp->AssociatedIrp.SystemBuffer;

        if (!p->target_pid || !p->base_va || !p->size)
        {
            st = STATUS_INVALID_PARAMETER;
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_ALLOC_SHADOW_MEMORY_PARAMS);
            break;
        }

        if (p->size > (MAXSIZE_T - (PAGE_SIZE - 1)))
        {
            st = STATUS_INTEGER_OVERFLOW;
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_ALLOC_SHADOW_MEMORY_PARAMS);
            break;
        }

        SIZE_T free_size = (SIZE_T)((p->size + PAGE_SIZE - 1) & ~(UINT64)(PAGE_SIZE - 1));
        PVOID free_base = (PVOID)p->base_va;
        if (!free_size || (UINT64)free_base > (~0ULL - free_size))
        {
            st = STATUS_INTEGER_OVERFLOW;
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_ALLOC_SHADOW_MEMORY_PARAMS);
            break;
        }

        PEPROCESS proc = NULL;
        st = PsLookupProcessByProcessId((HANDLE)p->target_pid, &proc);
        if (!NT_SUCCESS(st))
        {
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_ALLOC_SHADOW_MEMORY_PARAMS);
            break;
        }

        KAPC_STATE apc_state;
        KeStackAttachProcess(proc, &apc_state);

        UINT64 freed_shadow_cr3 = 0;
        if (TdStealthTrackHasPartialOverlap(p->target_pid, free_base, free_size))
        {
            st = STATUS_CONFLICTING_ADDRESSES;
        }

        for (;;)
        {
            if (!NT_SUCCESS(st))
                break;

            PVOID tracked_base = NULL;
            SIZE_T tracked_size = 0;
            UINT64 shadow_cr3 = 0;
            if (!TdStealthTrackFindOverlap(
                p->target_pid, free_base, free_size, &tracked_base, &tracked_size, &shadow_cr3))
                break;

            UINT64 tracked_start = (UINT64)tracked_base;
            UINT64 tracked_end = tracked_start + tracked_size;

            for (UINT64 page = tracked_start; page < tracked_end; page += PAGE_SIZE)
                TdStealthFreePage((PVOID)page);

            {
                UINT64 to_free = TdStealthTrackRemove(p->target_pid, tracked_base);
                if (to_free)
                    TdShadowFreeCr3(to_free);
            }
            freed_shadow_cr3 = shadow_cr3;
        }

        SIZE_T release_size = 0;
        if (NT_SUCCESS(st))
            st = ZwFreeVirtualMemory(ZwCurrentProcess(), &free_base, &release_size, MEM_RELEASE);
        if (NT_SUCCESS(st))
        {
            HYPERPLATFORM_LOG_INFO("[td-free] freed memory: pid=%llu VA=%p size=0x%llX shadow_cr3=0x%llX",
                       p->target_pid, (PVOID)p->base_va, (UINT64)free_size, freed_shadow_cr3);
            p->base_va = 0;
            p->shadow_cr3 = 0;
        }
        else
        {
            HYPERPLATFORM_LOG_ERROR("[td-free] ZwFreeVirtualMemory failed: pid=%llu VA=%p st=0x%08X",
                       p->target_pid, (PVOID)p->base_va, st);
        }

        p->size = (UINT64)free_size;
        p->status = (UINT64)(ULONG)st;
        irp->IoStatus.Information = sizeof(TD_ALLOC_SHADOW_MEMORY_PARAMS);

        KeUnstackDetachProcess(&apc_state);
        ObDereferenceObject(proc);
        break;
    }

    case IOCTL_SHADOW_PROTECT_MEMORY:
    {
        if (io->Parameters.DeviceIoControl.InputBufferLength < sizeof(TD_SHADOW_PROTECT_PARAMS) ||
            io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(TD_SHADOW_PROTECT_PARAMS))
        { st = STATUS_BUFFER_TOO_SMALL; HYPERPLATFORM_LOG_ERROR("[td-protect] EXIT: buffer too small in=%u out=%u",
            io->Parameters.DeviceIoControl.InputBufferLength,
            io->Parameters.DeviceIoControl.OutputBufferLength); break; }

        TD_SHADOW_PROTECT_PARAMS * p =
            (TD_SHADOW_PROTECT_PARAMS *)irp->AssociatedIrp.SystemBuffer;

        HYPERPLATFORM_LOG_INFO("[td-protect] ENTER: pid=%llu base=0x%llX size=%llu newProt=0x%llX",
            p->target_pid, p->base_va, p->size, p->new_protect);

        if (!p->target_pid || !p->base_va || !p->size)
        {
            st = STATUS_INVALID_PARAMETER;
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_SHADOW_PROTECT_PARAMS);
            break;
        }

        if (p->size > (MAXSIZE_T - (PAGE_SIZE - 1)))
        {
            st = STATUS_INTEGER_OVERFLOW;
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_SHADOW_PROTECT_PARAMS);
            break;
        }

        ULONG new_protect = 0;
        if (!TdNormalizeShadowProtect((ULONG)p->new_protect, &new_protect))
        {
            st = STATUS_INVALID_PARAMETER;
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_SHADOW_PROTECT_PARAMS);
            break;
        }

        UINT64 start = p->base_va & ~0xFFFULL;
        SIZE_T protect_size = (SIZE_T)((p->size + (p->base_va - start) + PAGE_SIZE - 1) & ~(UINT64)(PAGE_SIZE - 1));
        if (!protect_size || start > (~0ULL - protect_size))
        {
            st = STATUS_INTEGER_OVERFLOW;
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_SHADOW_PROTECT_PARAMS);
            break;
        }
        UINT64 end = start + protect_size;

        PEPROCESS proc = NULL;
        st = PsLookupProcessByProcessId((HANDLE)p->target_pid, &proc);
        if (!NT_SUCCESS(st))
        {
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_SHADOW_PROTECT_PARAMS);
            break;
        }

        KAPC_STATE apc_state;
        KeStackAttachProcess(proc, &apc_state);

        UINT64 caller_cr3 = __readcr3();
        PVOID tracked_base = NULL;
        SIZE_T tracked_size = 0;
        UINT64 shadow_cr3 = 0;
        UINT64 flush_shadow_cr3 = 0;
        BOOLEAN tracked = TdStealthTrackFindOverlap(
            p->target_pid, (PVOID)start, protect_size, &tracked_base, &tracked_size, &shadow_cr3);
        flush_shadow_cr3 = shadow_cr3;

        if (tracked)
        {
            UINT64 tracked_start = (UINT64)tracked_base;
            UINT64 tracked_end = (UINT64)tracked_base + tracked_size;
            if (start < tracked_start || end > tracked_end)
            {
                st = STATUS_CONFLICTING_ADDRESSES;
                goto ShadowProtectExit;
            }
        }

        PUINT64 old_view_pte = tracked ?
            TdResolveShadowPte(shadow_cr3, start) :
            TdResolveGuestPte(caller_cr3, start);
        if (!old_view_pte || !(*old_view_pte & 1))
        {
            // Shadow PTE not present - the real PTE may have been lazy-allocated
            // after TdExtendShadowCR3 copied it.  Re-sync from the real PTE.
            if (tracked && old_view_pte)
            {
                PUINT64 real_pte = TdResolveGuestPte(caller_cr3, start);
                if (real_pte && (*real_pte & 1))
                {
                    *old_view_pte = *real_pte;
                    HYPERPLATFORM_LOG_INFO("[td-protect] re-synced shadow PTE from real: pid=%llu va=%p real=0x%llX shadow_pte=%p",
                        p->target_pid, (PVOID)start, *real_pte, old_view_pte);
                    p->old_protect = TdProtectFromPte(*old_view_pte);
                }
                else
                {
                    HYPERPLATFORM_LOG_ERROR("[td-protect] re-sync FAILED: pid=%llu va=%p tracked=%u cr3=0x%llX shadow=0x%llX real_pte=%p",
                        p->target_pid, (PVOID)start, tracked, caller_cr3, shadow_cr3, real_pte);
                    st = STATUS_NOT_FOUND;
                    goto ShadowProtectExit;
                }
            }
            else
            {
                HYPERPLATFORM_LOG_ERROR("[td-protect] old view PTE not found: pid=%llu va=%p tracked=%u cr3=0x%llX shadow=0x%llX pte=%p",
                    p->target_pid, (PVOID)start, tracked, caller_cr3, shadow_cr3, old_view_pte);
                if (old_view_pte)
                    HYPERPLATFORM_LOG_ERROR("[td-protect] old view PTE present but !Present bit: *pte=0x%llX", *old_view_pte);
                else
                {
                    if (tracked)
                    {
                        HYPERPLATFORM_LOG_ERROR("[td-protect] tracked=true but TdResolveShadowPte returned NULL: shadow_cr3=0x%llX start=%p",
                            shadow_cr3, (PVOID)start);
                        UINT64 cr3_va = (UINT64)(ULONG_PTR)TdShadowVaFromPhys(shadow_cr3);
                        HYPERPLATFORM_LOG_ERROR("[td-protect] shadow_cr3_phys=0x%llX -> kernelVA=%p", shadow_cr3, (PVOID)cr3_va);
                        if (cr3_va)
                        {
                            UINT64 pml4e = *(PUINT64)cr3_va;
                            HYPERPLATFORM_LOG_ERROR("[td-protect] shadow PML4E[0]=0x%llX", pml4e);
                        }
                    }
                    else
                    {
                        HYPERPLATFORM_LOG_ERROR("[td-protect] tracked=false but TdResolveGuestPte returned NULL: caller_cr3=0x%llX start=%p",
                            caller_cr3, (PVOID)start);
                    }
                }
                st = STATUS_NOT_FOUND;
                goto ShadowProtectExit;
            }
        }

        BOOLEAN all_same_as_real = TRUE;
        for (UINT64 page = start; page < end; page += PAGE_SIZE)
        {
            PUINT64 real_pte = TdResolveGuestPte(caller_cr3, page);
            if (!real_pte || !(*real_pte & 1))
            {
                HYPERPLATFORM_LOG_ERROR("[td-protect] real PTE not found while scanning: pid=%llu va=%p cr3=0x%llX pte=%p",
                    p->target_pid, (PVOID)page, caller_cr3, real_pte);
                st = STATUS_NOT_FOUND;
                goto ShadowProtectExit;
            }

            UINT64 wanted = *real_pte;
            TdApplyProtectToPte(&wanted, new_protect);
            if (wanted != *real_pte)
                all_same_as_real = FALSE;
        }

        if (!tracked && !all_same_as_real)
        {
            if (!g_process_notify_registered)
            {
                HYPERPLATFORM_LOG_ERROR("[td-protect] process notify unavailable; refusing persistent shadow protect");
                st = STATUS_DEVICE_NOT_READY;
                goto ShadowProtectExit;
            }

            UINT64 existing = TdStealthFindShadowCr3ForPid(p->target_pid);
            if (existing)
                shadow_cr3 = TdExtendShadowCR3(existing, caller_cr3, start, protect_size);
            else
                shadow_cr3 = TdBuildShadowCR3(caller_cr3, start, protect_size);
            flush_shadow_cr3 = shadow_cr3;
            if (!shadow_cr3)
            {
                st = STATUS_UNSUCCESSFUL;
                goto ShadowProtectExit;
            }

            SIZE_T pages_installed = 0;
            for (UINT64 page = start; page < end; page += PAGE_SIZE)
            {
                UINT64 page_phys = MmGetPhysicalAddress((PVOID)page).QuadPart;
                UINT64 pt_pfn = 0;
                UINT32 pt_idx = 0;

                if (!page_phys || !TdResolveGuestPT(caller_cr3, page, &pt_pfn, &pt_idx))
                {
                    st = STATUS_UNSUCCESSFUL;
                    break;
                }

                NTSTATUS stealth_st = TdStealthAllocPage(
                    caller_cr3,
                    (PVOID)page,
                    page_phys,
                    NULL,
                    0,
                    TRUE,
                    pt_pfn,
                    pt_idx,
                    FALSE,
                    shadow_cr3,
                    TRUE,
                    TRUE);

                if (!NT_SUCCESS(stealth_st))
                {
                    st = stealth_st;
                    break;
                }

                pages_installed++;
            }

            if (!NT_SUCCESS(st))
            {
                for (SIZE_T i = 0; i < pages_installed; i++)
                    TdStealthFreePage((PVOID)(start + (i * PAGE_SIZE)));
                if (!existing)
                    TdShadowFreeCr3(shadow_cr3);
                shadow_cr3 = 0;
                goto ShadowProtectExit;
            }

            if (!TdStealthTrackAdd(p->target_pid, (PVOID)start, protect_size, shadow_cr3))
            {
                for (UINT64 page = start; page < end; page += PAGE_SIZE)
                    TdStealthFreePage((PVOID)page);
                if (!existing)
                    TdShadowFreeCr3(shadow_cr3);
                shadow_cr3 = 0;
                st = STATUS_INSUFFICIENT_RESOURCES;
                goto ShadowProtectExit;
            }

            tracked = TRUE;
            tracked_base = (PVOID)start;
            tracked_size = protect_size;
            flush_shadow_cr3 = shadow_cr3;
        }

        if (tracked)
        {
            for (UINT64 page = start; page < end; page += PAGE_SIZE)
            {
                PUINT64 real_pte = TdResolveGuestPte(caller_cr3, page);
                PUINT64 shadow_pte = TdResolveShadowPte(shadow_cr3, page);
                if (!real_pte || !(*real_pte & 1))
                {
                    HYPERPLATFORM_LOG_ERROR("[td-protect] real PTE gone while applying: pid=%llu va=%p real=%p realv=0x%llX",
                        p->target_pid, (PVOID)page, real_pte, real_pte ? *real_pte : 0);
                    st = STATUS_NOT_FOUND;
                    goto ShadowProtectExit;
                }
                // Re-sync shadow PTE on the fly if it's not present (lazy PTE).
                if (!shadow_pte || !(*shadow_pte & 1))
                {
                    if (shadow_pte)
                    {
                        *shadow_pte = *real_pte;
                        HYPERPLATFORM_LOG_INFO("[td-protect] re-synced shadow PTE on-the-fly: pid=%llu va=%p real=0x%llX",
                            p->target_pid, (PVOID)page, *real_pte);
                    }
                    else
                    {
                        HYPERPLATFORM_LOG_ERROR("[td-protect] shadow PTE NULL while applying: pid=%llu va=%p shadow_cr3=0x%llX",
                            p->target_pid, (PVOID)page, shadow_cr3);
                        st = STATUS_NOT_FOUND;
                        goto ShadowProtectExit;
                    }
                }

                UINT64 wanted = *real_pte;
                TdApplyProtectToPte(&wanted, new_protect);
                if (wanted == *real_pte)
                    *shadow_pte = *real_pte;
                else
                    *shadow_pte = wanted;

                // Data pages (non-executable): also write the REAL PTE. renderdoc
                // often runs the write instruction on the REAL CR3 (its instruction
                // fetch is cached from a prior shadow-CR3 window -> no fetch #PF ->
                // no shadow swap), so the write lands on the REAL PTE. Without this
                // the IAT write AVs on real RO despite the shadow PTE being W=1.
                // Code pages (PAGE_EXECUTE_*) keep the real PTE (NX) for stealth.
                if (new_protect == PAGE_READWRITE || new_protect == PAGE_READONLY)
                    *real_pte = wanted;

                if (page == start)
                {
                    HYPERPLATFORM_LOG_INFO("[td-protect] applied: pid=%llu va=%p real=0x%llX shadow=0x%llX new=0x%X spte=%p",
                        p->target_pid, (PVOID)page, *real_pte, *shadow_pte, new_protect, shadow_pte);
                }
            }

            BOOLEAN tracked_has_diff = FALSE;
            if (tracked_base && tracked_size)
            {
                UINT64 tracked_end = (UINT64)tracked_base + tracked_size;
                for (UINT64 page = (UINT64)tracked_base; page < tracked_end; page += PAGE_SIZE)
                {
                    PUINT64 real_pte = TdResolveGuestPte(caller_cr3, page);
                    PUINT64 shadow_pte = TdResolveShadowPte(shadow_cr3, page);
                    if (!real_pte || !(*real_pte & 1))
                    {
                        HYPERPLATFORM_LOG_ERROR("[td-protect] real PTE gone while checking diff: pid=%llu va=%p real=%p realv=0x%llX",
                            p->target_pid, (PVOID)page, real_pte, real_pte ? *real_pte : 0);
                        st = STATUS_NOT_FOUND;
                        goto ShadowProtectExit;
                    }
                    if (!shadow_pte || !(*shadow_pte & 1))
                    {
                        if (shadow_pte)
                        {
                            *shadow_pte = *real_pte;
                            HYPERPLATFORM_LOG_INFO("[td-protect] re-synced shadow PTE in diff: pid=%llu va=%p real=0x%llX",
                                p->target_pid, (PVOID)page, *real_pte);
                        }
                        else
                        {
                            HYPERPLATFORM_LOG_ERROR("[td-protect] shadow PTE NULL while checking diff: pid=%llu va=%p shadow_cr3=0x%llX",
                                p->target_pid, (PVOID)page, shadow_cr3);
                            st = STATUS_NOT_FOUND;
                            goto ShadowProtectExit;
                        }
                    }

                    if (TdProtectFromPte(*shadow_pte) != TdProtectFromPte(*real_pte))
                    {
                        tracked_has_diff = TRUE;
                        break;
                    }
                }
            }

            if (!tracked_has_diff && tracked_base && tracked_size)
            {
                TdFlushAddressRange((UINT64)tracked_base, tracked_size, caller_cr3, shadow_cr3);
                for (UINT64 page = (UINT64)tracked_base;
                     page < (UINT64)tracked_base + tracked_size;
                     page += PAGE_SIZE)
                    TdStealthFreePage((PVOID)page);

                {
                    // Refcount-aware: free the shared CR3 only if this was the
                    // last tracked range for the process.
                    UINT64 to_free = TdStealthTrackRemove(p->target_pid, tracked_base);
                    if (to_free)
                        TdShadowFreeCr3(to_free);
                }
                shadow_cr3 = 0;
                flush_shadow_cr3 = 0;
            }
        }

        TdFlushAddressRange(start, protect_size, caller_cr3, flush_shadow_cr3);
        st = STATUS_SUCCESS;

    ShadowProtectExit:
        p->base_va = start;
        p->size = (UINT64)protect_size;
        p->new_protect = new_protect;
        p->shadow_cr3 = shadow_cr3;
        if (p->status == 0)
            p->status = (UINT64)(ULONG)st;
        irp->IoStatus.Information = sizeof(TD_SHADOW_PROTECT_PARAMS);

        KeUnstackDetachProcess(&apc_state);
        ObDereferenceObject(proc);
        break;
    }

    case IOCTL_RESOLVE_EXPORT:
    {
        if (io->Parameters.DeviceIoControl.InputBufferLength < sizeof(TD_RESOLVE_EXPORT_PARAMS) ||
            io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(TD_RESOLVE_EXPORT_PARAMS))
        { st = STATUS_BUFFER_TOO_SMALL; break; }

        TD_RESOLVE_EXPORT_PARAMS * p = (TD_RESOLVE_EXPORT_PARAMS *)irp->AssociatedIrp.SystemBuffer;
        p->messageboxa_va = 0;
        p->sleepex_va = 0;

        if (!p->target_pid)
        {
            st = STATUS_INVALID_PARAMETER;
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_RESOLVE_EXPORT_PARAMS);
            break;
        }

        PEPROCESS proc = NULL;
        st = PsLookupProcessByProcessId((HANDLE)p->target_pid, &proc);
        if (!NT_SUCCESS(st))
        {
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_RESOLVE_EXPORT_PARAMS);
            break;
        }

        KAPC_STATE apc_state;
        KeStackAttachProcess(proc, &apc_state);

        UINT64 pMsgBox = 0;
        UINT64 pSleepEx = 0;
        PVOID user32_base = NULL;
        PVOID kernel32_base = NULL;

        __try {
            user32_base = TdFindModuleBaseA("user32.dll", NULL);
            kernel32_base = TdFindModuleBaseA("kernel32.dll", NULL);

            if (user32_base)
                pMsgBox = (UINT64)TdFindExportByName(user32_base, "MessageBoxA");

            if (kernel32_base)
                pSleepEx = (UINT64)TdFindExportByName(kernel32_base, "SleepEx");
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            HYPERPLATFORM_LOG_ERROR("[td] resolve export: exception walking PEB/exports");
            st = STATUS_UNSUCCESSFUL;
        }

        if (!pMsgBox)
            HYPERPLATFORM_LOG_WARN("[td] resolve export: MessageBoxA not found in user32");
        if (!pSleepEx)
            HYPERPLATFORM_LOG_WARN("[td] resolve export: SleepEx not found in kernel32");

        if (NT_SUCCESS(st) && (!pMsgBox || !pSleepEx))
            st = STATUS_NOT_FOUND;

        p->messageboxa_va = pMsgBox;
        p->sleepex_va = pSleepEx;
        p->status = (UINT64)(ULONG)st;
        irp->IoStatus.Information = sizeof(TD_RESOLVE_EXPORT_PARAMS);

        HYPERPLATFORM_LOG_INFO("[td] resolve export: pid=%llu MessageBoxA=0x%llX SleepEx=0x%llX",
                   p->target_pid, pMsgBox, pSleepEx);

        KeUnstackDetachProcess(&apc_state);
        ObDereferenceObject(proc);
        break;
    }

    case IOCTL_INSTALL_TRIGGER_JUMP:
    {
        if (io->Parameters.DeviceIoControl.InputBufferLength < sizeof(TD_TRIGGER_JUMP_PARAMS) ||
            io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(TD_TRIGGER_JUMP_PARAMS))
        { st = STATUS_BUFFER_TOO_SMALL; break; }

        TD_TRIGGER_JUMP_PARAMS * p =
            (TD_TRIGGER_JUMP_PARAMS *)irp->AssociatedIrp.SystemBuffer;

        if (!p->target_pid || !p->jump_to_va)
        {
            st = STATUS_INVALID_PARAMETER;
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_TRIGGER_JUMP_PARAMS);
            break;
        }

        PEPROCESS proc = NULL;
        st = PsLookupProcessByProcessId((HANDLE)p->target_pid, &proc);
        if (!NT_SUCCESS(st))
        {
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_TRIGGER_JUMP_PARAMS);
            break;
        }

        KAPC_STATE apc_state;
        KeStackAttachProcess(proc, &apc_state);

        PVOID trigger_fn = (PVOID)p->trigger_va;
        if (!trigger_fn)
            trigger_fn = TdResolveDefaultTrigger(proc, "td-trigger");

        if (!trigger_fn)
        {
            HYPERPLATFORM_LOG_ERROR("[td-trigger] cannot resolve trigger function");
            st = STATUS_NOT_FOUND;
        }
        else
        {
            UINT64 caller_cr3 = __readcr3();
            PVOID dummy_origin = NULL;
            UINT64 flags = p->flags ? p->flags : 2;

            st = TdInstallTriggerHookAllCpus(
                trigger_fn, (PVOID)p->jump_to_va, caller_cr3, flags, p->target_tid, &dummy_origin, NULL);

            HYPERPLATFORM_LOG_INFO("[td-trigger] hook %s trigger=%p jump=%p flags=0x%llX st=0x%08X",
                       NT_SUCCESS(st) ? "OK" : "FAILED",
                       trigger_fn, (PVOID)p->jump_to_va, flags, st);

            p->trigger_va = (UINT64)trigger_fn;
        }

        p->status = (UINT64)(ULONG)st;
        irp->IoStatus.Information = sizeof(TD_TRIGGER_JUMP_PARAMS);

        KeUnstackDetachProcess(&apc_state);
        ObDereferenceObject(proc);
        break;
    }

    case IOCTL_GET_MODULE_BASE:
    {
        if (io->Parameters.DeviceIoControl.InputBufferLength < sizeof(TD_GET_MODULE_BASE_PARAMS) ||
            io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(TD_GET_MODULE_BASE_PARAMS))
        { st = STATUS_BUFFER_TOO_SMALL; break; }

        TD_GET_MODULE_BASE_PARAMS * p = (TD_GET_MODULE_BASE_PARAMS *)irp->AssociatedIrp.SystemBuffer;
        p->module_base = 0;
        p->module_size = 0;

        // ensure null-termination
        p->module_name[sizeof(p->module_name) - 1] = '\0';

        if (!p->target_pid || !p->module_name[0])
        {
            st = STATUS_INVALID_PARAMETER;
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_GET_MODULE_BASE_PARAMS);
            break;
        }

        PEPROCESS proc = NULL;
        st = PsLookupProcessByProcessId((HANDLE)p->target_pid, &proc);
        if (!NT_SUCCESS(st))
        {
            p->status = (UINT64)(ULONG)st;
            irp->IoStatus.Information = sizeof(TD_GET_MODULE_BASE_PARAMS);
            break;
        }

        KAPC_STATE apc_state;
        KeStackAttachProcess(proc, &apc_state);

        __try {
            ULONG img_size = 0;
            PVOID base = TdFindModuleBaseA(p->module_name, &img_size);
            if (base)
            {
                p->module_base = (UINT64)base;
                p->module_size = img_size;
            }
            else
            {
                st = STATUS_NOT_FOUND;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            HYPERPLATFORM_LOG_ERROR("[td] get module base: exception walking PEB");
            st = STATUS_UNSUCCESSFUL;
        }

        p->status = (UINT64)(ULONG)st;
        irp->IoStatus.Information = sizeof(TD_GET_MODULE_BASE_PARAMS);

        HYPERPLATFORM_LOG_INFO("[td] get module base: pid=%llu name=%s base=0x%llX size=0x%llX",
                   p->target_pid, p->module_name, p->module_base, p->module_size);

        KeUnstackDetachProcess(&apc_state);
        ObDereferenceObject(proc);
        break;
    }

    case IOCTL_GET_SELF_PE_INFO:
    {
        if (io->Parameters.DeviceIoControl.InputBufferLength < sizeof(TD_GET_SELF_PE_INFO_PARAMS) ||
            io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(TD_GET_SELF_PE_INFO_PARAMS))
        { st = STATUS_BUFFER_TOO_SMALL; break; }

        TD_GET_SELF_PE_INFO_PARAMS * p = (TD_GET_SELF_PE_INFO_PARAMS *)irp->AssociatedIrp.SystemBuffer;
        p->rsrc_rva = 0;
        p->rsrc_size = 0;
        p->export_dir_rva = 0;
        p->export_dir_size = 0;
        p->size_of_image = 0;
        p->status = (UINT64)(ULONG)STATUS_INVALID_PARAMETER;

        // No attach needed: the cache is global driver state keyed by (pid, base).
        if (p->target_pid && p->module_base)
        {
            TD_SELF_PE_INFO_ENTRY entry;
            if (TdLookupSelfPeInfo(p->target_pid, p->module_base, &entry))
            {
                p->rsrc_rva = entry.rsrc_rva;
                p->rsrc_size = entry.rsrc_size;
                p->export_dir_rva = entry.export_dir_rva;
                p->export_dir_size = entry.export_dir_size;
                p->size_of_image = entry.size_of_image;
                p->status = 0;
            }
            else
            {
                p->status = (UINT64)(ULONG)STATUS_NOT_FOUND;
            }
        }

        HYPERPLATFORM_LOG_INFO("[td] get self pe info: pid=%llu base=0x%llX rsrc=0x%llX exp=0x%llX st=%llu",
                   p->target_pid, p->module_base, p->rsrc_rva, p->export_dir_rva, p->status);

        irp->IoStatus.Information = sizeof(TD_GET_SELF_PE_INFO_PARAMS);
        break;
    }

    case IOCTL_HIDE_DEVICE:
    {
        //
        // Hides the device & symlink from user-mode enumeration.
        // Called by version.dll after all init is done - the device is no longer
        // needed (EPT hooks are already installed). TdUnload checks g_device_hidden
        // and skips IoDeleteSymbolicLink / IoDeleteDevice when already torn down.
        //
        g_device_hidden = TRUE;

        UNICODE_STRING sym;
        RtlInitUnicodeString(&sym, TD_SYMLINK_NAME);
        // Best-effort: delete symlink first so namespace enumeration stops seeing
        // it, then delete the device object. Either failure is non-fatal.
        NTSTATUS st1 = IoDeleteSymbolicLink(&sym);
        if (!NT_SUCCESS(st1))
        {
            HYPERPLATFORM_LOG_WARN("[td] hide device: symlink delete failed 0x%08X (may already be removed)", st1);
        }

        if (g_dev_obj)
        {
            IoDeleteDevice(g_dev_obj);
            HYPERPLATFORM_LOG_INFO("[td] device + symlink hidden. IOCTL_HIDE_DEVICE done.");
        }
        else
        {
            HYPERPLATFORM_LOG_WARN("[td] hide device: g_dev_obj is NULL (already hidden?)");
        }

        st = STATUS_SUCCESS;
        break;
    }

    case IOCTL_INJECT_RENDERDOC:
    {
        // R3-triggered renderdoc shadow inject -- alternative to the automatic
        // LoadImage/d3d12-detect path. Lets R3 inject renderdoc into a given PID
        // on demand, useful to test TdInjectRenderdocShadow in isolation from the
        // wedge-prone auto path. Matches Injector/inject_renderdoc.cpp.
        // TdInjectRenderdocShadow attaches to the target itself (like the auto
        // path at the LoadImage callback), so we do NOT KeStackAttachProcess here.
        if (io->Parameters.DeviceIoControl.InputBufferLength < sizeof(TD_INJECT_RENDERDOC_PARAMS) ||
            io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(TD_INJECT_RENDERDOC_PARAMS))
        { st = STATUS_BUFFER_TOO_SMALL; break; }

        TD_INJECT_RENDERDOC_PARAMS * p = (TD_INJECT_RENDERDOC_PARAMS *)irp->AssociatedIrp.SystemBuffer;
        p->renderdoc_path[519] = L'\0';   // hard null-terminate (defensive vs. R3)

        PEPROCESS proc = NULL;
        NTSTATUS lookup_st = PsLookupProcessByProcessId((HANDLE)p->target_pid, &proc);
        if (!NT_SUCCESS(lookup_st) || !proc)
        {
            HYPERPLATFORM_LOG_ERROR("[rd-r3] PsLookupProcessByProcessId failed pid=%llu st=0x%08X",
                p->target_pid, lookup_st);
            p->status = (UINT64)lookup_st;
            irp->IoStatus.Information = sizeof(TD_INJECT_RENDERDOC_PARAMS);
            st = STATUS_SUCCESS;   // IOCTL ok; result delivered in p->status
            break;
        }

        UNICODE_STRING renderdoc_nt;
        RtlInitUnicodeString(&renderdoc_nt, p->renderdoc_path);

        HYPERPLATFORM_LOG_INFO("[rd-r3] inject renderdoc pid=%llu path=%wZ",
            p->target_pid, &renderdoc_nt);

        NTSTATUS inj_st = TdInjectRenderdocShadow(proc, &renderdoc_nt, "rd-r3", FALSE);
        ObDereferenceObject(proc);

        p->status = (UINT64)inj_st;
        irp->IoStatus.Information = sizeof(TD_INJECT_RENDERDOC_PARAMS);
        st = STATUS_SUCCESS;   // IOCTL ok; injection result in p->status (0 = set up OK)
        break;
    }

    default:
        st = STATUS_INVALID_DEVICE_REQUEST;
        HYPERPLATFORM_LOG_ERROR("[td-ioctl] unhandled IOCTL code=0x%08X", io->Parameters.DeviceIoControl.IoControlCode);
        break;
    }

    HYPERPLATFORM_LOG_INFO("[td-ioctl] exit: code=0x%08X st=0x%08lX info=%llu",
        io->Parameters.DeviceIoControl.IoControlCode,
        (ULONG)st, (ULONGLONG)irp->IoStatus.Information);

    irp->IoStatus.Status = st;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return st;
}

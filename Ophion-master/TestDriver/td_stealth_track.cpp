#include "td_common.h"

// =========================================================================
//  stealth inject tracking + process exit cleanup
// =========================================================================

//
// free param struct �?must match Ophion's EPT_STEALTH_FREE_PARAM
//
#pragma pack(push, 8)
#pragma pack(pop)

//
// track stealth inject allocations for process exit cleanup
//
#define MAX_STEALTH_TRACKS 64

STEALTH_TRACK_ENTRY g_stealth_tracks[MAX_STEALTH_TRACKS] = {};
KSPIN_LOCK g_stealth_track_lock;

BOOLEAN
TdStealthTrackAdd(UINT64 pid, PVOID va, SIZE_T size, UINT64 shadow_cr3, PMDL image_mdl,
                  UINT64 guest_cr3, UINT64 *page_pfns, UINT32 page_count)
{
    BOOLEAN added = FALSE;
    KIRQL old_irql;
    KeAcquireSpinLock(&g_stealth_track_lock, &old_irql);

    for (int i = 0; i < MAX_STEALTH_TRACKS; i++)
    {
        if (!g_stealth_tracks[i].active)
        {
            g_stealth_tracks[i].target_pid      = pid;
            g_stealth_tracks[i].target_va       = va;
            g_stealth_tracks[i].alloc_size      = size;
            g_stealth_tracks[i].shadow_cr3_phys = shadow_cr3;
            g_stealth_tracks[i].image_mdl       = image_mdl;
            g_stealth_tracks[i].guest_cr3       = guest_cr3;
            g_stealth_tracks[i].page_pfns       = page_pfns;   // ownership transferred to track
            g_stealth_tracks[i].page_count      = page_count;
            g_stealth_tracks[i].active          = TRUE;
            added = TRUE;
            break;
        }
    }

    // AddRef the shared CR3 while still holding the track lock (matches Remove's
    // Release-under-lock) so a concurrent Remove on another range cannot drop the
    // refcount to 0 and free the CR3 before this range's ref is recorded.
    if (added)
        TdShadowCr3AddRef(shadow_cr3);

    KeReleaseSpinLock(&g_stealth_track_lock, old_irql);
    return added;
}

UINT64
TdStealthTrackRemove(UINT64 pid, PVOID va, PMDL * out_mdl)
{
    UINT64 shadow_cr3 = 0;
    UINT64 to_free = 0;
    KIRQL old_irql;
    KeAcquireSpinLock(&g_stealth_track_lock, &old_irql);

    for (int i = 0; i < MAX_STEALTH_TRACKS; i++)
    {
        if (g_stealth_tracks[i].active &&
            g_stealth_tracks[i].target_pid == pid &&
            g_stealth_tracks[i].target_va == va)
        {
            shadow_cr3 = g_stealth_tracks[i].shadow_cr3_phys;
            PMDL mdl = g_stealth_tracks[i].image_mdl;
            RtlZeroMemory(&g_stealth_tracks[i], sizeof(g_stealth_tracks[i]));
            if (out_mdl)
                *out_mdl = mdl;
            else if (mdl)
                HYPERPLATFORM_LOG_WARN("[td-rw] TdStealthTrackRemove dropping image_mdl=%p (out_mdl=NULL)", mdl);
            break;
        }
    }

    // Release the shared CR3's refcount under the track lock. If this was the
    // last range, to_free is set and the caller frees via TdShadowFreeCr3
    // OUTSIDE the lock (it does PASSIVE page/MDL freeing).
    if (shadow_cr3)
        TdShadowCr3Release(shadow_cr3, &to_free);

    KeReleaseSpinLock(&g_stealth_track_lock, old_irql);
    return to_free;
}

// Find the (shared) shadow CR3 for a process, if any range is already tracked.
// All ranges of a process share one shadow CR3 (multi-range per process).
// NOTE: returns the cr3 without AddRef'ing; callers must not race a concurrent
// remove on the same pid (renderdoc's protect/restore is single-threaded per
// process). Hardening for concurrent multi-threaded range ops is a follow-up.
UINT64
TdStealthFindShadowCr3ForPid(UINT64 pid)
{
    UINT64 shadow_cr3 = 0;
    KIRQL old_irql;
    KeAcquireSpinLock(&g_stealth_track_lock, &old_irql);
    for (int i = 0; i < MAX_STEALTH_TRACKS; i++)
    {
        if (g_stealth_tracks[i].active && g_stealth_tracks[i].target_pid == pid)
        {
            shadow_cr3 = g_stealth_tracks[i].shadow_cr3_phys;
            break;
        }
    }
    KeReleaseSpinLock(&g_stealth_track_lock, old_irql);
    return shadow_cr3;
}

BOOLEAN
TdStealthTrackFindOverlap(UINT64 pid, PVOID base_va, SIZE_T size, PVOID * out_base, SIZE_T * out_size, UINT64 * out_shadow_cr3)
{
    if (!size)
        return FALSE;

    BOOLEAN found = FALSE;
    UINT64 req_base = (UINT64)base_va;
    if (req_base > (~0ULL - size))
        return FALSE;
    UINT64 req_end = req_base + size;

    KIRQL old_irql;
    KeAcquireSpinLock(&g_stealth_track_lock, &old_irql);

    for (int i = 0; i < MAX_STEALTH_TRACKS; i++)
    {
        STEALTH_TRACK_ENTRY * entry = &g_stealth_tracks[i];
        if (!entry->active || entry->target_pid != pid)
            continue;

        UINT64 base = (UINT64)entry->target_va;
        UINT64 end = base + entry->alloc_size;
        if (req_base < end && req_end > base)
        {
            if (out_base) *out_base = entry->target_va;
            if (out_size) *out_size = entry->alloc_size;
            if (out_shadow_cr3) *out_shadow_cr3 = entry->shadow_cr3_phys;
            found = TRUE;
            break;
        }
    }

    KeReleaseSpinLock(&g_stealth_track_lock, old_irql);
    return found;
}

BOOLEAN
TdStealthTrackHasPartialOverlap(UINT64 pid, PVOID base_va, SIZE_T size)
{
    if (!size)
        return FALSE;

    UINT64 req_base = (UINT64)base_va;
    if (req_base > (~0ULL - size))
        return TRUE;
    UINT64 req_end = req_base + size;
    BOOLEAN partial = FALSE;

    KIRQL old_irql;
    KeAcquireSpinLock(&g_stealth_track_lock, &old_irql);

    for (int i = 0; i < MAX_STEALTH_TRACKS; i++)
    {
        STEALTH_TRACK_ENTRY * entry = &g_stealth_tracks[i];
        if (!entry->active || entry->target_pid != pid)
            continue;

        UINT64 base = (UINT64)entry->target_va;
        UINT64 end = base + entry->alloc_size;
        if (req_base < end && req_end > base &&
            (base < req_base || end > req_end))
        {
            partial = TRUE;
            break;
        }
    }

    KeReleaseSpinLock(&g_stealth_track_lock, old_irql);
    return partial;
}

//
// free one stealth page via DPC broadcast �?VMCALL_STEALTH_FREE
// must be called while attached to the target process.
//
VOID
TdEptLifecycleResumeAll(VOID)
{
    if (!TdOphionAlive())
        return;

    // All CPUs meet at the DPC barrier before clearing quiesce locally.  This
    // is the TestDriver-side tail for SHADOW_ABORT/FREE lifecycle operations.
    KeGenericCallDpc([](PKDPC, PVOID, PVOID A1, PVOID A2) {
        KeSignalCallDpcSynchronize(A2);
        hv_vmcall_simple(VMCALL_EPT_LIFECYCLE_RESUME, 0, 0, 0);
        KeSignalCallDpcDone(A1);
    }, NULL);
}

BOOLEAN
TdStealthFreePage(PVOID target_va)
{
    if (!target_va || !TdOphionAlive()) return FALSE;
    UINT64 phys = MmGetPhysicalAddress(target_va).QuadPart;
    // phys may be 0 if page already freed/paged �?still try VMCALL with VA match
    TD_STEALTH_FREE_PARAM req = {};
    req.caller_cr3  = __readcr3();
    req.target_va   = target_va;
    req.target_phys = phys;

    KeGenericCallDpc([](PKDPC, PVOID Ctx, PVOID A1, PVOID A2) {
        hv_vmcall_simple(VMCALL_STEALTH_FREE, (UINT64)Ctx, 0, 0);
        KeSignalCallDpcSynchronize(A2);
        hv_vmcall_simple(VMCALL_EPT_LIFECYCLE_RESUME, 0, 0, 0);
        KeSignalCallDpcDone(A1);
    }, &req);
    return req.result;
}

//
// free one stealth page via DPC broadcast using a PRE-COMPUTED physical address.
// Does NOT call MmGetPhysicalAddress -> does NOT need to be attached to the target
// process. Safe to call from the process-exit callback in System context: the DPC
// runs at DISPATCH in System context, vmx_enter_guest_cr3() enters System CR3
// (page tables always valid -> no deadlock). ept_stealth_uninstall matches by
// PFN or guest VA (not by CR3), and pa_to_va for NonPaged pool shadow/fake-PT
// pages works under any CR3.
//
BOOLEAN
TdStealthFreePageSafe(PVOID target_va, UINT64 target_phys)
{
    if (!target_va || !TdOphionAlive()) return FALSE;
    TD_STEALTH_FREE_PARAM req = {};
    req.caller_cr3  = __readcr3();   // System CR3 (not attached to dying process)
    req.target_va   = target_va;
    req.target_phys = target_phys;   // pre-computed at injection time

    KeGenericCallDpc([](PKDPC, PVOID Ctx, PVOID A1, PVOID A2) {
        hv_vmcall_simple(VMCALL_STEALTH_FREE, (UINT64)Ctx, 0, 0);
        KeSignalCallDpcSynchronize(A2);
        hv_vmcall_simple(VMCALL_EPT_LIFECYCLE_RESUME, 0, 0, 0);
        KeSignalCallDpcDone(A1);
    }, &req);
    return req.result;
}

//
// process exit callback �?clean up stealth pages + fake PT before
// MiDeleteFinalPageTables destroys the address space.
//
VOID
TdCleanupStealthForProcess(PEPROCESS Process, UINT64 pid)
{
    // Serialize against hook install/explicit unhook. The process callback is
    // PASSIVE_LEVEL, so waiting on the synchronization-event gate is valid.
    TdR3HooksLock();

    // Process-notify runs for every process on the system.  Lifecycle DPCs are
    // global, so broadcasting them for an unrelated cmd/git/conhost exit can
    // quiesce an in-flight hook installation owned by another process.  Enter
    // the teardown barrier only when this PID actually owns tracked EPT state.
    BOOLEAN owns_ept_state = FALSE;
    UINT64 dying_cr3 = 0;
    for (int i = 0; i < MAX_R3_HOOKS; i++)
    {
        if (g_r3_hooks[i].active && g_r3_hooks[i].target_pid == pid)
        {
            owns_ept_state = TRUE;
            dying_cr3 = g_r3_hooks[i].target_cr3;
            break;
        }
    }

    if (!owns_ept_state || !dying_cr3)
    {
        KIRQL old_irql;
        KeAcquireSpinLock(&g_stealth_track_lock, &old_irql);
        for (int i = 0; i < MAX_STEALTH_TRACKS; i++)
        {
            if (g_stealth_tracks[i].active &&
                g_stealth_tracks[i].target_pid == pid)
            {
                owns_ept_state = TRUE;
                dying_cr3 = g_stealth_tracks[i].guest_cr3;
                break;
            }
        }
        KeReleaseSpinLock(&g_stealth_track_lock, old_irql);
    }

    if (!owns_ept_state)
    {
        TdR3HooksUnlock();
        return;
    }

    const BOOLEAN hv_alive = TdOphionAlive();
    if (!hv_alive)
    {
        HYPERPLATFORM_LOG_ERROR(
            "[td-rw] process exit pid=%llu while Ophion is not alive; skipping VMCALL cleanup",
            pid);
    }

    //
    // 0. retire (passthrough) this process's EPT hooks on the shared d3d12/dxgi
    //    pages. Without this, the hooks (and their proxy pointers) survive exit
    //    and the NEXT Box process gets dispatched to THIS process's freed proxy
    //    during its own hook re-install window -> 0xC0000005 (confirmed: the
    //    crash RIP was the prior run's CreateDXGIFactory2 proxy). VMCALL_EPT_UNHOOK
    //    can't be used here (it loads the dying CR3 on every CPU and deadlocks
    //    in the exit callback), so use the CR3-free VMCALL_EPT_UNHOOK_BY_CR3.
    //    The VMCALL does not switch CR3, so it is safe to issue from here.
    //
    if (hv_alive && dying_cr3)
    {
        NTSTATUS retire_status = STATUS_UNSUCCESSFUL;
        for (UINT32 attempt = 0; attempt < 3; ++attempt)
        {
            retire_status = TdEptUnhookByCr3AllCpus(dying_cr3);
            if (NT_SUCCESS(retire_status))
                break;
        }

        if (!NT_SUCCESS(retire_status))
        {
            // Releasing the tracked MDLs after a failed retirement can let an
            // armed PFN hook target unrelated reused memory. Keep ownership so
            // unload can retry with the saved CR3 match key.
            HYPERPLATFORM_LOG_ERROR(
                "[td-rw] process exit hook retirement failed; resources retained: pid=%llu st=0x%08X",
                pid, retire_status);
            TdR3HooksUnlock();
            return;
        }
    }
    else if (hv_alive)
    {
        HYPERPLATFORM_LOG_WARN(
            "[td-rw] process exit pid=%llu has tracked state but no saved CR3; resources retained",
            pid);
        TdR3HooksUnlock();
        return;
    }

    //
    // 1. clean up R3 EPT hooks for this process (unlock MDL pages, free trampoline)
    //
    for (int i = 0; i < MAX_R3_HOOKS; i++)
    {
        if (!g_r3_hooks[i].active || g_r3_hooks[i].target_pid != pid)
            continue;

        HYPERPLATFORM_LOG_INFO("[td-rw] process exit cleanup R3 hook: pid=%llu target=%p",
                   pid, g_r3_hooks[i].target_va);

        // snapshot before teardown (ZwFreeVirtualMemory zeroes trampoline_va).
        PVOID   trampoline_va = g_r3_hooks[i].trampoline_va;
        SIZE_T  trampoline_sz = g_r3_hooks[i].trampoline_size;
        PMDL    target_mdl    = g_r3_hooks[i].target_mdl;

        // The hypervisor record was retired above by saved CR3 without loading
        // the dying address space on every CPU. Do not use VMCALL_EPT_UNHOOK
        // here: that path switches CR3 and can deadlock in an exit callback.

        // attach: trampoline stealth-page free + trampoline free need the
        // process address space, still valid at exit-notify time.
        KAPC_STATE apc;
        KeStackAttachProcess(Process, &apc);

        // free the trampoline stealth page (registered in TdEptHookR3 via
        // TdStealthAllocPage with target_pid=0, so NOT in g_stealth_tracks and
        // never freed before). Without this the sp leaks in g_ept->stealth_pages
        // referencing this process's soon-freed shadow CR3. VMCALL_STEALTH_FREE
        // does not switch CR3, so it is safe from the exit callback. Must run
        // while the trampoline page is still mapped (before ZwFreeVirtualMemory).
        if (trampoline_va)
            TdStealthFreePage((PVOID)((UINT64)trampoline_va & ~0xFFFULL));

        // free trampoline memory
        if (trampoline_va != NULL && trampoline_sz > 0)
            ZwFreeVirtualMemory(ZwCurrentProcess(), &trampoline_va, &trampoline_sz, MEM_RELEASE);

        KeUnstackDetachProcess(&apc);

        // unlock target page MDL
        if (target_mdl != NULL)
        {
            MmUnlockPages(target_mdl);
            IoFreeMdl(target_mdl);
        }

        RtlZeroMemory(&g_r3_hooks[i], sizeof(g_r3_hooks[i]));
    }

    //
    // 1.5. abort stale shadow-CR3 windows on ALL vCPUs BEFORE freeing stealth
    //      page entries. If the game crashed with a shadow window open (MTF armed,
    //      nx_timer_restore pointing to a stealth page entry), the entry is about
    //      to be pool_manager_release'd. A subsequent MTF/#PF on that vCPU would
    //      dereference the freed pointer -> use-after-free -> triple fault.
    //      This VMCALL clears nx_timer_restore/nx_timer_real_cr3/MTF on every CPU
    //      without dereferencing the pointer (uses the value-copied real_cr3).
    //
    if (hv_alive)
    {
        KeGenericCallDpc([](PKDPC, PVOID, PVOID A1, PVOID A2) {
            hv_vmcall_simple(VMCALL_SHADOW_ABORT_ALL, 0, 0, 0);
            KeSignalCallDpcSynchronize(A2);
            KeSignalCallDpcDone(A1);
        }, NULL);
    }

    //
    // 2. clean up stealth tracks (shadow memory)
    //
    //    Two paths:
    //    - SAFE path (page_pfns != NULL, renderdoc injection): uses TdStealthFreePageSafe
    //      with pre-computed PFNs from System context. NO KeStackAttachProcess to the
    //      dying process -> no deadlock -> TdShadowFreeCr3 always runs -> no stale
    //      HV stealth entries -> 2nd injection does not freeze.
    //    - OLD path (page_pfns == NULL, ioctl protect/alloc): attaches to the dying
    //      process and uses MmGetPhysicalAddress. Retained for callers without
    //      pre-computed PFNs.
    //
    for (int i = 0; i < MAX_STEALTH_TRACKS; i++)
    {
        PVOID   va          = NULL;
        SIZE_T  sz          = 0;
        UINT64  *snap_pfns  = NULL;
        UINT32  snap_pcnt   = 0;

        KIRQL old_irql;
        KeAcquireSpinLock(&g_stealth_track_lock, &old_irql);

        if (g_stealth_tracks[i].active && g_stealth_tracks[i].target_pid == pid)
        {
            va         = g_stealth_tracks[i].target_va;
            sz         = g_stealth_tracks[i].alloc_size;
            snap_pfns  = g_stealth_tracks[i].page_pfns;
            snap_pcnt  = g_stealth_tracks[i].page_count;
        }

        KeReleaseSpinLock(&g_stealth_track_lock, old_irql);

        if (!va || !sz)
            continue;

        HYPERPLATFORM_LOG_WARN("[td-rw] process exit cleanup: pid=%llu va=%p size=0x%llX pfns=%u",
                   pid, va, (UINT64)sz, snap_pcnt);

        // Remove the tracked range. TdStealthTrackRemove decrements the shared
        // CR3's refcount and returns the CR3 only if this was the last range.
        PMDL track_mdl = NULL;
        UINT64 to_free = TdStealthTrackRemove(pid, va, &track_mdl);

        UINT64 base_va = (UINT64)va & ~0xFFFULL;
        UINT64 end_va  = ((UINT64)va + sz + PAGE_SIZE - 1) & ~0xFFFULL;

        if (snap_pfns && snap_pcnt)
        {
            //
            // SAFE PATH: no KeStackAttachProcess. Use stored PFNs.
            // DPC runs in System context -> vmx_enter_guest_cr3 enters System
            // CR3 (always valid) -> no deadlock. ept_stealth_uninstall matches
            // by PFN/VA (not CR3) -> correct entry removed.
            //
            UINT32 pfn_idx = 0;
            for (UINT64 page = base_va; page < end_va && pfn_idx < snap_pcnt; page += PAGE_SIZE, pfn_idx++)
                TdStealthFreePageSafe((PVOID)page, snap_pfns[pfn_idx]);

            // Safe to free shadow CR3 now: the pre-injection cleanup
            // (VMCALL_STEALTH_FREE_ALL in TdInjectRenderdocShadow) clears ALL
            // HV stealth state before any new injection, so even if the OS
            // reuses this PA, HV will never dereference it.
            if (to_free)
                TdShadowFreeCr3(to_free);

            // free the per-page PFN array (NonPaged pool, ownership was transferred
            // from TdStealthTrackAdd).
            ExFreePoolWithTag(snap_pfns, 'fPdS');
        }
        else
        {
            //
            // OLD PATH: attach to the dying process for MmGetPhysicalAddress.
            // Used by ioctl protect/alloc callers that don't have pre-computed PFNs.
            //
            KAPC_STATE apc;
            KeStackAttachProcess(Process, &apc);

            for (UINT64 page = base_va; page < end_va; page += PAGE_SIZE)
                TdStealthFreePage((PVOID)page);

            if (to_free)
                TdShadowFreeCr3(to_free);

            KeUnstackDetachProcess(&apc);
        }

        // unlock the image pages pinned at injection (MmProbeAndLockPages).
        // PASSIVE here (exit-notify); the track spinlock was released inside
        // TdStealthTrackRemove, so MmUnlockPages is safe.
        if (track_mdl)
        {
            MmUnlockPages(track_mdl);
            IoFreeMdl(track_mdl);
        }

        HYPERPLATFORM_LOG_WARN("[td-rw] process exit cleanup done: pid=%llu to_free=0x%llX",
                   pid, to_free);
    }

    // SHADOW_ABORT_ALL quiesces every vCPU while cleanup may release metadata
    // referenced by pending MTF/shadow windows.  Cleanup is complete here, so
    // release the barrier even when the exiting process owned no stealth pages.
    TdEptLifecycleResumeAll();
    TdR3HooksUnlock();
}

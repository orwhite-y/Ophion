/*
 * EPT_HOOK_NOTES.h
 *
 * EPT Hook implementation notes - lessons learned from porting
 * UnrealVTDbg's EPT hook to Ophion's architecture.
 *
 * These are hard-won debugging notes. Each item caused hours of debugging.
 * Keep this file as reference for anyone modifying the EPT hook code.
 *
 * ============================================================================
 *  1. PRIVATE HOST CR3 AND VMX-ROOT MEMORY ACCESS (RESOLVED)
 * ============================================================================
 *
 *  Ophion's USE_PRIVATE_HOST_CR3 creates a deep-copy of kernel page tables
 *  at init time. In VMX-root mode, HOST_CR3 = private copy.
 *
 *  ORIGINAL PROBLEM: Any memory allocated AFTER hostcr3_build() is NOT
 *  mapped in the private page tables. This includes:
 *    - Test driver's stack variables (DPC callback stack)
 *    - Other driver's global variables
 *    - NonPaged pool allocated after init
 *    - Stealth contiguous region (64MB, allocated in DriverEntry)
 *
 *  SYMPTOM: Accessing these addresses in VMX-root → #PF → private IDT
 *  halt handler → system freeze (no BSOD, just hangs).
 *
 *  SOLUTION (now implemented — USE_PRIVATE_HOST_CR3 = 1):
 *
 *    1. All VMM-critical allocations (pool manager, VMM stacks, MSR/IO
 *       bitmaps, VMXON/VMCS, EPT tables) happen BEFORE hostcr3_build()
 *       in vmx_init(). These are mapped in the private CR3 snapshot.
 *
 *    2. Guest memory access in VMX-root is wrapped by
 *       vmx_enter_guest_cr3() / vmx_leave_guest_cr3() which switch
 *       to system CR3. All VMCALL handlers (EPT hook, unhook, stealth)
 *       already do this. Register values are read from VMM stack
 *       (always mapped) BEFORE the CR3 switch.
 *
 *    3. Post-init allocations (stealth contiguous region) are dynamically
 *       mapped into private page tables via hostcr3_map_va().
 *
 *    4. Pool manager buffers (splits, hooked pages, trampolines) are
 *       pre-allocated at PASSIVE_LEVEL during pool_manager_init() and
 *       their physical addresses are cached. Safe under both CR3s.
 *
 *  This provides anti-cheat stealth (guest can't corrupt host page tables
 *  to redirect VMX-root execution) while maintaining full EPT hook support.
 *
 * ============================================================================
 *  2. VMCALL PARAMETER PASSING - DO NOT PASS POINTERS
 * ============================================================================
 *
 *  WRONG approach (what we tried first):
 *    // caller:
 *    EPT_HOOK_REQUEST req = { target, proxy, ... };
 *    vmcall(EPT_HOOK, &req, 0, 0);
 *    // handler:
 *    req = (EPT_HOOK_REQUEST *)regs->rdx;  // pointer to guest memory
 *    req->target_function;                  // CRASH - guest VA not accessible
 *
 *  RIGHT approach (how UnrealVTDbg does it):
 *    // caller:
 *    vmcall_ex(EPT_HOOK, target, proxy, &origin, cr3, hook_type, ...);
 *    // handler:
 *    target = regs->rdx;    // value, not pointer dereference
 *    proxy  = regs->r8;     // value
 *    cr3    = regs->r10;    // value
 *    // build local_req on VMM stack from register values
 *
 *  KEY INSIGHT: Register values are saved on the VMM stack by the vmexit
 *  assembly handler. Reading regs->rdx is a VMM stack access (always
 *  mapped in host CR3). The VALUE in rdx is just a number - no dereference
 *  needed. Only dereference guest pointers AFTER switching to guest CR3.
 *
 * ============================================================================
 *  3. VMCALL IDENTIFIER - USE RAX, NOT R10/R11/R12
 * ============================================================================
 *
 *  Ophion's normal VMCALLs use r10/r11/r12 as signature registers.
 *  EPT hook VMCALLs need r10-r15 for parameters (target, proxy, cr3, etc.)
 *
 *  SOLUTION: Use rax as identifier (like UnrealVTDbg's VMCALL_IDENTIFIER).
 *    mov rax, OPHION_VMCALL_ID    ; identifier in rax
 *    ; rcx/rdx/r8/r9 = first 4 params
 *    ; r10-r15 = extra params (loaded from stack, saved/restored)
 *    vmcall
 *
 *  Handler checks rax FIRST. If it matches OPHION_VMCALL_ID, dispatch
 *  to EPT handlers (no r10/r11/r12 signature check). Otherwise fall
 *  through to normal signature check.
 *
 * ============================================================================
 *  4. ASSEMBLY - CALLEE-SAVED REGISTERS (R12-R15)
 * ============================================================================
 *
 *  x64 Windows calling convention:
 *    volatile (caller-saved):     rax rcx rdx r8 r9 r10 r11
 *    non-volatile (callee-saved): rbx rbp rdi rsi r12 r13 r14 r15
 *
 *  If the VMCALL assembly wrapper modifies r12-r15 for signature/params,
 *  it MUST push/pop them. Otherwise the caller's saved registers get
 *  corrupted → crash after vmcall returns (e.g., KeSignalCallDpcDone
 *  reads garbage from r12 → BSOD).
 *
 *  Ophion's asm_vmx_vmcall correctly saves r10-r12.
 *  Test driver's hv_vmcall_ex must save r12-r15.
 *
 * ============================================================================
 *  5. MULTI-CPU DPC BROADCAST - RACE CONDITIONS
 * ============================================================================
 *
 *  KeGenericCallDpc runs the callback on ALL CPUs simultaneously.
 *  EPT hook data structures (g_ept->hooked_pages linked list, pool manager)
 *  are SHARED. Concurrent modification → list corruption → infinite loop
 *  → CLOCK_WATCHDOG_TIMEOUT BSOD.
 *
 *  SOLUTION for hook install:
 *    - First CPU (single VMCALL before DPC): does full install
 *      (allocate, copy page, LDE, trampoline, add to list)
 *    - DPC broadcast to all CPUs: only split + PTE + INVEPT
 *      (check hooked_pages list - if page already exists, skip full install)
 *
 *  SOLUTION for unhook:
 *    - Single VMCALL: restore all CPUs' PTEs + remove from list
 *    - DPC broadcast: only INVEPT to flush all CPUs' TLBs
 *    - Must set proxy function pointer to NULL BEFORE unhook to prevent
 *      crash if another CPU is mid-execution in the hook
 *
 * ============================================================================
 *  6. EPT SPLIT BUFFER - PAGE ALIGNMENT
 * ============================================================================
 *
 *  VMM_EPT_DYNAMIC_SPLIT contains PML1[512] (4KB page table).
 *  The EPT PML2 entry points to this PML1 table via physical page frame
 *  number. The PML1 array MUST be physically page-aligned.
 *
 *  ExAllocatePool2 does NOT guarantee page alignment for all sizes.
 *  MmAllocateContiguousMemory DOES guarantee physical contiguity and
 *  alignment for large allocations.
 *
 *  WRONG:  ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(VMM_EPT_DYNAMIC_SPLIT))
 *  RIGHT:  MmAllocateContiguousMemory(sizeof(VMM_EPT_DYNAMIC_SPLIT), max_phys)
 *
 *  Same applies to EPT_HOOKED_PAGE_INFO which contains
 *  DECLSPEC_ALIGN(PAGE_SIZE) fake_page_contents[PAGE_SIZE].
 *
 * ============================================================================
 *  7. MmGetPhysicalAddress IN VMX-ROOT
 * ============================================================================
 *
 *  MmGetPhysicalAddress walks the current CR3's page tables.
 *  In VMX-root with HOST_CR3 = system CR3, it generally works for
 *  kernel NonPaged memory. However:
 *
 *  - It's a Windows API - behavior in VMX-root is not guaranteed
 *  - With private host CR3, it walks the PRIVATE page tables which
 *    may not map recently allocated memory
 *  - For pool-allocated buffers, pre-compute physical addresses at
 *    PASSIVE_LEVEL during pool_manager_init() and cache them
 *
 *  pool_manager stores physical_address per entry. Use
 *  pool_manager_get_physical() instead of MmGetPhysicalAddress()
 *  for pool buffers in VMX-root.
 *
 * ============================================================================
 *  8. MmGetVirtualForPhysical (pa_to_va) IN VMX-ROOT
 * ============================================================================
 *
 *  ept_get_pml1() calls pa_to_va() → MmGetVirtualForPhysical().
 *  This may not work in VMX-root for pool-allocated split buffers.
 *
 *  SOLUTION: ept_split_large_page_pool() returns the split buffer pointer.
 *  Caller computes PML1 entry directly:
 *    split = ept_split_large_page_pool(page_table, phys_addr);
 *    pte = &split->PML1[ADDRMASK_EPT_PML1_INDEX(phys_addr)];
 *
 * ============================================================================
 *  9. EXECUTE-ONLY EPT PAGES
 * ============================================================================
 *
 *  The split-TLB technique uses:
 *    original page: R=1 W=1 X=0 (read/write ok, execute → violation)
 *    fake page:     R=0 W=0 X=1 (execute ok, read/write → violation)
 *
 *  X-only pages (R=0 W=0 X=1) require IA32_VMX_EPT_VPID_CAP bit 0
 *  (ExecuteOnlyPages) to be set. If NOT supported:
 *    R=0 W=0 X=1 → EPT MISCONFIGURATION → triple fault → BSOD
 *
 *  SOLUTION: Check g_ept->execute_only_supported. If FALSE, set R=1:
 *    fake page: R=1 W=0 X=1 (functional but reads see hook payload)
 *
 * ============================================================================
 *  10. EXECUTABLE POOL FOR TRAMPOLINES
 * ============================================================================
 *
 *  Trampoline buffers contain executable code (saved original instructions
 *  + absolute jump back). They MUST be in executable memory.
 *
 *  ExAllocatePool2 does NOT support POOL_FLAG_NON_PAGED_EXECUTE.
 *  Use legacy API:
 *    ExAllocatePoolWithTag(NonPagedPoolExecute, size, tag)
 *
 * ============================================================================
 *  11. INVEPT AFTER VMXOFF
 * ============================================================================
 *
 *  During driver unload:
 *    1. broadcast_terminate_all() → VMXOFF on all CPUs
 *    2. vmx_terminate() → ept_unhook_all()
 *
 *  ept_unhook_all() must NOT call asm_invept() after VMXOFF.
 *  INVEPT is a VMX instruction - executing it outside VMX operation → #UD → BSOD.
 *
 *  SOLUTION: ept_unhook_all() only restores PTEs and frees memory.
 *  No INVEPT needed - VMX is already off, there's no EPT to invalidate.
 *
 * ============================================================================
 *  12. NTSTATUS RETURN VALUE TRUNCATION
 * ============================================================================
 *
 *  hv_vmcall_ex is declared as returning NTSTATUS (32-bit LONG).
 *  The VMX-root handler sets regs->rax (64-bit). The upper 32 bits
 *  are truncated when the caller reads the return value as NTSTATUS.
 *
 *  Don't rely on the VMCALL return value for 64-bit data (pointers, etc.)
 *  Use shared memory (NonPaged globals) for returning large values.
 *
 * ============================================================================
 *  13. UNHOOK RACE CONDITION - TLB STALE ENTRIES
 * ============================================================================
 *
 *  After unhook restores PTE to RWX on all CPUs, other CPUs still have
 *  stale EPT TLB entries (RW-no-X). Until INVEPT, those CPUs will still
 *  get EPT violations for the previously-hooked page.
 *
 *  If the hooked_pages list entry was already removed, the violation
 *  handler won't find a match → used to inject #GP → BSOD.
 *
 *  SOLUTION: Violation handler for unmatched pages does INVEPT + retry
 *  instead of injecting #GP. After INVEPT, the CPU picks up the new PTE
 *  (RWX) and execution continues normally.
 *
 * ============================================================================
 *  14. VMWARE NESTED VIRTUALIZATION COMPATIBILITY
 * ============================================================================
 *
 *  Ophion's stealth features are designed for bare metal and break in
 *  VMware nested virtualization:
 *
 *  - Private HOST_IDT: custom NMI handler. VMware delivers interrupts
 *    differently. The private IDT's default handler (HLT) catches
 *    unexpected interrupts → system freeze.
 *
 *  - Private HOST_GDT: GDT layout in VMware may differ.
 *
 *  - CR4.VMXE hiding: VMware may need VMXE visible.
 *
 *  - VIRTUAL_NMI: VMware's nested VMX may not fully support it.
 *
 *  - ACK_INTERRUPT_ON_EXIT: interrupt acknowledgment model may differ.
 *
 *  VT_Driver works in VMware because it uses NONE of these features.
 *  It's a minimal hypervisor: system CR3/IDT/GDT, no stealth.
 *
 *  To run Ophion in VMware, disable:
 *    USE_PRIVATE_HOST_CR3  = 0
 *    USE_PRIVATE_HOST_IDT  = 0
 *    USE_PRIVATE_HOST_GDT  = 0
 *    STEALTH_HIDE_CR4_VMXE = 0
 *
 * ============================================================================
 *  15. COMPILER REORDERING ACROSS CR3 SWITCH
 * ============================================================================
 *
 *  When switching CR3 in VMX-root to access guest memory:
 *    saved_cr3 = __readcr3();
 *    __writecr3(guest_cr3);
 *    // access guest memory here
 *    __writecr3(saved_cr3);
 *
 *  The compiler may reorder memory reads/writes across __writecr3.
 *  Reading regs->rdx AFTER __writecr3(guest_cr3) may give wrong value
 *  if the VMM stack has different mapping under guest CR3.
 *
 *  SOLUTION: Read all values from VMM stack (regs->xxx) BEFORE
 *  switching CR3. Store in local variables (registers), then switch.
 *  Use volatile if needed to prevent reordering.
 *
 *  Better solution: don't use private host CR3 at all.
 *
 * ============================================================================
 */

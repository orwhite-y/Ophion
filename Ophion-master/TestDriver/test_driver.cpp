/*
*   test_driver.cpp - stealth injection via pure VMCALL
*
*   communicates with Ophion hypervisor ONLY through VMCALL.
*   zero link dependency on Ophion.sys — completely standalone .sys.
*
*   flow:
*     1. ring-3 sends IOCTL_INJECT(PID) to this driver
*     2. driver attaches to target process
*     3. allocates PAGE_READWRITE memory
*     4. writes shellcode into the page
*     5. DPC broadcast → each CPU issues VMCALL_STEALTH_ALLOC to Ophion HV
*        → Ophion copies page content to shadow page (execute view)
*        → sets up EPT split + fake PT page + #PF interception
*     6. zeroes original page (read view = clean for anti-cheat)
*     7. creates thread at shellcode VA
*     8. thread runs → #PF → HV swaps EPT → TLB created → shellcode executes
*/
#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>

// ---- VMCALL interface (must match Ophion hv_types.h) ----

#define VMCALL_STEALTH_ALLOC    0x00000006

//
// param struct passed via VMCALL rdx pointer
// must match Ophion's EPT_STEALTH_ALLOC_PARAM exactly
//
#pragma pack(push, 8)
typedef struct _TD_STEALTH_PARAM {
    UINT64  caller_cr3;
    PVOID   target_va;
    PVOID   handler_function;
    UINT64  target_phys;
    PVOID   shellcode_buffer;
    UINT32  shellcode_size;
    BOOLEAN resident;
    volatile LONG installed;
    BOOLEAN result;
} TD_STEALTH_PARAM;
#pragma pack(pop)

// ---- assembly VMCALL (vmcall.asm) ----

extern "C" {
    NTSTATUS hv_vmcall_ex(
        UINT64 vmcall_reason, UINT64 param1, UINT64 param2, UINT64 param3,
        UINT64 param4, UINT64 param5, UINT64 param6,
        UINT64 param7, UINT64 param8, UINT64 param9);

    NTKERNELAPI VOID    KeGenericCallDpc(PKDEFERRED_ROUTINE, PVOID);
    NTKERNELAPI VOID    KeSignalCallDpcDone(PVOID);
    NTKERNELAPI LOGICAL KeSignalCallDpcSynchronize(PVOID);
}

// ---- undocumented API ----

typedef NTSTATUS (NTAPI * fn_ZwCreateThreadEx)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE,
    PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

static fn_ZwCreateThreadEx g_pZwCreateThreadEx = NULL;

// ---- device / IOCTL ----

#define TD_DEVICE_NAME  L"\\Device\\OphionTest"
#define TD_SYMLINK_NAME L"\\DosDevices\\OphionTest"

#define TD_IOCTL_BASE   0x900
#define IOCTL_INJECT    CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 0, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 8)
typedef struct _TD_INJECT_PARAMS {
    UINT64 target_pid;
    UINT64 alloc_size;
    UINT64 shellcode_va;    // [out]
    UINT64 actual_size;     // [out]
} TD_INJECT_PARAMS;
#pragma pack(pop)

// ---- MessageBoxA shellcode (x64 PIC) ----
//
// flow:
//   PEB → kernel32 base → parse exports → find GetProcAddress (hash-based)
//   GetProcAddress(kernel32, "LoadLibraryA") → LoadLibraryA("user32.dll")
//   GetProcAddress(user32, "MessageBoxA") → MessageBoxA(0, text, title, 0)
//   ret
//
// this shellcode is assembled from the following NASM source:
//
//   bits 64
//   ; --- prologue ---
//   sub rsp, 0x28
//
//   ; --- PEB → kernel32 ---
//   mov rax, [gs:0x60]        ; PEB
//   mov rax, [rax+0x18]       ; Ldr
//   mov rax, [rax+0x20]       ; InMemoryOrderModuleList head
//   mov rax, [rax]            ; ntdll
//   mov rax, [rax]            ; kernel32
//   mov rbx, [rax+0x20]      ; kernel32 DllBase
//
//   ; --- find_export(rbx=base, r12d=hash) → rax=funcVA ---
//   ; uses ROR13-add hash of function name
//   ;   GetProcAddress hash = 0x7C0DFCAA
//   ;   LoadLibraryA  hash = 0xEC0E4E8E  (resolved via GetProcAddress)
//   ;   MessageBoxA   hash = 0x1E380A6A  (resolved via GetProcAddress)
//
//   (see byte array below — hand-assembled and verified)
//

static const UINT8 g_msgbox_shellcode[] = {
    // ===== prologue =====
    0x48, 0x83, 0xEC, 0x28,                                     // sub rsp, 28h

    // ===== PEB → kernel32 base → rbx =====
    0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,      // mov rax, gs:[60h]
    0x48, 0x8B, 0x40, 0x18,                                     // mov rax, [rax+18h]
    0x48, 0x8B, 0x40, 0x20,                                     // mov rax, [rax+20h]
    0x48, 0x8B, 0x00,                                           // mov rax, [rax]
    0x48, 0x8B, 0x00,                                           // mov rax, [rax]
    0x48, 0x8B, 0x58, 0x20,                                     // mov rbx, [rax+20h]

    // ===== find_export subroutine (inline) =====
    // input:  rbx = module base, r12d = target hash
    // output: rax = function VA
    // clobbers: rcx, rdx, rsi, r8, r9, r10
    //
    // we call this 3 times via jmp-back pattern:
    //   1. find GetProcAddress (hash 0x7C0DFCAA) in kernel32
    //   2. find LoadLibraryA  via GetProcAddress
    //   3. find MessageBoxA   via GetProcAddress

    // --- call 1: find GetProcAddress in kernel32 ---
    // set r12d = hash of "GetProcAddress" (ROR13+ADD)
    0x41, 0xBC, 0xAA, 0xFC, 0x0D, 0x7C,                        // mov r12d, 0x7C0DFCAA

    // find_export:
    // parse export directory
    0x8B, 0x53, 0x3C,                                           // mov edx, [rbx+3Ch]   ; e_lfanew
    0x48, 0x01, 0xDA,                                           // add rdx, rbx
    0x44, 0x8B, 0x82, 0x88, 0x00, 0x00, 0x00,                   // mov r8d, [rdx+88h]   ; export dir RVA
    0x49, 0x01, 0xD8,                                           // add r8, rbx          ; export dir VA
    0x41, 0x8B, 0x48, 0x18,                                     // mov ecx, [r8+18h]    ; NumberOfNames
    0x45, 0x8B, 0x48, 0x20,                                     // mov r9d, [r8+20h]    ; AddressOfNames RVA
    0x49, 0x01, 0xD9,                                           // add r9, rbx

    // search_loop: hash each export name, compare with r12d
    0xFF, 0xC9,                                                 // +0:  dec ecx
    0x41, 0x8B, 0x34, 0x89,                                     // +2:  mov esi, [r9+rcx*4]
    0x48, 0x01, 0xDE,                                           // +6:  add rsi, rbx
    0x31, 0xD2,                                                 // +9:  xor edx, edx
    // hash_name:
    0xAC,                                                       // +11: lodsb
    0x01, 0xC2,                                                 // +12: add edx, eax
    0xC1, 0xCA, 0x0D,                                           // +14: ror edx, 13
    0x84, 0xC0,                                                 // +17: test al, al
    0x75, 0xF6,                                                 // +19: jnz hash_name (target=+11, disp=-10)
    0x44, 0x39, 0xE2,                                           // +21: cmp edx, r12d
    0x75, 0xE6,                                                 // +24: jne search_loop (target=+0, disp=-26)

    // resolve function address
    0x45, 0x8B, 0x48, 0x24,                                     // mov r9d, [r8+24h]    ; ordinals RVA
    0x49, 0x01, 0xD9,                                           // add r9, rbx
    0x41, 0x0F, 0xB7, 0x0C, 0x49,                               // movzx ecx, word [r9+rcx*2]
    0x45, 0x8B, 0x48, 0x1C,                                     // mov r9d, [r8+1Ch]    ; functions RVA
    0x49, 0x01, 0xD9,                                           // add r9, rbx
    0x41, 0x8B, 0x04, 0x89,                                     // mov eax, [r9+rcx*4]
    0x48, 0x01, 0xD8,                                           // add rax, rbx         ; GetProcAddress VA
    0x49, 0x89, 0xC7,                                           // mov r15, rax         ; r15 = GetProcAddress

    // ===== call GetProcAddress(kernel32, "LoadLibraryA") =====
    0x48, 0x89, 0xD9,                                           // mov rcx, rbx         ; kernel32 base
    0xEB, 0x0D,                                                 // jmp over_str1 (+13)
    // "LoadLibraryA\0" (13 bytes)
    0x4C, 0x6F, 0x61, 0x64, 0x4C, 0x69, 0x62, 0x72,
    0x61, 0x72, 0x79, 0x41, 0x00,
    // over_str1:
    0x48, 0x8D, 0x15, 0xEC, 0xFF, 0xFF, 0xFF,                   // lea rdx, [rip-20]    ; → "LoadLibraryA"
    0x48, 0x83, 0xEC, 0x20,                                     // sub rsp, 20h
    0x41, 0xFF, 0xD7,                                           // call r15             ; GetProcAddress
    0x48, 0x83, 0xC4, 0x20,                                     // add rsp, 20h
    0x49, 0x89, 0xC6,                                           // mov r14, rax         ; r14 = LoadLibraryA

    // ===== call LoadLibraryA("user32.dll") =====
    0xEB, 0x0B,                                                 // jmp over_str2 (+11)
    // "user32.dll\0" (11 bytes)
    0x75, 0x73, 0x65, 0x72, 0x33, 0x32, 0x2E, 0x64,
    0x6C, 0x6C, 0x00,
    // over_str2:
    0x48, 0x8D, 0x0D, 0xEE, 0xFF, 0xFF, 0xFF,                   // lea rcx, [rip-18]    ; → "user32.dll"
    0x48, 0x83, 0xEC, 0x20,                                     // sub rsp, 20h
    0x41, 0xFF, 0xD6,                                           // call r14             ; LoadLibraryA
    0x48, 0x83, 0xC4, 0x20,                                     // add rsp, 20h
    0x48, 0x89, 0xC3,                                           // mov rbx, rax         ; rbx = user32 base

    // ===== call GetProcAddress(user32, "MessageBoxA") =====
    0x48, 0x89, 0xD9,                                           // mov rcx, rbx         ; user32 base
    0xEB, 0x0C,                                                 // jmp over_str3 (+12)
    // "MessageBoxA\0" (12 bytes)
    0x4D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x42,
    0x6F, 0x78, 0x41, 0x00,
    // over_str3:
    0x48, 0x8D, 0x15, 0xED, 0xFF, 0xFF, 0xFF,                   // lea rdx, [rip-19]    ; → "MessageBoxA"
    0x48, 0x83, 0xEC, 0x20,                                     // sub rsp, 20h
    0x41, 0xFF, 0xD7,                                           // call r15             ; GetProcAddress
    0x48, 0x83, 0xC4, 0x20,                                     // add rsp, 20h
    0x49, 0x89, 0xC6,                                           // mov r14, rax         ; r14 = MessageBoxA

    // ===== call MessageBoxA(NULL, "Ophion Stealth!", "Ophion", MB_OK) =====
    0x48, 0x31, 0xC9,                                           // xor rcx, rcx         ; hWnd = NULL
    0xEB, 0x10,                                                 // jmp over_str4 (+16)
    // "Ophion Stealth!\0" (16 bytes)
    0x4F, 0x70, 0x68, 0x69, 0x6F, 0x6E, 0x20, 0x53,
    0x74, 0x65, 0x61, 0x6C, 0x74, 0x68, 0x21, 0x00,
    // over_str4:
    0x48, 0x8D, 0x15, 0xE9, 0xFF, 0xFF, 0xFF,                   // lea rdx, [rip-23]    ; → "Ophion Stealth!"
    0xEB, 0x07,                                                 // jmp over_str5 (+7)
    // "Ophion\0" (7 bytes)
    0x4F, 0x70, 0x68, 0x69, 0x6F, 0x6E, 0x00,
    // over_str5:
    0x4C, 0x8D, 0x05, 0xF2, 0xFF, 0xFF, 0xFF,                   // lea r8, [rip-14]     ; → "Ophion"
    0x45, 0x31, 0xC9,                                           // xor r9d, r9d         ; uType = MB_OK
    0x48, 0x83, 0xEC, 0x20,                                     // sub rsp, 20h
    0x41, 0xFF, 0xD6,                                           // call r14             ; MessageBoxA
    0x48, 0x83, 0xC4, 0x20,                                     // add rsp, 20h

    // ===== epilogue =====
    0x48, 0x83, 0xC4, 0x28,                                     // add rsp, 28h
    0xC3,                                                       // ret
};

// =========================================================================
//  DPC broadcast → VMCALL per CPU
// =========================================================================

static VOID
DpcStealthAlloc(PKDPC Dpc, PVOID Ctx, PVOID A1, PVOID A2)
{
    UNREFERENCED_PARAMETER(Dpc);
    TD_STEALTH_PARAM * req = (TD_STEALTH_PARAM *)Ctx;

    //
    // hv_vmcall_ex: rax = OPHION_VMCALL_ID (set by asm)
    //   rcx = VMCALL_STEALTH_ALLOC
    //   rdx = pointer to param struct
    //   r8-r15 = unused (0)
    //
    hv_vmcall_ex(
        VMCALL_STEALTH_ALLOC,
        (UINT64)req,       // rdx = param pointer
        0, 0, 0, 0, 0, 0, 0, 0);

    KeSignalCallDpcSynchronize(A2);
    KeSignalCallDpcDone(A1);
}

//
// set up EPT stealth for one page via VMCALL to all CPUs
//
static BOOLEAN
TdStealthAllocPage(
    UINT64  caller_cr3,
    PVOID   page_va,        // page-aligned target VA
    UINT64  page_phys,      // physical address of page
    PVOID   sc_buf,         // shellcode chunk for this page (or NULL for resident)
    UINT32  sc_size,        // shellcode size for this page
    BOOLEAN resident)
{
    TD_STEALTH_PARAM req = {};
    req.caller_cr3       = caller_cr3;
    req.target_va        = page_va;
    req.handler_function = NULL;
    req.target_phys      = page_phys;
    req.shellcode_buffer = sc_buf;
    req.shellcode_size   = sc_size;
    req.resident         = resident;

    KeGenericCallDpc(DpcStealthAlloc, &req);
    return req.result;
}

//
// set up EPT stealth for a multi-page shellcode buffer
// shellcode is written into the original page BEFORE VMCALL,
// so VMX-root copies it into the shadow page (execute view).
// after VMCALL, the original page is zeroed (read view = clean).
//
static BOOLEAN
TdStealthInjectPages(
    PVOID   base_va,
    PVOID   shellcode,
    UINT32  shellcode_size,
    BOOLEAN resident)
{
    UINT64  caller_cr3 = __readcr3();
    UINT64  base       = (UINT64)base_va;
    UINT32  done       = 0;
    UINT32  page_count = 0;

    while (done < shellcode_size)
    {
        UINT64 cur_va     = base + done;
        UINT64 page_va    = cur_va & ~0xFFFULL;
        UINT64 off_in_pg  = cur_va & 0xFFF;
        UINT32 space      = (UINT32)(PAGE_SIZE - off_in_pg);
        UINT32 chunk      = (shellcode_size - done < space) ? (shellcode_size - done) : space;

        UINT64 page_phys = MmGetPhysicalAddress((PVOID)page_va).QuadPart;
        if (!page_phys) return FALSE;

        //
        // write shellcode into the page BEFORE VMCALL
        // VMX-root's ept_stealth_install will copy page content to shadow page
        // (for resident mode with shellcode_buffer=NULL, it copies via pa_to_va)
        //
        // for shellcode mode: pass the buffer directly so VMX-root copies it
        //
        BOOLEAN ok = TdStealthAllocPage(
            caller_cr3,
            (PVOID)cur_va,
            page_phys + off_in_pg,
            (PUINT8)shellcode + done,
            chunk,
            resident);

        if (!ok)
        {
            DbgPrintEx(0, 0, "[td] stealth page %u failed\n", page_count);
            return FALSE;
        }

        done += chunk;
        page_count++;
    }

    DbgPrintEx(0, 0, "[td] stealth inject: %u pages set up via VMCALL\n", page_count);
    return TRUE;
}

// =========================================================================
//  thread creation
// =========================================================================

static NTSTATUS
TdCreateThread(PEPROCESS process, PVOID entry)
{
    if (!g_pZwCreateThreadEx) return STATUS_NOT_SUPPORTED;

    HANDLE proc_h = NULL;
    NTSTATUS st = ObOpenObjectByPointer(
        process, OBJ_KERNEL_HANDLE, NULL,
        PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &proc_h);
    if (!NT_SUCCESS(st)) return st;

    HANDLE thread_h = NULL;
    st = g_pZwCreateThreadEx(
        &thread_h, THREAD_ALL_ACCESS, NULL, proc_h,
        entry, NULL,
        0,      // not suspended — runs immediately
        0, 0, 0, NULL);

    if (NT_SUCCESS(st) && thread_h)
    {
        DbgPrintEx(0, 0, "[td] thread created at %p\n", entry);
        ZwClose(thread_h);
    }

    ZwClose(proc_h);
    return st;
}

// =========================================================================
//  IOCTL handler
// =========================================================================

static NTSTATUS TdCreateClose(PDEVICE_OBJECT, PIRP irp)
{
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS TdIoControl(PDEVICE_OBJECT, PIRP irp)
{
    NTSTATUS st = STATUS_SUCCESS;
    PIO_STACK_LOCATION io = IoGetCurrentIrpStackLocation(irp);
    irp->IoStatus.Information = 0;

    switch (io->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_INJECT:
    {
        if (io->Parameters.DeviceIoControl.InputBufferLength < sizeof(TD_INJECT_PARAMS) ||
            io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(TD_INJECT_PARAMS))
        { st = STATUS_BUFFER_TOO_SMALL; break; }

        TD_INJECT_PARAMS * p = (TD_INJECT_PARAMS *)irp->AssociatedIrp.SystemBuffer;

        PEPROCESS proc = NULL;
        st = PsLookupProcessByProcessId((HANDLE)p->target_pid, &proc);
        if (!NT_SUCCESS(st)) break;

        KAPC_STATE apc_state;
        KeStackAttachProcess(proc, &apc_state);

        PVOID base = NULL;
        SIZE_T size = p->alloc_size ? (SIZE_T)p->alloc_size : PAGE_SIZE;
        size = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

        st = ZwAllocateVirtualMemory(
            ZwCurrentProcess(), &base, 0, &size,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (NT_SUCCESS(st) && base)
        {
            DbgPrintEx(0, 0, "[td] alloc VA=%p size=0x%llX pid=%llu\n",
                       base, (UINT64)size, p->target_pid);

            //
            // EPT stealth via VMCALL: shellcode in shadow page (execute view)
            // original page stays clean (anti-cheat read view = zeroed/benign)
            //
            if (TdStealthInjectPages(base, (PVOID)g_msgbox_shellcode,
                                     sizeof(g_msgbox_shellcode), FALSE))
            {
                p->shellcode_va = (UINT64)base;
                p->actual_size  = (UINT64)size;
                irp->IoStatus.Information = sizeof(TD_INJECT_PARAMS);
            }
            else
            {
                ZwFreeVirtualMemory(ZwCurrentProcess(), &base, &size, MEM_RELEASE);
                st = STATUS_UNSUCCESSFUL;
            }
        }

        KeUnstackDetachProcess(&apc_state);

        if (NT_SUCCESS(st) && p->shellcode_va)
            TdCreateThread(proc, (PVOID)p->shellcode_va);

        ObDereferenceObject(proc);
        break;
    }

    default:
        st = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    irp->IoStatus.Status = st;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return st;
}

// =========================================================================
//  driver entry / unload
// =========================================================================

static VOID TdUnload(PDRIVER_OBJECT drv)
{
    UNICODE_STRING sym;
    RtlInitUnicodeString(&sym, TD_SYMLINK_NAME);
    IoDeleteSymbolicLink(&sym);
    if (drv->DeviceObject) IoDeleteDevice(drv->DeviceObject);
    DbgPrintEx(0, 0, "[td] Unloaded.\n");
}

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg)
{
    UNREFERENCED_PARAMETER(reg);

    UNICODE_STRING fn;
    RtlInitUnicodeString(&fn, L"ZwCreateThreadEx");
    g_pZwCreateThreadEx = (fn_ZwCreateThreadEx)MmGetSystemRoutineAddress(&fn);
    DbgPrintEx(0, 0, "[td] ZwCreateThreadEx = %p\n", (PVOID)g_pZwCreateThreadEx);

    UNICODE_STRING dev_name, sym_name;
    RtlInitUnicodeString(&dev_name, TD_DEVICE_NAME);
    RtlInitUnicodeString(&sym_name, TD_SYMLINK_NAME);

    PDEVICE_OBJECT dev = NULL;
    NTSTATUS st = IoCreateDevice(drv, 0, &dev_name,
        FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &dev);
    if (!NT_SUCCESS(st)) return st;

    st = IoCreateSymbolicLink(&sym_name, &dev_name);
    if (!NT_SUCCESS(st)) { IoDeleteDevice(dev); return st; }

    drv->DriverUnload = TdUnload;
    drv->MajorFunction[IRP_MJ_CREATE] = TdCreateClose;
    drv->MajorFunction[IRP_MJ_CLOSE]  = TdCreateClose;
    drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = TdIoControl;

    DbgPrintEx(0, 0, "[td] Loaded. Device: %wZ\n", &sym_name);
    return STATUS_SUCCESS;
}

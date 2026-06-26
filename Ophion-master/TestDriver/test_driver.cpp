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
#include <ntimage.h>
#include "log.h"

// ---- undocumented PEB structures for user-mode module walk ----

extern "C" NTKERNELAPI PPEB PsGetProcessPeb(PEPROCESS Process);
extern "C" NTSYSAPI NTSTATUS NTAPI ZwProtectVirtualMemory(
    HANDLE ProcessHandle, PVOID * BaseAddress, PSIZE_T RegionSize,
    ULONG NewProtect, PULONG OldProtect);

typedef ULONG (NTAPI * fn_KeResumeThread)(PKTHREAD Thread);
static fn_KeResumeThread g_pKeResumeThread = NULL;

typedef struct _TD_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWCH   Buffer;
} TD_UNICODE_STRING;

typedef struct _TD_LDR_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    TD_UNICODE_STRING FullDllName;
    TD_UNICODE_STRING BaseDllName;
} TD_LDR_ENTRY;

typedef struct _TD_PEB_LDR_DATA {
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
} TD_PEB_LDR_DATA;

// ---- VMCALL interface (must match Ophion hv_types.h) ----

#define VMCALL_STEALTH_ALLOC    0x00000006
#define VMCALL_EPT_HOOK_INJECT  0x00000008

//
// EPT hook inject param — pre-built at PASSIVE_LEVEL, passed to VMX-root.
// must match Ophion's EPT_HOOK_INJECT_PARAM.
//
#pragma pack(push, 8)
typedef struct _TD_HOOK_INJECT_PARAM {
    UINT64  target_va;              // user VA of shellcode entry
    UINT64  target_phys;            // pre-computed PA of target page
    UINT64  handler_va;             // trampoline VA (VMCALL redirects here)
    PVOID   fake_page_buffer;       // kernel buffer: pre-built fake page
    UINT32  hook_size;              // bytes overwritten by VMCALL (from LDE)
    BOOLEAN force_read_access;
    //
    // pre-computed guest PT page info (for fake PT / NX hiding)
    //
    UINT64  pt_page_pfn;            // PFN of guest PT page containing target PTE
    UINT32  pt_pte_index;           // index within PT page (0-511)
    PVOID   pt_page_copy;           // kernel buffer with PT page content (4KB)
    PVOID   pt_page_va;             // system VA of real PT page (hostcr3-mapped)
    volatile LONG installed;
    BOOLEAN result;
    BOOLEAN fake_pt_ok;
    volatile LONG * dbg_pf_counter;
} TD_HOOK_INJECT_PARAM;
#pragma pack(pop)

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
    //
    // pre-computed guest PT info (filled at PASSIVE/DISPATCH level).
    // avoids MmGetVirtualForPhysical (pa_to_va) in VMX-root which deadlocks
    // when KeGenericCallDpc puts all CPUs into VMX-root simultaneously.
    //
    UINT64  pt_page_pfn;        // PFN of guest PT page containing target PTE
    UINT32  pt_pte_index;       // index within PT page (0-511)
    PVOID   pt_page_copy;       // NonPaged buffer with PT page content (4KB)
    PVOID   pt_page_va;         // system VA of real PT page (for MTF resync)
    PVOID   target_page_copy;   // NonPaged buffer with target page content (4KB)
    BOOLEAN pt_precomputed;     // TRUE = caller filled above fields at PASSIVE_LEVEL
    volatile LONG installed;
    BOOLEAN result;
} TD_STEALTH_PARAM;
#pragma pack(pop)

#define PFN_MASK_  0x000FFFFFFFFFF000ULL

//
// walk guest page tables at PASSIVE/DISPATCH level (safe, no VMX-root).
// returns FALSE if the VA is not mapped or uses large pages.
//
static BOOLEAN
TdResolveGuestPT(UINT64 cr3, UINT64 va, UINT64 * out_pt_pfn, UINT32 * out_pte_idx)
{
    PHYSICAL_ADDRESS pa;
    PUINT64 table;

    // PML4
    pa.QuadPart = (LONGLONG)(cr3 & PFN_MASK_);
    table = (PUINT64)MmGetVirtualForPhysical(pa);
    if (!table) return FALSE;
    UINT64 pml4e = table[(va >> 39) & 0x1FF];
    if (!(pml4e & 1)) return FALSE;

    // PDPT
    pa.QuadPart = (LONGLONG)(pml4e & PFN_MASK_);
    table = (PUINT64)MmGetVirtualForPhysical(pa);
    if (!table) return FALSE;
    UINT64 pdpe = table[(va >> 30) & 0x1FF];
    if (!(pdpe & 1) || (pdpe & (1ULL << 7))) return FALSE;  // 1GB page

    // PD
    pa.QuadPart = (LONGLONG)(pdpe & PFN_MASK_);
    table = (PUINT64)MmGetVirtualForPhysical(pa);
    if (!table) return FALSE;
    UINT64 pde = table[(va >> 21) & 0x1FF];
    if (!(pde & 1) || (pde & (1ULL << 7))) return FALSE;  // 2MB page

    *out_pt_pfn  = (pde & PFN_MASK_) >> 12;
    *out_pte_idx = (UINT32)((va >> 12) & 0x1FF);
    return TRUE;
}

// ---- assembly VMCALL (vmcall.asm) ----

extern "C" {
    NTSYSCALLAPI NTSTATUS NTAPI RtlCreateUserThread(
        HANDLE ProcessHandle, PSECURITY_DESCRIPTOR SecurityDescriptor,
        BOOLEAN CreateSuspended, ULONG StackZeroBits,
        SIZE_T StackReserve, SIZE_T StackCommit,
        PVOID StartAddress, PVOID Parameter,
        PHANDLE ThreadHandle, PCLIENT_ID ClientId);

    NTSTATUS hv_vmcall_ex(
        UINT64 vmcall_reason, UINT64 param1, UINT64 param2, UINT64 param3,
        UINT64 param4, UINT64 param5, UINT64 param6,
        UINT64 param7, UINT64 param8, UINT64 param9);

    // simple 4-param vmcall — no r12-r15 push/pop, no stack args.
    // safe for DPC callbacks (doesn't clobber A1/A2 save slots).
    NTSTATUS hv_vmcall_simple(
        UINT64 vmcall_reason, UINT64 param1, UINT64 param2, UINT64 param3);

    NTKERNELAPI VOID    KeGenericCallDpc(PKDEFERRED_ROUTINE, PVOID);
    NTKERNELAPI VOID    KeSignalCallDpcDone(PVOID);
    NTKERNELAPI LOGICAL KeSignalCallDpcSynchronize(PVOID);
}

// ---- undocumented API ----

#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001

typedef NTSTATUS (NTAPI * fn_ZwCreateThreadEx)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE,
    PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);


typedef NTSTATUS (NTAPI * fn_ZwResumeThread)(HANDLE, PULONG);

static fn_ZwCreateThreadEx g_pZwCreateThreadEx = NULL;
static fn_ZwResumeThread   g_pZwResumeThread   = NULL;

// ---- device / IOCTL ----

#define TD_DEVICE_NAME  L"\\Device\\OphionTest"
#define TD_SYMLINK_NAME L"\\DosDevices\\OphionTest"

#define TD_IOCTL_BASE   0x900
#define IOCTL_INJECT    CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EPT_HOOK    CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EPT_UNHOOK  CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EPT_HOOK_R3 CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EPT_UNHOOK_R3 CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 4, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 8)
typedef struct _TD_INJECT_PARAMS {
    UINT64 target_pid;
    UINT64 alloc_size;
    UINT64 trigger_va;      // [in]  R3 function to hook as trigger (0 = auto NtTestAlert)
    UINT64 shellcode_va;    // [out]
    UINT64 actual_size;     // [out]
} TD_INJECT_PARAMS;

//
// R3 EPT hook params — from user-mode app via DeviceIoControl
//
typedef struct _TD_R3_HOOK_PARAMS {
    UINT64 target_pid;          // [in]  target process PID
    UINT64 target_function_va;  // [in]  R3 VA to hook (e.g. NtCreateFile in ntdll)
    UINT64 proxy_function_va;   // [in]  R3 VA of proxy function in target process
    UINT64 hook_type;           // [in]  0=abs jmp, 1=VMCALL, 2=INT3
    UINT64 trampoline_va;       // [out] receives trampoline VA (R3, callable)
    UINT64 status;              // [out] NTSTATUS
} TD_R3_HOOK_PARAMS;

typedef struct _TD_R3_UNHOOK_PARAMS {
    UINT64 target_pid;          // [in]
    UINT64 target_function_va;  // [in]  same VA passed to hook
    UINT64 status;              // [out]
} TD_R3_UNHOOK_PARAMS;
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

// ---- DLL name matching helpers (used by PIC shellcode + gap finder) ----

static const WCHAR g_ntdll_name[] = L"ntdll.dll";
static const WCHAR g_k32_name[]  = L"kernel32.dll";

static BOOLEAN TdMatchDllName(const WCHAR * buf, USHORT buf_len, const WCHAR * target, USHORT target_len)
{
    USHORT i;
    WCHAR c;
    if (buf_len < target_len * sizeof(WCHAR)) return FALSE;
    for (i = 0; i < target_len; i++)
    {
        c = buf[i];
        if (c >= L'A' && c <= L'Z') c += 32;
        if (c != target[i]) return FALSE;
    }
    return TRUE;
}

// ---- PIC shellcode (zero API calls) ----
//
// finds MessageBoxA by PEB walk at BUILD TIME (driver side).
// shellcode itself only calls the pre-resolved function pointer.
// no LoadLibrary, no GetProcAddress, no runtime PEB walk.
//
// patch offset:
//   +6: pMessageBoxA (8 bytes, mov r12 imm64)
//
static const UINT8 g_shellcode_pic[] = {
    // --- prologue ---
    0x48, 0x83, 0xEC, 0x28,                                     // sub rsp, 28h

    // mov r12, pMessageBoxA (patched at offset 6)
    0x49, 0xBC,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,             // [6..13]

    // mov r13, pSleepEx (patched at offset 16)
    0x49, 0xBD,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,             // [16..23]

    // sub rsp, 40h (strings on stack)
    0x48, 0x83, 0xEC, 0x40,                                      // [24..27]

    // --- build "Ophion\0" at [rsp+20h] ---
    0xC7, 0x44, 0x24, 0x20,  0x4F, 0x70, 0x68, 0x69,            // "Ophi"
    0x66, 0xC7, 0x44, 0x24, 0x24,  0x6F, 0x6E,                  // "on"
    0xC6, 0x44, 0x24, 0x26,  0x00,                               // \0

    // --- build "Stealth OK\0" at [rsp+30h] ---
    0xC7, 0x44, 0x24, 0x30,  0x53, 0x74, 0x65, 0x61,            // "Stea"
    0xC7, 0x44, 0x24, 0x34,  0x6C, 0x74, 0x68, 0x20,            // "lth "
    0x66, 0xC7, 0x44, 0x24, 0x38,  0x4F, 0x4B,                  // "OK"
    0xC6, 0x44, 0x24, 0x3A,  0x00,                               // \0

    // --- loop_start (offset 76) ---
    // --- MessageBoxA(NULL, "Stealth OK", "Ophion", 0) ---
    0x48, 0x31, 0xC9,                                            // xor rcx, rcx
    0x48, 0x8D, 0x54, 0x24, 0x30,                                // lea rdx, [rsp+30h]
    0x4C, 0x8D, 0x44, 0x24, 0x20,                                // lea r8, [rsp+20h]
    0x45, 0x31, 0xC9,                                            // xor r9d, r9d
    0x41, 0xFF, 0xD4,                                            // call r12  (MessageBoxA)

    // --- SleepEx(3000, FALSE) ---
    0xB9, 0xB8, 0x0B, 0x00, 0x00,                               // mov ecx, 3000
    0x31, 0xD2,                                                   // xor edx, edx  (FALSE)
    0x41, 0xFF, 0xD5,                                            // call r13  (SleepEx)

    // --- jmp loop_start ---
    0xEB, 0xE1,                                                   // jmp -31 (back to loop_start at offset 76)
};

#define PIC_PATCH_MESSAGEBOX   6       // offset of pMessageBoxA imm64
#define PIC_PATCH_SLEEPEX      16      // offset of pSleepEx imm64

static const WCHAR g_user32_name[]  = L"user32.dll";
static const WCHAR g_kernel32_name[] = L"kernel32.dll";

//
// build PIC shellcode: resolve user32!MessageBoxA + kernel32!SleepEx
// via PEB walk + export table.
// zero runtime API calls — all resolution done here at PASSIVE_LEVEL.
// must be called while attached to the target process.
//
static BOOLEAN
TdBuildShellcodePIC(PVOID buf, SIZE_T buf_size)
{
    if (buf_size < sizeof(g_shellcode_pic)) return FALSE;

    RtlZeroMemory(buf, buf_size);
    RtlCopyMemory(buf, g_shellcode_pic, sizeof(g_shellcode_pic));

    PPEB peb = PsGetProcessPeb(PsGetCurrentProcess());
    if (!peb) return FALSE;

    UINT64 pMsgBox = 0;
    UINT64 pSleepEx = 0;
    PVOID user32_base = NULL;
    PVOID kernel32_base = NULL;

    __try {
        TD_PEB_LDR_DATA * ldr = *(TD_PEB_LDR_DATA **)((PUINT8)peb + 0x18);
        if (!ldr) return FALSE;

        PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
        PLIST_ENTRY cur = head->Flink;

        // find user32.dll and kernel32.dll in PEB module list
        while (cur != head)
        {
            TD_LDR_ENTRY * e = CONTAINING_RECORD(cur, TD_LDR_ENTRY, InMemoryOrderLinks);
            if (e->BaseDllName.Buffer)
            {
                if (!user32_base &&
                    TdMatchDllName(e->BaseDllName.Buffer, e->BaseDllName.Length, g_user32_name, 10))
                    user32_base = e->DllBase;

                if (!kernel32_base &&
                    TdMatchDllName(e->BaseDllName.Buffer, e->BaseDllName.Length, g_kernel32_name, 12))
                    kernel32_base = e->DllBase;
            }
            if (user32_base && kernel32_base) break;
            cur = cur->Flink;
        }

        if (!user32_base)
        {
            HYPERPLATFORM_LOG_ERROR("[td] PIC: user32.dll not found in target process");
            return FALSE;
        }
        if (!kernel32_base)
        {
            HYPERPLATFORM_LOG_ERROR("[td] PIC: kernel32.dll not found in target process");
            return FALSE;
        }

        // walk user32 export table to find MessageBoxA
        {
            PIMAGE_DOS_HEADER dos_h = (PIMAGE_DOS_HEADER)user32_base;
            PIMAGE_NT_HEADERS64 nt_h = (PIMAGE_NT_HEADERS64)((PUINT8)user32_base + dos_h->e_lfanew);
            ULONG exp_rva = nt_h->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            PIMAGE_EXPORT_DIRECTORY exp_d = (PIMAGE_EXPORT_DIRECTORY)((PUINT8)user32_base + exp_rva);
            PULONG names_arr = (PULONG)((PUINT8)user32_base + exp_d->AddressOfNames);
            PUSHORT ords_arr = (PUSHORT)((PUINT8)user32_base + exp_d->AddressOfNameOrdinals);
            PULONG funcs_arr = (PULONG)((PUINT8)user32_base + exp_d->AddressOfFunctions);

            for (ULONG i = 0; i < exp_d->NumberOfNames; i++)
            {
                const char * fn = (const char *)((PUINT8)user32_base + names_arr[i]);
                if (fn[0] == 'M' && fn[1] == 'e' && fn[2] == 's' && fn[3] == 's' &&
                    fn[4] == 'a' && fn[5] == 'g' && fn[6] == 'e' && fn[7] == 'B' &&
                    fn[8] == 'o' && fn[9] == 'x' && fn[10] == 'A' && fn[11] == '\0')
                {
                    pMsgBox = (UINT64)user32_base + funcs_arr[ords_arr[i]];
                    break;
                }
            }
        }

        // walk kernel32 export table to find SleepEx
        {
            PIMAGE_DOS_HEADER dos_h = (PIMAGE_DOS_HEADER)kernel32_base;
            PIMAGE_NT_HEADERS64 nt_h = (PIMAGE_NT_HEADERS64)((PUINT8)kernel32_base + dos_h->e_lfanew);
            ULONG exp_rva = nt_h->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            PIMAGE_EXPORT_DIRECTORY exp_d = (PIMAGE_EXPORT_DIRECTORY)((PUINT8)kernel32_base + exp_rva);
            PULONG names_arr = (PULONG)((PUINT8)kernel32_base + exp_d->AddressOfNames);
            PUSHORT ords_arr = (PUSHORT)((PUINT8)kernel32_base + exp_d->AddressOfNameOrdinals);
            PULONG funcs_arr = (PULONG)((PUINT8)kernel32_base + exp_d->AddressOfFunctions);

            for (ULONG i = 0; i < exp_d->NumberOfNames; i++)
            {
                const char * fn = (const char *)((PUINT8)kernel32_base + names_arr[i]);
                if (fn[0] == 'S' && fn[1] == 'l' && fn[2] == 'e' && fn[3] == 'e' &&
                    fn[4] == 'p' && fn[5] == 'E' && fn[6] == 'x' && fn[7] == '\0')
                {
                    pSleepEx = (UINT64)kernel32_base + funcs_arr[ords_arr[i]];
                    break;
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        HYPERPLATFORM_LOG_ERROR("[td] PIC: exception walking PEB/exports");
        return FALSE;
    }

    if (!pMsgBox)
    {
        HYPERPLATFORM_LOG_ERROR("[td] PIC: MessageBoxA not found in user32 exports");
        return FALSE;
    }
    if (!pSleepEx)
    {
        HYPERPLATFORM_LOG_ERROR("[td] PIC: SleepEx not found in kernel32 exports");
        return FALSE;
    }

    // patch addresses
    *(PUINT64)((PUINT8)buf + PIC_PATCH_MESSAGEBOX) = pMsgBox;
    *(PUINT64)((PUINT8)buf + PIC_PATCH_SLEEPEX)    = pSleepEx;

    HYPERPLATFORM_LOG_INFO("[td] PIC: user32=%p MessageBoxA=%llx kernel32=%p SleepEx=%llx size=%u (resident loop)",
               user32_base, pMsgBox, kernel32_base, pSleepEx, (UINT32)sizeof(g_shellcode_pic));
    return TRUE;
}

// =========================================================================
//  DPC broadcast → VMCALL per CPU
// =========================================================================

//
// set up EPT stealth for one page — single VMCALL from current CPU.
// HV internally loops all g_vcpu[i].ept_page_table to split + set PTE.
// NO KeGenericCallDpc — avoids 0x101 CLOCK_WATCHDOG when a CPU is
// stuck in VMX-root (Ophion HV pre-existing bug).
//
static BOOLEAN
TdStealthAllocPage(
    UINT64  caller_cr3,
    PVOID   page_va,        // page-aligned target VA
    UINT64  page_phys,      // physical address of page
    PVOID   sc_buf,         // shellcode chunk for this page (or NULL for resident)
    UINT32  sc_size,        // shellcode size for this page
    BOOLEAN resident,
    UINT64  pt_pfn,         // pre-computed PT page PFN (from TdResolveGuestPT)
    UINT32  pt_idx)         // pre-computed PTE index within PT page
{
    TD_STEALTH_PARAM req = {};
    req.caller_cr3       = caller_cr3;
    req.target_va        = page_va;
    req.handler_function = NULL;
    req.target_phys      = page_phys;
    req.shellcode_buffer = sc_buf;
    req.shellcode_size   = sc_size;
    req.resident         = resident;
    req.pt_page_pfn      = pt_pfn;
    req.pt_pte_index     = pt_idx;

    //
    // copy PT page and target page content into NonPaged kernel buffers.
    // VMX-root accesses these buffers (always valid under any CR3).
    // MmGetVirtualForPhysical returns process-relative VAs that are
    // invalid under system CR3 in VMX-root — so we copy the content here.
    //
    PVOID pt_buf  = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'htpS');
    PVOID tgt_buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'htpS');
    if (!pt_buf || !tgt_buf)
    {
        if (pt_buf)  ExFreePoolWithTag(pt_buf,  'htpS');
        if (tgt_buf) ExFreePoolWithTag(tgt_buf, 'htpS');
        return FALSE;
    }

    {
        PHYSICAL_ADDRESS pa;
        pa.QuadPart = (LONGLONG)(pt_pfn << 12);
        PVOID pt_va = MmGetVirtualForPhysical(pa);
        if (pt_va)
            RtlCopyMemory(pt_buf, pt_va, PAGE_SIZE);
        else
            RtlZeroMemory(pt_buf, PAGE_SIZE);

        pa.QuadPart = (LONGLONG)(page_phys & ~0xFFFULL);
        PVOID tgt_va = MmGetVirtualForPhysical(pa);
        if (tgt_va)
            RtlCopyMemory(tgt_buf, tgt_va, PAGE_SIZE);
        else
            RtlZeroMemory(tgt_buf, PAGE_SIZE);

        req.pt_page_va = pt_va;  // system VA for VMX-root MTF resync (NULL if unavailable)
    }

    req.pt_page_copy     = pt_buf;
    req.target_page_copy = tgt_buf;
    req.pt_precomputed   = TRUE;

    // DPC broadcast — every CPU does VMCALL, each splits its own EPT.
    // same pattern as EPT hook's KeGenericCallDpc.
    KeGenericCallDpc([](PKDPC, PVOID Ctx, PVOID A1, PVOID A2) {
        hv_vmcall_simple(VMCALL_STEALTH_ALLOC, (UINT64)Ctx, 0, 0);
        KeSignalCallDpcSynchronize(A2);
        KeSignalCallDpcDone(A1);
    }, &req);

    ExFreePoolWithTag(pt_buf,  'htpS');
    ExFreePoolWithTag(tgt_buf, 'htpS');
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

        //
        // page already has content from TdBuildShellcodePage — no need to touch.
        // (touching would overwrite first byte of shellcode with 0)
        // MmGetPhysicalAddress works because the page was already committed+written.
        //

        UINT64 page_phys = MmGetPhysicalAddress((PVOID)page_va).QuadPart;
        if (!page_phys)
        {
            HYPERPLATFORM_LOG_ERROR("[td] stealth page %u: MmGetPhysicalAddress=0 for VA=%p",
                       page_count, (PVOID)page_va);
            return FALSE;
        }

        //
        // pre-compute guest PT page info at PASSIVE/DISPATCH level (safe).
        // this avoids calling pa_to_va (MmGetVirtualForPhysical) in VMX-root
        // which deadlocks when KeGenericCallDpc puts all CPUs into VMX-root
        // and another CPU holds an OS internal lock.
        //
        UINT64 pt_pfn = 0;
        UINT32 pt_idx = 0;
        if (!TdResolveGuestPT(caller_cr3, page_va, &pt_pfn, &pt_idx))
        {
            HYPERPLATFORM_LOG_ERROR("[td] stealth page %u: PT walk failed for VA=%p",
                       page_count, (PVOID)page_va);
            return FALSE;
        }

        //
        // NX bit in real PTE is NOT cleared — Windows' MiAgeWorkingSet
        // can restore it at any time. the fake/exec PT pages handle NX hiding.
        //

        //
        // shellcode mode: pass the buffer directly so VMX-root copies it
        //
        BOOLEAN ok = TdStealthAllocPage(
            caller_cr3,
            (PVOID)cur_va,
            page_phys + off_in_pg,
            (PUINT8)shellcode + done,
            chunk,
            resident,
            pt_pfn,
            pt_idx);

        if (!ok)
        {
            HYPERPLATFORM_LOG_ERROR("[td] stealth page %u failed", page_count);
            return FALSE;
        }

        done += chunk;
        page_count++;
    }

    HYPERPLATFORM_LOG_INFO("[td] stealth inject: %u pages set up via VMCALL", page_count);
    return TRUE;
}

// =========================================================================
//  EPT Hook: NtCreateFile
// =========================================================================

#define VMCALL_EPT_HOOK     0x00000003
#define VMCALL_EPT_UNHOOK   0x00000004

//
// original NtCreateFile pointer (set by hook install, used by proxy)
//
typedef NTSTATUS (NTAPI * fn_NtCreateFile)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
    PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);

static fn_NtCreateFile g_orig_NtCreateFile = NULL;
static PVOID           g_hooked_target     = NULL;
static volatile LONG   g_hook_log_count    = 0;

//
// proxy function — called instead of NtCreateFile when EPT hook is active.
// logs the file path via DbgPrint, then calls original via trampoline.
//
static NTSTATUS NTAPI
HookedNtCreateFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength)
{
    //
    // log every 100th call to avoid flooding DbgPrint
    //
    LONG count = _InterlockedIncrement(&g_hook_log_count);
    if ((count % 100) == 1 && ObjectAttributes && ObjectAttributes->ObjectName)
    {
        HYPERPLATFORM_LOG_INFO_SAFE("[td-hook] NtCreateFile #%d: %wZ",
                   count, ObjectAttributes->ObjectName);
    }

    //
    // call original via trampoline
    //
    if (g_orig_NtCreateFile)
    {
        return g_orig_NtCreateFile(
            FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
            AllocationSize, FileAttributes, ShareAccess,
            CreateDisposition, CreateOptions, EaBuffer, EaLength);
    }

    return STATUS_UNSUCCESSFUL;
}

//
// DPC callback: each CPU issues VMCALL to install EPT hook
//
static VOID
DpcEptHook(PKDPC Dpc, PVOID Ctx, PVOID A1, PVOID A2)
{
    UNREFERENCED_PARAMETER(Dpc);

    struct _EPT_HOOK_CTX {
        PVOID   target;
        PVOID   proxy;
        PVOID * origin;
        UINT64  caller_cr3;
        UINT32  hook_type;
        NTSTATUS result;
    } * ctx = (struct _EPT_HOOK_CTX *)Ctx;

    //
    // hv_vmcall_ex: rax = OPHION_VMCALL_ID
    //   rcx = VMCALL_EPT_HOOK
    //   rdx = target_function
    //   r8  = proxy_function
    //   r9  = &origin_function
    //   r10 = caller_cr3
    //   r11 = hook_type
    //   r12 = target_cr3 (0 = R0 hook)
    //   r13 = user_trampoline (NULL = kernel pool)
    //   r14 = user_trampoline_pa (0)
    //
    ctx->result = hv_vmcall_ex(
        VMCALL_EPT_HOOK,
        (UINT64)ctx->target,
        (UINT64)ctx->proxy,
        (UINT64)ctx->origin,
        ctx->caller_cr3,
        (UINT64)ctx->hook_type,
        0,   // target_cr3 = 0 (R0 hook, all processes)
        0,   // user_trampoline = NULL (use kernel pool)
        0,   // user_trampoline_pa = 0
        0);

    KeSignalCallDpcSynchronize(A2);
    KeSignalCallDpcDone(A1);
}

static VOID
DpcEptUnhook(PKDPC Dpc, PVOID Ctx, PVOID A1, PVOID A2)
{
    UNREFERENCED_PARAMETER(Dpc);

    struct _EPT_UNHOOK_CTX {
        PVOID    target;
        UINT64   caller_cr3;
        NTSTATUS result;
    } * ctx = (struct _EPT_UNHOOK_CTX *)Ctx;

    ctx->result = hv_vmcall_ex(
        VMCALL_EPT_UNHOOK,
        (UINT64)ctx->target,
        0, 0,
        ctx->caller_cr3,
        0, 0, 0, 0, 0);

    KeSignalCallDpcSynchronize(A2);
    KeSignalCallDpcDone(A1);
}

static NTSTATUS
TdEptHookNtCreateFile(VOID)
{
    UNICODE_STRING fn_name;
    RtlInitUnicodeString(&fn_name, L"NtCreateFile");
    PVOID target = MmGetSystemRoutineAddress(&fn_name);
    if (!target)
    {
        HYPERPLATFORM_LOG_ERROR("[td] NtCreateFile not found");
        return STATUS_NOT_FOUND;
    }

    HYPERPLATFORM_LOG_INFO("[td] NtCreateFile = %p, proxy = %p", target, (PVOID)HookedNtCreateFile);

    struct {
        PVOID   target;
        PVOID   proxy;
        PVOID * origin;
        UINT64  caller_cr3;
        UINT32  hook_type;
        NTSTATUS result;
    } ctx = {};

    ctx.target     = target;
    ctx.proxy      = (PVOID)HookedNtCreateFile;
    ctx.origin     = (PVOID *)&g_orig_NtCreateFile;
    ctx.caller_cr3 = __readcr3();
    ctx.hook_type  = 0;   // absolute jump (14 bytes)

    KeGenericCallDpc(DpcEptHook, &ctx);

    if (NT_SUCCESS(ctx.result))
    {
        g_hooked_target = target;
        HYPERPLATFORM_LOG_INFO("[td] EPT hook installed! trampoline = %p", (PVOID)g_orig_NtCreateFile);
    }
    else
    {
        HYPERPLATFORM_LOG_ERROR("[td] EPT hook FAILED: 0x%08X", ctx.result);
    }

    return ctx.result;
}

static NTSTATUS
TdEptUnhookNtCreateFile(VOID)
{
    if (!g_hooked_target)
        return STATUS_NOT_FOUND;

    struct {
        PVOID    target;
        UINT64   caller_cr3;
        NTSTATUS result;
    } ctx = {};

    ctx.target     = g_hooked_target;
    ctx.caller_cr3 = __readcr3();

    KeGenericCallDpc(DpcEptUnhook, &ctx);

    if (NT_SUCCESS(ctx.result))
    {
        HYPERPLATFORM_LOG_INFO("[td] EPT hook removed. total calls logged: %d", g_hook_log_count);
        g_hooked_target = NULL;
        g_orig_NtCreateFile = NULL;
        g_hook_log_count = 0;
    }
    else
    {
        HYPERPLATFORM_LOG_ERROR("[td] EPT unhook FAILED: 0x%08X", ctx.result);
    }

    return ctx.result;
}

// =========================================================================
//  R3 EPT Hook — per-process, user-mode trampoline, MDL-locked
// =========================================================================

//
// tracking for active R3 hooks (simple array, max 16 concurrent R3 hooks)
//
#define MAX_R3_HOOKS 16

typedef struct _R3_HOOK_ENTRY {
    BOOLEAN     active;
    UINT64      target_pid;
    PVOID       target_va;
    PVOID       trampoline_va;      // R3 VA in target process
    SIZE_T      trampoline_size;
    PMDL        target_mdl;         // locks target page in physical memory
    UINT64      target_cr3;         // target process CR3 (PFN only)
} R3_HOOK_ENTRY;

static R3_HOOK_ENTRY g_r3_hooks[MAX_R3_HOOKS] = {};

static R3_HOOK_ENTRY *
R3HookFindFree(VOID)
{
    for (int i = 0; i < MAX_R3_HOOKS; i++)
        if (!g_r3_hooks[i].active) return &g_r3_hooks[i];
    return NULL;
}

static R3_HOOK_ENTRY *
R3HookFind(UINT64 pid, PVOID target_va)
{
    for (int i = 0; i < MAX_R3_HOOKS; i++)
        if (g_r3_hooks[i].active && g_r3_hooks[i].target_pid == pid &&
            g_r3_hooks[i].target_va == target_va)
            return &g_r3_hooks[i];
    return NULL;
}

//
// DPC callback for R3 EPT hook install
//
typedef struct _R3_HOOK_DPC_CTX {
    PVOID    target;
    PVOID    proxy;
    PVOID *  origin;
    UINT64   caller_cr3;
    UINT32   hook_type;
    UINT64   target_cr3;
    PVOID    user_trampoline;
    UINT64   user_trampoline_pa;
    UINT64   flags;             // bit 0 = force_read_access (shellcode self-read)
    NTSTATUS result;
} R3_HOOK_DPC_CTX;

static VOID
DpcEptHookR3(PKDPC Dpc, PVOID Ctx, PVOID A1, PVOID A2)
{
    UNREFERENCED_PARAMETER(Dpc);
    R3_HOOK_DPC_CTX * ctx = (R3_HOOK_DPC_CTX *)Ctx;

    ctx->result = hv_vmcall_ex(
        VMCALL_EPT_HOOK,
        (UINT64)ctx->target,
        (UINT64)ctx->proxy,
        (UINT64)ctx->origin,
        ctx->caller_cr3,
        (UINT64)ctx->hook_type,
        ctx->target_cr3,
        (UINT64)ctx->user_trampoline,
        ctx->user_trampoline_pa,
        ctx->flags);

    KeSignalCallDpcSynchronize(A2);
    KeSignalCallDpcDone(A1);
}

//
// install R3 EPT hook on a function in a target process.
// must be called at PASSIVE_LEVEL.
//
static NTSTATUS
TdEptHookR3(
    UINT64  target_pid,
    PVOID   target_va,
    PVOID   proxy_va,
    UINT32  hook_type,
    PVOID * out_trampoline)
{
    if (!target_va) return STATUS_INVALID_PARAMETER;

    R3_HOOK_ENTRY * entry = R3HookFindFree();
    if (!entry)
    {
        HYPERPLATFORM_LOG_ERROR("[td-r3] no free R3 hook slots");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // look up target process
    PEPROCESS proc = NULL;
    NTSTATUS st = PsLookupProcessByProcessId((HANDLE)target_pid, &proc);
    if (!NT_SUCCESS(st)) return st;

    KAPC_STATE apc;
    KeStackAttachProcess(proc, &apc);

    UINT64 target_cr3 = __readcr3();
    UINT64 caller_cr3 = target_cr3;

    //
    // 1. lock target page in physical memory via MDL
    //
    PVOID page_va = (PVOID)((UINT64)target_va & ~0xFFFULL);
    PMDL mdl = IoAllocateMdl(page_va, PAGE_SIZE, FALSE, FALSE, NULL);
    if (!mdl)
    {
        KeUnstackDetachProcess(&apc);
        ObDereferenceObject(proc);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {
        MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(mdl);
        KeUnstackDetachProcess(&apc);
        ObDereferenceObject(proc);
        HYPERPLATFORM_LOG_ERROR("[td-r3] MmProbeAndLockPages failed for %p", target_va);
        return STATUS_ACCESS_VIOLATION;
    }

    //
    // 2. allocate R3 executable trampoline in target process
    //
    PVOID tramp_va = NULL;
    SIZE_T tramp_size = PAGE_SIZE;
    st = ZwAllocateVirtualMemory(
        ZwCurrentProcess(), &tramp_va, 0, &tramp_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!NT_SUCCESS(st) || !tramp_va)
    {
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        KeUnstackDetachProcess(&apc);
        ObDereferenceObject(proc);
        HYPERPLATFORM_LOG_ERROR("[td-r3] trampoline alloc failed: 0x%08X", st);
        return st;
    }

    RtlZeroMemory(tramp_va, tramp_size);
    UINT64 tramp_pa = MmGetPhysicalAddress(tramp_va).QuadPart;

    HYPERPLATFORM_LOG_INFO("[td-r3] target=%p proxy=%p tramp=%p(PA=%llx) cr3=%llx pid=%llu type=%u",
               target_va, proxy_va, tramp_va, tramp_pa, target_cr3, target_pid, hook_type);

    //
    // 3. DPC broadcast VMCALL to install hook on all CPUs
    //
    PVOID origin_ptr = NULL;

    R3_HOOK_DPC_CTX ctx = {};
    ctx.target              = target_va;
    ctx.proxy               = proxy_va;
    ctx.origin              = &origin_ptr;
    ctx.caller_cr3          = caller_cr3;
    ctx.hook_type           = hook_type;
    ctx.target_cr3          = target_cr3;
    ctx.user_trampoline     = tramp_va;
    ctx.user_trampoline_pa  = tramp_pa;

    KeGenericCallDpc(DpcEptHookR3, &ctx);

    KeUnstackDetachProcess(&apc);

    if (NT_SUCCESS(ctx.result))
    {
        entry->active           = TRUE;
        entry->target_pid       = target_pid;
        entry->target_va        = target_va;
        entry->trampoline_va    = tramp_va;
        entry->trampoline_size  = tramp_size;
        entry->target_mdl       = mdl;
        entry->target_cr3       = target_cr3;

        if (out_trampoline)
            *out_trampoline = origin_ptr;

        HYPERPLATFORM_LOG_INFO("[td-r3] R3 EPT hook installed! trampoline=%p", origin_ptr);
    }
    else
    {
        //
        // failed — clean up: free trampoline, unlock MDL
        //
        KeStackAttachProcess(proc, &apc);
        ZwFreeVirtualMemory(ZwCurrentProcess(), &tramp_va, &tramp_size, MEM_RELEASE);
        KeUnstackDetachProcess(&apc);

        MmUnlockPages(mdl);
        IoFreeMdl(mdl);

        HYPERPLATFORM_LOG_ERROR("[td-r3] R3 EPT hook FAILED: 0x%08X", ctx.result);
    }

    ObDereferenceObject(proc);
    return ctx.result;
}

//
// remove R3 EPT hook and clean up resources
//
static NTSTATUS
TdEptUnhookR3(UINT64 target_pid, PVOID target_va)
{
    R3_HOOK_ENTRY * entry = R3HookFind(target_pid, target_va);
    if (!entry)
    {
        HYPERPLATFORM_LOG_WARN("[td-r3] hook entry not found for pid=%llu va=%p", target_pid, target_va);
        return STATUS_NOT_FOUND;
    }

    //
    // 1. unhook via VMCALL (DPC broadcast)
    //
    PEPROCESS proc = NULL;
    NTSTATUS st = PsLookupProcessByProcessId((HANDLE)target_pid, &proc);
    if (!NT_SUCCESS(st)) return st;

    KAPC_STATE apc;
    KeStackAttachProcess(proc, &apc);

    struct {
        PVOID    target;
        UINT64   caller_cr3;
        NTSTATUS result;
    } unhook_ctx = {};
    unhook_ctx.target     = target_va;
    unhook_ctx.caller_cr3 = __readcr3();

    KeGenericCallDpc(DpcEptUnhook, &unhook_ctx);

    //
    // 2. free trampoline in target process
    //
    if (entry->trampoline_va)
    {
        SIZE_T sz = entry->trampoline_size;
        ZwFreeVirtualMemory(ZwCurrentProcess(), &entry->trampoline_va, &sz, MEM_RELEASE);
    }

    KeUnstackDetachProcess(&apc);

    //
    // 3. unlock MDL
    //
    if (entry->target_mdl)
    {
        MmUnlockPages(entry->target_mdl);
        IoFreeMdl(entry->target_mdl);
    }

    HYPERPLATFORM_LOG_INFO("[td-r3] R3 hook removed: pid=%llu va=%p", target_pid, target_va);

    RtlZeroMemory(entry, sizeof(*entry));
    ObDereferenceObject(proc);
    return unhook_ctx.result;
}

//
// unhook all active R3 hooks (called from unload)
//
static VOID
TdEptUnhookAllR3(VOID)
{
    for (int i = 0; i < MAX_R3_HOOKS; i++)
    {
        if (!g_r3_hooks[i].active) continue;

        //
        // for inject hooks (target_mdl == NULL): the target process may have
        // already exited. don't attach — just VMCALL unhook by VA + clear entry.
        // EPT unhook only needs the VA to find the PFN in the hooked_pages list.
        // the VMCALL runs under system CR3, which is fine for EPT-only operations.
        //
        // for real R3 hooks (target_mdl != NULL): use the full unhook path.
        //
        if (g_r3_hooks[i].target_mdl == NULL)
        {
            // inject hook — lightweight unhook (no attach needed)
            PEPROCESS proc = NULL;
            NTSTATUS st = PsLookupProcessByProcessId(
                (HANDLE)g_r3_hooks[i].target_pid, &proc);

            if (NT_SUCCESS(st))
            {
                // process still alive — attach to resolve VA → PA for unhook
                KAPC_STATE apc;
                KeStackAttachProcess(proc, &apc);

                struct { PVOID target; UINT64 caller_cr3; NTSTATUS result; } ctx = {};
                ctx.target     = g_r3_hooks[i].target_va;
                ctx.caller_cr3 = __readcr3();
                KeGenericCallDpc(DpcEptUnhook, &ctx);

                KeUnstackDetachProcess(&apc);
                ObDereferenceObject(proc);
            }
            // else: process dead — EPT pages are orphaned but harmless.
            // the PFN won't be reused for anything meaningful until
            // ept_unhook_all() on HV unload restores all PTEs to RWX.

            RtlZeroMemory(&g_r3_hooks[i], sizeof(g_r3_hooks[i]));
        }
        else
        {
            // real R3 hook — full cleanup
            TdEptUnhookR3(g_r3_hooks[i].target_pid, g_r3_hooks[i].target_va);
        }
    }
}

// =========================================================================
//  thread creation
// =========================================================================

static NTSTATUS
TdCreateThread(PEPROCESS process, PVOID entry)
{
    //
    // try function pointer (resolved at init), fallback to manual syscall stub
    //
    if (g_pZwCreateThreadEx)
    {
        HANDLE proc_h = NULL;
        NTSTATUS st = ObOpenObjectByPointer(
            process, OBJ_KERNEL_HANDLE, NULL,
            PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &proc_h);
        if (!NT_SUCCESS(st)) return st;

        //
        // create thread NOT suspended — runs immediately.
        // all CPUs have EPT split (DPC broadcast), no affinity pinning needed.
        // NtResumeThread/ZwResumeThread may not be exported by ntoskrnl,
        // so avoid suspend+resume pattern entirely.
        //
        HANDLE thread_h = NULL;
        st = g_pZwCreateThreadEx(
            &thread_h, THREAD_ALL_ACCESS, NULL, proc_h,
            entry, NULL,
            0,      // flags = 0: not suspended
            0, 0, 0, NULL);

        if (NT_SUCCESS(st) && thread_h)
            ZwClose(thread_h);
        ZwClose(proc_h);
        return st;
    }

    //
    // fallback: attach to process, use RtlCreateUserThread
    // create SUSPENDED → pin to install CPU → resume
    //
    KAPC_STATE apc;
    KeStackAttachProcess(process, &apc);

    HANDLE thread_h = NULL;
    CLIENT_ID cid = {};
    //
    // pin CURRENT kernel thread to install CPU first.
    // then create user thread (not suspended) — it inherits scheduling
    // affinity from the current processor context.
    //
    ULONG cpu = KeGetCurrentProcessorNumberEx(NULL);
    KAFFINITY old_affinity = KeSetSystemAffinityThreadEx((KAFFINITY)1 << cpu);

    NTSTATUS st = RtlCreateUserThread(
        ZwCurrentProcess(),
        NULL, FALSE, 0, 0, 0,
        entry, NULL, &thread_h, &cid);

    KeRevertToUserAffinityThreadEx(old_affinity);
    KeUnstackDetachProcess(&apc);

    if (NT_SUCCESS(st) && thread_h)
    {
        // also set the thread's own affinity to install CPU
        KAFFINITY mask = (KAFFINITY)1 << cpu;
        ZwSetInformationThread(thread_h, ThreadAffinityMask, &mask, sizeof(mask));
        ZwClose(thread_h);
    }

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

// =========================================================================
//  DLL gap finder — find unused page-aligned gap in an image's VA range.
//
//  walks PE section headers to find alignment padding between sections
//  or after the last section. returns a committed page of zeros that
//  belongs to the DLL's VAD (MEM_IMAGE). no new allocation, no new VAD.
//
//  MUST be called while attached to the target process.
// =========================================================================

//
// find section tail padding in a DLL — unused zero bytes at the end of
// a section's last page. no full-page gap needed.
//
// returns page-aligned VA of the page containing padding.
// *out_offset = offset within page where padding starts (shellcode goes here).
// *out_avail  = available bytes from offset to end of page.
//
static PVOID
TdFindSectionPadding(PVOID image_base, SIZE_T min_size, ULONG * out_offset, ULONG * out_avail)
{
    PIMAGE_DOS_HEADER       dos;
    PIMAGE_NT_HEADERS64     nt;
    PIMAGE_SECTION_HEADER   sections, best_sec;
    ULONG num_sections, i, sec_end_raw, page_offset, avail, best_avail;
    PVOID page_va;

    if (!image_base || !out_offset || !out_avail) return NULL;

    best_sec = NULL;
    best_avail = 0;

    __try {
        dos = (PIMAGE_DOS_HEADER)image_base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

        nt = (PIMAGE_NT_HEADERS64)((PUINT8)image_base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

        num_sections = nt->FileHeader.NumberOfSections;
        sections = IMAGE_FIRST_SECTION(nt);

        //
        // find section with most tail padding on its last page.
        // prefer executable sections (.text) — shellcode blends in better.
        //
        for (i = 0; i < num_sections; i++)
        {
            sec_end_raw = sections[i].VirtualAddress + sections[i].Misc.VirtualSize;
            page_offset = sec_end_raw & (PAGE_SIZE - 1);

            // skip if section ends exactly on page boundary (no padding)
            if (page_offset == 0) continue;

            avail = PAGE_SIZE - page_offset;
            if (avail < min_size) continue;

            // prefer executable section, or largest padding
            if (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
            {
                if (!best_sec || !(best_sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) ||
                    avail > best_avail)
                {
                    best_sec = &sections[i];
                    best_avail = avail;
                }
            }
            else if (!best_sec || (!(best_sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
                     avail > best_avail))
            {
                best_sec = &sections[i];
                best_avail = avail;
            }
        }

        if (best_sec)
        {
            sec_end_raw = best_sec->VirtualAddress + best_sec->Misc.VirtualSize;
            page_offset = sec_end_raw & (PAGE_SIZE - 1);
            page_va = (PUINT8)image_base + (sec_end_raw & ~(PAGE_SIZE - 1));

            *out_offset = page_offset;
            *out_avail  = PAGE_SIZE - page_offset;

            HYPERPLATFORM_LOG_INFO("[td-gap] section padding: page=%p offset=0x%X avail=0x%X (section %.8s)",
                       page_va, page_offset, *out_avail, best_sec->Name);
            return page_va;
        }

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        HYPERPLATFORM_LOG_WARN("[td-gap] exception walking PE headers");
    }

    return NULL;
}

//
// find a DLL gap in the target process. tries ntdll first (always loaded,
// large image), then kernel32. must be called while attached.
//
static PVOID
TdFindGapInProcess(SIZE_T min_size, ULONG * out_offset, ULONG * out_avail)
{
    PPEB peb;
    TD_PEB_LDR_DATA * ldr;
    PLIST_ENTRY head, cur;
    TD_LDR_ENTRY * e;
    PVOID gap;

    peb = PsGetProcessPeb(PsGetCurrentProcess());
    if (!peb) return NULL;

    __try {
        ldr = *(TD_PEB_LDR_DATA **)((PUINT8)peb + 0x18);
        if (!ldr) return NULL;

        head = &ldr->InMemoryOrderModuleList;

        // first pass: try ntdll.dll
        cur = head->Flink;
        while (cur != head)
        {
            e = CONTAINING_RECORD(cur, TD_LDR_ENTRY, InMemoryOrderLinks);
            if (e->BaseDllName.Buffer &&
                TdMatchDllName(e->BaseDllName.Buffer, e->BaseDllName.Length, g_ntdll_name, 9))
            {
                gap = TdFindSectionPadding(e->DllBase, min_size, out_offset, out_avail);
                if (gap) return gap;
                break;
            }
            cur = cur->Flink;
        }

        // second pass: try kernel32.dll
        cur = head->Flink;
        while (cur != head)
        {
            e = CONTAINING_RECORD(cur, TD_LDR_ENTRY, InMemoryOrderLinks);
            if (e->BaseDllName.Buffer &&
                TdMatchDllName(e->BaseDllName.Buffer, e->BaseDllName.Length, g_k32_name, 12))
            {
                gap = TdFindSectionPadding(e->DllBase, min_size, out_offset, out_avail);
                if (gap) return gap;
                break;
            }
            cur = cur->Flink;
        }

        // third pass: any DLL with a gap
        cur = head->Flink;
        while (cur != head)
        {
            e = CONTAINING_RECORD(cur, TD_LDR_ENTRY, InMemoryOrderLinks);
            if (e->DllBase && e->SizeOfImage > PAGE_SIZE)
            {
                gap = TdFindSectionPadding(e->DllBase, min_size, out_offset, out_avail);
                if (gap) return gap;
            }
            cur = cur->Flink;
        }

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        HYPERPLATFORM_LOG_WARN("[td-gap] exception walking PEB");
    }

    return NULL;
}

// =========================================================================
//  PE Manual Mapper — kernel-side DLL loading, zero R3 API calls
//
//  flow:
//    1. injector reads DLL file → sends raw bytes via IOCTL_INJECT_DLL
//    2. driver attaches to target process
//    3. ZwAllocateVirtualMemory(PAGE_READWRITE) for image
//    4. copy sections, apply relocations, resolve imports (PEB walk)
//    5. build DllMain stub at image base (overwrites DOS header)
//    6. clear PE signature from header
//    7. ZwProtectVirtualMemory → PAGE_EXECUTE_READ for executable sections
//    8. EPT hook NtTestAlert → DllMain stub (oneshot, per-process CR3 filter)
//    9. create thread at NtTestAlert → DllMain runs → thread exits
//
//  result: DLL is loaded without LoadLibrary, no module list entry,
//  no load image notification, no file access from target process.
// =========================================================================

#define IOCTL_INJECT_DLL CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 5, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 8)
typedef struct _TD_INJECT_DLL_PARAMS {
    UINT64 target_pid;
    UINT32 dll_offset;     // offset of DLL data within this buffer (after header)
    UINT32 dll_size;       // size of raw DLL file
    UINT64 out_base;       // [out] mapped image base
    UINT64 out_entry;      // [out] DllMain VA
    UINT64 out_size;       // [out] image size
} TD_INJECT_DLL_PARAMS;
#pragma pack(pop)

//
// inline case-insensitive ASCII compare (kernel-safe, no runtime dependency)
//
static __forceinline BOOLEAN
TdAsciiEqualI(const char * a, const char * b)
{
    while (*a && *b)
    {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return FALSE;
        a++; b++;
    }
    return (*a == *b);
}

//
// TdFindModuleBaseA — find loaded module by ASCII name via PEB walk.
// walks PEB → Ldr → InMemoryOrderModuleList. compares BaseDllName
// (Unicode) with the given ASCII name (case-insensitive).
// must be called while attached to the target process.
//
static PVOID
TdFindModuleBaseA(const char * name_ascii)
{
    PPEB peb = PsGetProcessPeb(PsGetCurrentProcess());
    if (!peb) return NULL;

    // compute length of ASCII name
    USHORT name_len = 0;
    const char * p = name_ascii;
    while (*p) { name_len++; p++; }

    // check if name has ".dll" extension already
    BOOLEAN has_ext = FALSE;
    if (name_len >= 4)
    {
        const char * ext = name_ascii + name_len - 4;
        if ((ext[0] == '.' || ext[0] == '.') &&
            (ext[1] == 'd' || ext[1] == 'D') &&
            (ext[2] == 'l' || ext[2] == 'L') &&
            (ext[3] == 'l' || ext[3] == 'L'))
            has_ext = TRUE;
    }

    __try {
        TD_PEB_LDR_DATA * ldr = *(TD_PEB_LDR_DATA **)((PUINT8)peb + 0x18);
        if (!ldr) return NULL;

        PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
        PLIST_ENTRY cur = head->Flink;

        while (cur != head)
        {
            TD_LDR_ENTRY * e = CONTAINING_RECORD(cur, TD_LDR_ENTRY, InMemoryOrderLinks);
            if (e->BaseDllName.Buffer && e->BaseDllName.Length > 0)
            {
                USHORT wchar_count = e->BaseDllName.Length / sizeof(WCHAR);
                const WCHAR * wbuf = e->BaseDllName.Buffer;

                // compare Unicode BaseDllName with ASCII name
                BOOLEAN match = FALSE;

                if (has_ext)
                {
                    // exact match (with extension)
                    if (wchar_count == name_len)
                    {
                        match = TRUE;
                        for (USHORT i = 0; i < name_len; i++)
                        {
                            WCHAR wc = wbuf[i];
                            if (wc >= L'A' && wc <= L'Z') wc += 32;
                            char ac = name_ascii[i];
                            if (ac >= 'A' && ac <= 'Z') ac += 32;
                            if (wc != (WCHAR)ac) { match = FALSE; break; }
                        }
                    }
                }
                else
                {
                    // match without extension: BaseDllName could be "foo.dll"
                    // name_ascii is "foo" — compare first name_len chars,
                    // then check remaining is ".dll"
                    if (wchar_count == name_len + 4)
                    {
                        match = TRUE;
                        for (USHORT i = 0; i < name_len; i++)
                        {
                            WCHAR wc = wbuf[i];
                            if (wc >= L'A' && wc <= L'Z') wc += 32;
                            char ac = name_ascii[i];
                            if (ac >= 'A' && ac <= 'Z') ac += 32;
                            if (wc != (WCHAR)ac) { match = FALSE; break; }
                        }
                        if (match)
                        {
                            WCHAR c0 = wbuf[name_len];
                            WCHAR c1 = wbuf[name_len + 1]; if (c1 >= L'A' && c1 <= L'Z') c1 += 32;
                            WCHAR c2 = wbuf[name_len + 2]; if (c2 >= L'A' && c2 <= L'Z') c2 += 32;
                            WCHAR c3 = wbuf[name_len + 3]; if (c3 >= L'A' && c3 <= L'Z') c3 += 32;
                            if (c0 != L'.' || c1 != L'd' || c2 != L'l' || c3 != L'l')
                                match = FALSE;
                        }
                    }
                    // also try exact match (no extension on module name)
                    if (!match && wchar_count == name_len)
                    {
                        match = TRUE;
                        for (USHORT i = 0; i < name_len; i++)
                        {
                            WCHAR wc = wbuf[i];
                            if (wc >= L'A' && wc <= L'Z') wc += 32;
                            char ac = name_ascii[i];
                            if (ac >= 'A' && ac <= 'Z') ac += 32;
                            if (wc != (WCHAR)ac) { match = FALSE; break; }
                        }
                    }
                }

                if (match && e->DllBase)
                    return e->DllBase;
            }
            cur = cur->Flink;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        HYPERPLATFORM_LOG_WARN("[td-map] exception in TdFindModuleBaseA(\"%s\")", name_ascii);
    }

    return NULL;
}

//
// TdFindExportByName — find export by name from a module's export table.
// walks PE export directory. returns function VA. skips forwarded exports
// (returns NULL for forwards).
//
static PVOID
TdFindExportByName(PVOID module_base, const char * func_name)
{
    if (!module_base || !func_name) return NULL;

    __try {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module_base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((PUINT8)module_base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

        ULONG exp_rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        ULONG exp_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        if (!exp_rva) return NULL;

        PIMAGE_EXPORT_DIRECTORY exp_dir = (PIMAGE_EXPORT_DIRECTORY)((PUINT8)module_base + exp_rva);
        PULONG  names = (PULONG)((PUINT8)module_base + exp_dir->AddressOfNames);
        PUSHORT ords  = (PUSHORT)((PUINT8)module_base + exp_dir->AddressOfNameOrdinals);
        PULONG  funcs = (PULONG)((PUINT8)module_base + exp_dir->AddressOfFunctions);

        for (ULONG i = 0; i < exp_dir->NumberOfNames; i++)
        {
            const char * fn = (const char *)((PUINT8)module_base + names[i]);
            if (TdAsciiEqualI(fn, func_name))
            {
                ULONG func_rva = funcs[ords[i]];

                // check for forwarded export (RVA points inside export directory)
                if (func_rva >= exp_rva && func_rva < exp_rva + exp_size)
                    return NULL;  // forwarded — skip

                return (PUINT8)module_base + func_rva;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        HYPERPLATFORM_LOG_WARN("[td-map] exception in TdFindExportByName");
    }

    return NULL;
}

//
// TdFindExportByOrdinal — find export by ordinal from a module's export table.
//
static PVOID
TdFindExportByOrdinal(PVOID module_base, USHORT ordinal)
{
    if (!module_base) return NULL;

    __try {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module_base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((PUINT8)module_base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

        ULONG exp_rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        ULONG exp_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        if (!exp_rva) return NULL;

        PIMAGE_EXPORT_DIRECTORY exp_dir = (PIMAGE_EXPORT_DIRECTORY)((PUINT8)module_base + exp_rva);
        PULONG funcs = (PULONG)((PUINT8)module_base + exp_dir->AddressOfFunctions);

        ULONG index = ordinal - (USHORT)exp_dir->Base;
        if (index >= exp_dir->NumberOfFunctions)
            return NULL;

        ULONG func_rva = funcs[index];

        // check for forwarded export
        if (func_rva >= exp_rva && func_rva < exp_rva + exp_size)
            return NULL;

        return (PUINT8)module_base + func_rva;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        HYPERPLATFORM_LOG_WARN("[td-map] exception in TdFindExportByOrdinal");
    }

    return NULL;
}

//
// TdPeCopySections — copy PE headers and sections from raw DLL to mapped image.
//
static BOOLEAN
TdPeCopySections(PVOID mapped_base, PUINT8 raw_dll, SIZE_T raw_size)
{
    __try {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)raw_dll;
        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(raw_dll + dos->e_lfanew);

        // copy headers
        ULONG hdr_size = nt->OptionalHeader.SizeOfHeaders;
        if (hdr_size > raw_size) hdr_size = (ULONG)raw_size;
        RtlCopyMemory(mapped_base, raw_dll, hdr_size);

        // copy each section
        PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
        USHORT num_sec = nt->FileHeader.NumberOfSections;

        for (USHORT i = 0; i < num_sec; i++)
        {
            PVOID dst = (PUINT8)mapped_base + sec[i].VirtualAddress;

            if (sec[i].SizeOfRawData == 0)
            {
                // BSS — zero the virtual range
                ULONG virt_sz = sec[i].Misc.VirtualSize;
                if (virt_sz > 0)
                    RtlZeroMemory(dst, virt_sz);
                continue;
            }

            // validate raw data bounds
            if (sec[i].PointerToRawData + sec[i].SizeOfRawData > raw_size)
            {
                HYPERPLATFORM_LOG_WARN("[td-map] section %u raw data exceeds file size", i);
                continue;
            }

            PVOID src = raw_dll + sec[i].PointerToRawData;
            ULONG copy_size = sec[i].SizeOfRawData;

            RtlCopyMemory(dst, src, copy_size);

            // if VirtualSize > SizeOfRawData, zero the remainder
            if (sec[i].Misc.VirtualSize > copy_size)
                RtlZeroMemory((PUINT8)dst + copy_size, sec[i].Misc.VirtualSize - copy_size);
        }

        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        HYPERPLATFORM_LOG_ERROR("[td-map] exception in TdPeCopySections");
        return FALSE;
    }
}

//
// TdPeRelocate — apply base relocations.
// returns TRUE on success, FALSE if no relocation table and delta != 0.
//
static BOOLEAN
TdPeRelocate(PVOID mapped_base, PUINT8 raw_dll, UINT64 delta)
{
    if (delta == 0) return TRUE;

    __try {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)raw_dll;
        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(raw_dll + dos->e_lfanew);

        ULONG reloc_rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        ULONG reloc_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

        if (!reloc_rva || !reloc_size)
        {
            // no relocation table — check if DLL has RELOCS_STRIPPED
            if (nt->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
            {
                HYPERPLATFORM_LOG_ERROR("[td-map] no reloc table and delta != 0");
                return FALSE;
            }
            // relocation directory empty but delta != 0 and not stripped — fail
            HYPERPLATFORM_LOG_ERROR("[td-map] no reloc directory, delta=0x%llX", delta);
            return FALSE;
        }

        PIMAGE_BASE_RELOCATION block = (PIMAGE_BASE_RELOCATION)((PUINT8)mapped_base + reloc_rva);
        PIMAGE_BASE_RELOCATION end   = (PIMAGE_BASE_RELOCATION)((PUINT8)block + reloc_size);

        while (block < end && block->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
        {
            ULONG count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
            PUSHORT entries = (PUSHORT)((PUINT8)block + sizeof(IMAGE_BASE_RELOCATION));

            for (ULONG i = 0; i < count; i++)
            {
                USHORT type   = entries[i] >> 12;
                USHORT offset = entries[i] & 0x0FFF;
                PUINT8 target = (PUINT8)mapped_base + block->VirtualAddress + offset;

                switch (type)
                {
                case IMAGE_REL_BASED_ABSOLUTE:
                    // padding — skip
                    break;

                case IMAGE_REL_BASED_DIR64:
                    *(PUINT64)target += delta;
                    break;

                case IMAGE_REL_BASED_HIGHLOW:
                    *(PUINT32)target += (UINT32)delta;
                    break;

                default:
                    HYPERPLATFORM_LOG_WARN("[td-map] unsupported reloc type %u", type);
                    break;
                }
            }

            block = (PIMAGE_BASE_RELOCATION)((PUINT8)block + block->SizeOfBlock);
        }

        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        HYPERPLATFORM_LOG_ERROR("[td-map] exception in TdPeRelocate");
        return FALSE;
    }
}

//
// TdPeResolveImports — resolve imports manually via PEB walk.
// must be called while attached to the target process.
//
static BOOLEAN
TdPeResolveImports(PVOID mapped_base)
{
    __try {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mapped_base;
        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((PUINT8)mapped_base + dos->e_lfanew);

        ULONG imp_rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        ULONG imp_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

        if (!imp_rva || !imp_size)
        {
            HYPERPLATFORM_LOG_INFO("[td-map] no import directory — nothing to resolve");
            return TRUE;
        }

        PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)((PUINT8)mapped_base + imp_rva);

        while (imp->Name)
        {
            const char * dll_name = (const char *)((PUINT8)mapped_base + imp->Name);
            PVOID mod_base = TdFindModuleBaseA(dll_name);

            if (!mod_base)
            {
                HYPERPLATFORM_LOG_ERROR("[td-map] import DLL not found: %s", dll_name);
                imp++;
                continue;
            }

            HYPERPLATFORM_LOG_INFO("[td-map] resolving imports from %s (base=%p)", dll_name, mod_base);

            // OriginalFirstThunk = hint/name table, FirstThunk = IAT
            PIMAGE_THUNK_DATA64 oft = (PIMAGE_THUNK_DATA64)((PUINT8)mapped_base +
                (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
            PIMAGE_THUNK_DATA64 ft  = (PIMAGE_THUNK_DATA64)((PUINT8)mapped_base + imp->FirstThunk);

            while (oft->u1.AddressOfData)
            {
                PVOID resolved = NULL;

                if (oft->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                {
                    USHORT ordinal = (USHORT)(oft->u1.Ordinal & 0xFFFF);
                    resolved = TdFindExportByOrdinal(mod_base, ordinal);
                    if (!resolved)
                        HYPERPLATFORM_LOG_WARN("[td-map] unresolved import: %s!#%u", dll_name, ordinal);
                }
                else
                {
                    PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)((PUINT8)mapped_base + oft->u1.AddressOfData);
                    resolved = TdFindExportByName(mod_base, (const char *)ibn->Name);
                    if (!resolved)
                        HYPERPLATFORM_LOG_WARN("[td-map] unresolved import: %s!%s", dll_name, ibn->Name);
                }

                if (resolved)
                    ft->u1.Function = (UINT64)resolved;

                oft++;
                ft++;
            }

            imp++;
        }

        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        HYPERPLATFORM_LOG_ERROR("[td-map] exception in TdPeResolveImports");
        return FALSE;
    }
}

//
// TdBuildDllMainStub — build a small x64 stub that calls DllMain(base, DLL_PROCESS_ATTACH, NULL).
// placed at image base (overwrites DOS header). returns stub size.
//
// stub:
//   sub rsp, 28h
//   mov rcx, IMAGE_BASE
//   mov edx, 1              ; DLL_PROCESS_ATTACH
//   xor r8d, r8d            ; NULL
//   mov rax, ENTRY_POINT
//   call rax
//   add rsp, 28h
//   xor eax, eax
//   ret
//
static UINT32
TdBuildDllMainStub(PVOID stub_addr, UINT64 image_base, UINT64 entry_point)
{
    PUINT8 s = (PUINT8)stub_addr;
    UINT32 off = 0;

    // sub rsp, 28h
    s[off++] = 0x48; s[off++] = 0x83; s[off++] = 0xEC; s[off++] = 0x28;

    // mov rcx, IMAGE_BASE (imm64)
    s[off++] = 0x48; s[off++] = 0xB9;
    *(PUINT64)(s + off) = image_base; off += 8;

    // mov edx, 1
    s[off++] = 0xBA; s[off++] = 0x01; s[off++] = 0x00; s[off++] = 0x00; s[off++] = 0x00;

    // xor r8d, r8d
    s[off++] = 0x45; s[off++] = 0x31; s[off++] = 0xC0;

    // mov rax, ENTRY_POINT (imm64)
    s[off++] = 0x48; s[off++] = 0xB8;
    *(PUINT64)(s + off) = entry_point; off += 8;

    // call rax
    s[off++] = 0xFF; s[off++] = 0xD0;

    // add rsp, 28h
    s[off++] = 0x48; s[off++] = 0x83; s[off++] = 0xC4; s[off++] = 0x28;

    // xor eax, eax
    s[off++] = 0x31; s[off++] = 0xC0;

    // ret
    s[off++] = 0xC3;

    return off;
}

//
// TdManualMapInProcess — main manual map function.
// must be called while attached to the target process.
//
// parameters:
//   proc       — PEPROCESS (already attached)
//   raw_dll    — raw DLL file bytes (kernel buffer)
//   dll_size   — size of raw DLL
//   out_base   — receives mapped image base (user VA)
//   out_entry  — receives DllMain VA (user VA)
//
static NTSTATUS
TdManualMapInProcess(
    PEPROCESS proc,
    PUINT8    raw_dll,
    SIZE_T    dll_size,
    PVOID *   out_base,
    PVOID *   out_entry)
{
    UNREFERENCED_PARAMETER(proc);

    if (!raw_dll || dll_size < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64))
        return STATUS_INVALID_PARAMETER;

    __try {
        // 1. validate PE
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)raw_dll;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            HYPERPLATFORM_LOG_ERROR("[td-map] invalid DOS signature");
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(raw_dll + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
        {
            HYPERPLATFORM_LOG_ERROR("[td-map] invalid PE signature");
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        {
            HYPERPLATFORM_LOG_ERROR("[td-map] not AMD64 (machine=0x%04X)", nt->FileHeader.Machine);
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        if (!(nt->FileHeader.Characteristics & IMAGE_FILE_DLL))
        {
            HYPERPLATFORM_LOG_WARN("[td-map] image is not a DLL (characteristics=0x%04X)", nt->FileHeader.Characteristics);
        }

        // 2. get image size
        SIZE_T image_size = nt->OptionalHeader.SizeOfImage;
        if (image_size == 0 || image_size > 256 * 1024 * 1024)
        {
            HYPERPLATFORM_LOG_ERROR("[td-map] invalid SizeOfImage: 0x%llX", (UINT64)image_size);
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        // 3. allocate PAGE_READWRITE in target process (system chooses base)
        PVOID base = NULL;
        NTSTATUS st = ZwAllocateVirtualMemory(
            ZwCurrentProcess(), &base, 0, &image_size,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (!NT_SUCCESS(st) || !base)
        {
            HYPERPLATFORM_LOG_ERROR("[td-map] ZwAllocateVirtualMemory failed: 0x%08X", st);
            return st;
        }

        HYPERPLATFORM_LOG_INFO("[td-map] allocated image: base=%p size=0x%llX (preferred=0x%llX)",
                   base, (UINT64)image_size, nt->OptionalHeader.ImageBase);

        // 4. copy sections
        if (!TdPeCopySections(base, raw_dll, dll_size))
        {
            HYPERPLATFORM_LOG_ERROR("[td-map] TdPeCopySections failed");
            ZwFreeVirtualMemory(ZwCurrentProcess(), &base, &image_size, MEM_RELEASE);
            return STATUS_UNSUCCESSFUL;
        }

        // 5. apply relocations
        UINT64 delta = (UINT64)base - nt->OptionalHeader.ImageBase;
        if (!TdPeRelocate(base, raw_dll, delta))
        {
            HYPERPLATFORM_LOG_ERROR("[td-map] TdPeRelocate failed (delta=0x%llX)", delta);
            ZwFreeVirtualMemory(ZwCurrentProcess(), &base, &image_size, MEM_RELEASE);
            return STATUS_UNSUCCESSFUL;
        }

        // 6. resolve imports (requires PEB walk — must be attached)
        if (!TdPeResolveImports(base))
        {
            HYPERPLATFORM_LOG_WARN("[td-map] TdPeResolveImports had errors (continuing)");
        }

        // 7. build DllMain stub at base+0 (overwrites DOS header)
        PVOID entry = NULL;
        if (nt->OptionalHeader.AddressOfEntryPoint)
        {
            UINT64 entry_point_va = (UINT64)base + nt->OptionalHeader.AddressOfEntryPoint;
            UINT32 stub_size = TdBuildDllMainStub(base, (UINT64)base, entry_point_va);

            HYPERPLATFORM_LOG_INFO("[td-map] DllMain stub: base=%p entry=0x%llX stub_size=%u",
                       base, entry_point_va, stub_size);

            // 8. zero from stub end to SizeOfHeaders (clear remaining PE header data)
            ULONG hdr_size = nt->OptionalHeader.SizeOfHeaders;
            if (stub_size < hdr_size)
                RtlZeroMemory((PUINT8)base + stub_size, hdr_size - stub_size);

            entry = base;  // stub is at base+0
        }
        else
        {
            HYPERPLATFORM_LOG_WARN("[td-map] no entry point in DLL");
            // zero the entire header area
            RtlZeroMemory(base, nt->OptionalHeader.SizeOfHeaders);
            entry = NULL;
        }

        // set output before we lose access to nt headers (they're overwritten)
        *out_base  = base;
        *out_entry = entry;

        // 9. change protection for executable sections
        // re-parse the mapped image headers (we need section headers which are
        // after the optional header, so they survive the stub overwrite at offset 0)
        {
            // use the RAW dll headers to get section info (mapped headers partially overwritten)
            PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
            USHORT num_sec = nt->FileHeader.NumberOfSections;

            for (USHORT i = 0; i < num_sec; i++)
            {
                if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
                {
                    PVOID sec_base = (PUINT8)base + sec[i].VirtualAddress;
                    SIZE_T sec_size = sec[i].Misc.VirtualSize;
                    if (sec_size == 0) continue;

                    // round up to page
                    sec_size = (sec_size + 0xFFF) & ~(SIZE_T)0xFFF;

                    ULONG old_prot = 0;
                    st = ZwProtectVirtualMemory(
                        ZwCurrentProcess(), &sec_base, &sec_size,
                        PAGE_EXECUTE_READ, &old_prot);

                    if (NT_SUCCESS(st))
                        HYPERPLATFORM_LOG_INFO("[td-map] section %u (%.8s) → PAGE_EXECUTE_READ", i, sec[i].Name);
                    else
                        HYPERPLATFORM_LOG_WARN("[td-map] section %u protect failed: 0x%08X", i, st);
                }
            }

            // header page (contains our stub) → PAGE_EXECUTE_READ
            if (entry)
            {
                PVOID hdr_base = base;
                SIZE_T hdr_prot_size = PAGE_SIZE;
                ULONG old_prot = 0;
                st = ZwProtectVirtualMemory(
                    ZwCurrentProcess(), &hdr_base, &hdr_prot_size,
                    PAGE_EXECUTE_READ, &old_prot);

                if (NT_SUCCESS(st))
                    HYPERPLATFORM_LOG_INFO("[td-map] header page → PAGE_EXECUTE_READ");
                else
                    HYPERPLATFORM_LOG_WARN("[td-map] header page protect failed: 0x%08X", st);
            }
        }

        HYPERPLATFORM_LOG_INFO("[td-map] manual map complete: base=%p entry=%p", base, entry);
        return STATUS_SUCCESS;

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        HYPERPLATFORM_LOG_ERROR("[td-map] exception in TdManualMapInProcess");
        return STATUS_UNSUCCESSFUL;
    }
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
        //
        // EPT hook-based shellcode injection — ALL pre-built at PASSIVE_LEVEL.
        // VMX-root only does EPT manipulation, NEVER touches user VA (SMAP safe).
        //
        // flow:
        //   1. alloc PAGE_READWRITE in target (NX=1 in PTE, clean VAD)
        //   2. build shellcode, copy to kernel buffer, patch VMCALL at entry
        //   3. build trampoline at PASSIVE_LEVEL: [saved bytes] + [abs jmp back]
        //   4. zero original page (COW may change PA), walk PT AFTER zero
        //   5. copy PT page to buffer, force NX=0 in buffer (NOT real PTE)
        //   6. VMCALL_EPT_HOOK_INJECT: EPT split + fake PT(NX=1) + exec PT(NX=0)
        //   7. create thread → #PF(NX) → HV swaps to exec PT → TLB(NX=0) → executes
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
        // try section tail padding first — shellcode goes into the zero-padded
        // tail of a section's last page. no new allocation, no new VAD.
        // original page content preserved (real DLL code stays in front).
        //
        PVOID base = TdFindGapInProcess(sizeof(g_shellcode_pic) + 32, &gap_offset, &gap_avail);
        if (base)
        {
            HYPERPLATFORM_LOG_INFO("[td] inject: section padding VA=%p+0x%X avail=0x%X pid=%llu",
                       base, gap_offset, gap_avail, p->target_pid);
        }

        if (!base)
        {
            //
            // no gap found — refuse to inject. never allocate new memory
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
        // gap mode:  copy original page (preserving DLL code) → write shellcode at gap_offset
        // fallback:  page starts empty → write shellcode at offset 0
        // original page is NOT zeroed in gap mode — DLL code stays intact.
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
        // the shared DLL page PA is used by ALL processes — EPT hooking
        // the shared PA would affect every process.
        //
        // direct PTE manipulation: set Write bit in PTE → write byte → COW.
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
                        // PT → PTE
                        cow_pa.QuadPart = (LONGLONG)((*pde & 0x000FFFFFFFFFF000ULL) + ((cow_va >> 12) & 0x1FF) * 8);
                        PUINT64 pte = (PUINT64)MmGetVirtualForPhysical(cow_pa);
                        if (pte && (*pte & 1))
                        {
                            // set Write bit, write, restore
                            UINT64 orig_pte = *pte;
                            *pte = orig_pte | (1ULL << 1);  // set W bit
                            __invlpg((PVOID)cow_va);         // flush TLB for this VA

                            // write to padding → triggers COW
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
        // gap mode: original page untouched — DLL code + zero padding stays

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
        // HV intercepts VMCALL → set RIP = base+0xF00 → trampoline → jmp back.
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
        // NEVER clear NX in real PTE — Windows' MiAgeWorkingSet restores it.
        // instead: copy PT page to kernel buffer, force NX=0 in the COPY.
        // VMX-root builds exec PT from this copy (NX=0), fake PT gets NX=1.
        //
        UINT64 pt_pfn = 0;
        UINT32 pt_idx = 0;
        PVOID  pt_page_buf = NULL;

        PVOID pt_real_va = NULL;  // system VA of real PT page (for VMX-root resync)

        //
        // DISABLED fake PT for gap mode — the #PF + MTF single-step conflicts
        // with the VMCALL at shellcode entry (MTF fires before VMCALL executes,
        // restoring fake PT NX=1, causing infinite #PF loop).
        //
        // gap mode uses EPT X=0 path instead: EPT violation → shadow → VMCALL.
        // PTE NX bit is already 0 (PAGE_EXECUTE_READ .text section), no fake PT needed.
        //
        // TODO: fix #PF handler to not arm MTF for inject hook pages, then re-enable.
        //
        //
        // fake PT disabled for gap mode — the #PF + MTF single-step conflicts
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
        inj_req.force_read_access = FALSE;  // execute-only: reads → original page (zeros)
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
            // EPT binds to the zeroed page's PA. reads → zeros. execute → fake page.

            HYPERPLATFORM_LOG_INFO("[td] inject: EPT hook OK, fake_pt=%s",
                       inj_req.fake_pt_ok ? "YES" : "NO");

            // track for cleanup (no MDL — page is one-shot inject, not persistent)
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
        // gap address is NOT in CFG bitmap — can't create thread there directly.
        // instead: EPT hook a legit function → redirect to entry_va (gap shellcode).
        // thread entry = trigger function (in CFG bitmap) → EPT hook → shellcode.
        //
        // NtYieldExecution: cold function, rarely monitored by anti-cheat.
        // takes no params, returns immediately — perfect as thread entry stub.
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
        // --- step 8: EPT hook trigger → entry_va (single VMCALL, CPU 0) ---
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
        // trigger hook only on CPU 0's EPT → thread MUST run on CPU 0.
        // SUSPENDED → set affinity → resume.
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

                        if (g_pZwResumeThread)
                        {
                            ULONG prev = 0;
                            g_pZwResumeThread(thr_h, &prev);
                        }
                        else if (g_pKeResumeThread)
                        {
                            PETHREAD thr_obj = NULL;
                            if (NT_SUCCESS(ObReferenceObjectByHandle(thr_h, THREAD_ALL_ACCESS,
                                    *PsThreadType, KernelMode, (PVOID *)&thr_obj, NULL)))
                            {
                                g_pKeResumeThread((PKTHREAD)thr_obj);
                                ObDereferenceObject(thr_obj);
                            }
                        }
                        HYPERPLATFORM_LOG_INFO("[td] inject: thread SUSPENDED+CPU0+RESUMED trigger=%p", trigger_fn);
                        cleanup_thr_h = thr_h;  // keep for async cleanup (don't close yet)
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
        // --- step 10: async cleanup — unhook trigger ASAP, inject stays resident ---
        //
        // trigger hook only needed for first thread creation → shellcode entry.
        // once thread is running, unhook trigger immediately to minimize
        // EPT violation exposure on NtYieldExecution.
        // inject page EPT stealth stays permanently — shellcode runs forever.
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

                        // short delay — let thread start executing (trigger fires once)
                        LARGE_INTEGER delay;
                        delay.QuadPart = -5LL * 10000000LL;  // 5 sec
                        KeDelayExecutionThread(KernelMode, FALSE, &delay);

                        // thread handle kept open but not waited on (thread runs forever)
                        ZwClose(c->thread_handle);

                        HYPERPLATFORM_LOG_INFO("[td] cleanup: unhooking trigger, inject stays resident");

                        // unhook trigger only — inject page stays
                        PEPROCESS proc2 = NULL;
                        if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)c->target_pid, &proc2)))
                        {
                            KAPC_STATE apc2;
                            KeStackAttachProcess(proc2, &apc2);

                            KAFFINITY old = KeSetSystemAffinityThreadEx((KAFFINITY)1);

                            // unhook trigger (NtYieldExecution) — no longer needed
                            hv_vmcall_ex(VMCALL_EPT_UNHOOK,
                                (UINT64)c->trigger_fn, 0, 0,
                                c->target_cr3, 0, 0, 0, 0, 0);

                            // inject page EPT stealth KEPT — shellcode runs permanently
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
                ZwClose(cleanup_thr_h);
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
        // manual-map DLL injection — zero R3 API calls.
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
            // resolve trigger from ntdll (NtYieldExecution preferred, cold function)
            //
            PVOID trigger_fn = NULL;
            {
                static const char * trigger_candidates[] = {
                    "NtYieldExecution", "RtlSetCurrentTransaction", "NtTestAlert", NULL
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
            // EPT hook trigger → stub (oneshot, per-process CR3 filter)
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
            // create thread at trigger → EPT hook → DllMain stub
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

                            if (g_pZwResumeThread)
                            {
                                ULONG prev = 0;
                                g_pZwResumeThread(thr_h, &prev);
                            }
                            else if (g_pKeResumeThread)
                            {
                                PETHREAD thr_obj = NULL;
                                if (NT_SUCCESS(ObReferenceObjectByHandle(thr_h, THREAD_ALL_ACCESS,
                                        *PsThreadType, KernelMode, (PVOID *)&thr_obj, NULL)))
                                {
                                    g_pKeResumeThread((PKTHREAD)thr_obj);
                                    ObDereferenceObject(thr_obj);
                                }
                            }
                            HYPERPLATFORM_LOG_INFO("[td-map] thread SUSPENDED+CPU0+RESUMED trigger=%p", trigger_fn);
                            ZwClose(thr_h);
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
    if (g_hooked_target)
    {
        HYPERPLATFORM_LOG_INFO("[td] Unhooking R0 hook before unload...");
        TdEptUnhookNtCreateFile();
    }

    TdEptUnhookAllR3();

    UNICODE_STRING sym;
    RtlInitUnicodeString(&sym, TD_SYMLINK_NAME);
    IoDeleteSymbolicLink(&sym);
    if (drv->DeviceObject) IoDeleteDevice(drv->DeviceObject);
    HYPERPLATFORM_LOG_INFO("[td] Unloaded.");
    LogTermination();
}

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg)
{
    UNREFERENCED_PARAMETER(reg);

    //
    // init log system — file output, truncate on load
    //
    static const wchar_t kLogFilePath[] = L"\\SystemRoot\\T.log";
    auto log_status = LogInitialization(kLogPutLevelDebug, kLogFilePath);
    if (log_status == STATUS_REINITIALIZATION_NEEDED)
        LogRegisterReinitialization(drv);

    UNICODE_STRING fn;
    // try NtCreateThreadEx first (more likely exported), then ZwCreateThreadEx
    RtlInitUnicodeString(&fn, L"NtCreateThreadEx");
    g_pZwCreateThreadEx = (fn_ZwCreateThreadEx)MmGetSystemRoutineAddress(&fn);
    if (!g_pZwCreateThreadEx)
    {
        RtlInitUnicodeString(&fn, L"ZwCreateThreadEx");
        g_pZwCreateThreadEx = (fn_ZwCreateThreadEx)MmGetSystemRoutineAddress(&fn);
    }
    RtlInitUnicodeString(&fn, L"NtResumeThread");
    g_pZwResumeThread = (fn_ZwResumeThread)MmGetSystemRoutineAddress(&fn);
    if (!g_pZwResumeThread)
    {
        RtlInitUnicodeString(&fn, L"ZwResumeThread");
        g_pZwResumeThread = (fn_ZwResumeThread)MmGetSystemRoutineAddress(&fn);
    }

    RtlInitUnicodeString(&fn, L"KeResumeThread");
    g_pKeResumeThread = (fn_KeResumeThread)MmGetSystemRoutineAddress(&fn);

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

    HYPERPLATFORM_LOG_INFO("[td] Loaded. Device: %wZ", &sym_name);
    return STATUS_SUCCESS;
}

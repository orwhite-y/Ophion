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

// ---- undocumented PEB structures for user-mode module walk ----

extern "C" NTKERNELAPI PPEB PsGetProcessPeb(PEPROCESS Process);
extern "C" NTSYSAPI NTSTATUS NTAPI ZwProtectVirtualMemory(
    HANDLE ProcessHandle, PVOID * BaseAddress, PSIZE_T RegionSize,
    ULONG NewProtect, PULONG OldProtect);

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
#define VMCALL_READ_R3          0x00000009
#define VMCALL_WRITE_R3         0x0000000A
#define VMCALL_EPT_SHADOW_PAGE  0x0000000B

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

// ---- LoadImage callback — path spoofing for DLL hijack hiding ----
//
// all registered LoadImage callbacks share the SAME UNICODE_STRING pointer.
// if our callback runs first (driver loads before AC), we modify the buffer
// before AC's callback sees it. AC sees the spoofed System32 path.
//

#define MAX_SPOOF_ENTRIES 8

typedef struct _IMAGE_SPOOF_ENTRY {
    BOOLEAN active;
    WCHAR   real_name[64];      // DLL filename to match (e.g. L"version.dll")
    WCHAR   fake_path[260];     // full NT path to spoof (e.g. L"\\..\\System32\\version.dll")
    USHORT  fake_path_len;      // byte length of fake_path (not including null)
} IMAGE_SPOOF_ENTRY;

static IMAGE_SPOOF_ENTRY g_spoof_entries[MAX_SPOOF_ENTRIES] = {};
static BOOLEAN g_image_callback_registered = FALSE;

//
// case-insensitive wchar match of filename portion of a full path.
// returns TRUE if path ends with \filename (case-insensitive).
//
static BOOLEAN TdPathEndsWith(PCUNICODE_STRING path, const WCHAR * filename, USHORT name_chars)
{
    if (!path || !path->Buffer || !filename) return FALSE;

    USHORT path_chars = path->Length / sizeof(WCHAR);
    if (path_chars < name_chars) return FALSE;

    const WCHAR * tail = path->Buffer + (path_chars - name_chars);
    USHORT i;
    WCHAR a, b;

    // check char before filename is backslash (or path starts with filename)
    if (path_chars > name_chars)
    {
        if (*(tail - 1) != L'\\') return FALSE;
    }

    for (i = 0; i < name_chars; i++)
    {
        a = tail[i];
        b = filename[i];
        if (a >= L'A' && a <= L'Z') a += 32;
        if (b >= L'A' && b <= L'Z') b += 32;
        if (a != b) return FALSE;
    }
    return TRUE;
}

static VOID NTAPI TdLoadImageCallback(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo)
{
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(ImageInfo);

    if (!FullImageName || !FullImageName->Buffer) return;

    int i;
    for (i = 0; i < MAX_SPOOF_ENTRIES; i++)
    {
        if (!g_spoof_entries[i].active) continue;

        USHORT name_len = (USHORT)wcslen(g_spoof_entries[i].real_name);
        if (TdPathEndsWith(FullImageName, g_spoof_entries[i].real_name, name_len))
        {
            //
            // match! overwrite the shared UNICODE_STRING to point to our fake path.
            // all subsequent callbacks (including AC) see the spoofed path.
            // the original UNICODE_STRING is stack-allocated by the caller
            // (MiMapViewOfImageSection), so modifying it is safe.
            //
            DbgPrintEx(0, 0, "[td-spoof] intercepted: %wZ → %ls\n",
                       FullImageName, g_spoof_entries[i].fake_path);

            FullImageName->Buffer = g_spoof_entries[i].fake_path;
            FullImageName->Length = g_spoof_entries[i].fake_path_len;
            FullImageName->MaximumLength = g_spoof_entries[i].fake_path_len + sizeof(WCHAR);
            return;
        }
    }
}

// ---- device / IOCTL ----

#define TD_DEVICE_NAME  L"\\Device\\OphionTest"
#define TD_SYMLINK_NAME L"\\DosDevices\\OphionTest"

#define TD_IOCTL_BASE   0x900
#define IOCTL_INJECT    CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EPT_HOOK    CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EPT_UNHOOK  CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EPT_HOOK_R3 CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READ_R3     CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 5, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_R3    CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PROTECT_DLL CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DLL_DUALVIEW CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 8, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SPOOF_PATH   CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 9, METHOD_BUFFERED, FILE_ANY_ACCESS)
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

typedef struct _TD_PROTECT_DLL_PARAMS {
    UINT64 target_pid;      // [in]  process containing the DLL
    UINT64 dll_base;        // [in]  DLL base address to protect
    UINT64 status;          // [out] NTSTATUS
} TD_PROTECT_DLL_PARAMS;

//
// DLL dual-view: read→original legitimate DLL, execute→your code.
// caller provides:
//   target_pid:    process with the injected DLL
//   dll_base:      base address of the injected DLL in target
//   dll_size:      SizeOfImage of the injected DLL
//   legit_path:    kernel path to the legitimate DLL file (read view)
//
typedef struct _TD_SPOOF_PATH_PARAMS {
    WCHAR  real_name[64];       // [in] DLL filename to intercept (e.g. L"version.dll")
    WCHAR  fake_path[260];      // [in] NT path to spoof (e.g. L"\\SystemRoot\\System32\\version.dll")
    UINT64 status;              // [out]
} TD_SPOOF_PATH_PARAMS;

typedef struct _TD_DLL_DUALVIEW_PARAMS {
    UINT64 target_pid;          // [in]
    UINT64 dll_base;            // [in]  injected DLL base in target
    UINT64 dll_size;            // [in]  SizeOfImage (bytes, page-aligned)
    WCHAR  legit_path[260];     // [in]  path to legitimate DLL (e.g. L"\\SystemRoot\\System32\\version.dll")
    UINT64 pages_hooked;        // [out] number of pages successfully hooked
    UINT64 status;              // [out] NTSTATUS
} TD_DLL_DUALVIEW_PARAMS;

typedef struct _TD_RW_R3_PARAMS {
    UINT64 target_pid;      // [in]
    UINT64 target_va;       // [in]  user-mode VA to read/write
    UINT64 size;            // [in]  bytes (max PAGE_SIZE)
    UINT64 buffer_va;       // [in]  user-mode buffer in caller process
    UINT64 status;          // [out] NTSTATUS
} TD_RW_R3_PARAMS;
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

// ---- Data-driven shellcode (split code/data) ----
//
// Code page (EPT execute-only, R=0): only instructions, no embedded data.
// Data lives in the trampoline page (separate VA, normal RWX, not EPT hooked).
// This allows changed_entry R=0 → memory scanners read zeros from code page.
//
// Code page layout:
//   +0x000: shellcode stub (code only)
//
// Trampoline page layout:
//   +0x000: [saved bytes] + [abs jmp back]   (trampoline code, 18 bytes)
//   +0x100: UINT64  pLoadLibraryA
//   +0x108: UINT64  pGetProcAddress
//   +0x110: char    "user32.dll\0"
//   +0x120: char    "MessageBoxA\0"
//   +0x130: char    "Ophion Stealth!\0"
//   +0x140: char    "Ophion\0"
//
// shellcode uses: mov rbp, <absolute tramp_va + 0x100>  (patched at runtime)
//

// stub: rbp loaded with absolute data pointer (patched at build time)
// offset 7-14: 8 bytes to be patched with tramp_va + 0x100
static const UINT8 g_shellcode_stub[] = {
    0x48, 0x83, 0xEC, 0x28,                         // sub rsp, 28h         ; align stack
    0x48, 0xBD,                                     // mov rbp, imm64       ; (6 bytes opcode+prefix)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // imm64 placeholder   ; patched to tramp_va+0x100

    // LoadLibraryA("user32.dll")
    0x48, 0x8B, 0x45, 0x00,                         // mov rax, [rbp+0]     ; pLoadLibraryA
    0x48, 0x8D, 0x4D, 0x10,                         // lea rcx, [rbp+10h]   ; "user32.dll"
    0x48, 0x83, 0xEC, 0x20,                         // sub rsp, 20h
    0xFF, 0xD0,                                     // call rax
    0x48, 0x83, 0xC4, 0x20,                         // add rsp, 20h

    // GetProcAddress(user32, "MessageBoxA")
    0x48, 0x89, 0xC1,                               // mov rcx, rax         ; user32 handle
    0x48, 0x8B, 0x45, 0x08,                         // mov rax, [rbp+8]     ; pGetProcAddress
    0x48, 0x8D, 0x55, 0x20,                         // lea rdx, [rbp+20h]   ; "MessageBoxA"
    0x48, 0x83, 0xEC, 0x20,                         // sub rsp, 20h
    0xFF, 0xD0,                                     // call rax
    0x48, 0x83, 0xC4, 0x20,                         // add rsp, 20h

    // MessageBoxA(NULL, "Ophion Stealth!", "Ophion", MB_OK)
    0x48, 0x89, 0xC3,                               // mov rbx, rax         ; MessageBoxA
    0x48, 0x31, 0xC9,                               // xor rcx, rcx         ; hWnd = NULL
    0x48, 0x8D, 0x55, 0x30,                         // lea rdx, [rbp+30h]   ; "Ophion Stealth!"
    0x4C, 0x8D, 0x45, 0x40,                         // lea r8, [rbp+40h]    ; "Ophion"
    0x45, 0x31, 0xC9,                               // xor r9d, r9d         ; uType = 0
    0x48, 0x83, 0xEC, 0x20,                         // sub rsp, 20h
    0xFF, 0xD3,                                     // call rbx
    0x48, 0x83, 0xC4, 0x20,                         // add rsp, 20h

    0x48, 0x83, 0xC4, 0x28,                         // add rsp, 28h
    0xC3,                                           // ret
};

//
// build shellcode code page: stub only, NO data.
// data_va = absolute address of data area (on trampoline page).
// must be called while attached to the target process.
//
static VOID
TdBuildShellcodePage(PVOID buf, UINT64 data_va)
{
    // zero only the shellcode area (buf may not be page-aligned for gap mode)
    RtlZeroMemory(buf, sizeof(g_shellcode_stub));

    // copy stub
    RtlCopyMemory(buf, g_shellcode_stub, sizeof(g_shellcode_stub));

    // patch mov rbp, imm64 — write absolute data_va at offset 6
    *(PUINT64)((PUINT8)buf + 6) = data_va;
}

//
// build data block on the trampoline page at +0x100.
// must be called while attached to the target process (PEB walk).
//
static VOID
TdBuildDataBlock(PVOID tramp_base)
{
    PUINT8 data = (PUINT8)tramp_base + 0x100;

    PPEB peb = PsGetProcessPeb(PsGetCurrentProcess());
    if (!peb) return;

    __try {
        TD_PEB_LDR_DATA * ldr = *(TD_PEB_LDR_DATA **)((PUINT8)peb + 0x18);
        if (!ldr) return;

        PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
        PLIST_ENTRY cur  = head->Flink;
        PVOID kernel32_base = NULL;

        while (cur != head)
        {
            TD_LDR_ENTRY * e = CONTAINING_RECORD(cur, TD_LDR_ENTRY, InMemoryOrderLinks);
            if (e->BaseDllName.Buffer && e->BaseDllName.Length >= 20)
            {
                BOOLEAN match = TRUE;
                const WCHAR target[] = L"kernel32.dll";
                for (USHORT i = 0; i < 12; i++)
                {
                    WCHAR c = e->BaseDllName.Buffer[i];
                    if (c >= L'A' && c <= L'Z') c += 32;
                    if (c != target[i]) { match = FALSE; break; }
                }
                if (match) { kernel32_base = e->DllBase; break; }
            }
            cur = cur->Flink;
        }

        if (!kernel32_base) return;

        PIMAGE_DOS_HEADER dos_h = (PIMAGE_DOS_HEADER)kernel32_base;
        PIMAGE_NT_HEADERS64 nt_h = (PIMAGE_NT_HEADERS64)((PUINT8)kernel32_base + dos_h->e_lfanew);
        ULONG exp_rva = nt_h->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        PIMAGE_EXPORT_DIRECTORY exp_d = (PIMAGE_EXPORT_DIRECTORY)((PUINT8)kernel32_base + exp_rva);

        PULONG  names_arr    = (PULONG)((PUINT8)kernel32_base + exp_d->AddressOfNames);
        PUSHORT ordinals_arr = (PUSHORT)((PUINT8)kernel32_base + exp_d->AddressOfNameOrdinals);
        PULONG  funcs_arr    = (PULONG)((PUINT8)kernel32_base + exp_d->AddressOfFunctions);

        UINT64 pLoadLibraryA = 0, pGetProcAddress = 0;

        for (ULONG i = 0; i < exp_d->NumberOfNames; i++)
        {
            const char * fn = (const char *)((PUINT8)kernel32_base + names_arr[i]);
            if (!pLoadLibraryA && strcmp(fn, "LoadLibraryA") == 0)
                pLoadLibraryA = (UINT64)kernel32_base + funcs_arr[ordinals_arr[i]];
            if (!pGetProcAddress && strcmp(fn, "GetProcAddress") == 0)
                pGetProcAddress = (UINT64)kernel32_base + funcs_arr[ordinals_arr[i]];
            if (pLoadLibraryA && pGetProcAddress) break;
        }

        *(PUINT64)(data + 0x00) = pLoadLibraryA;
        *(PUINT64)(data + 0x08) = pGetProcAddress;
        RtlCopyMemory(data + 0x10, "user32.dll",       11);
        RtlCopyMemory(data + 0x20, "MessageBoxA",      12);
        RtlCopyMemory(data + 0x30, "Ophion Stealth!",  16);
        RtlCopyMemory(data + 0x40, "Ophion",            7);

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // PEB walk failed silently
    }
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
            DbgPrintEx(0, 0, "[td] stealth page %u: MmGetPhysicalAddress=0 for VA=%p\n",
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
            DbgPrintEx(0, 0, "[td] stealth page %u: PT walk failed for VA=%p\n",
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
        DbgPrintEx(0, 0, "[td-hook] NtCreateFile #%d: %wZ\n",
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
        DbgPrintEx(0, 0, "[td] NtCreateFile not found\n");
        return STATUS_NOT_FOUND;
    }

    DbgPrintEx(0, 0, "[td] NtCreateFile = %p, proxy = %p\n", target, (PVOID)HookedNtCreateFile);

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
        DbgPrintEx(0, 0, "[td] EPT hook installed! trampoline = %p\n", (PVOID)g_orig_NtCreateFile);
    }
    else
    {
        DbgPrintEx(0, 0, "[td] EPT hook FAILED: 0x%08X\n", ctx.result);
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
        DbgPrintEx(0, 0, "[td] EPT hook removed. total calls logged: %d\n", g_hook_log_count);
        g_hooked_target = NULL;
        g_orig_NtCreateFile = NULL;
        g_hook_log_count = 0;
    }
    else
    {
        DbgPrintEx(0, 0, "[td] EPT unhook FAILED: 0x%08X\n", ctx.result);
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
        DbgPrintEx(0, 0, "[td-r3] no free R3 hook slots\n");
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
        DbgPrintEx(0, 0, "[td-r3] MmProbeAndLockPages failed for %p\n", target_va);
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
        DbgPrintEx(0, 0, "[td-r3] trampoline alloc failed: 0x%08X\n", st);
        return st;
    }

    RtlZeroMemory(tramp_va, tramp_size);
    UINT64 tramp_pa = MmGetPhysicalAddress(tramp_va).QuadPart;

    DbgPrintEx(0, 0, "[td-r3] target=%p proxy=%p tramp=%p(PA=%llx) cr3=%llx pid=%llu type=%u\n",
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

        DbgPrintEx(0, 0, "[td-r3] R3 EPT hook installed! trampoline=%p\n", origin_ptr);
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

        DbgPrintEx(0, 0, "[td-r3] R3 EPT hook FAILED: 0x%08X\n", ctx.result);
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
        DbgPrintEx(0, 0, "[td-r3] hook entry not found for pid=%llu va=%p\n", target_pid, target_va);
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

    DbgPrintEx(0, 0, "[td-r3] R3 hook removed: pid=%llu va=%p\n", target_pid, target_va);

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

            DbgPrintEx(0, 0, "[td-gap] section padding: page=%p offset=0x%X avail=0x%X (section %.8s)\n",
                       page_va, page_offset, *out_avail, best_sec->Name);
            return page_va;
        }

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(0, 0, "[td-gap] exception walking PE headers\n");
    }

    return NULL;
}

//
// find a DLL gap in the target process. tries ntdll first (always loaded,
// large image), then kernel32. must be called while attached.
//
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
        DbgPrintEx(0, 0, "[td-gap] exception walking PEB\n");
    }

    return NULL;
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

        SIZE_T size = PAGE_SIZE;
        BOOLEAN used_gap = FALSE;
        ULONG gap_offset = 0, gap_avail = 0;

        //
        // try section tail padding first — shellcode goes into the zero-padded
        // tail of a section's last page. no new allocation, no new VAD.
        // original page content preserved (real DLL code stays in front).
        //
        PVOID base = TdFindGapInProcess(sizeof(g_shellcode_stub) + 32, &gap_offset, &gap_avail);
        if (base)
        {
            used_gap = TRUE;
            DbgPrintEx(0, 0, "[td] inject: section padding VA=%p+0x%X avail=0x%X pid=%llu\n",
                       base, gap_offset, gap_avail, p->target_pid);
        }

        if (!base)
        {
            //
            // fallback: allocate new page (PAGE_EXECUTE_READWRITE for CFG).
            //
            st = ZwAllocateVirtualMemory(
                ZwCurrentProcess(), &base, 0, &size,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

            if (!NT_SUCCESS(st) || !base)
            {
                KeUnstackDetachProcess(&apc_state);
                ObDereferenceObject(proc);
                break;
            }
            gap_offset = 0;  // shellcode at page start
        }

        DbgPrintEx(0, 0, "[td] inject: VA=%p offset=0x%X pid=%llu gap=%d\n",
                   base, gap_offset, p->target_pid, used_gap);

        // --- step 1: allocate data page (PAGE_READWRITE, no execute) ---
        //
        // tramp_va holds ONLY data (+0x100). NO code — trampoline code lives
        // inside the shadow page at offset 0xF00 (EPT X-only, hidden).
        // PAGE_READWRITE: no RWX allocation, clean VAD.
        //
        PVOID tramp_va = NULL;
        SIZE_T tramp_size = PAGE_SIZE;
        NTSTATUS tramp_st = ZwAllocateVirtualMemory(
            ZwCurrentProcess(), &tramp_va, 0, &tramp_size,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (!NT_SUCCESS(tramp_st) || !tramp_va)
        {
            if (!used_gap) ZwFreeVirtualMemory(ZwCurrentProcess(), &base, &size, MEM_RELEASE);
            KeUnstackDetachProcess(&apc_state);
            ObDereferenceObject(proc);
            st = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        RtlZeroMemory(tramp_va, tramp_size);

        // --- step 2: build data block on data page ---
        TdBuildDataBlock(tramp_va);

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
            ZwFreeVirtualMemory(ZwCurrentProcess(), &tramp_va, &tramp_size, MEM_RELEASE);
            if (!used_gap) ZwFreeVirtualMemory(ZwCurrentProcess(), &base, &size, MEM_RELEASE);
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
        // .text is PAGE_EXECUTE_READ → change to RW → write padding byte → COW
        // → restore to original protection. the write is in padding (zeros),
        // restored immediately, so page content is unchanged.
        //
        if (used_gap)
        {
            UINT64 pa_before = MmGetPhysicalAddress(base).QuadPart;
            ULONG _old_p = 0, _tmp_p = 0;
            PVOID _pb = base;
            SIZE_T _ps = PAGE_SIZE;

            NTSTATUS vp_st = ZwProtectVirtualMemory(
                ZwCurrentProcess(), &_pb, &_ps, PAGE_EXECUTE_READWRITE, &_old_p);

            if (NT_SUCCESS(vp_st))
            {
                // write to padding area triggers COW → private physical page
                ((volatile UINT8 *)base)[gap_offset] = 0x01;
                ((volatile UINT8 *)base)[gap_offset] = 0x00;  // restore

                // restore original protection
                _pb = base; _ps = PAGE_SIZE;
                ZwProtectVirtualMemory(ZwCurrentProcess(), &_pb, &_ps, _old_p, &_tmp_p);
            }

            UINT64 pa_after = MmGetPhysicalAddress(base).QuadPart;
            DbgPrintEx(0, 0, "[td] inject: COW %s (PA %llx → %llx)\n",
                       (pa_before != pa_after) ? "OK" : "SAME", pa_before, pa_after);
        }

        // copy original page content (DLL code in front, zeros in padding)
        RtlCopyMemory(fake_buf, base, PAGE_SIZE);

        // build shellcode at gap_offset inside fake_buf
        TdBuildShellcodePage((PUINT8)fake_buf + gap_offset, (UINT64)tramp_va + 0x100);

        if (!used_gap)
        {
            // fallback: zero the original page (COW → private PA)
            RtlZeroMemory(base, PAGE_SIZE);
        }
        // gap mode: original page untouched — DLL code + zero padding stays

        UINT64 base_phys = MmGetPhysicalAddress(base).QuadPart;
        DbgPrintEx(0, 0, "[td] inject: PA=%llx entry=%p\n", base_phys, entry_va);

        if (!base_phys)
        {
            ZwFreeVirtualMemory(ZwCurrentProcess(), &tramp_va, &tramp_size, MEM_RELEASE);
            RtlSecureZeroMemory(fake_buf, PAGE_SIZE);
            ExFreePoolWithTag(fake_buf, 'kjnI');
            if (!used_gap) ZwFreeVirtualMemory(ZwCurrentProcess(), &base, &size, MEM_RELEASE);
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

        DbgPrintEx(0, 0, "[td] inject: trampoline at shadow+0xF00, entry at +0x%X\n", gap_offset);

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
        if (!used_gap && TdResolveGuestPT(caller_cr3, (UINT64)base & ~0xFFFULL, &pt_pfn, &pt_idx))
        {
            PHYSICAL_ADDRESS ptpa;
            ptpa.QuadPart = (LONGLONG)(pt_pfn << 12);
            pt_real_va = MmGetVirtualForPhysical(ptpa);

            pt_page_buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'kjnI');
            if (pt_page_buf)
            {
                if (pt_real_va)
                    RtlCopyMemory(pt_page_buf, pt_real_va, PAGE_SIZE);
                else
                    RtlZeroMemory(pt_page_buf, PAGE_SIZE);
                ((PUINT64)pt_page_buf)[pt_idx] &= ~(1ULL << 63);
            }

            DbgPrintEx(0, 0, "[td] inject: PT PFN=%llx idx=%u va=%p\n", pt_pfn, pt_idx, pt_real_va);
        }
        else if (!used_gap)
        {
            DbgPrintEx(0, 0, "[td] inject: WARNING — PT walk failed, no fake PT support\n");
        }

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

            DbgPrintEx(0, 0, "[td] inject: EPT hook OK, fake_pt=%s\n",
                       inj_req.fake_pt_ok ? "YES" : "NO");

            // track for cleanup (no MDL — page is one-shot inject, not persistent)
            R3_HOOK_ENTRY * he = R3HookFindFree();
            if (he)
            {
                he->active          = TRUE;
                he->target_pid      = p->target_pid;
                he->target_va       = base;
                he->trampoline_va   = tramp_va;
                he->trampoline_size = tramp_size;
                he->target_mdl      = NULL;
                he->target_cr3      = caller_cr3;
            }

            p->shellcode_va = (UINT64)entry_va;
            p->actual_size  = (UINT64)size;
            irp->IoStatus.Information = sizeof(TD_INJECT_PARAMS);
            DbgPrintEx(0, 0, "[td] inject: EPT hook OK\n");
        }
        else
        {
            DbgPrintEx(0, 0, "[td] inject: EPT hook FAILED\n");
            ZwFreeVirtualMemory(ZwCurrentProcess(), &tramp_va, &tramp_size, MEM_RELEASE);
            if (!used_gap) ZwFreeVirtualMemory(ZwCurrentProcess(), &base, &size, MEM_RELEASE);
            st = STATUS_UNSUCCESSFUL;
        }

        //
        // --- step 7: resolve trigger function (valid CFG target) ---
        //
        // gap address is NOT in CFG bitmap — can't create thread there directly.
        // instead: EPT hook a legit function → redirect to entry_va (gap shellcode).
        // thread entry = trigger function (in CFG bitmap) → EPT hook → shellcode.
        //
        PVOID trigger_fn = (PVOID)p->trigger_va;
        if (!trigger_fn && NT_SUCCESS(st))
        {
            // auto-resolve NtTestAlert from ntdll
            UNICODE_STRING fn_name;
            RtlInitUnicodeString(&fn_name, L"NtTestAlert");
            trigger_fn = MmGetSystemRoutineAddress(&fn_name);
            // NtTestAlert is a Zw/Nt export — kernel VA. need the user-mode ntdll VA.
            // for user-mode: walk PEB to find ntdll!NtTestAlert RVA.
            trigger_fn = NULL;  // can't use kernel VA for R3 hook
        }

        // resolve trigger from target process's ntdll via PEB walk
        if (!trigger_fn && NT_SUCCESS(st))
        {
            PPEB peb = PsGetProcessPeb(proc);
            if (peb)
            {
                TD_PEB_LDR_DATA * ldr = NULL;
                PLIST_ENTRY ldr_head = NULL, ldr_cur = NULL;
                TD_LDR_ENTRY * ldr_e = NULL;

                __try {
                    ldr = *(TD_PEB_LDR_DATA **)((PUINT8)peb + 0x18);
                    if (ldr)
                    {
                        ldr_head = &ldr->InMemoryOrderModuleList;
                        ldr_cur = ldr_head->Flink;
                        while (ldr_cur != ldr_head)
                        {
                            ldr_e = CONTAINING_RECORD(ldr_cur, TD_LDR_ENTRY, InMemoryOrderLinks);
                            if (ldr_e->BaseDllName.Buffer &&
                                TdMatchDllName(ldr_e->BaseDllName.Buffer, ldr_e->BaseDllName.Length,
                                               g_ntdll_name, 9))
                            {
                                // find NtTestAlert export in ntdll
                                PIMAGE_DOS_HEADER dos_h = (PIMAGE_DOS_HEADER)ldr_e->DllBase;
                                PIMAGE_NT_HEADERS64 nt_h = (PIMAGE_NT_HEADERS64)((PUINT8)ldr_e->DllBase + dos_h->e_lfanew);
                                ULONG exp_rva = nt_h->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                                PIMAGE_EXPORT_DIRECTORY exp_d = (PIMAGE_EXPORT_DIRECTORY)((PUINT8)ldr_e->DllBase + exp_rva);
                                PULONG names = (PULONG)((PUINT8)ldr_e->DllBase + exp_d->AddressOfNames);
                                PUSHORT ords = (PUSHORT)((PUINT8)ldr_e->DllBase + exp_d->AddressOfNameOrdinals);
                                PULONG funcs = (PULONG)((PUINT8)ldr_e->DllBase + exp_d->AddressOfFunctions);
                                ULONG ei;

                                for (ei = 0; ei < exp_d->NumberOfNames; ei++)
                                {
                                    const char * fn = (const char *)((PUINT8)ldr_e->DllBase + names[ei]);
                                    if (strcmp(fn, "NtTestAlert") == 0)
                                    {
                                        trigger_fn = (PUINT8)ldr_e->DllBase + funcs[ords[ei]];
                                        break;
                                    }
                                }
                                break;
                            }
                            ldr_cur = ldr_cur->Flink;
                        }
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    DbgPrintEx(0, 0, "[td] inject: trigger resolve exception\n");
                }
            }
        }

        if (!trigger_fn && NT_SUCCESS(st))
        {
            DbgPrintEx(0, 0, "[td] inject: cannot resolve trigger function\n");
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
                (UINT64)trigger_fn,         // target: NtTestAlert
                (UINT64)entry_va,           // proxy: shellcode in gap
                (UINT64)&dummy_origin,      // origin (unused)
                caller_cr3,                 // caller CR3
                1,                          // hook_type = VMCALL (0F 01 C1)
                caller_cr3,                 // target_cr3 (per-process filter)
                0, 0, 0);                   // no user trampoline

            KeRevertToUserAffinityThreadEx(old_aff);

            DbgPrintEx(0, 0, "[td] inject: trigger hook %s (trigger=%p → entry=%p st=0x%08X)\n",
                       NT_SUCCESS(hook_st) ? "OK" : "FAILED", trigger_fn, entry_va, hook_st);
        }

        if (!NT_SUCCESS(hook_st))
            st = hook_st;

        KeUnstackDetachProcess(&apc_state);

        //
        // --- step 9: create thread at trigger function (valid CFG target) ---
        //
        if (NT_SUCCESS(st) && p->shellcode_va)
        {
            NTSTATUS thr_st = TdCreateThread(proc, trigger_fn);
            p->actual_size |= ((UINT64)(UINT32)thr_st << 32);
            DbgPrintEx(0, 0, "[td] inject: thread at trigger=%p st=0x%08X\n", trigger_fn, thr_st);
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

    case IOCTL_SPOOF_PATH:
    {
        //
        // configure LoadImage path spoofing.
        // must be called BEFORE the target DLL is loaded.
        // registers the LoadImage callback on first use.
        //
        if (io->Parameters.DeviceIoControl.InputBufferLength < sizeof(TD_SPOOF_PATH_PARAMS) ||
            io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(TD_SPOOF_PATH_PARAMS))
        { st = STATUS_BUFFER_TOO_SMALL; break; }

        TD_SPOOF_PATH_PARAMS * p = (TD_SPOOF_PATH_PARAMS *)irp->AssociatedIrp.SystemBuffer;

        // register callback on first use
        if (!g_image_callback_registered)
        {
            NTSTATUS cb_st = PsSetLoadImageNotifyRoutine(TdLoadImageCallback);
            if (NT_SUCCESS(cb_st))
            {
                g_image_callback_registered = TRUE;
                DbgPrintEx(0, 0, "[td-spoof] LoadImage callback registered\n");
            }
            else
            {
                p->status = (UINT64)cb_st;
                irp->IoStatus.Information = sizeof(TD_SPOOF_PATH_PARAMS);
                st = STATUS_SUCCESS;
                break;
            }
        }

        // find free slot
        int slot = -1;
        for (int i = 0; i < MAX_SPOOF_ENTRIES; i++)
        {
            if (!g_spoof_entries[i].active) { slot = i; break; }
        }

        if (slot < 0)
        {
            p->status = (UINT64)STATUS_INSUFFICIENT_RESOURCES;
            irp->IoStatus.Information = sizeof(TD_SPOOF_PATH_PARAMS);
            st = STATUS_SUCCESS;
            break;
        }

        wcscpy_s(g_spoof_entries[slot].real_name, 64, p->real_name);
        wcscpy_s(g_spoof_entries[slot].fake_path, 260, p->fake_path);
        g_spoof_entries[slot].fake_path_len = (USHORT)(wcslen(p->fake_path) * sizeof(WCHAR));
        g_spoof_entries[slot].active = TRUE;

        p->status = (UINT64)STATUS_SUCCESS;
        irp->IoStatus.Information = sizeof(TD_SPOOF_PATH_PARAMS);
        st = STATUS_SUCCESS;

        DbgPrintEx(0, 0, "[td-spoof] added: %ls → %ls\n",
                   g_spoof_entries[slot].real_name, g_spoof_entries[slot].fake_path);
        break;
    }

    case IOCTL_DLL_DUALVIEW:
    {
        //
        // DLL dual-view: read→legitimate DLL, execute→injected DLL.
        // hooks PE header + .text pages only. .data/.rdata untouched.
        //
        if (io->Parameters.DeviceIoControl.InputBufferLength < sizeof(TD_DLL_DUALVIEW_PARAMS) ||
            io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(TD_DLL_DUALVIEW_PARAMS))
        { st = STATUS_BUFFER_TOO_SMALL; break; }

        TD_DLL_DUALVIEW_PARAMS * p = (TD_DLL_DUALVIEW_PARAMS *)irp->AssociatedIrp.SystemBuffer;
        p->pages_hooked = 0;
        p->status = 0;

        // --- 1. read legitimate DLL from disk ---
        UNICODE_STRING legit_upath;
        RtlInitUnicodeString(&legit_upath, p->legit_path);
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &legit_upath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        IO_STATUS_BLOCK iosb;
        HANDLE hFile = NULL;
        NTSTATUS file_st = ZwCreateFile(&hFile, GENERIC_READ, &oa, &iosb,
            NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);

        if (!NT_SUCCESS(file_st))
        {
            DbgPrintEx(0, 0, "[td-dv] cannot open legit DLL: 0x%08X\n", file_st);
            p->status = (UINT64)file_st;
            irp->IoStatus.Information = sizeof(TD_DLL_DUALVIEW_PARAMS);
            st = STATUS_SUCCESS;
            break;
        }

        FILE_STANDARD_INFORMATION fsi;
        ZwQueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi), FileStandardInformation);
        SIZE_T legit_file_size = (SIZE_T)fsi.EndOfFile.QuadPart;

        PVOID legit_buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, legit_file_size, 'vDlL');
        if (!legit_buf)
        {
            ZwClose(hFile);
            p->status = (UINT64)STATUS_INSUFFICIENT_RESOURCES;
            irp->IoStatus.Information = sizeof(TD_DLL_DUALVIEW_PARAMS);
            st = STATUS_SUCCESS;
            break;
        }

        LARGE_INTEGER offset_zero = {};
        ZwReadFile(hFile, NULL, NULL, NULL, &iosb, legit_buf, (ULONG)legit_file_size, &offset_zero, NULL);
        ZwClose(hFile);

        DbgPrintEx(0, 0, "[td-dv] legit DLL loaded: %llu bytes\n", (UINT64)legit_file_size);

        // --- 2. parse legitimate DLL: find .text section ---
        PIMAGE_DOS_HEADER legit_dos = (PIMAGE_DOS_HEADER)legit_buf;
        PIMAGE_NT_HEADERS64 legit_nt = (PIMAGE_NT_HEADERS64)((PUINT8)legit_buf + legit_dos->e_lfanew);
        PIMAGE_SECTION_HEADER legit_secs = IMAGE_FIRST_SECTION(legit_nt);
        ULONG legit_text_rva = 0, legit_text_rawoff = 0, legit_text_rawsz = 0;
        ULONG legit_hdr_size = legit_nt->OptionalHeader.SizeOfHeaders;
        USHORT li;

        for (li = 0; li < legit_nt->FileHeader.NumberOfSections; li++)
        {
            if (legit_secs[li].Characteristics & IMAGE_SCN_MEM_EXECUTE)
            {
                legit_text_rva    = legit_secs[li].VirtualAddress;
                legit_text_rawoff = legit_secs[li].PointerToRawData;
                legit_text_rawsz  = legit_secs[li].SizeOfRawData;
                break;
            }
        }

        // --- 3. attach to target, parse injected DLL's .text ---
        PEPROCESS dv_proc = NULL;
        file_st = PsLookupProcessByProcessId((HANDLE)p->target_pid, &dv_proc);
        if (!NT_SUCCESS(file_st))
        {
            ExFreePoolWithTag(legit_buf, 'vDlL');
            p->status = (UINT64)file_st;
            irp->IoStatus.Information = sizeof(TD_DLL_DUALVIEW_PARAMS);
            st = STATUS_SUCCESS;
            break;
        }

        KAPC_STATE dv_apc;
        KeStackAttachProcess(dv_proc, &dv_apc);

        PVOID dll_base_va = (PVOID)p->dll_base;
        PIMAGE_DOS_HEADER inj_dos = (PIMAGE_DOS_HEADER)dll_base_va;
        PIMAGE_NT_HEADERS64 inj_nt = (PIMAGE_NT_HEADERS64)((PUINT8)dll_base_va + inj_dos->e_lfanew);
        PIMAGE_SECTION_HEADER inj_secs = IMAGE_FIRST_SECTION(inj_nt);
        ULONG inj_text_rva = 0, inj_text_vsize = 0;
        ULONG inj_hdr_size = inj_nt->OptionalHeader.SizeOfHeaders;
        USHORT ii;

        for (ii = 0; ii < inj_nt->FileHeader.NumberOfSections; ii++)
        {
            if (inj_secs[ii].Characteristics & IMAGE_SCN_MEM_EXECUTE)
            {
                inj_text_rva   = inj_secs[ii].VirtualAddress;
                inj_text_vsize = inj_secs[ii].Misc.VirtualSize;
                break;
            }
        }

        ULONG inj_hdr_pages  = (inj_hdr_size + PAGE_SIZE - 1) / PAGE_SIZE;

        //
        // hook range = legit DLL's .text size (not injected DLL's .text).
        // because we show legit PE header → AC reads legit .text size worth of pages.
        // legit .text MUST be ≤ injected .text, otherwise legit's .text range
        // extends into injected .data → read/write conflict (user code reads
        // .data but EPT shows legit .text content → crash).
        //
        //
        // hook range = MIN(legit .text, injected .text).
        // if legit > injected: only hook up to injected .text (avoid .data overlap).
        //   AC may see mismatched content beyond hook range — acceptable tradeoff.
        //   production: pad your .text to match legit DLL at compile time.
        // if legit ≤ injected: hook all legit .text pages — perfect match.
        //
        ULONG hook_text_size = (legit_text_rawsz < inj_text_vsize) ? legit_text_rawsz : inj_text_vsize;
        if (legit_text_rawsz > inj_text_vsize)
        {
            DbgPrintEx(0, 0, "[td-dv] WARNING: legit .text (%u) > injected .text (%u), partial cover\n",
                       legit_text_rawsz, inj_text_vsize);
        }

        ULONG hook_text_pages = (hook_text_size + PAGE_SIZE - 1) / PAGE_SIZE;

        DbgPrintEx(0, 0, "[td-dv] injected: base=%p .text RVA=0x%X size=0x%X\n",
                   dll_base_va, inj_text_rva, inj_text_vsize);
        DbgPrintEx(0, 0, "[td-dv] hook range: hdr=%u pages, .text=%u pages (legit .text=0x%X)\n",
                   inj_hdr_pages, hook_text_pages, hook_text_size);

        // --- 4. per-page EPT hook: header + .text ---
        //
        // for each page:
        //   a. save injected page content to kernel buffer (shadow)
        //   b. overwrite injected page with legitimate DLL content
        //   c. VMCALL_EPT_SHADOW_PAGE: EPT split
        //
        PVOID page_buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'vDpg');
        ULONG hooked = 0;
        ULONG total_pages = inj_hdr_pages + hook_text_pages;
        ULONG pi;

        if (!page_buf)
        {
            KeUnstackDetachProcess(&dv_apc);
            ObDereferenceObject(dv_proc);
            ExFreePoolWithTag(legit_buf, 'vDlL');
            p->status = (UINT64)STATUS_INSUFFICIENT_RESOURCES;
            irp->IoStatus.Information = sizeof(TD_DLL_DUALVIEW_PARAMS);
            st = STATUS_SUCCESS;
            break;
        }

        for (pi = 0; pi < total_pages; pi++)
        {
            PVOID inj_page_va;
            PUINT8 legit_src;
            ULONG legit_avail;

            if (pi < inj_hdr_pages)
            {
                // PE header page
                inj_page_va = (PUINT8)dll_base_va + pi * PAGE_SIZE;
                legit_src = (PUINT8)legit_buf + pi * PAGE_SIZE;
                legit_avail = (legit_hdr_size > pi * PAGE_SIZE) ? (legit_hdr_size - pi * PAGE_SIZE) : 0;
            }
            else
            {
                // .text page
                ULONG text_pi = pi - inj_hdr_pages;
                inj_page_va = (PUINT8)dll_base_va + inj_text_rva + text_pi * PAGE_SIZE;
                legit_src = (PUINT8)legit_buf + legit_text_rawoff + text_pi * PAGE_SIZE;
                legit_avail = (legit_text_rawsz > text_pi * PAGE_SIZE) ? (legit_text_rawsz - text_pi * PAGE_SIZE) : 0;
            }

            // a. save injected page to kernel buffer (= shadow content for execution)
            RtlCopyMemory(page_buf, inj_page_va, PAGE_SIZE);

            // b. overwrite injected page with legitimate DLL content.
            //    try MDL first (no API call). fallback to ZwProtectVirtualMemory
            //    for pages where MDL IoWriteAccess fails (e.g. image READONLY pages).
            {
                PVOID page_aligned = (PVOID)((UINT64)inj_page_va & ~(PAGE_SIZE - 1));
                BOOLEAN write_ok = FALSE;

                // method 1: MDL (stealthy, no protection change)
                PMDL wmdl = IoAllocateMdl(page_aligned, PAGE_SIZE, FALSE, FALSE, NULL);
                if (wmdl)
                {
                    __try {
                        MmProbeAndLockPages(wmdl, UserMode, IoWriteAccess);
                        PVOID mapped = MmMapLockedPagesSpecifyCache(
                            wmdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
                        if (mapped)
                        {
                            if (legit_avail >= PAGE_SIZE)
                                RtlCopyMemory(mapped, legit_src, PAGE_SIZE);
                            else
                            {
                                if (legit_avail > 0)
                                    RtlCopyMemory(mapped, legit_src, legit_avail);
                                RtlZeroMemory((PUINT8)mapped + legit_avail, PAGE_SIZE - legit_avail);
                            }
                            MmUnmapLockedPages(mapped, wmdl);
                            write_ok = TRUE;
                        }
                        MmUnlockPages(wmdl);
                    } __except (EXCEPTION_EXECUTE_HANDLER) { }
                    IoFreeMdl(wmdl);
                }

                // method 2: fallback — ZwProtectVirtualMemory (for READONLY image pages)
                if (!write_ok)
                {
                    PVOID pb = page_aligned;
                    SIZE_T ps = PAGE_SIZE;
                    ULONG op = 0, tp = 0;
                    if (NT_SUCCESS(ZwProtectVirtualMemory(ZwCurrentProcess(), &pb, &ps,
                                                          PAGE_READWRITE, &op)))
                    {
                        if (legit_avail >= PAGE_SIZE)
                            RtlCopyMemory(inj_page_va, legit_src, PAGE_SIZE);
                        else
                        {
                            if (legit_avail > 0)
                                RtlCopyMemory(inj_page_va, legit_src, legit_avail);
                            RtlZeroMemory((PUINT8)inj_page_va + legit_avail, PAGE_SIZE - legit_avail);
                        }
                        pb = page_aligned; ps = PAGE_SIZE;
                        ZwProtectVirtualMemory(ZwCurrentProcess(), &pb, &ps, op, &tp);
                        write_ok = TRUE;
                    }
                }

                if (!write_ok)
                {
                    DbgPrintEx(0, 0, "[td-dv] write failed for page %u\n", pi);
                    continue;
                }
            }

            // c. get PA (post-write, may have COW'd)
            UINT64 page_pa = MmGetPhysicalAddress(inj_page_va).QuadPart;
            if (!page_pa) continue;

            // d. VMCALL: set up EPT split
            NTSTATUS vmst = hv_vmcall_simple(VMCALL_EPT_SHADOW_PAGE, page_pa, (UINT64)page_buf, 0);
            if (NT_SUCCESS(vmst))
                hooked++;
        }

        ExFreePoolWithTag(page_buf, 'vDpg');
        KeUnstackDetachProcess(&dv_apc);
        ObDereferenceObject(dv_proc);
        ExFreePoolWithTag(legit_buf, 'vDlL');

        p->pages_hooked = (UINT64)hooked;
        p->status = (hooked > 0) ? (UINT64)STATUS_SUCCESS : (UINT64)STATUS_UNSUCCESSFUL;
        irp->IoStatus.Information = sizeof(TD_DLL_DUALVIEW_PARAMS);
        st = STATUS_SUCCESS;

        DbgPrintEx(0, 0, "[td-dv] done: %u/%u pages hooked\n", hooked, total_pages);
        break;
    }

    case IOCTL_PROTECT_DLL:
    {
        //
        // EPT hook LdrUnloadDll in target process — blocks unload of specified DLL.
        // filtering happens entirely in VMX-root (no user-mode proxy needed).
        //
        if (io->Parameters.DeviceIoControl.InputBufferLength < sizeof(TD_PROTECT_DLL_PARAMS) ||
            io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(TD_PROTECT_DLL_PARAMS))
        { st = STATUS_BUFFER_TOO_SMALL; break; }

        TD_PROTECT_DLL_PARAMS * p = (TD_PROTECT_DLL_PARAMS *)irp->AssociatedIrp.SystemBuffer;

        PEPROCESS prot_proc = NULL;
        st = PsLookupProcessByProcessId((HANDLE)p->target_pid, &prot_proc);
        if (!NT_SUCCESS(st)) { p->status = (UINT64)st; st = STATUS_SUCCESS; break; }

        KAPC_STATE prot_apc;
        KeStackAttachProcess(prot_proc, &prot_apc);

        UINT64 prot_cr3 = __readcr3();

        // resolve LdrUnloadDll from target's ntdll
        PVOID ldr_unload_dll = NULL;
        {
            PPEB peb = PsGetProcessPeb(PsGetCurrentProcess());
            TD_PEB_LDR_DATA * ldr = NULL;
            PLIST_ENTRY head = NULL, cur = NULL;
            TD_LDR_ENTRY * e = NULL;

            __try {
                ldr = *(TD_PEB_LDR_DATA **)((PUINT8)peb + 0x18);
                if (ldr)
                {
                    head = &ldr->InMemoryOrderModuleList;
                    cur = head->Flink;
                    while (cur != head)
                    {
                        e = CONTAINING_RECORD(cur, TD_LDR_ENTRY, InMemoryOrderLinks);
                        if (e->BaseDllName.Buffer &&
                            TdMatchDllName(e->BaseDllName.Buffer, e->BaseDllName.Length, g_ntdll_name, 9))
                        {
                            PIMAGE_DOS_HEADER dh = (PIMAGE_DOS_HEADER)e->DllBase;
                            PIMAGE_NT_HEADERS64 nh = (PIMAGE_NT_HEADERS64)((PUINT8)e->DllBase + dh->e_lfanew);
                            ULONG erva = nh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                            PIMAGE_EXPORT_DIRECTORY ed = (PIMAGE_EXPORT_DIRECTORY)((PUINT8)e->DllBase + erva);
                            PULONG na = (PULONG)((PUINT8)e->DllBase + ed->AddressOfNames);
                            PUSHORT oa = (PUSHORT)((PUINT8)e->DllBase + ed->AddressOfNameOrdinals);
                            PULONG fa = (PULONG)((PUINT8)e->DllBase + ed->AddressOfFunctions);
                            ULONG ei;
                            for (ei = 0; ei < ed->NumberOfNames; ei++)
                            {
                                if (strcmp((const char *)((PUINT8)e->DllBase + na[ei]), "LdrUnloadDll") == 0)
                                {
                                    ldr_unload_dll = (PUINT8)e->DllBase + fa[oa[ei]];
                                    break;
                                }
                            }
                            break;
                        }
                        cur = cur->Flink;
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) { }
        }

        if (!ldr_unload_dll)
        {
            KeUnstackDetachProcess(&prot_apc);
            ObDereferenceObject(prot_proc);
            p->status = (UINT64)STATUS_NOT_FOUND;
            irp->IoStatus.Information = sizeof(TD_PROTECT_DLL_PARAMS);
            st = STATUS_SUCCESS;
            break;
        }

        DbgPrintEx(0, 0, "[td] protect: LdrUnloadDll=%p dll_base=%llx pid=%llu\n",
                   ldr_unload_dll, p->dll_base, p->target_pid);

        //
        // EPT hook LdrUnloadDll → itself (trampoline calls original).
        // protect_dll_base passed in flags upper bits.
        // VMX-root filter: RCX == dll_base → return SUCCESS, skip unload.
        //
        KAFFINITY old_aff = KeSetSystemAffinityThreadEx((KAFFINITY)1);  // CPU 0

        PVOID dummy_origin = NULL;
        UINT64 flags = (p->dll_base << 16) | 0;  // upper 48 bits = dll_base, bit 0 = 0

        NTSTATUS hook_st = hv_vmcall_ex(
            VMCALL_EPT_HOOK,
            (UINT64)ldr_unload_dll,     // target
            (UINT64)ldr_unload_dll,     // proxy = same (trampoline calls original for non-match)
            (UINT64)&dummy_origin,      // origin
            prot_cr3,                   // caller CR3
            1,                          // hook_type = VMCALL
            prot_cr3,                   // target_cr3 (per-process)
            0,                          // user_trampoline = NULL
            0,                          // user_trampoline_pa = 0
            flags);                     // flags with protect_dll_base

        KeRevertToUserAffinityThreadEx(old_aff);
        KeUnstackDetachProcess(&prot_apc);
        ObDereferenceObject(prot_proc);

        p->status = (UINT64)hook_st;
        irp->IoStatus.Information = sizeof(TD_PROTECT_DLL_PARAMS);
        st = STATUS_SUCCESS;

        DbgPrintEx(0, 0, "[td] protect: hook %s (st=0x%08X)\n",
                   NT_SUCCESS(hook_st) ? "OK" : "FAILED", hook_st);
        break;
    }

    case IOCTL_READ_R3:
    case IOCTL_WRITE_R3:
    {
        if (io->Parameters.DeviceIoControl.InputBufferLength < sizeof(TD_RW_R3_PARAMS) ||
            io->Parameters.DeviceIoControl.OutputBufferLength < sizeof(TD_RW_R3_PARAMS))
        { st = STATUS_BUFFER_TOO_SMALL; break; }

        TD_RW_R3_PARAMS * p = (TD_RW_R3_PARAMS *)irp->AssociatedIrp.SystemBuffer;
        BOOLEAN is_write = (io->Parameters.DeviceIoControl.IoControlCode == IOCTL_WRITE_R3);

        if (!p->target_va || !p->size || p->size > PAGE_SIZE || !p->buffer_va)
        { p->status = (UINT64)STATUS_INVALID_PARAMETER; st = STATUS_SUCCESS; break; }

        // look up target process CR3
        PEPROCESS rw_proc = NULL;
        st = PsLookupProcessByProcessId((HANDLE)p->target_pid, &rw_proc);
        if (!NT_SUCCESS(st)) { p->status = (UINT64)st; st = STATUS_SUCCESS; break; }

        //
        // get target process CR3 by briefly attaching.
        // (EPROCESS.DirectoryTableBase is at different offsets per build,
        //  attaching + __readcr3 is the most reliable way)
        //
        KAPC_STATE rw_apc;
        KeStackAttachProcess(rw_proc, &rw_apc);
        UINT64 target_cr3 = __readcr3();
        KeUnstackDetachProcess(&rw_apc);

        //
        // kernel NonPaged buffer for VMCALL (user buffer may not be mapped
        // under target CR3 — we're reading caller's buffer, not target's)
        //
        PVOID kbuf = ExAllocatePool2(POOL_FLAG_NON_PAGED, (SIZE_T)p->size, 'r3RW');
        if (!kbuf)
        {
            ObDereferenceObject(rw_proc);
            p->status = (UINT64)STATUS_INSUFFICIENT_RESOURCES;
            st = STATUS_SUCCESS;
            break;
        }

        if (is_write)
        {
            // copy from user buffer to kernel buffer first
            __try {
                RtlCopyMemory(kbuf, (PVOID)p->buffer_va, (SIZE_T)p->size);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                ExFreePoolWithTag(kbuf, 'r3RW');
                ObDereferenceObject(rw_proc);
                p->status = (UINT64)STATUS_ACCESS_VIOLATION;
                st = STATUS_SUCCESS;
                break;
            }
        }

        //
        // VMCALL — VMX-root switches to target_cr3, reads/writes directly.
        // no syscall, no handle, no attach. invisible to ring 0/3 monitoring.
        //
        NTSTATUS rw_st = hv_vmcall_ex(
            is_write ? VMCALL_WRITE_R3 : VMCALL_READ_R3,
            target_cr3,
            p->target_va,
            (UINT64)kbuf,
            p->size,
            0, 0, 0, 0, 0);

        if (NT_SUCCESS(rw_st) && !is_write)
        {
            // copy from kernel buffer to user buffer
            __try {
                RtlCopyMemory((PVOID)p->buffer_va, kbuf, (SIZE_T)p->size);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                rw_st = STATUS_ACCESS_VIOLATION;
            }
        }

        //
        // if page not resident, try page-in from guest mode and retry
        //
        if (rw_st == (NTSTATUS)0xC0000225ULL)  // STATUS_NOT_FOUND (page not resident)
        {
            KeStackAttachProcess(rw_proc, &rw_apc);
            MmIsAddressValid((PVOID)(ULONG_PTR)p->target_va);  // triggers soft page-in
            KeUnstackDetachProcess(&rw_apc);

            // retry VMCALL
            rw_st = hv_vmcall_ex(
                is_write ? VMCALL_WRITE_R3 : VMCALL_READ_R3,
                target_cr3, p->target_va, (UINT64)kbuf, p->size,
                0, 0, 0, 0, 0);

            if (NT_SUCCESS(rw_st) && !is_write)
            {
                __try {
                    RtlCopyMemory((PVOID)p->buffer_va, kbuf, (SIZE_T)p->size);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    rw_st = STATUS_ACCESS_VIOLATION;
                }
            }
        }

        RtlSecureZeroMemory(kbuf, (SIZE_T)p->size);
        ExFreePoolWithTag(kbuf, 'r3RW');
        ObDereferenceObject(rw_proc);

        p->status = (UINT64)rw_st;
        irp->IoStatus.Information = sizeof(TD_RW_R3_PARAMS);
        st = STATUS_SUCCESS;
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
        DbgPrintEx(0, 0, "[td] Unhooking R0 hook before unload...\n");
        TdEptUnhookNtCreateFile();
    }

    TdEptUnhookAllR3();

    if (g_image_callback_registered)
    {
        PsRemoveLoadImageNotifyRoutine(TdLoadImageCallback);
        g_image_callback_registered = FALSE;
    }

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

    // set LDRP_IMAGE_INTEGRITY_FORCED on our driver module.
    // without this, PsSetLoadImageNotifyRoutine fails on Win10 1607+
    // for test-signed / unsigned drivers (integrity check).
    {
        typedef struct _KLDR_DATA_TABLE_ENTRY {
            LIST_ENTRY InLoadOrderLinks;
            PVOID ExceptionTable;
            ULONG ExceptionTableSize;
            PVOID GpValue;
            PVOID NonPagedDebugInfo;
            PVOID DllBase;
            PVOID EntryPoint;
            ULONG SizeOfImage;
            UNICODE_STRING FullDllName;
            UNICODE_STRING BaseDllName;
            ULONG Flags;
        } KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

        PKLDR_DATA_TABLE_ENTRY pLdrData = (PKLDR_DATA_TABLE_ENTRY)drv->DriverSection;
        if (pLdrData)
            pLdrData->Flags |= 0x20;  // LDRP_IMAGE_INTEGRITY_FORCED
    }

    // register LoadImage callback early — before AC drivers load.
    if (NT_SUCCESS(PsSetLoadImageNotifyRoutine(TdLoadImageCallback)))
    {
        g_image_callback_registered = TRUE;
        DbgPrintEx(0, 0, "[td] LoadImage callback registered (early)\n");
    }

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

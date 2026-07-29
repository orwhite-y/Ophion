/*
*   td_common.h - shared declarations for TestDriver (split from test_driver.cpp)
*/
#pragma once

// ---- includes ----
#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>
#include <ntimage.h>
#include "log.h"


// ---- extern "C" kernel APIs ----
extern "C" {
    // ---- undocumented PEB structures for user-mode module walk ----
    
    extern "C" NTKERNELAPI PPEB PsGetProcessPeb(PEPROCESS Process);
    extern "C" NTKERNELAPI NTSTATUS PsGetProcessExitStatus(PEPROCESS Process);
    extern "C" NTSYSAPI NTSTATUS NTAPI ZwProtectVirtualMemory(
    HANDLE ProcessHandle, PVOID * BaseAddress, PSIZE_T RegionSize,
    ULONG NewProtect, PULONG OldProtect);
    extern "C" NTSYSAPI PVOID NTAPI RtlPcToFileHeader(PVOID PcValue, PVOID * BaseOfImage);
    extern "C" NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);
    
}

// ---- typedefs and defines (from original L35-198) ----
typedef ULONG (NTAPI * fn_KeResumeThread)(PKTHREAD Thread);

typedef NTSTATUS (NTAPI * fn_PsResumeThread)(PETHREAD Thread, PULONG PreviousSuspendCount);


typedef struct _TD_SYSTEM_SERVICE_DESCRIPTOR_TABLE {
    PULONG ServiceTableBase;
    PULONG ServiceCounterTableBase;
    ULONG_PTR NumberOfServices;
    PUCHAR ParamTableBase;
} TD_SYSTEM_SERVICE_DESCRIPTOR_TABLE, *PTD_SYSTEM_SERVICE_DESCRIPTOR_TABLE;

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
} TD_LDR_ENTRY, *PTD_LDR_ENTRY;

typedef struct _TD_PEB_LDR_DATA {
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
} TD_PEB_LDR_DATA;

// ---- VMCALL interface (must match Ophion hv_types.h) ----

#define VMCALL_STEALTH_ALLOC    0x00000006
#define VMCALL_STEALTH_FREE     0x00000007
#define VMCALL_EPT_HOOK_INJECT  0x00000008
#define VMCALL_EPT_SET_EXTERNAL_FIRED 0x00000009
#define VMCALL_EPT_UNHOOK_BY_CR3 0x0000000A   // retire all R3 hooks for a CR3 (no CR3 switch - safe from process-exit callback)

//
// EPT hook inject param 闂?pre-built at PASSIVE_LEVEL, passed to VMX-root.
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
    UINT64  target_pid;
    PVOID   target_va;
    PVOID   handler_function;
    UINT64  target_phys;
    PVOID   shellcode_buffer;
    UINT32  shellcode_size;
    BOOLEAN resident;
    BOOLEAN intercept_write;
    //
    // pre-computed guest PT info (filled at PASSIVE/DISPATCH level).
    // avoids MmGetVirtualForPhysical (pa_to_va) in VMX-root which deadlocks
    // when KeGenericCallDpc puts all CPUs into VMX-root simultaneously.
    //
    UINT64  pt_page_pfn;        // PFN of guest PT page containing target PTE
    UINT32  pt_pte_index;       // index within PT page (0-511)
    PVOID   pt_page_copy;       // NonPaged buffer with PT page content (4KB)
    PVOID   pt_page_va;         // shadow mode: shadow PT page VA; else real PT page VA (for MTF resync)
    PVOID   target_page_copy;   // NonPaged buffer with target page content (4KB)
    BOOLEAN pt_precomputed;     // TRUE = caller filled above fields at PASSIVE_LEVEL
    BOOLEAN use_fake_pt;        // TRUE = create fake PT page (NX hiding)
    UINT64  shadow_cr3_phys;    // physical address of shadow PML4 (0 = no shadow CR3)
    BOOLEAN no_ept_split;       // TRUE = shadow CR3 only, keep target EPT mapping unchanged
    PVOID   shadow_pte_va;      // VA of this page's shadow PTE (NonPaged pool, computed via TdResolveShadowPte at PASSIVE); HV writes it directly on #PF (NULL = none)
    PVOID   real_page_map;      // ptr to STEALTH_REAL_PAGE_ENTRY[real_page_count] (MDL-mapped real PT pages, NULL = none)
    UINT32  real_page_count;    // number of entries in real_page_map
    volatile LONG installed;
    BOOLEAN result;
} TD_STEALTH_PARAM;
#pragma pack(pop)

#define PFN_MASK_  0x000FFFFFFFFFF000ULL
#define NX_BIT_    (1ULL << 63)

extern "C" {
    NTSTATUS hv_vmcall_ex(UINT64 vmcall_reason, UINT64 param1, UINT64 param2, UINT64 param3, UINT64 param4, UINT64 param5, UINT64 param6, UINT64 param7, UINT64 param8, UINT64 param9);
    NTSTATUS hv_vmcall_simple(UINT64 vmcall_reason, UINT64 param1, UINT64 param2, UINT64 param3);
    NTSYSCALLAPI NTSTATUS NTAPI RtlCreateUserThread(HANDLE ProcessHandle, PSECURITY_DESCRIPTOR SecurityDescriptor, BOOLEAN CreateSuspended, ULONG StackZeroBits, SIZE_T StackReserve, SIZE_T StackCommit, PVOID StartAddress, PVOID Parameter, PHANDLE ThreadHandle, PCLIENT_ID ClientId);
    NTKERNELAPI VOID KeGenericCallDpc(PKDEFERRED_ROUTINE Routine, PVOID Context);
    NTKERNELAPI VOID KeSignalCallDpcDone(PVOID SystemArgument1);
    NTKERNELAPI LOGICAL KeSignalCallDpcSynchronize(PVOID SystemArgument2);
}


// ---- shadow CR3 types (from shadow section) ----
#define MAX_SHADOW_PAGES_PER_CR3 256
#define MAX_SHADOW_CR3_ALLOCS    64
typedef struct _STEALTH_REAL_PAGE_ENTRY {
    UINT64  pa;     // physical address (page-aligned) of a real guest PT page
    PVOID   va;     // MmMapLockedPagesSpecifyCache system VA, valid under g_system_cr3
    PVOID   mdl;    // PMDL for this page (TestDriver-only; HV ignores it)
} STEALTH_REAL_PAGE_ENTRY, *PSTEALTH_REAL_PAGE_ENTRY;

#define MAX_REAL_PAGES_PER_SHADOW  64   // PML4 + PDPT + PDs + PTs along the range

typedef struct _TD_SHADOW_BUILD_CONTEXT {
    PVOID  pages[MAX_SHADOW_PAGES_PER_CR3];
    UINT32 page_count;
    STEALTH_REAL_PAGE_ENTRY real_pages[MAX_REAL_PAGES_PER_SHADOW];
    UINT32 real_page_count;
} TD_SHADOW_BUILD_CONTEXT;

typedef struct _TD_SHADOW_CR3_ALLOCATION {
    BOOLEAN active;
    UINT64  shadow_cr3_phys;
    UINT32  page_count;
    PVOID   pages[MAX_SHADOW_PAGES_PER_CR3];
    PSTEALTH_REAL_PAGE_ENTRY real_page_map;  // NonPaged buffer shared with HV (NULL = none)
    UINT32  real_page_count;
    LONG    refcount;     // #tracked ranges sharing this CR3 (multi-range per process); freed at 0
} TD_SHADOW_CR3_ALLOCATION;


// ---- inject target types ----
#ifndef TD_INJECT_TARGET_NAME
#define TD_INJECT_TARGET_NAME   L"Box.exe"
#endif
#ifndef TD_INJECT_LOADER_NAME
#define TD_INJECT_LOADER_NAME   L"ophion_loader.dll"
#endif
#ifndef MAX_PATH
#define MAX_PATH 260
#endif
#define TD_MAX_INJECT_TARGETS 16
typedef struct _TD_INJECT_TARGET {
    HANDLE  pid;
    BOOLEAN active;
    BOOLEAN injected;
    WCHAR   loader_nt_path[MAX_PATH];
} TD_INJECT_TARGET;


// ---- self PE info types ----
#define TD_SELF_PE_INFO_MAX 16
typedef struct _TD_SELF_PE_INFO_ENTRY {
    UINT64 pid;
    UINT64 module_base;
    UINT64 rsrc_rva;
    UINT64 rsrc_size;
    UINT64 export_dir_rva;
    UINT64 export_dir_size;
    UINT64 size_of_image;
} TD_SELF_PE_INFO_ENTRY;


// ---- thread creation types ----
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001
typedef NTSTATUS (NTAPI * fn_ZwCreateThreadEx)(
PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE,
PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);


typedef NTSTATUS (NTAPI * fn_ZwResumeThread)(HANDLE, PULONG);


// ---- IOCTL defines and param structs ----
#define TD_DEVICE_NAME  L"\\Device\\OphionTest"
#define TD_SYMLINK_NAME L"\\DosDevices\\OphionTest"

#define TD_IOCTL_BASE   0x900
#define IOCTL_INJECT    CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EPT_HOOK    CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EPT_UNHOOK  CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EPT_HOOK_R3 CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EPT_UNHOOK_R3 CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_RESOLVE_EXPORT CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 12, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_MODULE_BASE CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 13, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HIDE_DEVICE     CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 14, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_SELF_PE_INFO CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 15, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INJECT_RENDERDOC  CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 16, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 8)
typedef struct _TD_RESOLVE_EXPORT_PARAMS {
    UINT64 target_pid;          // [in]  target process PID
    UINT64 messageboxa_va;      // [out] user32!MessageBoxA VA in target process
    UINT64 sleepex_va;          // [out] kernel32!SleepEx VA in target process
    UINT64 status;              // [out] NTSTATUS
} TD_RESOLVE_EXPORT_PARAMS;

typedef struct _TD_GET_MODULE_BASE_PARAMS {
    UINT64 target_pid;          // [in]  target process PID
    char   module_name[256];    // [in]  module name (e.g. "user32.dll"), ASCII, null-terminated
    UINT64 module_base;         // [out] base address of the module (0 = not found)
    UINT64 module_size;         // [out] size of image in bytes
    UINT64 status;              // [out] NTSTATUS
} TD_GET_MODULE_BASE_PARAMS;

// Query cached PE info for a manually-mapped renderdoc module whose headers
// were erased after mapping. The driver caches this at map time (before
// erasure); R3 queries it to walk .rsrc / resolve exports post-erasure.
typedef struct _TD_GET_SELF_PE_INFO_PARAMS {
    UINT64 target_pid;          // [in]  caller process PID
    UINT64 module_base;         // [in]  renderdoc mapped base
    UINT64 rsrc_rva;            // [out] DataDirectory[RESOURCE].VirtualAddress
    UINT64 rsrc_size;           // [out] DataDirectory[RESOURCE].Size
    UINT64 export_dir_rva;      // [out] DataDirectory[EXPORT].VirtualAddress
    UINT64 export_dir_size;     // [out] DataDirectory[EXPORT].Size
    UINT64 size_of_image;       // [out] OptionalHeader.SizeOfImage
    UINT64 status;              // [out] NTSTATUS (0 = ok)
} TD_GET_SELF_PE_INFO_PARAMS;

typedef struct _TD_INJECT_PARAMS {
    UINT64 target_pid;
    UINT64 alloc_size;
    UINT64 trigger_va;      // [in]  R3 function to hook as trigger (0 = auto NtTestAlert)
    UINT64 shellcode_va;    // [out]
    UINT64 actual_size;     // [out]
} TD_INJECT_PARAMS;

//
// R3 renderdoc shadow-inject params (must match Injector/inject_renderdoc.cpp).
// renderdoc_path is an NT path like "\??\C:\dir\renderdoc.dll".
//
#pragma pack(push, 8)
typedef struct _TD_INJECT_RENDERDOC_PARAMS {
    UINT64 target_pid;          // [in]  target process PID
    WCHAR  renderdoc_path[520]; // [in]  NT path to renderdoc.dll (null-terminated)
    UINT64 status;              // [out] NTSTATUS from TdInjectRenderdocShadow (0 = ok)
} TD_INJECT_RENDERDOC_PARAMS;
#pragma pack(pop)

//
// R3 EPT hook params 闂?from user-mode app via DeviceIoControl
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


// ---- DPC types ----
#define TD_MAX_DPC_CPUS 64
#define TD_STEALTH_DPC_TAG 'dStT'
#define TD_STEALTH_REQ_TAG 'rStT'
typedef struct _TD_STEALTH_ALLOC_DPC_CTX {
    KEVENT           done_event;
    KDPC             dpcs[TD_MAX_DPC_CPUS];
    TD_STEALTH_PARAM * req;
    PVOID            pt_buf;
    PVOID            tgt_buf;
    volatile LONG    pending_count;
    volatile LONG    ref_count;
    volatile LONG    success_count;
    volatile LONG    failure_count;
    volatile LONG    cleanup_on_complete;
} TD_STEALTH_ALLOC_DPC_CTX;


// ---- EPT hook types ----
#define VMCALL_EPT_HOOK     0x00000003
#define VMCALL_EPT_UNHOOK   0x00000004
typedef NTSTATUS (NTAPI * fn_NtCreateFile)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
    PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);

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

#define TD_PERCPU_VMCALL_TAG 'cVdT'
typedef enum _TD_PERCPU_VMCALL_OP {
    TdPerCpuVmcallHookTrigger = 1,
    TdPerCpuVmcallUnhook      = 2,
} TD_PERCPU_VMCALL_OP;

typedef struct _TD_PERCPU_VMCALL_CTX {
    KEVENT                done_event;
    KDPC                  dpcs[TD_MAX_DPC_CPUS];
    TD_PERCPU_VMCALL_OP   op;
    volatile LONG         pending_count;
    volatile LONG         success_count;
    volatile LONG         failure_count;
    volatile LONG         first_failure;
    ULONG                 cpu_count;
    PVOID                 target;
    PVOID                 proxy;
    PVOID *               origin;
    UINT64                caller_cr3;
    UINT32                hook_type;
    UINT64                target_cr3;
    PVOID                 user_trampoline;
    UINT64                user_trampoline_pa;
    UINT64                flags;
    UINT64                expected_tid;
} TD_PERCPU_VMCALL_CTX;


// ---- IOCTL additional defines ----
#define IOCTL_INJECT_DLL CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 5, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INJECT_RW  CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INJECT_RW_SHADOW CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ALLOC_SHADOW_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 8, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INSTALL_TRIGGER_JUMP CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 9, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FREE_SHADOW_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 10, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SHADOW_PROTECT_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 11, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define TD_MAX_INJECT_RW_SIZE (16ULL * 1024ULL * 1024ULL)

#pragma pack(push, 8)
typedef struct _TD_INJECT_RW_PARAMS {
    UINT64 target_pid;
    UINT64 trigger_va;      // [in]  R3 function to hook as trigger (0 = auto)
    UINT64 shellcode_va;    // [out] allocated VA
    UINT64 alloc_size;      // [out] allocated size
    UINT64 shellcode_size;  // [in] bytes appended after this struct
    UINT64 alloc_protect;   // [in] PAGE_READWRITE/PAGE_WRITECOPY, 0 = PAGE_READWRITE
} TD_INJECT_RW_PARAMS;

typedef struct _TD_ALLOC_SHADOW_MEMORY_PARAMS {
    UINT64 target_pid;      // [in]
    UINT64 size;            // [in/out] requested size, rounded to page size on success
    UINT64 need_execute;    // [in] 0=plain RW allocation, nonzero=shadow CR3 executable view
    UINT64 alloc_protect;   // [in] PAGE_READWRITE/PAGE_WRITECOPY, 0 = PAGE_READWRITE
    UINT64 base_va;         // [out]
    UINT64 shadow_cr3;      // [out] physical address of shadow PML4, 0 for plain RW
    UINT64 status;          // [out] NTSTATUS
} TD_ALLOC_SHADOW_MEMORY_PARAMS;

typedef struct _TD_SHADOW_PROTECT_PARAMS {
    UINT64 target_pid;      // [in]
    UINT64 base_va;         // [in]
    UINT64 size;            // [in/out] requested size, rounded to page size on success
    UINT64 new_protect;     // [in] PAGE_READONLY/PAGE_READWRITE/PAGE_EXECUTE*
    UINT64 old_protect;     // [out] previous shadow view protect, or real PTE protect
    UINT64 shadow_cr3;      // [out] active shadow CR3, 0 if restored to original view
    UINT64 status;          // [out] NTSTATUS
} TD_SHADOW_PROTECT_PARAMS;

typedef struct _TD_TRIGGER_JUMP_PARAMS {
    UINT64 target_pid;      // [in]
    UINT64 trigger_va;      // [in/out] 0 = auto ntdll trigger
    UINT64 jump_to_va;      // [in] destination RIP for VMCALL hook
    UINT64 flags;           // [in] bit1=oneshot, 0 uses default oneshot
    UINT64 target_tid;      // [in] 0 = any thread, non-0 = only this TID
    UINT64 status;          // [out] NTSTATUS
} TD_TRIGGER_JUMP_PARAMS;
#pragma pack(pop)

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


// ---- stealth track types ----
#pragma pack(push, 8)
typedef struct _TD_STEALTH_FREE_PARAM {
    UINT64  caller_cr3;
    PVOID   target_va;
    UINT64  target_phys;
    volatile LONG freed;
    BOOLEAN result;
} TD_STEALTH_FREE_PARAM;
#pragma pack(pop)

//
// track stealth inject allocations for process exit cleanup
//
#define MAX_STEALTH_TRACKS 64
typedef struct _STEALTH_TRACK_ENTRY {
    BOOLEAN active;
    UINT64  target_pid;
    PVOID   target_va;
    SIZE_T  alloc_size;
    UINT64  shadow_cr3_phys;
    PMDL    image_mdl;       // locked image pages (MmProbeAndLockPages), NULL if none
} STEALTH_TRACK_ENTRY;


// ---- vmcall assembly declarations ----
extern "C" {
            NTKERNELAPI VOID    KeGenericCallDpc(PKDEFERRED_ROUTINE, PVOID);
    NTKERNELAPI VOID    KeSignalCallDpcDone(PVOID);
    NTKERNELAPI LOGICAL KeSignalCallDpcSynchronize(PVOID);
}

// ---- file-scope variables (extern) ----
extern fn_KeResumeThread g_pKeResumeThread;
extern fn_PsResumeThread  g_pPsResumeThread;
extern KSPIN_LOCK         g_shadow_alloc_lock;
extern TD_SHADOW_CR3_ALLOCATION g_shadow_allocs[];
extern BOOLEAN g_process_notify_registered;
extern BOOLEAN g_process_notify_ex_registered;
extern TD_INJECT_TARGET g_inject_targets[];
extern KSPIN_LOCK g_inject_target_lock;
extern BOOLEAN g_inject_target_lock_init;
extern BOOLEAN g_loadimage_registered;
extern TD_SELF_PE_INFO_ENTRY g_SelfPeInfoCache[];
extern KSPIN_LOCK g_SelfPeInfoLock;
extern BOOLEAN g_SelfPeInfoLockInit;
extern fn_ZwCreateThreadEx g_pZwCreateThreadEx;
extern fn_ZwResumeThread   g_pZwResumeThread;
extern const WCHAR g_ntdll_name[];
extern const WCHAR g_k32_name[];
extern const UINT8 g_shellcode_pic[];
extern const UINT32 g_shellcode_pic_size;
extern const WCHAR g_user32_name[];
extern const WCHAR g_kernel32_name[];
extern fn_NtCreateFile g_orig_NtCreateFile;
extern PVOID           g_hooked_target;
extern volatile LONG   g_hook_log_count;
extern volatile LONG64 g_test_injected_pid;
extern R3_HOOK_ENTRY g_r3_hooks[];
extern STEALTH_TRACK_ENTRY g_stealth_tracks[];
extern KSPIN_LOCK g_stealth_track_lock;
extern PDEVICE_OBJECT g_dev_obj;
extern BOOLEAN g_device_hidden;

// ---- function prototypes ----
__forceinline BOOLEAN
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

__forceinline BOOLEAN
TdAsciiEqualIBounded(const char * a, const char * b, ULONG max_len)
{
    for (ULONG i = 0; i < max_len; i++)
    {
        char ca = a[i], cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return FALSE;
        if (!ca) return TRUE;
    }
    return FALSE;
}

__forceinline BOOLEAN
TdAsciiStartsWithI(const char * text, const char * prefix)
{
    while (*prefix)
    {
        char ca = *text, cb = *prefix;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return FALSE;
        text++;
        prefix++;
    }
    return TRUE;
}
BOOLEAN TdBuildShellcodePIC(PVOID buf, SIZE_T buf_size);
BOOLEAN TdExtractSyscallIndexFromStub(PVOID stub, PULONG index_out);
BOOLEAN TdInjectBuildLoaderPath(PCUNICODE_STRING exe_path, WCHAR * out, ULONG out_chars);
BOOLEAN TdInjectMatchBasename(PCUNICODE_STRING image, const WCHAR * target, USHORT target_chars);
BOOLEAN TdInjectTargetClaim(HANDLE pid, WCHAR * out_path, ULONG path_chars);
BOOLEAN TdIsTargetProcessName(PEPROCESS proc);
BOOLEAN TdLookupSelfPeInfo(UINT64 pid, UINT64 module_base, TD_SELF_PE_INFO_ENTRY * out);
BOOLEAN TdMatchDllName(const WCHAR * buf, USHORT buf_len, const WCHAR * target, USHORT target_len);
BOOLEAN TdNormalizeShadowProtect(ULONG protect, ULONG * out_protect);
BOOLEAN TdPeCopySections(PVOID mapped_base, PUINT8 raw_dll, SIZE_T raw_size);
BOOLEAN TdPeRelocate(PVOID mapped_base, PUINT8 raw_dll, UINT64 delta);
BOOLEAN TdPeResolveImports(PVOID mapped_base);
BOOLEAN TdResolveGuestPT(UINT64 cr3, UINT64 va, UINT64 * out_pt_pfn, UINT32 * out_pte_idx);
BOOLEAN TdResolveShadowPT(UINT64 shadow_cr3, UINT64 va, UINT64 * out_pt_pfn, UINT32 * out_pte_idx, PVOID * out_pt_va);
BOOLEAN TdResolveUserSyscallIndex(const char * export_name, PULONG index_out);
BOOLEAN TdShadowCr3Release(UINT64 shadow_cr3_phys, UINT64 * out_to_free);
BOOLEAN TdShadowExtendCr3Pages(UINT64 shadow_cr3_phys, TD_SHADOW_BUILD_CONTEXT * ctx);
BOOLEAN TdShadowFreeCr3(UINT64 shadow_cr3_phys);
BOOLEAN TdShadowMapRealPage(TD_SHADOW_BUILD_CONTEXT * ctx, UINT64 pa);
BOOLEAN TdShadowRegisterCr3(UINT64 shadow_cr3_phys, TD_SHADOW_BUILD_CONTEXT * ctx);
BOOLEAN TdStealthFreePage(PVOID target_va);
BOOLEAN TdStealthInjectPages( PVOID base_va, PVOID shellcode, UINT32 shellcode_size, BOOLEAN resident);
BOOLEAN TdStealthTrackAdd(UINT64 pid, PVOID va, SIZE_T size, UINT64 shadow_cr3, PMDL image_mdl = NULL);
BOOLEAN TdStealthTrackFindOverlap(UINT64 pid, PVOID base_va, SIZE_T size, PVOID * out_base, SIZE_T * out_size, UINT64 * out_shadow_cr3);
BOOLEAN TdStealthTrackHasPartialOverlap(UINT64 pid, PVOID base_va, SIZE_T size);
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg);
NTSTATUS NTAPI HookedNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
NTSTATUS TdCreateClose(PDEVICE_OBJECT, PIRP irp);
NTSTATUS TdCreateThread(PEPROCESS process, PVOID entry);
NTSTATUS TdEptHookNtCreateFile(VOID);
NTSTATUS TdEptHookR3( UINT64 target_pid, PVOID target_va, PVOID proxy_va, UINT32 hook_type, PVOID * out_trampoline);
NTSTATUS TdEptUnhookNtCreateFile(VOID);
NTSTATUS TdEptUnhookR3(UINT64 target_pid, PVOID target_va);
NTSTATUS TdInjectRenderdocShadow(PEPROCESS proc, PCUNICODE_STRING renderdoc_path, const char * log_prefix, BOOLEAN wait_for_completion);
NTSTATUS TdInstallTriggerHookAllCpus( PVOID trigger_fn, PVOID proxy_va, UINT64 caller_cr3, UINT64 flags, UINT64 expected_tid, PVOID * origin, volatile LONG * fired_signal);
NTSTATUS TdIoControl(PDEVICE_OBJECT, PIRP irp);
NTSTATUS TdMakeKernelThreadHandle(HANDLE thread_h, HANDLE * kernel_thread_h, UINT64 * thread_id);
NTSTATUS TdManualMapInProcess( PEPROCESS proc, PUINT8 raw_dll, SIZE_T dll_size, PVOID * out_base, PVOID * out_entry);
NTSTATUS TdNtResumeThreadBySSDT(HANDLE thread_h, PULONG previous_count);
NTSTATUS TdReadFileKernel(PCUNICODE_STRING nt_path, PUINT8 * out_buf, SIZE_T * out_size);
NTSTATUS TdResumeThreadHandle(HANDLE thread_h, PULONG previous_count);
NTSTATUS TdRunPerCpuVmcall(TD_PERCPU_VMCALL_CTX * ctx, ULONG timeout_ms);
NTSTATUS TdRunStealthAllocOnCpus(TD_STEALTH_PARAM * req, PVOID pt_buf, PVOID tgt_buf);
NTSTATUS TdStealthAllocPage(UINT64 caller_cr3, PVOID page_va, UINT64 page_phys, PVOID sc_buf, UINT32 sc_size, BOOLEAN resident, UINT64 pt_pfn, UINT32 pt_idx, BOOLEAN use_fake_pt, UINT64 shadow_cr3_phys, BOOLEAN no_ept_split, BOOLEAN intercept_write);
NTSTATUS TdUnhookTriggerAllCpus(PVOID trigger_fn, UINT64 caller_cr3);
PTD_SYSTEM_SERVICE_DESCRIPTOR_TABLE TdGetSSDTBase();
PUINT64 TdMapPhys(UINT64 phys_page);
PUINT64 TdResolveGuestPte(UINT64 cr3, UINT64 va);
PUINT64 TdResolveShadowPte(UINT64 shadow_cr3, UINT64 va);
PVOID TdFindExportByName(PVOID module_base, const char * func_name);
PVOID TdFindExportByNameEx(PVOID module_base, const char * func_name, ULONG depth);
PVOID TdFindExportByOrdinal(PVOID module_base, USHORT ordinal);
PVOID TdFindGapInProcess(SIZE_T min_size, ULONG * out_offset, ULONG * out_avail);
PVOID TdFindModuleBaseA(const char * name_ascii, ULONG * out_size);
PVOID TdFindSectionPadding(PVOID image_base, SIZE_T min_size, ULONG * out_offset, ULONG * out_avail);
PVOID TdGetNtoskrnlBase(ULONG * image_size);
PVOID TdGetSSDTEntry(ULONG index);
PVOID TdResolveDefaultTrigger(PEPROCESS proc, const char * log_prefix);
PVOID TdResolveNtoskrnlExport(const char * func_name);
PVOID TdSearchPattern(const UCHAR * pattern, UCHAR wildcard, SIZE_T length, PUCHAR base, SIZE_T size);
PVOID TdShadowAllocPage(TD_SHADOW_BUILD_CONTEXT * ctx);
PVOID TdShadowVaFromPhys(UINT64 phys);
R3_HOOK_ENTRY * R3HookFind(UINT64 pid, PVOID target_va);
R3_HOOK_ENTRY * R3HookFindFree(VOID);
UINT32 TdBuildDllMainStub(PVOID stub_addr, UINT64 image_base, UINT64 entry_point, UINT64 rtl_add_function_table_va, UINT64 pdata_va, UINT32 pdata_count);
UINT64 TdBuildShadowCR3(UINT64 cr3, UINT64 base_va, SIZE_T size);
UINT64 TdExtendShadowCR3(UINT64 shadow_cr3_phys, UINT64 cr3, UINT64 base_va, SIZE_T size);
UINT64 TdStealthFindShadowCr3ForPid(UINT64 pid);
UINT64 TdStealthTrackRemove(UINT64 pid, PVOID va, PMDL * out_mdl = NULL);
ULONG TdGetPreviousModeOffset();
ULONG TdProtectFromPte(UINT64 pte);
VOID DpcEptHook(PKDPC Dpc, PVOID Ctx, PVOID A1, PVOID A2);
VOID DpcEptHookR3(PKDPC Dpc, PVOID Ctx, PVOID A1, PVOID A2);
VOID DpcEptUnhook(PKDPC Dpc, PVOID Ctx, PVOID A1, PVOID A2);
VOID DpcEptUnhookByCr3(PKDPC Dpc, PVOID Ctx, PVOID A1, PVOID A2);
VOID TdApplyProtectToPte(PUINT64 pte, ULONG protect);
void TdCacheSelfPeInfo(UINT64 pid, UINT64 module_base, PIMAGE_NT_HEADERS64 nt);
void TdCleanupSelfPeInfo(UINT64 pid);
VOID TdCleanupStealthForProcess(PEPROCESS Process, UINT64 pid);
VOID TdCloseCreatedThreadHandle(HANDLE thread_h, BOOLEAN thread_started);
VOID TdEptUnhookAllR3(VOID);
VOID TdFlushAddressRange(UINT64 base_va, SIZE_T size, UINT64 target_cr3, UINT64 shadow_cr3);
VOID TdFlushAddressRangeForCr3(UINT64 base, UINT64 size, UINT64 cr3);
VOID TdHideFromPsLoadedModuleList(PDRIVER_OBJECT drv);
void TdInjectTargetAdd(HANDLE pid, PCUNICODE_STRING exe_path);
void TdInjectTargetRemove(HANDLE pid);
VOID TdLoadImageNotify(PUNICODE_STRING ImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo);
VOID TdPerCpuVmcallDpc(PKDPC Dpc, PVOID Ctx, PVOID, PVOID);
VOID TdProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);
VOID TdProcessNotifyLegacy(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create);
VOID TdShadowCr3AddRef(UINT64 shadow_cr3_phys);
VOID TdShadowFreePageList(PVOID * pages, UINT32 page_count);
VOID TdShadowGetRealMap(UINT64 shadow_cr3_phys, PVOID * out_map, UINT32 * out_count);
VOID TdShadowUnmapRealPage(STEALTH_REAL_PAGE_ENTRY * e);
VOID TdStealthAllocDpc(PKDPC Dpc, PVOID Ctx, PVOID, PVOID);
VOID TdStealthAllocReleaseCtx(TD_STEALTH_ALLOC_DPC_CTX * ctx);
VOID TdUnload(PDRIVER_OBJECT drv);


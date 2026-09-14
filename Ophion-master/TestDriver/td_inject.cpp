#include "td_common.h"
#include "td_memload_shellcode.h"

// =========================================================================
//  inject target tracking (for LoadImage callback)
// =========================================================================

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

TD_INJECT_TARGET g_inject_targets[TD_MAX_INJECT_TARGETS];
KSPIN_LOCK g_inject_target_lock;
BOOLEAN g_inject_target_lock_init = FALSE;
BOOLEAN g_loadimage_registered = FALSE;

// match the basename of a full image path against a wide name (case-insensitive)
BOOLEAN TdInjectMatchBasename(PCUNICODE_STRING image, const WCHAR * target, USHORT target_chars)
{
    if (!image || !image->Buffer || !target) return FALSE;
    const WCHAR * buf = image->Buffer;
    USHORT len = image->Length / sizeof(WCHAR);
    USHORT base_off = 0;
    for (USHORT i = 0; i < len; i++)
        if (buf[i] == L'\\') base_off = (USHORT)(i + 1);
    USHORT base_len = (USHORT)(len - base_off);
    if (base_len != target_chars) return FALSE;
    const WCHAR * b = buf + base_off;
    for (USHORT i = 0; i < target_chars; i++)
    {
        WCHAR ca = b[i], cb = target[i];
        if (ca >= L'a' && ca <= L'z') ca -= 32;
        if (cb >= L'a' && cb <= L'z') cb -= 32;
        if (ca != cb) return FALSE;
    }
    return TRUE;
}

// Build the loader NT path from the target exe full path:
//   "\??\C:\dir\Box.exe" -> "\??\C:\dir\ophion_loader.dll"
BOOLEAN TdInjectBuildLoaderPath(PCUNICODE_STRING exe_path, WCHAR * out, ULONG out_chars)
{
    if (!exe_path || !exe_path->Buffer || !out || out_chars < 8) return FALSE;
    const WCHAR * src = exe_path->Buffer;
    USHORT src_chars = exe_path->Length / sizeof(WCHAR);
    if (src_chars == 0 || src_chars >= out_chars) return FALSE;
    USHORT last_slash = 0;
    for (USHORT i = 0; i < src_chars; i++)
    {
        out[i] = src[i];
        if (src[i] == L'\\') last_slash = (USHORT)(i + 1);
    }
    static const WCHAR loader[] = TD_INJECT_LOADER_NAME;
    USHORT loader_chars = (USHORT)((sizeof(loader) / sizeof(WCHAR)) - 1);
    if ((ULONG)last_slash + loader_chars + 1 > out_chars) return FALSE;
    for (USHORT i = 0; i < loader_chars; i++) out[last_slash + i] = loader[i];
    out[last_slash + loader_chars] = L'\0';
    return TRUE;
}

void TdInjectTargetAdd(HANDLE pid, PCUNICODE_STRING exe_path)
{
    KIRQL old;
    KeAcquireSpinLock(&g_inject_target_lock, &old);
    for (ULONG i = 0; i < TD_MAX_INJECT_TARGETS; i++)
    {
        if (!g_inject_targets[i].active)
        {
            g_inject_targets[i].pid = pid;
            g_inject_targets[i].injected = FALSE;
            if (TdInjectBuildLoaderPath(exe_path, g_inject_targets[i].loader_nt_path, MAX_PATH))
                g_inject_targets[i].active = TRUE;
            KeReleaseSpinLock(&g_inject_target_lock, old);
            HYPERPLATFORM_LOG_INFO("[td-inj] target recorded: pid=%llu loader=%ws",
                (UINT64)pid, g_inject_targets[i].loader_nt_path);
            return;
        }
    }
    KeReleaseSpinLock(&g_inject_target_lock, old);
}

void TdInjectTargetRemove(HANDLE pid)
{
    KIRQL old;
    KeAcquireSpinLock(&g_inject_target_lock, &old);
    for (ULONG i = 0; i < TD_MAX_INJECT_TARGETS; i++)
    {
        if (g_inject_targets[i].active && g_inject_targets[i].pid == pid)
        {
            g_inject_targets[i].active = FALSE;
            g_inject_targets[i].injected = FALSE;
            break;
        }
    }
    KeReleaseSpinLock(&g_inject_target_lock, old);
}

// claim a not-yet-injected target; copies loader path out under the lock.
BOOLEAN TdInjectTargetClaim(HANDLE pid, WCHAR * out_path, ULONG path_chars)
{
    BOOLEAN claimed = FALSE;
    KIRQL old;
    KeAcquireSpinLock(&g_inject_target_lock, &old);
    for (ULONG i = 0; i < TD_MAX_INJECT_TARGETS; i++)
    {
        if (g_inject_targets[i].active && !g_inject_targets[i].injected && g_inject_targets[i].pid == pid)
        {
            g_inject_targets[i].injected = TRUE;
            if (out_path && path_chars)
            {
                ULONG j = 0;
                for (; j < path_chars - 1 && g_inject_targets[i].loader_nt_path[j]; j++)
                    out_path[j] = g_inject_targets[i].loader_nt_path[j];
                out_path[j] = L'\0';
            }
            claimed = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_inject_target_lock, old);
    return claimed;
}

// ---------------------------------------------------------------------------
// Per-process cached PE info for manually-mapped renderdoc.
// TdManualMapInProcess caches the resource + export directory RVAs (read from
// the intact raw_dll NT headers) before the mapped image's headers are erased.
// R3 queries it via IOCTL_GET_SELF_PE_INFO to walk .rsrc / resolve exports
// post-erasure. Freed at process exit (TdCleanupSelfPeInfo).
// ---------------------------------------------------------------------------
#define TD_SELF_PE_INFO_MAX 16

TD_SELF_PE_INFO_ENTRY g_SelfPeInfoCache[TD_SELF_PE_INFO_MAX];
KSPIN_LOCK g_SelfPeInfoLock;
BOOLEAN g_SelfPeInfoLockInit = FALSE;

// Cache PE info (read from intact raw_dll NT headers) for (pid, mapped base).
// Called from TdManualMapInProcess before header erasure.
void TdCacheSelfPeInfo(UINT64 pid, UINT64 module_base, PIMAGE_NT_HEADERS64 nt)
{
    if (!pid || !module_base || !nt) return;
    KIRQL old;
    KeAcquireSpinLock(&g_SelfPeInfoLock, &old);
    // Overwrite an existing entry for (pid, module_base); else take first free slot.
    ULONG slot = TD_SELF_PE_INFO_MAX;
    for (ULONG i = 0; i < TD_SELF_PE_INFO_MAX; i++)
    {
        if (g_SelfPeInfoCache[i].pid == pid &&
            g_SelfPeInfoCache[i].module_base == module_base)
        {
            slot = i;
            break;
        }
        if (slot == TD_SELF_PE_INFO_MAX && g_SelfPeInfoCache[i].pid == 0)
            slot = i;
    }
    if (slot < TD_SELF_PE_INFO_MAX)
    {
        g_SelfPeInfoCache[slot].pid = pid;
        g_SelfPeInfoCache[slot].module_base = module_base;
        g_SelfPeInfoCache[slot].rsrc_rva =
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
        g_SelfPeInfoCache[slot].rsrc_size =
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
        g_SelfPeInfoCache[slot].export_dir_rva =
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        g_SelfPeInfoCache[slot].export_dir_size =
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        g_SelfPeInfoCache[slot].size_of_image = nt->OptionalHeader.SizeOfImage;
    }
    KeReleaseSpinLock(&g_SelfPeInfoLock, old);
}

// Look up cached PE info for (pid, module_base). Returns TRUE and fills *out.
BOOLEAN TdLookupSelfPeInfo(UINT64 pid, UINT64 module_base, TD_SELF_PE_INFO_ENTRY * out)
{
    if (!pid || !module_base || !out) return FALSE;
    BOOLEAN found = FALSE;
    KIRQL old;
    KeAcquireSpinLock(&g_SelfPeInfoLock, &old);
    for (ULONG i = 0; i < TD_SELF_PE_INFO_MAX; i++)
    {
        if (g_SelfPeInfoCache[i].pid == pid &&
            g_SelfPeInfoCache[i].module_base == module_base)
        {
            *out = g_SelfPeInfoCache[i];
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_SelfPeInfoLock, old);
    return found;
}

// Free all cached entries for a process (called at process exit).
void TdCleanupSelfPeInfo(UINT64 pid)
{
    if (!pid) return;
    KIRQL old;
    KeAcquireSpinLock(&g_SelfPeInfoLock, &old);
    for (ULONG i = 0; i < TD_SELF_PE_INFO_MAX; i++)
    {
        if (g_SelfPeInfoCache[i].pid == pid)
            g_SelfPeInfoCache[i].pid = 0;
    }
    KeReleaseSpinLock(&g_SelfPeInfoLock, old);
}

// Read a file from kernel into a NonPaged buffer.
NTSTATUS TdReadFileKernel(PCUNICODE_STRING nt_path, PUINT8 * out_buf, SIZE_T * out_size)
{
    *out_buf = NULL; *out_size = 0;
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, (PUNICODE_STRING)nt_path,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    IO_STATUS_BLOCK iosb = {};
    HANDLE h = NULL;
    NTSTATUS st = ZwCreateFile(&h, GENERIC_READ | SYNCHRONIZE, &oa, &iosb, NULL,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
    if (!NT_SUCCESS(st)) return st;

    FILE_STANDARD_INFORMATION fsi = {};
    st = ZwQueryInformationFile(h, &iosb, &fsi, sizeof(fsi), FileStandardInformation);
    if (!NT_SUCCESS(st)) { ZwClose(h); return st; }

    SIZE_T size = (SIZE_T)fsi.EndOfFile.QuadPart;
    if (size == 0 || size > 64 * 1024 * 1024) { ZwClose(h); return STATUS_FILE_TOO_LARGE; }

    PUINT8 buf = (PUINT8)ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'fRdO');
    if (!buf) { ZwClose(h); return STATUS_INSUFFICIENT_RESOURCES; }

    LARGE_INTEGER off = {};
    iosb = {};
    st = ZwReadFile(h, NULL, NULL, NULL, &iosb, buf, (ULONG)size, &off, NULL);
    ZwClose(h);
    if (!NT_SUCCESS(st)) { ExFreePoolWithTag(buf, 'fRdO'); return st; }

    *out_buf = buf;
    *out_size = (SIZE_T)iosb.Information;
    return STATUS_SUCCESS;
}

// ---- assembly VMCALL (vmcall.asm) ----


// ---- undocumented API ----

#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001




fn_ZwCreateThreadEx g_pZwCreateThreadEx = NULL;
fn_ZwResumeThread   g_pZwResumeThread   = NULL;

//
// resolve a function by name from ntoskrnl.exe's export table.
// this finds APIs that MmGetSystemRoutineAddress cannot see
// (e.g. PsResumeThread, KeResumeThread, etc.).
// Blackbone uses the same technique.
//
PVOID
TdResolveNtoskrnlExport(const char * func_name)
{
    static PVOID g_ntoskrnl_base = NULL;
    if (!g_ntoskrnl_base)
    {
        UNICODE_STRING fn_name;
        PVOID known_routine = NULL;
        PVOID image_base = NULL;

        RtlInitUnicodeString(&fn_name, L"NtClose");
        known_routine = (PVOID)MmGetSystemRoutineAddress(&fn_name);
        if (!known_routine)
        {
            RtlInitUnicodeString(&fn_name, L"ZwClose");
            known_routine = (PVOID)MmGetSystemRoutineAddress(&fn_name);
        }

        if (known_routine)
            RtlPcToFileHeader(known_routine, &image_base);

        g_ntoskrnl_base = image_base;
        if (!g_ntoskrnl_base)
        {
            HYPERPLATFORM_LOG_WARN("[td] TdResolveNtoskrnlExport: failed to locate ntoskrnl base");
        }
    }

    if (!g_ntoskrnl_base || !func_name)
        return NULL;

    __try
    {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)g_ntoskrnl_base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return NULL;

        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((PUINT8)g_ntoskrnl_base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
            return NULL;

        ULONG exp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        ULONG exp_sz  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        if (!exp_rva || exp_sz < sizeof(IMAGE_EXPORT_DIRECTORY))
            return NULL;

        PIMAGE_EXPORT_DIRECTORY exp_dir = (PIMAGE_EXPORT_DIRECTORY)((PUINT8)g_ntoskrnl_base + exp_rva);
        PULONG names = (PULONG)((PUINT8)g_ntoskrnl_base + exp_dir->AddressOfNames);
        PUSHORT ords = (PUSHORT)((PUINT8)g_ntoskrnl_base + exp_dir->AddressOfNameOrdinals);
        PULONG funcs = (PULONG)((PUINT8)g_ntoskrnl_base + exp_dir->AddressOfFunctions);

        for (ULONG i = 0; i < exp_dir->NumberOfNames; i++)
        {
            const char * fn = (const char *)((PUINT8)g_ntoskrnl_base + names[i]);
            if (fn && TdAsciiEqualI(fn, func_name))
            {
                USHORT ord = ords[i];
                if (ord < exp_dir->NumberOfFunctions)
                {
                    ULONG func_rva = funcs[ord];
                    if (func_rva >= exp_rva && func_rva < exp_rva + exp_sz)
                        return NULL;  // forwarded export �?skip
                    PVOID resolved = (PUINT8)g_ntoskrnl_base + func_rva;
                    HYPERPLATFORM_LOG_INFO("[td] nt export %s = %p", func_name, resolved);
                    return resolved;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        HYPERPLATFORM_LOG_WARN("[td] TdResolveNtoskrnlExport exception for %s", func_name);
    }

    return NULL;
}

PVOID
TdGetNtoskrnlBase(ULONG * image_size)
{
    static PVOID g_nt_base = NULL;
    static ULONG g_nt_size = 0;

    if (!g_nt_base)
    {
        UNICODE_STRING fn_name;
        PVOID known_routine = NULL;
        PVOID image_base = NULL;

        RtlInitUnicodeString(&fn_name, L"NtClose");
        known_routine = (PVOID)MmGetSystemRoutineAddress(&fn_name);
        if (!known_routine)
        {
            RtlInitUnicodeString(&fn_name, L"ZwClose");
            known_routine = (PVOID)MmGetSystemRoutineAddress(&fn_name);
        }

        if (known_routine)
            RtlPcToFileHeader(known_routine, &image_base);

        if (image_base)
        {
            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)image_base;
            PIMAGE_NT_HEADERS64 nt = NULL;
            if (dos->e_magic == IMAGE_DOS_SIGNATURE)
                nt = (PIMAGE_NT_HEADERS64)((PUINT8)image_base + dos->e_lfanew);
            g_nt_base = image_base;
            if (nt && nt->Signature == IMAGE_NT_SIGNATURE)
                g_nt_size = nt->OptionalHeader.SizeOfImage;
        }
    }

    if (image_size)
        *image_size = g_nt_size;
    return g_nt_base;
}

PVOID
TdSearchPattern(const UCHAR * pattern, UCHAR wildcard, SIZE_T length, PUCHAR base, SIZE_T size)
{
    if (!pattern || !base || !length || size < length)
        return NULL;

    for (SIZE_T i = 0; i <= size - length; i++)
    {
        BOOLEAN match = TRUE;
        for (SIZE_T j = 0; j < length; j++)
        {
            if (pattern[j] != wildcard && base[i + j] != pattern[j])
            {
                match = FALSE;
                break;
            }
        }
        if (match)
            return base + i;
    }

    return NULL;
}

PTD_SYSTEM_SERVICE_DESCRIPTOR_TABLE
TdGetSSDTBase()
{
    static PTD_SYSTEM_SERVICE_DESCRIPTOR_TABLE g_ssdt = NULL;
    if (g_ssdt)
        return g_ssdt;

    PUCHAR nt_base = (PUCHAR)TdGetNtoskrnlBase(NULL);
    if (!nt_base)
        return NULL;

    PIMAGE_DOS_HEADER dos_h = (PIMAGE_DOS_HEADER)nt_base;
    PIMAGE_NT_HEADERS64 nt = NULL;
    if (dos_h->e_magic == IMAGE_DOS_SIGNATURE)
        nt = (PIMAGE_NT_HEADERS64)(nt_base + dos_h->e_lfanew);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    PIMAGE_SECTION_HEADER first_sec = IMAGE_FIRST_SECTION(nt);
    for (USHORT i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER sec = &first_sec[i];
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) ||
            !(sec->Characteristics & IMAGE_SCN_MEM_NOT_PAGED) ||
            (sec->Characteristics & IMAGE_SCN_MEM_DISCARDABLE))
        {
            continue;
        }

        if (*(PULONG)sec->Name == 'TINI' || *(PULONG)sec->Name == 'EGAP')
            continue;

        static const UCHAR pattern[] = {
            0x4C, 0x8D, 0x15, 0xCC, 0xCC, 0xCC, 0xCC,
            0x4C, 0x8D, 0x1D, 0xCC, 0xCC, 0xCC, 0xCC, 0xF7
        };

        PUCHAR found = (PUCHAR)TdSearchPattern(pattern, 0xCC, sizeof(pattern),
            nt_base + sec->VirtualAddress, sec->Misc.VirtualSize);
        if (found)
        {
            g_ssdt = (PTD_SYSTEM_SERVICE_DESCRIPTOR_TABLE)
                (found + *(PLONG)(found + 3) + 7);
            return g_ssdt;
        }
    }

    return NULL;
}

PVOID
TdGetSSDTEntry(ULONG index)
{
    PTD_SYSTEM_SERVICE_DESCRIPTOR_TABLE ssdt = TdGetSSDTBase();
    if (!ssdt || !ssdt->ServiceTableBase || index >= ssdt->NumberOfServices)
        return NULL;

    return (PUCHAR)ssdt->ServiceTableBase + (((PLONG)ssdt->ServiceTableBase)[index] >> 4);
}

ULONG
TdGetPreviousModeOffset()
{
    static ULONG g_prev_mode_offset = 0;
    if (g_prev_mode_offset)
        return g_prev_mode_offset;

    UNICODE_STRING fn_name;
    RtlInitUnicodeString(&fn_name, L"ExGetPreviousMode");
    PUCHAR p = (PUCHAR)MmGetSystemRoutineAddress(&fn_name);
    if (!p)
        return 0;

    for (SIZE_T i = 0; i + 6 < 0x40; i++)
    {
        if (p[i] == 0x0F && p[i + 1] == 0xB6)
        {
            UCHAR modrm = p[i + 2];
            if ((modrm & 0xC0) == 0x80)
            {
                g_prev_mode_offset = *(ULONG UNALIGNED *)(p + i + 3);
                break;
            }
        }
    }

    return g_prev_mode_offset;
}

NTSTATUS
TdResumeThreadHandle(HANDLE thread_h, PULONG previous_count)
{
    if (!thread_h)
        return STATUS_INVALID_PARAMETER;

    ULONG local_prev = 0;
    PULONG prev = previous_count ? previous_count : &local_prev;

    if (g_pZwResumeThread)
        return g_pZwResumeThread(thread_h, prev);

    if (!g_pPsResumeThread && !g_pKeResumeThread)
        return TdNtResumeThreadBySSDT(thread_h, prev);

    PETHREAD thread_obj = NULL;
    NTSTATUS st = ObReferenceObjectByHandle(thread_h, THREAD_ALL_ACCESS,
        *PsThreadType, KernelMode, (PVOID *)&thread_obj, NULL);
    if (!NT_SUCCESS(st))
        return st;

    if (g_pPsResumeThread)
    {
        st = g_pPsResumeThread(thread_obj, prev);
    }
    else if (g_pKeResumeThread)
    {
        *prev = g_pKeResumeThread((PKTHREAD)thread_obj);
        st = STATUS_SUCCESS;
    }
    else
    {
        st = TdNtResumeThreadBySSDT(thread_h, prev);
    }

    ObDereferenceObject(thread_obj);
    return st;
}

NTSTATUS
TdMakeKernelThreadHandle(HANDLE thread_h, HANDLE * kernel_thread_h, UINT64 * thread_id)
{
    if (!thread_h || !kernel_thread_h)
        return STATUS_INVALID_PARAMETER;

    *kernel_thread_h = NULL;
    if (thread_id)
        *thread_id = 0;

    PETHREAD thread_obj = NULL;
    NTSTATUS st = ObReferenceObjectByHandle(thread_h, THREAD_ALL_ACCESS,
        *PsThreadType, KernelMode, (PVOID *)&thread_obj, NULL);
    if (!NT_SUCCESS(st))
        return st;

    if (thread_id)
        *thread_id = (UINT64)(ULONG_PTR)PsGetThreadId(thread_obj);

    st = ObOpenObjectByPointer(
        thread_obj,
        OBJ_KERNEL_HANDLE,
        NULL,
        THREAD_ALL_ACCESS,
        *PsThreadType,
        KernelMode,
        kernel_thread_h);

    ObDereferenceObject(thread_obj);
    return st;
}

VOID
TdCloseCreatedThreadHandle(HANDLE thread_h, BOOLEAN thread_started)
{
    UNREFERENCED_PARAMETER(thread_started);

    if (!thread_h)
        return;

    ZwClose(thread_h);
}

// ---- device / IOCTL ----

// forward declarations for globals defined at driver entry / unload section.
// NOT static - extern matches the non-static definitions below.
extern PDEVICE_OBJECT g_dev_obj;
extern BOOLEAN g_device_hidden;

#define TD_DEVICE_NAME  L"\\Device\\RMCoreTst"
#define TD_SYMLINK_NAME L"\\DosDevices\\RMCoreTst"

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


// Query cached PE info for a manually-mapped renderdoc module whose headers
// were erased after mapping. The driver caches this at map time (before
// erasure); R3 queries it to walk .rsrc / resolve exports post-erasure.


//
// R3 renderdoc shadow-inject params (must match Injector/inject_renderdoc.cpp).
// renderdoc_path is an NT path like "\??\C:\dir\renderdoc.dll".
//
#pragma pack(push, 8)
#pragma pack(pop)

//
// R3 EPT hook params �?from user-mode app via DeviceIoControl
//

#pragma pack(pop)

// ---- MessageBoxA shellcode (x64 PIC) ----
//
// flow:
//   PEB �?kernel32 base �?parse exports �?find GetProcAddress (hash-based)
//   GetProcAddress(kernel32, "LoadLibraryA") �?LoadLibraryA("user32.dll")
//   GetProcAddress(user32, "MessageBoxA") �?MessageBoxA(0, text, title, 0)
//   ret
//
// this shellcode is assembled from the following NASM source:
//
//   bits 64
//   ; --- prologue ---
//   sub rsp, 0x28
//
//   ; --- PEB �?kernel32 ---
//   mov rax, [gs:0x60]        ; PEB
//   mov rax, [rax+0x18]       ; Ldr
//   mov rax, [rax+0x20]       ; InMemoryOrderModuleList head
//   mov rax, [rax]            ; ntdll
//   mov rax, [rax]            ; kernel32
//   mov rbx, [rax+0x20]      ; kernel32 DllBase
//
//   ; --- find_export(rbx=base, r12d=hash) �?rax=funcVA ---
//   ; uses ROR13-add hash of function name
//   ;   GetProcAddress hash = 0x7C0DFCAA
//   ;   LoadLibraryA  hash = 0xEC0E4E8E  (resolved via GetProcAddress)
//   ;   MessageBoxA   hash = 0x1E380A6A  (resolved via GetProcAddress)
//
//   (see byte array below �?hand-assembled and verified)
//

// ---- DLL name matching helpers (used by PIC shellcode + gap finder) ----

extern const WCHAR g_ntdll_name[] = L"ntdll.dll";
extern const WCHAR g_k32_name[]  = L"kernel32.dll";

BOOLEAN TdMatchDllName(const WCHAR * buf, USHORT buf_len, const WCHAR * target, USHORT target_len)
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
extern const UINT8 g_shellcode_pic[] = {
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

extern const UINT32 g_shellcode_pic_size = (UINT32)sizeof(g_shellcode_pic);

#define PIC_PATCH_MESSAGEBOX   6       // offset of pMessageBoxA imm64
#define PIC_PATCH_SLEEPEX      16      // offset of pSleepEx imm64

extern const WCHAR g_user32_name[]  = L"user32.dll";
extern const WCHAR g_kernel32_name[] = L"kernel32.dll";

//
// build PIC shellcode: resolve user32!MessageBoxA + kernel32!SleepEx
// via PEB walk + export table.
// zero runtime API calls �?all resolution done here at PASSIVE_LEVEL.
// must be called while attached to the target process.
//
BOOLEAN
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
//  DPC broadcast �?VMCALL per CPU
// =========================================================================

//
// set up EPT stealth for one page �?single VMCALL from current CPU.
// HV internally loops all g_vcpu[i].ept_page_table to split + set PTE.
// NO KeGenericCallDpc �?avoids 0x101 CLOCK_WATCHDOG when a CPU is
// stuck in VMX-root (Ophion HV pre-existing bug).
//
#ifndef TD_MAX_DPC_CPUS
#define TD_MAX_DPC_CPUS 64
#endif
#define TD_STEALTH_DPC_TAG 'dStT'
#define TD_STEALTH_REQ_TAG 'rStT'


VOID
TdStealthAllocReleaseCtx(TD_STEALTH_ALLOC_DPC_CTX * ctx)
{
    if (_InterlockedDecrement(&ctx->ref_count) != 0)
        return;

    if (ctx->cleanup_on_complete)
    {
        if (ctx->pt_buf)
            ExFreePoolWithTag(ctx->pt_buf, 'htpS');
        if (ctx->tgt_buf)
            ExFreePoolWithTag(ctx->tgt_buf, 'htpS');
        if (ctx->req)
            ExFreePoolWithTag(ctx->req, TD_STEALTH_REQ_TAG);
    }

    ExFreePoolWithTag(ctx, TD_STEALTH_DPC_TAG);
}

VOID
TdStealthAllocDpc(PKDPC Dpc, PVOID Ctx, PVOID, PVOID)
{
    UNREFERENCED_PARAMETER(Dpc);
    TD_STEALTH_ALLOC_DPC_CTX * ctx = (TD_STEALTH_ALLOC_DPC_CTX *)Ctx;
    NTSTATUS st = hv_vmcall_simple(VMCALL_STEALTH_ALLOC, (UINT64)ctx->req, 0, 0);

    if (NT_SUCCESS(st))
        _InterlockedIncrement(&ctx->success_count);
    else
        _InterlockedIncrement(&ctx->failure_count);

    if (_InterlockedDecrement(&ctx->pending_count) == 0)
        KeSetEvent(&ctx->done_event, IO_NO_INCREMENT, FALSE);
    TdStealthAllocReleaseCtx(ctx);
}

NTSTATUS
TdRunStealthAllocOnCpus(TD_STEALTH_PARAM * req, PVOID pt_buf, PVOID tgt_buf)
{
    ULONG active_count = KeQueryActiveProcessorCount(NULL);
    if (active_count == 0)
        return STATUS_UNSUCCESSFUL;
    if (active_count > TD_MAX_DPC_CPUS)
        active_count = TD_MAX_DPC_CPUS;

    TD_STEALTH_ALLOC_DPC_CTX * ctx = (TD_STEALTH_ALLOC_DPC_CTX *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(TD_STEALTH_ALLOC_DPC_CTX), TD_STEALTH_DPC_TAG);
    if (!ctx)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(ctx, sizeof(*ctx));
    ctx->req = req;
    ctx->pt_buf = pt_buf;
    ctx->tgt_buf = tgt_buf;
    ctx->pending_count = (LONG)active_count;
    ctx->ref_count = (LONG)active_count + 1;
    KeInitializeEvent(&ctx->done_event, NotificationEvent, FALSE);

    //
    // Owner-first: the current CPU performs the full install alone.  Only after
    // it publishes the shared stealth-page metadata do the secondary DPCs run.
    // This prevents every CPU from simultaneously taking the VMX-root full-install
    // interlock path (the CLOCK_WATCHDOG_TIMEOUT path seen in the dump).
    //
    NTSTATUS primary_st = hv_vmcall_simple(VMCALL_STEALTH_ALLOC, (UINT64)req, 0, 0);
    if (!NT_SUCCESS(primary_st))
    {
        HYPERPLATFORM_LOG_ERROR("[td-rw] stealth alloc primary failed: st=0x%08X", primary_st);
        ExFreePoolWithTag(ctx, TD_STEALTH_DPC_TAG);
        return primary_st;
    }

    // Every DPC now takes the fast "already installed" branch and only updates
    // its own vCPU EPT.  The owner CPU may be included; repeating its update is
    // harmless and keeps the logic independent of processor numbering.
    for (ULONG cpu = 0; cpu < active_count; cpu++)
    {
        KeInitializeDpc(&ctx->dpcs[cpu], TdStealthAllocDpc, ctx);
        KeSetTargetProcessorDpc(&ctx->dpcs[cpu], (CCHAR)cpu);
        if (!KeInsertQueueDpc(&ctx->dpcs[cpu], NULL, NULL))
        {
            _InterlockedIncrement(&ctx->failure_count);
            if (_InterlockedDecrement(&ctx->pending_count) == 0)
                KeSetEvent(&ctx->done_event, IO_NO_INCREMENT, FALSE);
            TdStealthAllocReleaseCtx(ctx);
        }
    }

    LARGE_INTEGER timeout;
    timeout.QuadPart = -2LL * 1000LL * 10000LL;
    NTSTATUS wait_st = KeWaitForSingleObject(
        &ctx->done_event,
        Executive,
        KernelMode,
        FALSE,
        &timeout);

    if (wait_st == STATUS_TIMEOUT)
    {
        HYPERPLATFORM_LOG_ERROR("[td-rw] stealth alloc timeout: done=%d/%u fail=%d",
            (LONG)(active_count - ctx->pending_count), active_count, ctx->failure_count);
        _InterlockedExchange(&ctx->cleanup_on_complete, 1);
        TdStealthAllocReleaseCtx(ctx);
        return STATUS_IO_TIMEOUT;
    }

    NTSTATUS st = (ctx->failure_count == 0 && ctx->success_count != 0) ?
        STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    TdStealthAllocReleaseCtx(ctx);
    return st;
}

NTSTATUS
TdStealthAllocPage(
    UINT64  caller_cr3,
    PVOID   page_va,        // page-aligned target VA
    UINT64  page_phys,      // physical address of page
    PVOID   sc_buf,         // shellcode chunk for this page (or NULL for resident)
    UINT32  sc_size,        // shellcode size for this page
    BOOLEAN resident,
    UINT64  pt_pfn,         // pre-computed PT page PFN (from TdResolveGuestPT)
    UINT32  pt_idx,         // pre-computed PTE index within PT page
    BOOLEAN use_fake_pt = FALSE,  // TRUE = create fake PT (NX hiding)
    UINT64  shadow_cr3_phys = 0,  // shadow CR3 phys (NX=0 for target, 0=not used)
    BOOLEAN no_ept_split = FALSE, // TRUE = shadow CR3 only, no EPT page split
    BOOLEAN intercept_write = FALSE)
{
    TD_STEALTH_PARAM * req = (TD_STEALTH_PARAM *)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(TD_STEALTH_PARAM), TD_STEALTH_REQ_TAG);
    if (!req)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(req, sizeof(*req));

    UINT64 effective_pt_pfn = pt_pfn;
    UINT32 effective_pt_idx = pt_idx;
    PVOID effective_pt_va = NULL;
    PVOID shadow_pte_va = NULL;

    if (no_ept_split && shadow_cr3_phys)
    {
        if (!TdResolveShadowPT(shadow_cr3_phys, (UINT64)page_va,
            &effective_pt_pfn, &effective_pt_idx, &effective_pt_va))
        {
            ExFreePoolWithTag(req, TD_STEALTH_REQ_TAG);
            return STATUS_UNSUCCESSFUL;
        }
        // shadow PT page VA is a system-global NonPaged-pool VA (the original
        // ExAllocatePool2 VA tracked in g_shadow_allocs by TdShadowVaFromPhys).
        // Pass the exact shadow PTE VA so the HV writes *shadow_pte_va =
        // (real_pte & ~NX) on #PF WITHOUT pa_to_va: MmGetVirtualForPhysical
        // returns NULL for these NonPaged-pool pages in VMX-root, so the old
        // HV shadow-walk always bailed and the stale snapshot PTE (pre-DLL-load
        // PFN) survived -> CPU fetched wrong bytes -> execute AV.
        if (effective_pt_va)
            shadow_pte_va = &((PUINT64)effective_pt_va)[effective_pt_idx];
    }

    req->caller_cr3       = caller_cr3;
    req->target_pid       = 0;
    req->target_va        = page_va;
    req->handler_function = NULL;
    req->target_phys      = page_phys;
    req->shellcode_buffer = sc_buf;
    req->shellcode_size   = sc_size;
    req->resident         = resident;
    req->pt_page_pfn      = effective_pt_pfn;
    req->pt_pte_index     = effective_pt_idx;
    req->use_fake_pt      = use_fake_pt;
    req->shadow_cr3_phys  = shadow_cr3_phys;
    req->no_ept_split     = no_ept_split;
    req->shadow_pte_va    = shadow_pte_va;
    req->intercept_write  = intercept_write;

    // pass the shared real-page map (MDL-mapped real PT pages) so the HV can
    // walk the guest's real page tables under g_system_cr3 without pa_to_va.
    // (NULL/0 when no shadow CR3 or map build failed -- HV falls back to pa_to_va.)
    TdShadowGetRealMap(shadow_cr3_phys, &req->real_page_map, &req->real_page_count);

    //
    // copy PT page and target page content into NonPaged kernel buffers.
    // VMX-root accesses these buffers (always valid under any CR3).
    // MmGetVirtualForPhysical returns process-relative VAs that are
    // invalid under system CR3 in VMX-root �?so we copy the content here.
    //
    PVOID pt_buf  = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'htpS');
    PVOID tgt_buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'htpS');
    if (!pt_buf || !tgt_buf)
    {
        if (pt_buf)  ExFreePoolWithTag(pt_buf,  'htpS');
        if (tgt_buf) ExFreePoolWithTag(tgt_buf, 'htpS');
        ExFreePoolWithTag(req, TD_STEALTH_REQ_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    {
        PHYSICAL_ADDRESS pa;
        pa.QuadPart = (LONGLONG)(effective_pt_pfn << 12);
        PVOID pt_va = effective_pt_va ? effective_pt_va : MmGetVirtualForPhysical(pa);
        PVOID target_page_base = (PVOID)((UINT64)page_va & ~0xFFFULL);

        __try
        {
            if (pt_va)
                RtlCopyMemory(pt_buf, pt_va, PAGE_SIZE);
            else
                RtlZeroMemory(pt_buf, PAGE_SIZE);

            //
            // We are still attached to the target process here, so copy the
            // target page through its current process VA instead of trying to
            // re-derive a transient VA from the physical page.
            //
            if (target_page_base)
                RtlCopyMemory(tgt_buf, target_page_base, PAGE_SIZE);
            else
                RtlZeroMemory(tgt_buf, PAGE_SIZE);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            ExFreePoolWithTag(pt_buf, 'htpS');
            ExFreePoolWithTag(tgt_buf, 'htpS');
            ExFreePoolWithTag(req, TD_STEALTH_REQ_TAG);
            HYPERPLATFORM_LOG_ERROR("[td-rw] TdStealthAllocPage copy fault: page_va=%p pt_va=%p",
                target_page_base, pt_va);
            return GetExceptionCode();
        }

        if (!effective_pt_va)
            effective_pt_va = pt_va;

        req->pt_page_va = effective_pt_va;  // shadow mode: shadow PT page VA; else real PT page VA
    }

    req->pt_page_copy     = pt_buf;
    req->target_page_copy = tgt_buf;
    req->pt_precomputed   = TRUE;

    // DPC broadcast �?every CPU does VMCALL, each splits its own EPT.
    // same pattern as EPT hook's KeGenericCallDpc.
    NTSTATUS run_st = TdRunStealthAllocOnCpus(req, pt_buf, tgt_buf);
    if (run_st == STATUS_IO_TIMEOUT)
        return run_st;

    ExFreePoolWithTag(pt_buf,  'htpS');
    ExFreePoolWithTag(tgt_buf, 'htpS');
    ExFreePoolWithTag(req, TD_STEALTH_REQ_TAG);
    return run_st;
}

//
// set up EPT stealth for a multi-page shellcode buffer
// shellcode is written into the original page BEFORE VMCALL,
// so VMX-root copies it into the shadow page (execute view).
// after VMCALL, the original page is zeroed (read view = clean).
//
BOOLEAN
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
        // page already has content from TdBuildShellcodePage �?no need to touch.
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
        // NX bit in real PTE is NOT cleared �?Windows' MiAgeWorkingSet
        // can restore it at any time. the fake/exec PT pages handle NX hiding.
        //

        //
        // shellcode mode: pass the buffer directly so VMX-root copies it
        //
        NTSTATUS stealth_st = TdStealthAllocPage(
            caller_cr3,
            (PVOID)cur_va,
            page_phys + off_in_pg,
            (PUINT8)shellcode + done,
            chunk,
            resident,
            pt_pfn,
            pt_idx,
            FALSE,
            0,
            FALSE,
            FALSE);

        if (!NT_SUCCESS(stealth_st))
        {
            HYPERPLATFORM_LOG_ERROR("[td] stealth page %u failed: 0x%08X", page_count, stealth_st);
            return FALSE;
        }

        done += chunk;
        page_count++;
    }

    HYPERPLATFORM_LOG_INFO("[td] stealth inject: %u pages set up via VMCALL", page_count);
    return TRUE;
}

// =========================================================================
//  TdInjectMemDllX64 -- port of "InjectX64" (Inject project, inject/Inject.c)
//
//  R3 gives only a PID + a DLL file path. This reads the DLL, then performs
//  the same 3-allocation manual-map trick the source uses:
//
//    1. ufileDll  : raw DLL FILE image  (PAGE_READWRITE, stays NX)   -> rcx
//    2. uShellcode: MemLoadShellcode_x64 blob (RX, NX cleared)        -> thread entry
//    3. uImage    : buffer for the loader to map the real image into  (RX, NX cleared)
//
//  The loader blob (compiled in the source) walks the PEB, resolves imports
//  by hash, maps/relocates the DLL, and calls DllMain. Its internal
//  "VirtualAlloc image" call site at blob offset 0x50f is patched so the
//  loader uses our pre-allocated uImage instead of calling VirtualAlloc:
//      0x50f: 0x90                  NOP first byte of "mov edx,eax"
//      0x510: 48 B8 <imm64=uImage>   mov rax, uImage   (overwrites the
//                                     VirtualAlloc result in rax)
//
//  Thread entry = uShellcode, start context (rcx) = ufileDll. We wait for the
//  loader thread to finish, then release every allocation.
//
//  Memory model differs from the source:
//    - source "AllocateMemory"          -> target ZwAllocateVirtualMemory
//      PAGE_READWRITE + SetExecutePage  -> here: NX cleared via PTE walk
//      (TdResolveGuestPte + TdApplyProtectToPte + TdFlushAddressRangeForCr3).
//    - source "AllocateMemoryNotExecute"-> same alloc, NX left set.
//    - source "FreeMemory"              -> ZwFreeVirtualMemory(MEM_RELEASE).
//
//  Must be called at PASSIVE_LEVEL with a referenced PEPROCESS (we attach here).
// =========================================================================

// blob offsets baked into MemLoadShellcode_x64 (see td_memload_shellcode.h)
#define MEMLOAD_PATCH_NOEXEC   0x50F   // "mov edx,eax" first byte -> NOP
#define MEMLOAD_PATCH_IMM_OFF  0x512   // imm64 slot of "mov rax, imm64"

static NTSTATUS
TdTargetAlloc(
    _In_  SIZE_T size,
    _In_  BOOLEAN make_exec,
    _Out_ PVOID * out_va,
    _Out_ SIZE_T * out_alloc_size,
    _Out_ UINT64 * out_cr3)
{
    PVOID va = NULL;
    SIZE_T sz = size;
    NTSTATUS st = ZwAllocateVirtualMemory(
        ZwCurrentProcess(), &va, 0, &sz,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(st) || !va)
        return NT_SUCCESS(st) ? STATUS_NO_MEMORY : st;

    RtlZeroMemory(va, sz);   // source does memset(0) in both alloc helpers

    *out_va = va;
    *out_alloc_size = sz;
    *out_cr3 = __readcr3();  // target CR3 while attached

    if (make_exec)
    {
        // Port of SetExecutePage(): clear NX for every page in [va, va+sz).
        // While attached, __readcr3() is the target DirBase so the guest walk
        // lands on the target's real PTEs.
        UINT64 cr3 = *out_cr3;
        for (UINT64 p = (UINT64)va; p < (UINT64)va + sz; p += PAGE_SIZE)
        {
            PUINT64 pte = TdResolveGuestPte(cr3, p);
            if (pte)
                TdApplyProtectToPte(pte, PAGE_EXECUTE_READWRITE);
        }
        TdFlushAddressRangeForCr3((UINT64)va & ~(UINT64)(PAGE_SIZE - 1), sz, cr3);
    }
    return STATUS_SUCCESS;
}

static VOID
TdTargetFree(PVOID va, SIZE_T size)
{
    if (!va) return;
    SIZE_T sz = size;
    ZwFreeVirtualMemory(ZwCurrentProcess(), &va, &sz, MEM_RELEASE);
}

// Port of CreateRemoteThreadByProcess, but NOT suspended and with a start
// context (rcx) -- the source's helper always passed Arg, TdCreateThread
// cannot, so we call g_pZwCreateThreadEx directly and hand back the thread
// object for the caller to wait on and dereference.
static NTSTATUS
TdTargetCreateThreadWithArg(
    _In_  PEPROCESS proc,
    _In_  PVOID entry,
    _In_  PVOID arg,
    _Out_ PETHREAD * out_thread)
{
    *out_thread = NULL;
    if (!g_pZwCreateThreadEx) return STATUS_NOT_SUPPORTED;

    HANDLE proc_h = NULL;
    NTSTATUS st = ObOpenObjectByPointer(proc, OBJ_KERNEL_HANDLE, NULL,
        PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &proc_h);
    if (!NT_SUCCESS(st)) return st;

    HANDLE thread_h = NULL;
    st = g_pZwCreateThreadEx(
        &thread_h, THREAD_ALL_ACCESS, NULL, proc_h,
        entry, arg,
        0,                // flags = 0 (run immediately, matches source)
        0,                // ZeroBits
        0x100000,         // StackSize  (source: 0x100000)
        0x200000,         // MaxStackSize (source: 0x200000)
        NULL);            // AttributeList
    ZwClose(proc_h);

    if (!NT_SUCCESS(st) || !thread_h)
    {
        if (thread_h) ZwClose(thread_h);
        return NT_SUCCESS(st) ? STATUS_UNSUCCESSFUL : st;
    }

    PETHREAD thr = NULL;
    st = ObReferenceObjectByHandle(thread_h, THREAD_ALL_ACCESS,
        *PsThreadType, KernelMode, (PVOID *)&thr, NULL);
    ZwClose(thread_h);
    if (!NT_SUCCESS(st) || !thr)
        return NT_SUCCESS(st) ? STATUS_UNSUCCESSFUL : st;

    *out_thread = thr;
    return STATUS_SUCCESS;
}

NTSTATUS
TdInjectMemDllX64(
    _In_  PEPROCESS proc,
    _In_  PCUNICODE_STRING dll_nt_path,
    _Out_opt_ UINT64 * out_image_va,
    _Out_opt_ SIZE_T * out_image_size)
{
    if (out_image_va) *out_image_va = 0;
    if (out_image_size) *out_image_size = 0;

    // --- 1. validate process still alive (source: PsGetProcessExitStatus) ---
    if (PsGetProcessExitStatus(proc) != STATUS_PENDING)
        return STATUS_PROCESS_IS_TERMINATING;

    // --- 2. read the DLL file into a nonpaged kernel buffer ---
    PUINT8 raw_dll = NULL;
    SIZE_T dll_size = 0;
    NTSTATUS st = TdReadFileKernel(dll_nt_path, &raw_dll, &dll_size);
    if (!NT_SUCCESS(st))
    {
        HYPERPLATFORM_LOG_ERROR("[inject-x64] read DLL failed 0x%08X", st);
        return st;
    }

    // --- 3. parse PE: validate + read SizeOfImage ---
    SIZE_T image_size = 0;
    ULONG  entry_rva  = 0;
    __try
    {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)raw_dll;
        if (dll_size < sizeof(IMAGE_DOS_HEADER) || dos->e_magic != IMAGE_DOS_SIGNATURE)
        { st = STATUS_INVALID_IMAGE_FORMAT; __leave; }
        if ((SIZE_T)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > dll_size)
        { st = STATUS_INVALID_IMAGE_FORMAT; __leave; }
        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(raw_dll + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
        { st = STATUS_INVALID_IMAGE_FORMAT; __leave; }
        if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        { st = STATUS_INVALID_IMAGE_FORMAT; __leave; }
        image_size = (SIZE_T)nt->OptionalHeader.SizeOfImage;
        entry_rva  = nt->OptionalHeader.AddressOfEntryPoint;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        st = STATUS_INVALID_IMAGE_FORMAT;
    }
    if (!NT_SUCCESS(st) || image_size == 0 || image_size > 256 * 1024 * 1024)
    {
        HYPERPLATFORM_LOG_ERROR("[inject-x64] bad PE, SizeOfImage=0x%llX st=0x%08X",
            (UINT64)image_size, st);
        ExFreePoolWithTag(raw_dll, 'fRdO');
        return NT_SUCCESS(st) ? STATUS_INVALID_IMAGE_FORMAT : st;
    }

    // --- 4. allocate the three target regions while attached ---
    KAPC_STATE apc;
    KeStackAttachProcess(proc, &apc);

    PVOID ufileDll = NULL; SIZE_T sz_file = 0; UINT64 cr3 = 0;
    PVOID uShell   = NULL; SIZE_T sz_shel = 0;
    PVOID uImage   = NULL; SIZE_T sz_img  = 0;
    BOOLEAN have_file = FALSE, have_shel = FALSE, have_img = FALSE;
    BOOLEAN keep_image = FALSE;   // source keeps uImage alive on success
    st = STATUS_UNSUCCESSFUL;

    // ufileDll: raw file image, NX left set (source: AllocateMemoryNotExecute)
    do
    {
        if (!NT_SUCCESS(TdTargetAlloc(dll_size, FALSE, &ufileDll, &sz_file, &cr3)))
            break;
        have_file = TRUE;
        __try { RtlCopyMemory(ufileDll, raw_dll, dll_size); }
        __except (EXCEPTION_EXECUTE_HANDLER) { break; }

        // uShellcode: loader blob, executable (source: AllocateMemory)
        if (!NT_SUCCESS(TdTargetAlloc(sizeof(MemLoadShellcode_x64), TRUE,
                                         &uShell, &sz_shel, &cr3)))
            break;
        have_shel = TRUE;
        __try { RtlCopyMemory(uShell, MemLoadShellcode_x64, sizeof(MemLoadShellcode_x64)); }
        __except (EXCEPTION_EXECUTE_HANDLER) { break; }

        // uImage: destination for the real mapped image, executable
        if (!NT_SUCCESS(TdTargetAlloc(image_size, TRUE, &uImage, &sz_img, &cr3)))
            break;
        have_img = TRUE;

        // --- 5. patch the loader: point its "VirtualAlloc" result at uImage ---
        // Same bytes the source writes at offsets 0x50f-0x515:
        //   uShellcode[0x50f] = 0x90;    NOP
        //   uShellcode[0x510] = 0x48;    REX.W
        //   uShellcode[0x511] = 0xb8;    mov rax, imm64
        //   *(PULONG64)(uShellcode+0x512) = (ULONG64)uImage;
        ((PUINT8)uShell)[MEMLOAD_PATCH_NOEXEC]      = 0x90;
        ((PUINT8)uShell)[MEMLOAD_PATCH_NOEXEC + 1]  = 0x48;
        ((PUINT8)uShell)[MEMLOAD_PATCH_NOEXEC + 2]  = 0xB8;
        *(UINT64 *)((PUINT8)uShell + MEMLOAD_PATCH_IMM_OFF) = (UINT64)uImage;

        // --- 6. run loader in the target (rcx = ufileDll) ---
        PETHREAD thr = NULL;
        NTSTATUS thr_st = TdTargetCreateThreadWithArg(
            proc, uShell, ufileDll, &thr);
        if (!NT_SUCCESS(thr_st))
        {
            HYPERPLATFORM_LOG_ERROR("[inject-x64] thread create failed 0x%08X", thr_st);
            st = thr_st;
            break;
        }

        // Wait for the loader to map the DLL and call DllMain, then return.
        KeWaitForSingleObject(thr, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(thr);

        // Source clears only one page of uImage after the thread completes.
        __try { RtlZeroMemory(uImage, PAGE_SIZE); } __except (EXCEPTION_EXECUTE_HANDLER) {}

        keep_image = TRUE;
        if (out_image_va) *out_image_va = (UINT64)uImage;
        if (out_image_size) *out_image_size = image_size;
        st = STATUS_SUCCESS;
        HYPERPLATFORM_LOG_INFO("[inject-x64] OK: file=%p shell=%p image=%p entry=%p size=0x%llX",
            ufileDll, uShell, uImage,
            (PVOID)((PUINT8)uImage + entry_rva), (UINT64)image_size);
    } while (0);

    // --- 7. release allocations (source model) ---
    // Success: loader ran DllMain and uImage now holds the live mapped DLL,
    // so free the staging buffers (ufileDll, uShellcode) but NOT uImage.
    // Failure: free whatever was allocated (uImage is freed when thread
    // creation fails, matching Inject.c's isuimageDll behavior).
    if (have_file) TdTargetFree(ufileDll, sz_file);
    if (have_shel) TdTargetFree(uShell,   sz_shel);
    if (have_img && !keep_image) TdTargetFree(uImage, sz_img);

    KeUnstackDetachProcess(&apc);
    ExFreePoolWithTag(raw_dll, 'fRdO');
    return st;
}


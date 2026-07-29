#include "td_common.h"

// =========================================================================
//  DLL gap finder 閳?find unused page-aligned gap in an image's VA range.
//
//  walks PE section headers to find alignment padding between sections
//  or after the last section. returns a committed page of zeros that
//  belongs to the DLL's VAD (MEM_IMAGE). no new allocation, no new VAD.
//
//  MUST be called while attached to the target process.
// =========================================================================

//
// find section tail padding in a DLL 閳?unused zero bytes at the end of
// a section's last page. no full-page gap needed.
//
// returns page-aligned VA of the page containing padding.
// *out_offset = offset within page where padding starts (shellcode goes here).
// *out_avail  = available bytes from offset to end of page.
//
PVOID
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
        // prefer executable sections (.text) 閳?shellcode blends in better.
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
PVOID
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
//  PE Manual Mapper 閳?kernel-side DLL loading, zero R3 API calls
//
//  flow:
//    1. injector reads DLL file 閳?sends raw bytes via IOCTL_INJECT_DLL
//    2. driver attaches to target process
//    3. ZwAllocateVirtualMemory(PAGE_READWRITE) for image
//    4. copy sections, apply relocations, resolve imports (PEB walk)
//    5. build DllMain stub at image base (overwrites DOS header)
//    6. clear PE signature from header
//    7. ZwProtectVirtualMemory 閳?PAGE_EXECUTE_READ for executable sections
//    8. EPT hook NtTestAlert 閳?DllMain stub (oneshot, per-process CR3 filter)
//    9. create thread at NtTestAlert 閳?DllMain runs 閳?thread exits
//
//  result: DLL is loaded without LoadLibrary, no module list entry,
//  no load image notification, no file access from target process.
// =========================================================================

#define IOCTL_INJECT_DLL CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 5, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INJECT_RW  CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INJECT_RW_SHADOW CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ALLOC_SHADOW_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 8, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INSTALL_TRIGGER_JUMP CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 9, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FREE_SHADOW_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 10, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SHADOW_PROTECT_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 11, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define TD_MAX_INJECT_RW_SIZE (16ULL * 1024ULL * 1024ULL)

#pragma pack(push, 8)



#pragma pack(pop)

#pragma pack(push, 8)
#pragma pack(pop)

//

//
// TdFindModuleBaseA 閳?find loaded module by ASCII name via PEB walk.
// walks PEB 閳?Ldr 閳?InMemoryOrderModuleList. compares BaseDllName
// (Unicode) with the given ASCII name (case-insensitive).
// must be called while attached to the target process.
//
PVOID
TdFindModuleBaseA(const char * name_ascii, ULONG * out_size)
{
    if (out_size)
        *out_size = 0;

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
        if ((ext[0] == '.') &&
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
        ULONG seen = 0;

        while (cur != head && seen++ < 512)
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
                    // name_ascii is "foo" 閳?compare first name_len chars,
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
                {
                    if (out_size)
                        *out_size = e->SizeOfImage;
                    return e->DllBase;
                }
            }
            cur = cur->Flink;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        HYPERPLATFORM_LOG_WARN("[td-map] exception in TdFindModuleBaseA(\"%s\")", name_ascii);
    }

    return NULL;
}

//
// TdFindExportByName 閳?find export by name from a module's export table.
// walks PE export directory. returns function VA. skips forwarded exports
// (returns NULL for forwards).
//
PVOID
TdFindExportByNameEx(PVOID module_base, const char * func_name, ULONG depth)
{
    if (!module_base || !func_name) return NULL;
    if (depth > 4) return NULL;

    __try {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module_base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((PUINT8)module_base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

        ULONG exp_rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        ULONG exp_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        if (!exp_rva || exp_size < sizeof(IMAGE_EXPORT_DIRECTORY)) return NULL;
        if (exp_rva + exp_size < exp_rva) return NULL;

        PIMAGE_EXPORT_DIRECTORY exp_dir = (PIMAGE_EXPORT_DIRECTORY)((PUINT8)module_base + exp_rva);
        if (!exp_dir->NumberOfNames || !exp_dir->NumberOfFunctions ||
            exp_dir->NumberOfNames > 0x10000 ||
            exp_dir->NumberOfFunctions > 0x10000 ||
            !exp_dir->AddressOfNames || !exp_dir->AddressOfNameOrdinals ||
            !exp_dir->AddressOfFunctions)
            return NULL;

        PULONG  names = (PULONG)((PUINT8)module_base + exp_dir->AddressOfNames);
        PUSHORT ords  = (PUSHORT)((PUINT8)module_base + exp_dir->AddressOfNameOrdinals);
        PULONG  funcs = (PULONG)((PUINT8)module_base + exp_dir->AddressOfFunctions);

        for (ULONG i = 0; i < exp_dir->NumberOfNames; i++)
        {
            const char * fn = (const char *)((PUINT8)module_base + names[i]);
            if (TdAsciiEqualIBounded(fn, func_name, 256))
            {
                USHORT ord = ords[i];
                if (ord >= exp_dir->NumberOfFunctions)
                    return NULL;

                ULONG func_rva = funcs[ord];
                if (!func_rva)
                    return NULL;

                if (func_rva >= exp_rva && func_rva < exp_rva + exp_size)
                {
                    const char * fwd = (const char *)((PUINT8)module_base + func_rva);
                    const char * exp_end = (const char *)((PUINT8)module_base + exp_rva + exp_size);
                    char dll_name[128] = {};
                    char export_name[128] = {};
                    ULONG dll_len = 0;
                    ULONG export_len = 0;
                    BOOLEAN saw_dot = FALSE;
                    BOOLEAN saw_null = FALSE;

                    for (const char * p = fwd; p < exp_end && (ULONG)(p - fwd) < 255; p++)
                    {
                        char c = *p;
                        if (!c) { saw_null = TRUE; break; }

                        if (!saw_dot)
                        {
                            if (c == '.')
                            {
                                saw_dot = TRUE;
                                continue;
                            }
                            if (dll_len + 1 >= sizeof(dll_name))
                                return NULL;
                            dll_name[dll_len++] = c;
                        }
                        else
                        {
                            if (export_len + 1 >= sizeof(export_name))
                                return NULL;
                            export_name[export_len++] = c;
                        }
                    }

                    if (!saw_dot || !saw_null || !dll_len || !export_len)
                        return NULL;

                    PVOID forward_base = TdFindModuleBaseA(dll_name, NULL);
                    if (!forward_base &&
                        (TdAsciiStartsWithI(dll_name, "api-") ||
                         TdAsciiStartsWithI(dll_name, "ext-")))
                    {
                        forward_base = TdFindModuleBaseA("kernelbase.dll", NULL);
                    }
                    if (!forward_base)
                        return NULL;

                    return TdFindExportByNameEx(forward_base, export_name, depth + 1);
                }

                // check for forwarded export (RVA points inside export directory)
                if (func_rva >= exp_rva && func_rva < exp_rva + exp_size)
                    return NULL;  // forwarded 閳?skip

                return (PUINT8)module_base + func_rva;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        HYPERPLATFORM_LOG_WARN("[td-map] exception in TdFindExportByName");
    }

    return NULL;
}

PVOID
TdFindExportByName(PVOID module_base, const char * func_name)
{
    return TdFindExportByNameEx(module_base, func_name, 0);
}

BOOLEAN
TdExtractSyscallIndexFromStub(PVOID stub, PULONG index_out)
{
    if (!stub || !index_out)
        return FALSE;

    __try {
        PUCHAR p = (PUCHAR)stub;

        if (p[0] == 0xE9)
        {
            LONG rel = *(LONG UNALIGNED *)(p + 1);
            p = p + 5 + rel;
        }
        else if (p[0] == 0xFF && p[1] == 0x25)
        {
            LONG rel = *(LONG UNALIGNED *)(p + 2);
            PUCHAR * indirect = (PUCHAR *)(p + 6 + rel);
            p = *indirect;
        }

        for (SIZE_T i = 0; i + 7 < 0x20; i++)
        {
            if (p[i] == 0xB8)
            {
                ULONG idx = *(ULONG UNALIGNED *)(p + i + 1);
                for (SIZE_T j = i + 5; j + 1 < 0x20; j++)
                {
                    if (p[j] == 0x0F && p[j + 1] == 0x05)
                    {
                        *index_out = idx;
                        return TRUE;
                    }
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }

    return FALSE;
}

BOOLEAN
TdResolveUserSyscallIndex(const char * export_name, PULONG index_out)
{
    if (!export_name || !index_out)
        return FALSE;

    PVOID ntdll_base = TdFindModuleBaseA("ntdll", NULL);
    if (!ntdll_base)
        ntdll_base = TdFindModuleBaseA("ntdll.dll", NULL);
    if (!ntdll_base)
        return FALSE;

    PVOID stub = TdFindExportByName(ntdll_base, export_name);
    if (!stub)
        return FALSE;

    return TdExtractSyscallIndexFromStub(stub, index_out);
}

typedef NTSTATUS (NTAPI * fn_NtResumeThreadSsdt)(HANDLE, PULONG);

NTSTATUS
TdNtResumeThreadBySSDT(HANDLE thread_h, PULONG previous_count)
{
    static ULONG g_resume_index = (ULONG)-1;

    if (!thread_h)
        return STATUS_INVALID_PARAMETER;

    if (g_resume_index == (ULONG)-1)
    {
        ULONG idx = 0;
        if (!TdResolveUserSyscallIndex("NtResumeThread", &idx) &&
            !TdResolveUserSyscallIndex("ZwResumeThread", &idx))
        {
            HYPERPLATFORM_LOG_WARN("[td] TdNtResumeThreadBySSDT: failed to resolve syscall index");
            return STATUS_NOT_FOUND;
        }

        g_resume_index = idx;
        HYPERPLATFORM_LOG_INFO("[td] TdNtResumeThreadBySSDT: syscall index=0x%X", g_resume_index);
    }

    fn_NtResumeThreadSsdt nt_resume =
        (fn_NtResumeThreadSsdt)TdGetSSDTEntry(g_resume_index);
    if (!nt_resume)
    {
        HYPERPLATFORM_LOG_WARN("[td] TdNtResumeThreadBySSDT: SSDT entry lookup failed for 0x%X", g_resume_index);
        return STATUS_NOT_FOUND;
    }

    ULONG prev_mode_offset = TdGetPreviousModeOffset();
    if (!prev_mode_offset)
    {
        HYPERPLATFORM_LOG_WARN("[td] TdNtResumeThreadBySSDT: PreviousMode offset not found");
        return STATUS_NOT_FOUND;
    }

    PULONG prev_arg = previous_count;
    ULONG local_prev = 0;
    if (!prev_arg)
        prev_arg = &local_prev;

    PUCHAR p_prev_mode = (PUCHAR)PsGetCurrentThread() + prev_mode_offset;
    UCHAR saved_mode = *p_prev_mode;
    *p_prev_mode = KernelMode;
    NTSTATUS st = nt_resume(thread_h, prev_arg);
    *p_prev_mode = saved_mode;
    return st;
}

PVOID
TdResolveDefaultTrigger(PEPROCESS proc, const char * log_prefix)
{
    static const char * trigger_candidates[] = {
        "NtTestAlert", "RtlSetCurrentTransaction", NULL
    };

    PVOID trigger_fn = NULL;
    PPEB peb = PsGetProcessPeb(proc);
    if (!peb)
        return NULL;

    __try {
        TD_PEB_LDR_DATA * ldr = *(TD_PEB_LDR_DATA **)((PUINT8)peb + 0x18);
        if (!ldr)
            return NULL;

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
                        HYPERPLATFORM_LOG_INFO("[%s] trigger=%s at %p", log_prefix, *c, trigger_fn);
                }
                break;
            }
            ldr_cur = ldr_cur->Flink;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        HYPERPLATFORM_LOG_WARN("[%s] exception resolving trigger", log_prefix);
    }

    return trigger_fn;
}

//
// TdFindExportByOrdinal 閳?find export by ordinal from a module's export table.
//
PVOID
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
// TdPeCopySections 閳?copy PE headers and sections from raw DLL to mapped image.
//
BOOLEAN
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
                // BSS 閳?zero the virtual range
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
// TdPeRelocate 閳?apply base relocations.
// returns TRUE on success, FALSE if no relocation table and delta != 0.
//
BOOLEAN
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
            // no relocation table 閳?check if DLL has RELOCS_STRIPPED
            if (nt->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
            {
                HYPERPLATFORM_LOG_ERROR("[td-map] no reloc table and delta != 0");
                return FALSE;
            }
            // relocation directory empty but delta != 0 and not stripped 閳?fail
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
                    // padding 閳?skip
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
// TdPeResolveImports 閳?resolve imports manually via PEB walk.
// must be called while attached to the target process.
//
BOOLEAN
TdPeResolveImports(PVOID mapped_base)
{
    __try {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mapped_base;
        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((PUINT8)mapped_base + dos->e_lfanew);

        ULONG imp_rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        ULONG imp_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

        if (!imp_rva || !imp_size)
        {
            HYPERPLATFORM_LOG_INFO("[td-map] no import directory 閳?nothing to resolve");
            return TRUE;
        }

        PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)((PUINT8)mapped_base + imp_rva);

        while (imp->Name)
        {
            const char * dll_name = (const char *)((PUINT8)mapped_base + imp->Name);
            PVOID mod_base = TdFindModuleBaseA(dll_name, NULL);

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
// TdBuildDllMainStub 閳?build a small x64 stub that calls DllMain(base, DLL_PROCESS_ATTACH, NULL).
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
UINT32
TdBuildDllMainStub(PVOID stub_addr, UINT64 image_base, UINT64 entry_point,
                   UINT64 rtl_add_function_table_va, UINT64 pdata_va, UINT32 pdata_count)
{
    PUINT8 s = (PUINT8)stub_addr;
    UINT32 off = 0;

    // sub rsp, 28h
    s[off++] = 0x48; s[off++] = 0x83; s[off++] = 0xEC; s[off++] = 0x28;

    // optional: RtlAddFunctionTable(pdata, count, base) -- registers .pdata so
    // SEH/.pdata unwind resolves during CRT init (required for static-CRT DLLs
    // like renderdoc; without it CRT init FAST_FAILs).
    if (rtl_add_function_table_va && pdata_count)
    {
        // mov rcx, PDATA_VA (imm64)
        s[off++] = 0x48; s[off++] = 0xB9;
        *(PUINT64)(s + off) = pdata_va; off += 8;
        // mov edx, COUNT (imm32, zero-extends to rdx)
        s[off++] = 0xBA;
        *(PUINT32)(s + off) = pdata_count; off += 4;
        // mov r8, IMAGE_BASE (imm64)   49 B8
        s[off++] = 0x49; s[off++] = 0xB8;
        *(PUINT64)(s + off) = image_base; off += 8;
        // mov rax, RTLADDFUNCTIONTABLE_VA (imm64)
        s[off++] = 0x48; s[off++] = 0xB8;
        *(PUINT64)(s + off) = rtl_add_function_table_va; off += 8;
        // call rax
        s[off++] = 0xFF; s[off++] = 0xD0;
    }

    // mov rcx, IMAGE_BASE (imm64)   (hinstDLL)
    s[off++] = 0x48; s[off++] = 0xB9;
    *(PUINT64)(s + off) = image_base; off += 8;

    // mov edx, 1  (DLL_PROCESS_ATTACH)
    s[off++] = 0xBA; s[off++] = 0x01; s[off++] = 0x00; s[off++] = 0x00; s[off++] = 0x00;

    // xor r8d, r8d  (lpvReserved = 0)
    s[off++] = 0x45; s[off++] = 0x31; s[off++] = 0xC0;

    // mov rax, ENTRY_POINT (imm64)
    s[off++] = 0x48; s[off++] = 0xB8;
    *(PUINT64)(s + off) = entry_point; off += 8;

    // call rax
    s[off++] = 0xFF; s[off++] = 0xD0;

    // add rsp, 28h
    s[off++] = 0x48; s[off++] = 0x83; s[off++] = 0xC4; s[off++] = 0x28;

    // xor eax, eax  (return TRUE)
    s[off++] = 0x31; s[off++] = 0xC0;

    // ret
    s[off++] = 0xC3;

    return off;
}

//
// TdManualMapInProcess 閳?main manual map function.
// must be called while attached to the target process.
//
// parameters:
//   proc       閳?PEPROCESS (already attached)
//   raw_dll    閳?raw DLL file bytes (kernel buffer)
//   dll_size   閳?size of raw DLL
//   out_base   閳?receives mapped image base (user VA)
//   out_entry  閳?receives DllMain VA (user VA)
//
NTSTATUS
TdManualMapInProcess(
    PEPROCESS proc,
    PUINT8    raw_dll,
    SIZE_T    dll_size,
    PVOID *   out_base,
    PVOID *   out_entry)
{
    // `proc` is used below to cache per-process PE info (TdCacheSelfPeInfo)
    // before header erasure, so R3 can recover the resource/export RVAs.

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

        // 6. resolve imports (requires PEB walk 閳?must be attached)
        if (!TdPeResolveImports(base))
        {
            HYPERPLATFORM_LOG_WARN("[td-map] TdPeResolveImports had errors (continuing)");
        }

        // 6.5 cache PE info (resource + export dir RVAs) for this mapped image.
        // R3 queries it via IOCTL_GET_SELF_PE_INFO to walk .rsrc / resolve
        // exports (the mapped headers are preserved below, but the cache saves
        // R3 from re-parsing the image). `nt` points into raw_dll (intact
        // on-disk headers), so the DataDirectory reads are always valid; key by
        // the mapped `base` so R3 (which only knows g_renderdoc_hModule == base)
        // can look it up.
        TdCacheSelfPeInfo((UINT64)(ULONG_PTR)PsGetProcessId(proc), (UINT64)base, nt);

        // 7. build DllMain stub AFTER the PE headers (at base + stub_off,
        //    16-byte aligned, in the header padding before the first section).
        //    Preserving the DOS/NT headers is required: a CRT-linked DLL's SEH
        //    unwind walks RtlLookupFunctionEntry -> RtlImageNtHeader(image_base),
        //    which validates the "MZ" signature and e_lfanew. The old base+0 stub
        //    overwrote "MZ" and zeroed e_lfanew/NT headers, so any exception during
        //    CRT init became an unrecoverable crash (FAST_FAIL on static-CRT DLLs
        //    like renderdoc). The stub still lives in page 0, so it stays inside
        //    the stealth/NX region and runs via shadow CR3 + #PF.
        PVOID entry = NULL;
        ULONG  hdr_size = nt->OptionalHeader.SizeOfHeaders;
        UINT32 stub_off = (hdr_size + 15) & ~15u;   // 16-byte aligned, after headers

        // keep the stub inside page 0 (before the first section at SectionAlignment)
        // so it remains within the stealth-registered region. Allow up to 128 bytes
        // (DllMain stub with the optional RtlAddFunctionTable block is ~78 bytes).
        if (stub_off + 128 > 0x1000)
        {
            HYPERPLATFORM_LOG_ERROR("[td-map] no room for stub after headers (SizeOfHeaders=0x%X)",
                        hdr_size);
            ZwFreeVirtualMemory(ZwCurrentProcess(), &base, &image_size, MEM_RELEASE);
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        if (nt->OptionalHeader.AddressOfEntryPoint)
        {
            UINT64 entry_point_va = (UINT64)base + nt->OptionalHeader.AddressOfEntryPoint;

            // Resolve .pdata (exception directory) + ntdll!RtlAddFunctionTable so the
            // stub registers the function table before calling DllMain. Without this,
            // SEH/.pdata unwind can't resolve during CRT init -> FAST_FAIL on static-CRT
            // DLLs (e.g. renderdoc). Skipped if the image has no exception directory.
            UINT64 rtl_va = 0;
            UINT64 pdata_va = 0;
            UINT32 pdata_count = 0;
            IMAGE_DATA_DIRECTORY* exc =
                &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
            if (exc->Size && exc->VirtualAddress)
            {
                PVOID ntdll_base = TdFindModuleBaseA("ntdll.dll", NULL);
                rtl_va = ntdll_base ? (UINT64)TdFindExportByName(ntdll_base, "RtlAddFunctionTable") : 0;
                if (rtl_va)
                {
                    pdata_va = (UINT64)base + exc->VirtualAddress;
                    pdata_count = exc->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
                }
                else
                {
                    HYPERPLATFORM_LOG_WARN("[td-map] RtlAddFunctionTable not resolved; SEH unwind may fail");
                }
            }

            UINT32 stub_size = TdBuildDllMainStub((PUINT8)base + stub_off,
                                                  (UINT64)base, entry_point_va,
                                                  rtl_va, pdata_va, pdata_count);
            HYPERPLATFORM_LOG_INFO("[td-map] DllMain stub: base=%p stub_off=0x%X entry=0x%llX rtl_add_fn_tbl=0x%llX pdata=0x%llX count=%u stub_size=%u",
                       base, stub_off, entry_point_va, rtl_va, pdata_va, pdata_count, stub_size);
            entry = (PUINT8)base + stub_off;
        }
        else
        {
            HYPERPLATFORM_LOG_WARN("[td-map] no entry point in DLL");
            entry = NULL;
        }

        // headers are preserved (not zeroed) so CRT SEH unwind can resolve them.
        *out_base  = base;
        *out_entry = entry;

        // 9. executable sections + header stub page: do NOT mark PAGE_EXECUTE_READ
        // in the REAL PTE. Stealth rule: any executable memory in the target
        // process must be shadowed. The real PTE stays PAGE_READWRITE (NX=1,
        // non-executable) so scanners reading the real CR3 see no executable
        // private memory. The shadow CR3 built later in TdInjectRenderdocShadow
        // (TdBuildShadowCR3 / TdExtendShadowCR3) clears NX on every PTE across
        // the whole image range, so .text and the header DllMain stub page
        // execute under the shadow CR3. Never modify real PTEs to executable
        // (matches the shadow-alloc pattern: "never modifies real PTEs - no
        // conflict with MiAgeWorkingSet").

        HYPERPLATFORM_LOG_INFO("[td-map] manual map complete: base=%p entry=%p", base, entry);
        return STATUS_SUCCESS;

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        HYPERPLATFORM_LOG_ERROR("[td-map] exception in TdManualMapInProcess");
        return STATUS_UNSUCCESSFUL;
    }
}

// =========================================================================
//  TdInjectRenderdocShadow 閳?automated renderdoc injection via LoadImage callback
// =========================================================================
//
// Called from TdLoadImageNotify when user32.dll loads in a recorded target.
// Must be called at PASSIVE_LEVEL with proc referenced (not yet attached).
// Flow:
//   1. attach, read renderdoc.dll from disk
//   2. TdManualMapInProcess (alloc RW, copy sections, reloc, imports, DllMain stub)
//   3. build shadow CR3 for the mapped image range (NX cleared)
//   4. EPT stealth per page + track for process-exit cleanup
//   5. create SUSPENDED thread at mapped_base (DllMain stub entry, no trigger)
//   6. resume thread -> direct DllMain execution (shadow CR3 via stealth #PF)
//   7. async cleanup: release thread handle, keep inject resident
//
NTSTATUS
TdInjectRenderdocShadow(PEPROCESS proc, PCUNICODE_STRING renderdoc_path, const char * log_prefix, BOOLEAN wait_for_completion)
{
    NTSTATUS st = STATUS_SUCCESS;
    KAPC_STATE apc_state;
    UINT64 caller_cr3 = 0;
    SIZE_T image_size = 0;
    PUINT8 raw_dll = NULL;
    SIZE_T dll_size = 0;
    PVOID mapped_base = NULL;
    PVOID mapped_entry = NULL;
    UINT64 shadow_cr3 = 0;
    BOOLEAN thread_started = FALSE;
    BOOLEAN stealth_tracked = FALSE;
    SIZE_T pages_installed = 0;
    SIZE_T total_pages = 0;
    UINT64 target_pid = (UINT64)PsGetProcessId(proc);
    PVOID trigger_fn = NULL;
    HANDLE cleanup_thr_h = NULL;
    UINT64 expected_tid = 0;
    BOOLEAN trigger_hooked = FALSE;

    // 1. attach to target
    KeStackAttachProcess(proc, &apc_state);
    caller_cr3 = __readcr3();

    // 2. read renderdoc.dll from disk
    st = TdReadFileKernel(renderdoc_path, &raw_dll, &dll_size);
    if (!NT_SUCCESS(st))
    {
        HYPERPLATFORM_LOG_ERROR("[%s] TdReadFileKernel failed: 0x%08X", log_prefix, st);
        KeUnstackDetachProcess(&apc_state);
        return st;
    }
    HYPERPLATFORM_LOG_INFO("[%s] read renderdoc: %wZ size=0x%llX", log_prefix, renderdoc_path, (UINT64)dll_size);

    // 3. manual map in target process (alloc RW, copy sections, reloc, imports, DllMain stub)
    st = TdManualMapInProcess(proc, raw_dll, dll_size, &mapped_base, &mapped_entry);
    if (!NT_SUCCESS(st) || !mapped_base)
    {
        HYPERPLATFORM_LOG_ERROR("[%s] TdManualMapInProcess failed: 0x%08X", log_prefix, st);
        ExFreePoolWithTag(raw_dll, 'fRdO');
        KeUnstackDetachProcess(&apc_state);
        return st;
    }

    // compute image size from raw PE headers
    {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)raw_dll;
        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(raw_dll + dos->e_lfanew);
        image_size = nt->OptionalHeader.SizeOfImage;
    }

    HYPERPLATFORM_LOG_INFO("[%s] manual map complete: base=%p entry=%p size=0x%llX",
        log_prefix, mapped_base, mapped_entry, (UINT64)image_size);

    // 3.5 [DISABLED] Pinning the image pages with MmProbeAndLockPages was meant
    //     to stop the stale-PFN crash (OS repage changes real PFNs under the
    //     shadow CR3 snapshot). But it hard-freezes the system on the 2nd Box
    //     run: 1st run works, 2nd run hangs during DllMain at shadow-CR3
    //     activation (the shadow CR3 PA gets reused across runs). Root cause not
    //     yet pinned - likely a deadlock between the locked pages and the
    //     shadow-CR3 stealth resync. A reproducible freeze is worse than the
    //     intermittent (1/6) stale-PFN crash, so locking is disabled: image_mdl
    //     stays NULL -> no lock, no unlock. Revisit with a non-locking fix, e.g.
    //     extend stealth_refresh_shadow_code_pte to resync the whole image (not
    //     just the faulting 2MB) to close the cross-2MB stale-PFN gap.
    PMDL image_mdl = NULL;

    // 4. build shadow CR3 for the mapped image range (NX cleared)
    //    image_size is already page-aligned from ZwAllocateVirtualMemory
    total_pages = (image_size + PAGE_SIZE - 1) / PAGE_SIZE;

    UINT64 existing = TdStealthFindShadowCr3ForPid(target_pid);
    shadow_cr3 = existing
        ? TdExtendShadowCR3(existing, caller_cr3, (UINT64)mapped_base, image_size)
        : TdBuildShadowCR3(caller_cr3, (UINT64)mapped_base, image_size);

    if (!shadow_cr3)
    {
        HYPERPLATFORM_LOG_ERROR("[%s] shadow CR3 build failed", log_prefix);
        ExFreePoolWithTag(raw_dll, 'fRdO');
        ZwFreeVirtualMemory(ZwCurrentProcess(), &mapped_base, &image_size, MEM_RELEASE);
        KeUnstackDetachProcess(&apc_state);
        return STATUS_UNSUCCESSFUL;
    }

    // 5. EPT stealth: shadow page = original (no zeroing needed since shadow CR3 handles NX)
    //    We need to set up per-page stealth so the shadow CR3 pages are recognized.
    for (SIZE_T off = 0; off < image_size; off += PAGE_SIZE)
    {
        PVOID page_va = (PUINT8)mapped_base + off;
        UINT64 page_phys = MmGetPhysicalAddress(page_va).QuadPart;
        UINT64 pt_pfn = 0;
        UINT32 pt_idx = 0;

        if (!page_phys || !TdResolveGuestPT(caller_cr3, (UINT64)page_va, &pt_pfn, &pt_idx))
        {
            HYPERPLATFORM_LOG_ERROR("[%s] PT/PA resolve failed VA=%p at off=0x%llX",
                log_prefix, page_va, (UINT64)off);
            break;
        }

        NTSTATUS ss = TdStealthAllocPage(
            caller_cr3, page_va, page_phys,
            NULL, 0, TRUE, pt_pfn, pt_idx,
            FALSE, shadow_cr3, TRUE, FALSE);

        if (!NT_SUCCESS(ss))
        {
            HYPERPLATFORM_LOG_ERROR("[%s] stealth setup failed VA=%p st=0x%08X", log_prefix, page_va, ss);
            break;
        }
        pages_installed++;
    }

    if (pages_installed != total_pages)
    {
        HYPERPLATFORM_LOG_ERROR("[%s] stealth setup incomplete: %llu/%llu pages",
            log_prefix, (UINT64)pages_installed, (UINT64)total_pages);
        for (SIZE_T i = 0; i < pages_installed; i++)
            TdStealthFreePage((PUINT8)mapped_base + (i * PAGE_SIZE));
        if (!existing)
            TdShadowFreeCr3(shadow_cr3);
        ZwFreeVirtualMemory(ZwCurrentProcess(), &mapped_base, &image_size, MEM_RELEASE);
        ExFreePoolWithTag(raw_dll, 'fRdO');
        KeUnstackDetachProcess(&apc_state);
        return STATUS_UNSUCCESSFUL;
    }

    if (!mapped_entry)
    {
        HYPERPLATFORM_LOG_ERROR("[%s] mapped entry is NULL", log_prefix);
        for (SIZE_T i = 0; i < total_pages; i++)
            TdStealthFreePage((PUINT8)mapped_base + (i * PAGE_SIZE));
        if (!existing)
            TdShadowFreeCr3(shadow_cr3);
        ZwFreeVirtualMemory(ZwCurrentProcess(), &mapped_base, &image_size, MEM_RELEASE);
        ExFreePoolWithTag(raw_dll, 'fRdO');
        KeUnstackDetachProcess(&apc_state);
        return STATUS_UNSUCCESSFUL;
    }

    // 6. track for process exit cleanup
    if (!TdStealthTrackAdd(target_pid, mapped_base, image_size, shadow_cr3, image_mdl))
    {
        HYPERPLATFORM_LOG_ERROR("[%s] stealth track table full", log_prefix);
        for (SIZE_T i = 0; i < pages_installed; i++)
            TdStealthFreePage((PUINT8)mapped_base + (i * PAGE_SIZE));
        if (!existing)
            TdShadowFreeCr3(shadow_cr3);
        ZwFreeVirtualMemory(ZwCurrentProcess(), &mapped_base, &image_size, MEM_RELEASE);
        ExFreePoolWithTag(raw_dll, 'fRdO');
        KeUnstackDetachProcess(&apc_state);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    stealth_tracked = TRUE;

    HYPERPLATFORM_LOG_INFO("[%s] shadow CR3 built: PA=0x%llX (VA=%p size=0x%llX, %llu pages NX cleared)",
        log_prefix, shadow_cr3, mapped_base, (UINT64)image_size, (UINT64)total_pages);

    // 7. resolve NtTestAlert (ntdll export) - the CFG-valid thread entry point.
    //    thread is created SUSPENDED at NtTestAlert, then EPT-hooked to redirect
    //    to mapped_base (DllMain stub), bypassing CFG on the manual-mapped image.
    {
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
                            trigger_fn = TdFindExportByName(ldr_e->DllBase, "NtTestAlert");
                            if (trigger_fn)
                                HYPERPLATFORM_LOG_INFO("[%s] NtTestAlert=%p (ntdll=%p)",
                                    log_prefix, trigger_fn, ldr_e->DllBase);
                            break;
                        }
                        ldr_cur = ldr_cur->Flink;
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                HYPERPLATFORM_LOG_WARN("[%s] exception resolving NtTestAlert", log_prefix);
            }
        }
    }

    if (!trigger_fn)
    {
        HYPERPLATFORM_LOG_ERROR("[%s] cannot resolve NtTestAlert", log_prefix);
        st = STATUS_NOT_FOUND;
    }

    // 8. create thread at trigger (SUSPENDED) - before hook, no race
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
                        HYPERPLATFORM_LOG_ERROR("[%s] cannot convert created thread handle: st=0x%08X tid=%llu",
                            log_prefix, kh_st, expected_tid);
                        if (kernel_thr_h)
                            ZwClose(kernel_thr_h);
                        st = NT_SUCCESS(kh_st) ? STATUS_UNSUCCESSFUL : kh_st;
                    }
                    else
                    {
                        cleanup_thr_h = kernel_thr_h;
                        HYPERPLATFORM_LOG_INFO("[%s] thread SUSPENDED trigger=%p tid=%llu",
                            log_prefix, trigger_fn, expected_tid);
                    }
                }
                else
                {
                    HYPERPLATFORM_LOG_ERROR("[%s] ZwCreateThreadEx failed: 0x%08X", log_prefix, thr_st);
                    st = thr_st;
                }
                ZwClose(thr_proc_h);
            }
            else
            {
                HYPERPLATFORM_LOG_ERROR("[%s] ObOpenObjectByPointer failed: 0x%08X", log_prefix, oh_st);
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
                    HYPERPLATFORM_LOG_ERROR("[%s] cannot convert fallback thread handle: st=0x%08X tid=%llu",
                        log_prefix, kh_st, expected_tid);
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
            HYPERPLATFORM_LOG_INFO("[%s] fallback RtlCreateUserThread trigger=%p tid=%llu st=0x%08X",
                       log_prefix, trigger_fn, expected_tid, thr_st);
        }
    }

    // 9. prepare cleanup ctx before resume so we can signal immediate unhook
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
        wi = IoAllocateWorkItem(g_dev_obj);
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
        cleanup_ctx->shellcode_va  = mapped_base;
        cleanup_ctx->target_cr3    = caller_cr3;
        cleanup_ctx->target_pid    = target_pid;
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

    // 10. EPT hook trigger -> mapped_entry (DllMain stub at base+stub_off) (TID-filtered, oneshot)
    if (NT_SUCCESS(st) && expected_tid)
    {
        PVOID dummy_origin = NULL;
        volatile LONG * fired_ptr = cleanup_ctx ? &cleanup_ctx->fired_signal : NULL;
        NTSTATUS hook_st = TdInstallTriggerHookAllCpus(
            trigger_fn, mapped_entry, caller_cr3, 2, expected_tid, &dummy_origin, fired_ptr);

        HYPERPLATFORM_LOG_INFO("[%s] trigger hook %s trigger=%p sc=%p tid=%llu st=0x%08X",
                   log_prefix, NT_SUCCESS(hook_st) ? "OK" : "FAILED",
                   trigger_fn, mapped_entry, expected_tid, hook_st);

        if (!NT_SUCCESS(hook_st))
            st = hook_st;
        else
            trigger_hooked = TRUE;
    }

    KeUnstackDetachProcess(&apc_state);

    // 11. resume thread (now hook is active with correct TID)
    if (NT_SUCCESS(st) && cleanup_thr_h)
    {
        ULONG prev_count = 0;
        NTSTATUS resume_st = TdResumeThreadHandle(cleanup_thr_h, &prev_count);
        if (NT_SUCCESS(resume_st))
        {
            HYPERPLATFORM_LOG_INFO("[%s] thread RESUMED trigger=%p tid=%llu prev=%u",
                log_prefix, trigger_fn, expected_tid, prev_count);
            thread_started = TRUE;
            st = STATUS_SUCCESS;
        }
        else
        {
            HYPERPLATFORM_LOG_ERROR("[%s] thread resume failed: 0x%08X", log_prefix, resume_st);
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

    // 11.5 (NtCreateFile path only): synchronously wait for the DllMain thread
    // to EXIT so the D3D12/DXGI EPT hooks are guaranteed installed before we
    // return. renderdoc's DllMain is fully synchronous (win32_libentry.cpp:
    // VEH/UEF -> Initialise -> RegisterHooks, which places every EPT hook via
    // IOCTL_EPT_HOOK_R3 before returning) and the DllMain stub then `ret`s, so
    // thread exit == hooks installed. Without this wait, CreateFile("test")
    // returns before RegisterHooks finishes, and Box.exe's very next
    // D3D12CreateDevice misses the hook (race) -> no F12 overlay.
    // MUST NOT be used from the LoadImage notify path: that callback runs under
    // the loader lock and renderdoc DllMain calls LoadLibrary -> deadlock.
    if (wait_for_completion && NT_SUCCESS(st) && thread_started && cleanup_thr_h)
    {
        PETHREAD trig_thread = NULL;
        NTSTATUS ref_st = ObReferenceObjectByHandle(
            cleanup_thr_h, 0, *PsThreadType, KernelMode, (PVOID *)&trig_thread, NULL);
        if (NT_SUCCESS(ref_st) && trig_thread)
        {
            // KeWaitForSingleObject takes the object pointer, not the handle.
            // 30s ceiling only - DllMain + RegisterHooks normally finishes in
            // well under 1s. Bounds the damage if DllMain ever hangs instead of
            // blocking CreateFile("test") forever (a NULL timeout would).
            LARGE_INTEGER wait_to;
            wait_to.QuadPart = -30LL * 10000000LL;
            NTSTATUS wait_st = KeWaitForSingleObject(
                trig_thread, Executive, KernelMode, FALSE, &wait_to);
            HYPERPLATFORM_LOG_INFO("[%s] DllMain thread wait done st=0x%08X",
                log_prefix, wait_st);
            ObDereferenceObject(trig_thread);
        }
        else
        {
            HYPERPLATFORM_LOG_WARN("[%s] DllMain thread ref failed: 0x%08X",
                log_prefix, ref_st);
        }
    }

    // 12. async cleanup - unhook trigger immediately after first hit
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

            HYPERPLATFORM_LOG_INFO("[td-inj-shadow] cleanup: unhooking trigger (fired=%ld), inject stays resident",
                c->fired_signal);

            PEPROCESS proc2 = NULL;
            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)c->target_pid, &proc2)))
            {
                KAPC_STATE apc2;
                KeStackAttachProcess(proc2, &apc2);

                TdUnhookTriggerAllCpus(c->trigger_fn, c->target_cr3);
                KeUnstackDetachProcess(&apc2);
                ObDereferenceObject(proc2);

                HYPERPLATFORM_LOG_INFO("[td-inj-shadow] cleanup: trigger unhook=%p, inject RESIDENT=%p",
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
        PMDL cleanup_mdl = NULL;
        UINT64 cleanup_shadow_cr3 = TdStealthTrackRemove(target_pid, mapped_base, &cleanup_mdl);
        for (SIZE_T i = 0; i < pages_installed; i++)
            TdStealthFreePage((PUINT8)mapped_base + (i * PAGE_SIZE));
        if (cleanup_shadow_cr3)
            TdShadowFreeCr3(cleanup_shadow_cr3);
        if (cleanup_mdl)
        {
            MmUnlockPages(cleanup_mdl);
            IoFreeMdl(cleanup_mdl);
        }
        ZwFreeVirtualMemory(ZwCurrentProcess(), &mapped_base, &image_size, MEM_RELEASE);
        KeUnstackDetachProcess(&cleanup_apc);
        stealth_tracked = FALSE;
    }

    ExFreePoolWithTag(raw_dll, 'fRdO');
    return st;
}


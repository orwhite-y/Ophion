/*
*   injector.cpp - Ophion ring-3 test tool
*
*   commands:
*     inject <process>         stealth shellcode injection (MessageBox)
*     hook                     R0 EPT hook NtCreateFile (kernel-wide, logs to DbgView)
*     unhook                   remove R0 EPT hook
*     hookr3 <pid> <va> <proxy> [type]   R3 EPT hook (per-process)
*     unhookr3 <pid> <va>                remove R3 EPT hook
*/

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

// ---- IOCTL codes (must match TestDriver) ----

#define TD_IOCTL_BASE     0x900
#define IOCTL_INJECT      CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EPT_HOOK    CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EPT_UNHOOK  CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EPT_HOOK_R3   CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EPT_UNHOOK_R3 CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INJECT_DLL    CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 5, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INJECT_RW     CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INJECT_RW_SHADOW CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ALLOC_SHADOW_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 8, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INSTALL_TRIGGER_JUMP CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 9, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FREE_SHADOW_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 10, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SHADOW_PROTECT_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 11, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_RESOLVE_EXPORT CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 12, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ---- shared structs (must match TestDriver) ----

#pragma pack(push, 8)
typedef struct _TD_RESOLVE_EXPORT_PARAMS {
    UINT64 target_pid;          // [in]  target process PID
    UINT64 messageboxa_va;      // [out] user32!MessageBoxA VA in target process
    UINT64 sleepex_va;          // [out] kernel32!SleepEx VA in target process
    UINT64 status;              // [out] NTSTATUS
} TD_RESOLVE_EXPORT_PARAMS;

typedef struct _TD_INJECT_PARAMS {
    UINT64 target_pid;
    UINT64 alloc_size;
    UINT64 trigger_va;      // [in]  0 = auto (NtTestAlert)
    UINT64 shellcode_va;    // [out]
    UINT64 actual_size;     // [out]
} TD_INJECT_PARAMS;

typedef struct _TD_R3_HOOK_PARAMS {
    UINT64 target_pid;
    UINT64 target_function_va;
    UINT64 proxy_function_va;
    UINT64 hook_type;
    UINT64 trampoline_va;   // [out]
    UINT64 status;           // [out]
} TD_R3_HOOK_PARAMS;

typedef struct _TD_R3_UNHOOK_PARAMS {
    UINT64 target_pid;
    UINT64 target_function_va;
    UINT64 status;           // [out]
} TD_R3_UNHOOK_PARAMS;

typedef struct _TD_INJECT_DLL_PARAMS {
    UINT64 target_pid;
    UINT32 dll_offset;     // offset of DLL data within this buffer (after header)
    UINT32 dll_size;       // size of raw DLL file
    UINT64 out_base;       // [out] mapped image base
    UINT64 out_entry;      // [out] DllMain VA
    UINT64 out_size;       // [out] image size
} TD_INJECT_DLL_PARAMS;

typedef struct _TD_INJECT_RW_PARAMS {
    UINT64 target_pid;
    UINT64 trigger_va;      // [in]  R3 function to hook as trigger (0 = auto)
    UINT64 shellcode_va;    // [out] allocated VA
    UINT64 alloc_size;      // [out] allocated size
    UINT64 shellcode_size;  // [in] bytes appended after this struct
    UINT64 alloc_protect;   // [in] PAGE_READWRITE/PAGE_WRITECOPY, 0 = PAGE_READWRITE
} TD_INJECT_RW_PARAMS;

typedef struct _TD_ALLOC_SHADOW_MEMORY_PARAMS {
    UINT64 target_pid;
    UINT64 size;
    UINT64 need_execute;
    UINT64 alloc_protect;
    UINT64 base_va;
    UINT64 shadow_cr3;
    UINT64 status;
} TD_ALLOC_SHADOW_MEMORY_PARAMS;

typedef struct _TD_SHADOW_PROTECT_PARAMS {
    UINT64 target_pid;
    UINT64 base_va;
    UINT64 size;
    UINT64 new_protect;
    UINT64 old_protect;
    UINT64 shadow_cr3;
    UINT64 status;
} TD_SHADOW_PROTECT_PARAMS;

typedef struct _TD_TRIGGER_JUMP_PARAMS {
    UINT64 target_pid;
    UINT64 trigger_va;
    UINT64 jump_to_va;
    UINT64 flags;
    UINT64 status;
} TD_TRIGGER_JUMP_PARAMS;
#pragma pack(pop)

// ---- helpers ----

static DWORD FindProcessByName(const wchar_t* name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe = {};
    pe.dwSize = sizeof(pe);

    DWORD pid = 0;
    if (Process32FirstW(snap, &pe))
    {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0)
            {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return pid;
}

static HANDLE OpenDevice()
{
    HANDLE h = CreateFileW(
        L"\\\\.\\OphionTest",
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL);

    if (h == INVALID_HANDLE_VALUE)
    {
        printf("[-] Cannot open \\Device\\OphionTest (error %u)\n", GetLastError());
        printf("    Make sure Ophion.sys and TestEptHook.sys are loaded.\n");
    }
    return h;
}

static DWORD ParseRwProtect(const wchar_t* value)
{
    if (!value || !*value || _wcsicmp(value, L"rw") == 0)
        return PAGE_READWRITE;

    if (_wcsicmp(value, L"wc") == 0 || _wcsicmp(value, L"copy") == 0 ||
        _wcsicmp(value, L"writecopy") == 0)
        return PAGE_WRITECOPY;

    DWORD protect = (DWORD)wcstoul(value, NULL, 0);
    if (protect == PAGE_READWRITE || protect == PAGE_WRITECOPY)
        return protect;

    printf("[-] Unsupported RW protect: %ls (use rw, wc, 0x4, or 0x8)\n", value);
    return 0;
}

static DWORD ParseShadowProtect(const wchar_t* value)
{
    if (!value || !*value)
        return 0;

    if (_wcsicmp(value, L"r") == 0 || _wcsicmp(value, L"ro") == 0 ||
        _wcsicmp(value, L"readonly") == 0)
        return PAGE_READONLY;

    if (_wcsicmp(value, L"rw") == 0 || _wcsicmp(value, L"readwrite") == 0)
        return PAGE_READWRITE;

    if (_wcsicmp(value, L"x") == 0 || _wcsicmp(value, L"exec") == 0)
        return PAGE_EXECUTE;

    if (_wcsicmp(value, L"rx") == 0 || _wcsicmp(value, L"er") == 0 ||
        _wcsicmp(value, L"execute_read") == 0)
        return PAGE_EXECUTE_READ;

    if (_wcsicmp(value, L"rwx") == 0 || _wcsicmp(value, L"erw") == 0 ||
        _wcsicmp(value, L"execute_readwrite") == 0)
        return PAGE_EXECUTE_READWRITE;

    DWORD protect = (DWORD)wcstoul(value, NULL, 0);
    switch (protect)
    {
    case PAGE_READONLY:
    case PAGE_READWRITE:
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
        return protect;
    default:
        printf("[-] Unsupported shadow protect: %ls (use r, rw, x, rx, rwx, or numeric PAGE_*)\n", value);
        return 0;
    }
}

// ---- R3 shellcode builder for injectrw/injectrwshadow ----

static const BYTE g_shellcode_pic_r3[] = {
    0x48, 0x83, 0xEC, 0x28,
    0x49, 0xBC,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x49, 0xBD,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x83, 0xEC, 0x40,
    0xC7, 0x44, 0x24, 0x20, 0x4F, 0x70, 0x68, 0x69,
    0x66, 0xC7, 0x44, 0x24, 0x24, 0x6F, 0x6E,
    0xC6, 0x44, 0x24, 0x26, 0x00,
    0xC7, 0x44, 0x24, 0x30, 0x53, 0x74, 0x65, 0x61,
    0xC7, 0x44, 0x24, 0x34, 0x6C, 0x74, 0x68, 0x20,
    0x66, 0xC7, 0x44, 0x24, 0x38, 0x4F, 0x4B,
    0xC6, 0x44, 0x24, 0x3A, 0x00,
    0x48, 0x31, 0xC9,
    0x48, 0x8D, 0x54, 0x24, 0x30,
    0x4C, 0x8D, 0x44, 0x24, 0x20,
    0x45, 0x31, 0xC9,
    0x41, 0xFF, 0xD4,
    0xB9, 0xB8, 0x0B, 0x00, 0x00,
    0x31, 0xD2,
    0x41, 0xFF, 0xD5,
    0xEB, 0xE1,
};

#define R3_PIC_PATCH_MESSAGEBOX 6
#define R3_PIC_PATCH_SLEEPEX    16

typedef struct _REMOTE_MODULE_INFO {
    UINT64 base;
    wchar_t path[MAX_PATH];
} REMOTE_MODULE_INFO;

static bool FindRemoteModuleInfo(DWORD pid, const wchar_t* module_name, REMOTE_MODULE_INFO* info)
{
    if (!info) return false;
    ZeroMemory(info, sizeof(*info));

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return false;

    MODULEENTRY32W me = {};
    me.dwSize = sizeof(me);

    bool found = false;
    if (Module32FirstW(snap, &me))
    {
        do {
            if (_wcsicmp(me.szModule, module_name) == 0)
            {
                info->base = (UINT64)me.modBaseAddr;
                wcsncpy_s(info->path, me.szExePath, _TRUNCATE);
                found = true;
                break;
            }
        } while (Module32NextW(snap, &me));
    }

    CloseHandle(snap);
    return found;
}

static void AsciiModuleToWideDll(const char* ascii, wchar_t* wide, SIZE_T wide_count)
{
    if (!wide_count) return;

    SIZE_T i = 0;
    for (; ascii[i] && i < wide_count - 1; i++)
    {
        char c = ascii[i];
        if (c >= 'a' && c <= 'z') c -= 32;
        wide[i] = (wchar_t)c;
    }

    if (i + 4 < wide_count && !(i >= 4 &&
        wide[i - 4] == L'.' &&
        (wide[i - 3] == L'D' || wide[i - 3] == L'd') &&
        (wide[i - 2] == L'L' || wide[i - 2] == L'l') &&
        (wide[i - 1] == L'L' || wide[i - 1] == L'l')))
    {
        wide[i++] = L'.';
        wide[i++] = L'd';
        wide[i++] = L'l';
        wide[i++] = L'l';
    }

    wide[i] = L'\0';
}

static bool ReadFileToBuffer(const wchar_t* path, BYTE** out_data, DWORD* out_size)
{
    *out_data = NULL;
    *out_size = 0;

    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return false;

    LARGE_INTEGER li = {};
    if (!GetFileSizeEx(file, &li) || li.QuadPart <= 0 || li.QuadPart > 64LL * 1024 * 1024)
    {
        CloseHandle(file);
        return false;
    }

    DWORD size = (DWORD)li.QuadPart;
    BYTE* data = (BYTE*)malloc(size);
    if (!data)
    {
        CloseHandle(file);
        return false;
    }

    DWORD got = 0;
    bool ok = ReadFile(file, data, size, &got, NULL) && got == size;
    CloseHandle(file);

    if (!ok)
    {
        free(data);
        return false;
    }

    *out_data = data;
    *out_size = size;
    return true;
}

static void* RvaToFilePtr(BYTE* image, DWORD image_size, IMAGE_NT_HEADERS64* nt, DWORD rva, DWORD need)
{
    if (!image || !nt || !need)
        return NULL;

    if (rva > image_size || need > image_size - rva)
        return NULL;

    if (rva < nt->OptionalHeader.SizeOfHeaders)
        return image + rva;

    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    BYTE* sec_end = (BYTE*)sec + (UINT64)nt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    if (sec_end > image + image_size)
        return NULL;

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        DWORD va = sec[i].VirtualAddress;
        DWORD raw = sec[i].PointerToRawData;
        DWORD raw_size = sec[i].SizeOfRawData;
        DWORD span = sec[i].Misc.VirtualSize > raw_size ? sec[i].Misc.VirtualSize : raw_size;

        if (rva >= va && rva - va < span && need <= span - (rva - va))
        {
            DWORD off = raw + (rva - va);
            if (off <= image_size && need <= image_size - off)
                return image + off;
            return NULL;
        }
    }

    return NULL;
}

static bool FileAnsiEquals(BYTE* image, DWORD image_size, const char* file_str, const char* expected)
{
    UINT64 off = (UINT64)((BYTE*)file_str - image);
    if (off >= image_size)
        return false;

    for (DWORD i = 0; expected[i]; i++)
    {
        if (off + i >= image_size || file_str[i] != expected[i])
            return false;
    }

    DWORD end = (DWORD)(off + strlen(expected));
    return end < image_size && file_str[strlen(expected)] == '\0';
}

static char* FileAnsiFindChar(BYTE* image, DWORD image_size, char* file_str, char ch)
{
    UINT64 off = (UINT64)((BYTE*)file_str - image);
    if (off >= image_size)
        return NULL;

    for (DWORD i = (DWORD)off; i < image_size; i++)
    {
        if (image[i] == ch)
            return (char*)(image + i);
        if (image[i] == '\0')
            return NULL;
    }

    return NULL;
}

static UINT64 ResolveRemoteExportFromFile(
    DWORD pid,
    const wchar_t* module_path,
    UINT64 module_base,
    const char* export_name,
    int depth)
{
    if (!module_base || !module_path || !export_name || depth > 4)
        return 0;

    BYTE* image = NULL;
    DWORD image_size = 0;
    if (!ReadFileToBuffer(module_path, &image, &image_size))
        return 0;

    UINT64 result = 0;
    IMAGE_NT_HEADERS64* nt = NULL;
    DWORD exp_rva = 0;
    DWORD exp_size = 0;
    IMAGE_EXPORT_DIRECTORY* exp = NULL;
    DWORD* names = NULL;
    WORD* ords = NULL;
    DWORD* funcs = NULL;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)image;
    if (image_size < sizeof(*dos) || dos->e_magic != IMAGE_DOS_SIGNATURE)
        goto Exit;

    if (dos->e_lfanew < 0 || (DWORD)dos->e_lfanew > image_size - sizeof(IMAGE_NT_HEADERS64))
        goto Exit;

    nt = (IMAGE_NT_HEADERS64*)(image + dos->e_lfanew);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE)
        goto Exit;

    exp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    exp_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (!exp_rva || !exp_size)
        goto Exit;

    exp = (IMAGE_EXPORT_DIRECTORY*)RvaToFilePtr(
        image, image_size, nt, exp_rva, sizeof(IMAGE_EXPORT_DIRECTORY));
    if (!exp || !exp->NumberOfNames || !exp->AddressOfNames ||
        !exp->AddressOfNameOrdinals || !exp->AddressOfFunctions)
        goto Exit;

    names = (DWORD*)RvaToFilePtr(image, image_size, nt,
        exp->AddressOfNames, exp->NumberOfNames * sizeof(DWORD));
    ords = (WORD*)RvaToFilePtr(image, image_size, nt,
        exp->AddressOfNameOrdinals, exp->NumberOfNames * sizeof(WORD));
    funcs = (DWORD*)RvaToFilePtr(image, image_size, nt,
        exp->AddressOfFunctions, exp->NumberOfFunctions * sizeof(DWORD));
    if (!names || !ords || !funcs)
        goto Exit;

    for (DWORD i = 0; i < exp->NumberOfNames; i++)
    {
        char* name = (char*)RvaToFilePtr(image, image_size, nt, names[i], 1);
        if (!name)
            continue;
        if (!FileAnsiEquals(image, image_size, name, export_name))
            continue;

        WORD ord = ords[i];
        if (ord >= exp->NumberOfFunctions)
            break;

        DWORD func_rva = funcs[ord];
        if (func_rva >= exp_rva && func_rva < exp_rva + exp_size)
        {
            char* fwd = (char*)RvaToFilePtr(image, image_size, nt, func_rva, 1);
            if (fwd)
            {
                char* dot = FileAnsiFindChar(image, image_size, fwd, '.');
                if (dot && dot != fwd && dot[1])
                {
                    char fwd_mod_ascii[64] = {};
                    SIZE_T mod_len = (SIZE_T)(dot - fwd);
                    if (mod_len >= sizeof(fwd_mod_ascii))
                        mod_len = sizeof(fwd_mod_ascii) - 1;
                    memcpy(fwd_mod_ascii, fwd, mod_len);

                    wchar_t fwd_mod[MAX_PATH] = {};
                    AsciiModuleToWideDll(fwd_mod_ascii, fwd_mod, _countof(fwd_mod));

                    REMOTE_MODULE_INFO fwd_info = {};
                    if (dot[1] != '#' && FindRemoteModuleInfo(pid, fwd_mod, &fwd_info))
                        result = ResolveRemoteExportFromFile(pid, fwd_info.path, fwd_info.base, dot + 1, depth + 1);
                }
            }
        }
        else
        {
            result = module_base + func_rva;
        }
        break;
    }

Exit:
    free(image);
    return result;
}

static UINT64 ResolveRemoteExport(DWORD pid, const wchar_t* module_name, const char* export_name)
{
    REMOTE_MODULE_INFO info = {};
    if (!FindRemoteModuleInfo(pid, module_name, &info))
        return 0;

    return ResolveRemoteExportFromFile(pid, info.path, info.base, export_name, 0);
}

static bool ResolveShellcodeApisR3(DWORD pid, TD_RESOLVE_EXPORT_PARAMS* rp)
{
    HANDLE dev = OpenDevice();
    if (dev == INVALID_HANDLE_VALUE) return false;

    ZeroMemory(rp, sizeof(*rp));
    rp->target_pid = (UINT64)pid;

    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(dev, IOCTL_RESOLVE_EXPORT, rp, sizeof(*rp), rp, sizeof(*rp), &bytes, NULL);
    CloseHandle(dev);

    if (!ok || bytes < sizeof(TD_RESOLVE_EXPORT_PARAMS) || rp->status != 0 || !rp->messageboxa_va || !rp->sleepex_va)
    {
        printf("[-] ResolveShellcodeApisR3: driver resolve export failed (ok=%u status=0x%llX msgbox=0x%llX sleepex=0x%llX)\n",
            ok, rp->status, rp->messageboxa_va, rp->sleepex_va);
        return false;
    }

    return true;
}

static bool BuildShellcodeR3(DWORD pid, BYTE* out_buf, DWORD out_size, DWORD* out_shellcode_size)
{
    if (out_size < sizeof(g_shellcode_pic_r3)) return false;

    TD_RESOLVE_EXPORT_PARAMS rp = {};
    if (!ResolveShellcodeApisR3(pid, &rp))
        return false;

    ZeroMemory(out_buf, out_size);
    memcpy(out_buf, g_shellcode_pic_r3, sizeof(g_shellcode_pic_r3));
    *(UINT64*)(out_buf + R3_PIC_PATCH_MESSAGEBOX) = rp.messageboxa_va;
    *(UINT64*)(out_buf + R3_PIC_PATCH_SLEEPEX) = rp.sleepex_va;
    *out_shellcode_size = (DWORD)sizeof(g_shellcode_pic_r3);

    printf("[+] R3 shellcode built via driver: MessageBoxA=0x%llX SleepEx=0x%llX size=0x%X\n",
        rp.messageboxa_va, rp.sleepex_va, *out_shellcode_size);
    return true;
}

static bool EmitByte(BYTE* buf, DWORD cap, DWORD* pos, BYTE v)
{
    if (*pos >= cap) return false;
    buf[(*pos)++] = v;
    return true;
}

static bool EmitBytes(BYTE* buf, DWORD cap, DWORD* pos, const BYTE* src, DWORD len)
{
    if (len > cap || *pos > cap - len) return false;
    memcpy(buf + *pos, src, len);
    *pos += len;
    return true;
}

static bool EmitU32(BYTE* buf, DWORD cap, DWORD* pos, UINT32 v)
{
    return EmitBytes(buf, cap, pos, (const BYTE*)&v, sizeof(v));
}

static bool EmitU64(BYTE* buf, DWORD cap, DWORD* pos, UINT64 v)
{
    return EmitBytes(buf, cap, pos, (const BYTE*)&v, sizeof(v));
}

static bool EmitRel32(BYTE* buf, DWORD cap, DWORD* pos, DWORD instr_end_abs, DWORD target_abs)
{
    INT64 rel = (INT64)target_abs - (INT64)instr_end_abs;
    if (rel < INT_MIN || rel > INT_MAX) return false;
    return EmitU32(buf, cap, pos, (UINT32)(INT32)rel);
}

static bool WritePageString(BYTE* out_buf, DWORD out_size, DWORD abs_off, const char* s)
{
    size_t len = strlen(s) + 1;
    if (len > out_size || abs_off > out_size - len) return false;
    memcpy(out_buf + abs_off, s, len);
    return true;
}

static bool BuildShellcodeR3PageWalk(DWORD pid, BYTE* out_buf, DWORD out_size, DWORD* out_shellcode_size)
{
    const DWORD kPageSize = 0x1000;
    const DWORD kPageCount = 10;
    const DWORD kPayloadSize = kPageSize * kPageCount;
    const DWORD kTextOff = 0x300;
    const DWORD kCaptionOff = 0x340;

    if (out_size < kPayloadSize) return false;

    TD_RESOLVE_EXPORT_PARAMS rp = {};
    if (!ResolveShellcodeApisR3(pid, &rp))
        return false;

    ZeroMemory(out_buf, out_size);

    for (DWORD page = 0; page < kPageCount; page++)
    {
        BYTE* code = out_buf + page * kPageSize;
        DWORD pos = 0;
        DWORD page_abs = page * kPageSize;
        DWORD text_abs = page_abs + kTextOff;
        DWORD caption_abs = page_abs + kCaptionOff;
        char text[64] = {};
        const char caption[] = "Ophion multi-page";

        snprintf(text, sizeof(text), "Shadow page test %u/%u", page + 1, kPageCount);
        if (!WritePageString(out_buf, out_size, text_abs, text) ||
            !WritePageString(out_buf, out_size, caption_abs, caption))
            return false;

        const BYTE prolog[] = { 0x48, 0x83, 0xEC, 0x28 };       // sub rsp, 28h
        const BYTE xor_ecx[] = { 0x31, 0xC9 };                  // xor ecx, ecx
        const BYTE lea_rdx[] = { 0x48, 0x8D, 0x15 };            // lea rdx, [rip+disp32]
        const BYTE lea_r8[] = { 0x4C, 0x8D, 0x05 };             // lea r8, [rip+disp32]
        const BYTE xor_r9d[] = { 0x45, 0x31, 0xC9 };            // xor r9d, r9d
        const BYTE mov_rax[] = { 0x48, 0xB8 };                  // mov rax, imm64
        const BYTE call_rax[] = { 0xFF, 0xD0 };                 // call rax
        const BYTE epilog[] = { 0x48, 0x83, 0xC4, 0x28 };       // add rsp, 28h

        if (!EmitBytes(code, kPageSize, &pos, prolog, sizeof(prolog)) ||
            !EmitBytes(code, kPageSize, &pos, xor_ecx, sizeof(xor_ecx)))
            return false;

        DWORD lea_abs = page_abs + pos;
        if (!EmitBytes(code, kPageSize, &pos, lea_rdx, sizeof(lea_rdx)) ||
            !EmitRel32(code, kPageSize, &pos, lea_abs + 7, text_abs))
            return false;

        lea_abs = page_abs + pos;
        if (!EmitBytes(code, kPageSize, &pos, lea_r8, sizeof(lea_r8)) ||
            !EmitRel32(code, kPageSize, &pos, lea_abs + 7, caption_abs) ||
            !EmitBytes(code, kPageSize, &pos, xor_r9d, sizeof(xor_r9d)) ||
            !EmitBytes(code, kPageSize, &pos, mov_rax, sizeof(mov_rax)) ||
            !EmitU64(code, kPageSize, &pos, rp.messageboxa_va) ||
            !EmitBytes(code, kPageSize, &pos, call_rax, sizeof(call_rax)) ||
            !EmitBytes(code, kPageSize, &pos, epilog, sizeof(epilog)))
            return false;

        if (page + 1 < kPageCount)
        {
            DWORD jmp_abs = page_abs + pos;
            if (!EmitByte(code, kPageSize, &pos, 0xE9) ||
                !EmitRel32(code, kPageSize, &pos, jmp_abs + 5, (page + 1) * kPageSize))
                return false;
        }
        else
        {
            DWORD loop_abs = page_abs + pos;
            const BYTE mov_ecx_1000[] = { 0xB9, 0xE8, 0x03, 0x00, 0x00 }; // mov ecx, 1000
            const BYTE xor_edx[] = { 0x31, 0xD2 };                        // xor edx, edx
            DWORD jmp_abs = 0;

            if (!EmitBytes(code, kPageSize, &pos, prolog, sizeof(prolog)) ||
                !EmitBytes(code, kPageSize, &pos, mov_ecx_1000, sizeof(mov_ecx_1000)) ||
                !EmitBytes(code, kPageSize, &pos, xor_edx, sizeof(xor_edx)) ||
                !EmitBytes(code, kPageSize, &pos, mov_rax, sizeof(mov_rax)) ||
                !EmitU64(code, kPageSize, &pos, rp.sleepex_va) ||
                !EmitBytes(code, kPageSize, &pos, call_rax, sizeof(call_rax)) ||
                !EmitBytes(code, kPageSize, &pos, epilog, sizeof(epilog)))
                return false;

            jmp_abs = page_abs + pos;
            if (!EmitByte(code, kPageSize, &pos, 0xE9) ||
                !EmitRel32(code, kPageSize, &pos, jmp_abs + 5, loop_abs))
                return false;
        }
    }

    *out_shellcode_size = kPayloadSize;
    printf("[+] R3 10-page test shellcode built via driver: MessageBoxA=0x%llX SleepEx=0x%llX size=0x%X pages=%u\n",
        rp.messageboxa_va, rp.sleepex_va, *out_shellcode_size, kPageCount);
    return true;
}

// ---- stealth inject ----

static int CmdInject(const wchar_t* target_name)
{
    printf("[*] Stealth Inject: %ls\n", target_name);

    DWORD pid = FindProcessByName(target_name);
    if (!pid) { printf("[-] Process not found.\n"); return 1; }
    printf("[+] PID: %u\n", pid);

    HANDLE dev = OpenDevice();
    if (dev == INVALID_HANDLE_VALUE) return 1;

    TD_INJECT_PARAMS p = {};
    p.target_pid = (UINT64)pid;

    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(dev, IOCTL_INJECT, &p, sizeof(p), &p, sizeof(p), &bytes, NULL);

    if (ok)
    {
        UINT32 thr_status = (UINT32)(p.actual_size >> 32);
        printf("[+] Stealth VA: 0x%llX\n", p.shellcode_va);
        printf("[+] Thread status: 0x%08X\n", thr_status);
        if (thr_status == 0)
            printf("[+] Thread created OK. Watch for MessageBox from PID %u.\n", pid);
        else
            printf("[-] Thread creation failed: 0x%08X\n", thr_status);
    }
    else
        printf("[-] IOCTL_INJECT failed (error %u)\n", GetLastError());

    CloseHandle(dev);
    return ok ? 0 : 1;
}

// ---- R0 EPT hook (NtCreateFile) ----

static int CmdHook()
{
    printf("[*] Installing R0 EPT hook on NtCreateFile...\n");

    HANDLE dev = OpenDevice();
    if (dev == INVALID_HANDLE_VALUE) return 1;

    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(dev, IOCTL_EPT_HOOK, NULL, 0, NULL, 0, &bytes, NULL);

    if (ok)
        printf("[+] Hook installed. Check DbgView for [td-hook] messages.\n");
    else
        printf("[-] IOCTL_EPT_HOOK failed (error %u)\n", GetLastError());

    CloseHandle(dev);
    return ok ? 0 : 1;
}

static int CmdUnhook()
{
    printf("[*] Removing R0 EPT hook...\n");

    HANDLE dev = OpenDevice();
    if (dev == INVALID_HANDLE_VALUE) return 1;

    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(dev, IOCTL_EPT_UNHOOK, NULL, 0, NULL, 0, &bytes, NULL);

    if (ok)
        printf("[+] Hook removed.\n");
    else
        printf("[-] IOCTL_EPT_UNHOOK failed (error %u)\n", GetLastError());

    CloseHandle(dev);
    return ok ? 0 : 1;
}

// ---- R3 EPT hook (per-process) ----

static int CmdHookR3(UINT64 pid, UINT64 target_va, UINT64 proxy_va, UINT64 hook_type)
{
    printf("[*] Installing R3 EPT hook: pid=%llu target=0x%llX proxy=0x%llX type=%llu\n",
           pid, target_va, proxy_va, hook_type);

    HANDLE dev = OpenDevice();
    if (dev == INVALID_HANDLE_VALUE) return 1;

    TD_R3_HOOK_PARAMS p = {};
    p.target_pid         = pid;
    p.target_function_va = target_va;
    p.proxy_function_va  = proxy_va;
    p.hook_type          = hook_type;

    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(dev, IOCTL_EPT_HOOK_R3, &p, sizeof(p), &p, sizeof(p), &bytes, NULL);

    if (ok && p.status == 0)
    {
        printf("[+] R3 hook installed.\n");
        printf("    trampoline VA: 0x%llX\n", p.trampoline_va);
        printf("    Only PID %llu sees the hook. Other processes unaffected.\n", pid);
    }
    else
        printf("[-] R3 hook failed (ioctl=%u status=0x%llX)\n", GetLastError(), p.status);

    CloseHandle(dev);
    return (ok && p.status == 0) ? 0 : 1;
}

static int CmdUnhookR3(UINT64 pid, UINT64 target_va)
{
    printf("[*] Removing R3 EPT hook: pid=%llu target=0x%llX\n", pid, target_va);

    HANDLE dev = OpenDevice();
    if (dev == INVALID_HANDLE_VALUE) return 1;

    TD_R3_UNHOOK_PARAMS p = {};
    p.target_pid         = pid;
    p.target_function_va = target_va;

    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(dev, IOCTL_EPT_UNHOOK_R3, &p, sizeof(p), &p, sizeof(p), &bytes, NULL);

    if (ok && p.status == 0)
        printf("[+] R3 hook removed.\n");
    else
        printf("[-] R3 unhook failed (ioctl=%u status=0x%llX)\n", GetLastError(), p.status);

    CloseHandle(dev);
    return (ok && p.status == 0) ? 0 : 1;
}

// ---- DLL manual-map inject ----

static int CmdInjectDll(const wchar_t* target_name, const wchar_t* dll_path)
{
    printf("[*] Manual Map Inject: %ls <- %ls\n", target_name, dll_path);

    // 1. find target PID
    DWORD pid = FindProcessByName(target_name);
    if (!pid) { printf("[-] Process not found: %ls\n", target_name); return 1; }
    printf("[+] PID: %u\n", pid);

    // 2. read DLL file
    HANDLE hFile = CreateFileW(dll_path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("[-] Cannot open DLL: %ls (error %u)\n", dll_path, GetLastError());
        return 1;
    }

    DWORD dll_size = GetFileSize(hFile, NULL);
    if (dll_size == INVALID_FILE_SIZE || dll_size == 0)
    {
        printf("[-] Invalid DLL file size.\n");
        CloseHandle(hFile);
        return 1;
    }

    printf("[+] DLL size: %u bytes\n", dll_size);

    // 3. allocate IOCTL buffer: header + DLL data
    DWORD total_size = sizeof(TD_INJECT_DLL_PARAMS) + dll_size;
    UINT8* buf = (UINT8*)VirtualAlloc(NULL, total_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf)
    {
        printf("[-] VirtualAlloc failed (error %u)\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }

    // 4. fill header
    TD_INJECT_DLL_PARAMS* p = (TD_INJECT_DLL_PARAMS*)buf;
    memset(p, 0, sizeof(*p));
    p->target_pid = (UINT64)pid;
    p->dll_offset = sizeof(TD_INJECT_DLL_PARAMS);
    p->dll_size   = dll_size;

    // 5. copy DLL data after header
    DWORD bytes_read = 0;
    if (!ReadFile(hFile, buf + sizeof(TD_INJECT_DLL_PARAMS), dll_size, &bytes_read, NULL) ||
        bytes_read != dll_size)
    {
        printf("[-] ReadFile failed (error %u, read %u/%u)\n", GetLastError(), bytes_read, dll_size);
        VirtualFree(buf, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return 1;
    }
    CloseHandle(hFile);

    // 6. send IOCTL
    HANDLE dev = OpenDevice();
    if (dev == INVALID_HANDLE_VALUE)
    {
        VirtualFree(buf, 0, MEM_RELEASE);
        return 1;
    }

    DWORD out_bytes = 0;
    BOOL ok = DeviceIoControl(dev, IOCTL_INJECT_DLL,
                              buf, total_size,
                              buf, sizeof(TD_INJECT_DLL_PARAMS),
                              &out_bytes, NULL);

    if (ok && out_bytes >= sizeof(TD_INJECT_DLL_PARAMS))
    {
        printf("[+] Manual map success!\n");
        printf("    Base:  0x%llX\n", p->out_base);
        printf("    Entry: 0x%llX\n", p->out_entry);
        printf("    Size:  0x%llX\n", p->out_size);
    }
    else
    {
        printf("[-] IOCTL_INJECT_DLL failed (error %u)\n", GetLastError());
    }

    CloseHandle(dev);
    VirtualFree(buf, 0, MEM_RELEASE);
    return ok ? 0 : 1;
}

// ---- RW-alloc + EPT stealth inject ----

static int CmdInjectRW(const wchar_t* target_name, DWORD alloc_protect)
{
    printf("[*] RW-alloc + EPT stealth inject: %ls protect=0x%X\n", target_name, alloc_protect);

    DWORD pid = FindProcessByName(target_name);
    if (!pid) { printf("[-] Process not found: %ls\n", target_name); return 1; }
    printf("[+] PID: %u\n", pid);

    HANDLE dev = OpenDevice();
    if (dev == INVALID_HANDLE_VALUE) return 1;

    DWORD shellcode_size = 0;
    DWORD total_size = sizeof(TD_INJECT_RW_PARAMS) + sizeof(g_shellcode_pic_r3);
    BYTE* buf = (BYTE*)calloc(1, total_size);
    if (!buf)
    {
        CloseHandle(dev);
        return 1;
    }

    TD_INJECT_RW_PARAMS* p = (TD_INJECT_RW_PARAMS*)buf;
    p->target_pid = (UINT64)pid;
    p->alloc_protect = alloc_protect;
    if (!BuildShellcodeR3(pid, buf + sizeof(TD_INJECT_RW_PARAMS),
                          total_size - sizeof(TD_INJECT_RW_PARAMS),
                          &shellcode_size))
    {
        free(buf);
        CloseHandle(dev);
        return 1;
    }
    p->shellcode_size = shellcode_size;

    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(dev, IOCTL_INJECT_RW,
        buf, total_size, buf, total_size, &bytes, NULL);

    if (ok && bytes >= sizeof(TD_INJECT_RW_PARAMS))
    {
        printf("[+] Inject OK!\n");
        printf("    Shellcode VA: 0x%llX\n", p->shellcode_va);
        printf("    Alloc size:   0x%llX\n", p->alloc_size);
        printf("    R3 SC size:   0x%llX\n", p->shellcode_size);
        printf("    RW protect:   0x%llX\n", p->alloc_protect);
        printf("[+] RW page allocated, EPT read=zeroed, EPT exec=shellcode.\n");
        printf("[+] Trigger hook active. Watch for MessageBox from PID %u.\n", pid);
    }
    else
        printf("[-] IOCTL_INJECT_RW failed (error %u)\n", GetLastError());

    free(buf);
    CloseHandle(dev);
    return ok ? 0 : 1;
}

// ---- RW-alloc + shadow CR3 NX bypass inject ----

static int CmdInjectRWShadow(const wchar_t* target_name, DWORD alloc_protect)
{
    printf("[*] RW-alloc + shadow CR3 inject: %ls protect=0x%X\n", target_name, alloc_protect);

    DWORD pid = FindProcessByName(target_name);
    if (!pid) { printf("[-] Process not found: %ls\n", target_name); return 1; }
    printf("[+] PID: %u\n", pid);

    HANDLE dev = OpenDevice();
    if (dev == INVALID_HANDLE_VALUE) return 1;

    const DWORD shadow_test_shellcode_capacity = 10 * 0x1000;
    DWORD shellcode_size = 0;
    DWORD total_size = sizeof(TD_INJECT_RW_PARAMS) + shadow_test_shellcode_capacity;
    BYTE* buf = (BYTE*)calloc(1, total_size);
    if (!buf)
    {
        CloseHandle(dev);
        return 1;
    }

    TD_INJECT_RW_PARAMS* p = (TD_INJECT_RW_PARAMS*)buf;
    p->target_pid = (UINT64)pid;
    p->alloc_protect = alloc_protect;
    if (!BuildShellcodeR3PageWalk(pid, buf + sizeof(TD_INJECT_RW_PARAMS),
                                  total_size - sizeof(TD_INJECT_RW_PARAMS),
                                  &shellcode_size))
    {
        free(buf);
        CloseHandle(dev);
        return 1;
    }
    p->shellcode_size = shellcode_size;

    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(dev, IOCTL_INJECT_RW_SHADOW,
        buf, total_size, buf, total_size, &bytes, NULL);

    if (ok && bytes >= sizeof(TD_INJECT_RW_PARAMS))
    {
        printf("[+] Inject OK!\n");
        printf("    Shellcode VA: 0x%llX\n", p->shellcode_va);
        printf("    Alloc size:   0x%llX\n", p->alloc_size);
        printf("    R3 SC size:   0x%llX\n", p->shellcode_size);
        printf("    RW protect:   0x%llX\n", p->alloc_protect);
        printf("[+] RW page allocated, shadow CR3 NX bypass active, no EPT page split.\n");
        printf("[+] Trigger hook active. Watch for MessageBox from PID %u.\n", pid);
    }
    else
        printf("[-] IOCTL_INJECT_RW_SHADOW failed (error %u)\n", GetLastError());

    free(buf);
    CloseHandle(dev);
    return ok ? 0 : 1;
}

// ---- generic RW allocation, optional shadow CR3 executable view ----

static int CmdAllocMem(const wchar_t* target_name, UINT64 size, bool need_execute, DWORD alloc_protect)
{
    printf("[*] Alloc memory: %ls size=0x%llX exec=%u protect=0x%X\n",
        target_name, size, need_execute ? 1 : 0, alloc_protect);

    DWORD pid = FindProcessByName(target_name);
    if (!pid) { printf("[-] Process not found: %ls\n", target_name); return 1; }
    printf("[+] PID: %u\n", pid);

    HANDLE dev = OpenDevice();
    if (dev == INVALID_HANDLE_VALUE) return 1;

    TD_ALLOC_SHADOW_MEMORY_PARAMS p = {};
    p.target_pid = (UINT64)pid;
    p.size = size;
    p.need_execute = need_execute ? 1 : 0;
    p.alloc_protect = alloc_protect;

    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(dev, IOCTL_ALLOC_SHADOW_MEMORY,
        &p, sizeof(p), &p, sizeof(p), &bytes, NULL);

    if (ok && bytes >= sizeof(TD_ALLOC_SHADOW_MEMORY_PARAMS))
    {
        printf("[+] Alloc status: 0x%08llX\n", p.status);
        printf("    Base VA:    0x%llX\n", p.base_va);
        printf("    Size:       0x%llX\n", p.size);
        printf("    Protect:    0x%llX\n", p.alloc_protect);
        printf("    Shadow CR3: 0x%llX\n", p.shadow_cr3);
    }
    else
    {
        printf("[-] IOCTL_ALLOC_SHADOW_MEMORY failed (error %u)\n", GetLastError());
        printf("    Driver status: 0x%08llX\n", p.status);
    }

    CloseHandle(dev);
    return (ok && p.status == 0) ? 0 : 1;
}

static int CmdFreeMem(const wchar_t* target_name, UINT64 base_va, UINT64 size)
{
    printf("[*] Free memory: %ls base=0x%llX size=0x%llX\n",
        target_name, base_va, size);

    DWORD pid = FindProcessByName(target_name);
    if (!pid) { printf("[-] Process not found: %ls\n", target_name); return 1; }
    printf("[+] PID: %u\n", pid);

    HANDLE dev = OpenDevice();
    if (dev == INVALID_HANDLE_VALUE) return 1;

    TD_ALLOC_SHADOW_MEMORY_PARAMS p = {};
    p.target_pid = (UINT64)pid;
    p.base_va = base_va;
    p.size = size;

    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(dev, IOCTL_FREE_SHADOW_MEMORY,
        &p, sizeof(p), &p, sizeof(p), &bytes, NULL);

    if (ok && bytes >= sizeof(TD_ALLOC_SHADOW_MEMORY_PARAMS))
    {
        printf("[+] Free status: 0x%08llX\n", p.status);
        printf("    Base VA: 0x%llX\n", p.base_va);
        printf("    Size:    0x%llX\n", p.size);
    }
    else
    {
        printf("[-] IOCTL_FREE_SHADOW_MEMORY failed (error %u)\n", GetLastError());
        printf("    Driver status: 0x%08llX\n", p.status);
    }

    CloseHandle(dev);
    return (ok && p.status == 0) ? 0 : 1;
}

static int CmdShadowProtect(UINT64 pid, UINT64 base_va, UINT64 size, DWORD new_protect)
{
    printf("[*] Shadow protect: pid=%llu base=0x%llX size=0x%llX protect=0x%X\n",
        pid, base_va, size, new_protect);

    HANDLE dev = OpenDevice();
    if (dev == INVALID_HANDLE_VALUE) return 1;

    TD_SHADOW_PROTECT_PARAMS p = {};
    p.target_pid = pid;
    p.base_va = base_va;
    p.size = size;
    p.new_protect = new_protect;

    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(dev, IOCTL_SHADOW_PROTECT_MEMORY,
        &p, sizeof(p), &p, sizeof(p), &bytes, NULL);

    if (ok && bytes >= sizeof(TD_SHADOW_PROTECT_PARAMS))
    {
        printf("[+] Protect status: 0x%08llX\n", p.status);
        printf("    Base VA:    0x%llX\n", p.base_va);
        printf("    Size:       0x%llX\n", p.size);
        printf("    OldProtect: 0x%llX\n", p.old_protect);
        printf("    NewProtect: 0x%llX\n", p.new_protect);
        printf("    Shadow CR3: 0x%llX\n", p.shadow_cr3);
    }
    else
    {
        printf("[-] IOCTL_SHADOW_PROTECT_MEMORY failed (error %u)\n", GetLastError());
        printf("    Driver status: 0x%08llX\n", p.status);
    }

    CloseHandle(dev);
    return (ok && p.status == 0) ? 0 : 1;
}

static bool ShadowProtectSelf(UINT64 base_va, UINT64 size, DWORD new_protect, DWORD* old_protect)
{
    HANDLE dev = OpenDevice();
    if (dev == INVALID_HANDLE_VALUE) return false;

    TD_SHADOW_PROTECT_PARAMS p = {};
    p.target_pid = GetCurrentProcessId();
    p.base_va = base_va;
    p.size = size;
    p.new_protect = new_protect;

    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(dev, IOCTL_SHADOW_PROTECT_MEMORY,
        &p, sizeof(p), &p, sizeof(p), &bytes, NULL);
    CloseHandle(dev);

    if (!ok || bytes < sizeof(TD_SHADOW_PROTECT_PARAMS) || p.status != 0)
    {
        printf("[-] ShadowProtectSelf failed: ok=%u gle=%u status=0x%08llX base=0x%llX size=0x%llX protect=0x%X\n",
            ok, GetLastError(), p.status, base_va, size, new_protect);
        return false;
    }

    if (old_protect)
        *old_protect = (DWORD)p.old_protect;

    printf("[+] ShadowProtectSelf OK: base=0x%llX size=0x%llX old=0x%X new=0x%X shadow_cr3=0x%llX\n",
        p.base_va, p.size, (DWORD)p.old_protect, (DWORD)p.new_protect, p.shadow_cr3);
    return true;
}

static void PrintBytesLine(const char* label, const BYTE* p, SIZE_T len)
{
    printf("%s", label);
    for (SIZE_T i = 0; i < len; i++)
        printf(" %02X", p[i]);
    printf("\n");
}

static bool IsGapByte(BYTE b)
{
    return b == 0xCC || b == 0x90 || b == 0x00;
}

static BYTE* FindNtdllCodeGap(SIZE_T needed_len)
{
    const BYTE gap_types[] = { 0xCC, 0x90, 0x00 };
    SIZE_T min_run = needed_len < 16 ? 16 : needed_len;

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        return NULL;

    BYTE* base = (BYTE*)ntdll;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
    {
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;

        BYTE* start = base + sec->VirtualAddress;
        SIZE_T size = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
        if (size < needed_len)
            continue;

        for (SIZE_T type_idx = 0; type_idx < sizeof(gap_types); type_idx++)
        {
            BYTE gap_byte = gap_types[type_idx];
            if (!IsGapByte(gap_byte) || size < min_run)
                continue;

            for (SIZE_T off = 0; off <= size - min_run; off++)
            {
                BYTE* p = start + off;
                UINT_PTR page0 = (UINT_PTR)p & ~0xFFFULL;
                UINT_PTR page1 = ((UINT_PTR)p + needed_len - 1) & ~0xFFFULL;
                if (page0 != page1)
                    continue;

                bool match = true;
                for (SIZE_T j = 0; j < min_run; j++)
                {
                    if (p[j] != gap_byte)
                    {
                        match = false;
                        break;
                    }
                }

                if (match)
                    return p;
            }
        }
    }

    return NULL;
}

static int CmdShadowGapTest()
{
    enum { patch_len = 8 };
    BYTE* gap = FindNtdllCodeGap(patch_len);
    if (!gap)
    {
        printf("[-] Could not find a suitable ntdll executable gap in current process.\n");
        return 1;
    }

    BYTE original[patch_len] = {};
    BYTE pattern[patch_len] = { 0x48, 0x31, 0xC0, 0x90, 0x90, 0x90, 0xCC, 0xCC };
    memcpy(original, gap, patch_len);

    MEMORY_BASIC_INFORMATION mbi = {};
    if (!VirtualQuery(gap, &mbi, sizeof(mbi)))
    {
        printf("[-] VirtualQuery failed for gap=%p gle=%u\n", gap, GetLastError());
        return 1;
    }

    volatile BYTE touch = 0;
    BYTE* page_base = (BYTE*)((UINT_PTR)gap & ~0xFFFULL);
    for (SIZE_T i = 0; i < 0x1000; i += 0x40)
        touch ^= page_base[i];
    UNREFERENCED_PARAMETER(touch);

    printf("[*] Shadow gap test current pid=%u ntdll gap=%p len=0x%llX\n",
        GetCurrentProcessId(), gap, (UINT64)patch_len);
    printf("    VQ Base=%p AllocBase=%p Region=0x%llX State=0x%X Protect=0x%X Type=0x%X\n",
        mbi.BaseAddress, mbi.AllocationBase, (UINT64)mbi.RegionSize, mbi.State, mbi.Protect, mbi.Type);
    PrintBytesLine("    Before:", original, patch_len);

    DWORD old_protect = 0;
    if (!ShadowProtectSelf((UINT64)gap, patch_len, PAGE_EXECUTE_READWRITE, &old_protect))
        return 1;

    int result = 0;
    bool write_ok = false;
    __try
    {
        memcpy(gap, pattern, patch_len);
        write_ok = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        printf("[-] Write test pattern faulted: 0x%08X\n", GetExceptionCode());
    }

    PrintBytesLine("    After write:", gap, patch_len);
    if (!write_ok)
        result = 1;

    bool restore_ok = false;
    if (write_ok)
    {
        __try
        {
            memcpy(gap, original, patch_len);
            restore_ok = true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            printf("[-] Restore original bytes faulted: 0x%08X\n", GetExceptionCode());
        }
    }

    PrintBytesLine("    Restored:", gap, patch_len);
    if (!restore_ok)
        result = 1;

    if (!old_protect)
        old_protect = PAGE_EXECUTE_READ;
    if (!ShadowProtectSelf((UINT64)gap, patch_len, old_protect, NULL))
        result = 1;

    PrintBytesLine("    Final:", gap, patch_len);
    if (result == 0)
        printf("[+] Shadow gap test completed.\n");
    else
        printf("[-] Shadow gap test completed with errors.\n");
    return result;
}

// ---- trigger hook, redirect selected trigger VA to selected jump VA ----

static int CmdTriggerJump(UINT64 pid, UINT64 trigger_va, UINT64 jump_to_va, UINT64 flags)
{
    printf("[*] Trigger jump: pid=%llu trigger=0x%llX jump=0x%llX flags=0x%llX\n",
        pid, trigger_va, jump_to_va, flags);

    HANDLE dev = OpenDevice();
    if (dev == INVALID_HANDLE_VALUE) return 1;

    TD_TRIGGER_JUMP_PARAMS p = {};
    p.target_pid = pid;
    p.trigger_va = trigger_va;
    p.jump_to_va = jump_to_va;
    p.flags = flags;

    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(dev, IOCTL_INSTALL_TRIGGER_JUMP,
        &p, sizeof(p), &p, sizeof(p), &bytes, NULL);

    if (ok && bytes >= sizeof(TD_TRIGGER_JUMP_PARAMS))
    {
        printf("[+] Trigger status: 0x%08llX\n", p.status);
        printf("    Trigger VA: 0x%llX\n", p.trigger_va);
        printf("    Jump VA:    0x%llX\n", p.jump_to_va);
    }
    else
    {
        printf("[-] IOCTL_INSTALL_TRIGGER_JUMP failed (error %u)\n", GetLastError());
        printf("    Driver status: 0x%08llX\n", p.status);
    }

    CloseHandle(dev);
    return (ok && p.status == 0) ? 0 : 1;
}

// ---- resolve export (MessageBoxA + SleepEx) via driver ----

static int CmdResolveExport(const wchar_t* target_name)
{
    printf("[*] Resolve Export: %ls\n", target_name);

    DWORD pid = FindProcessByName(target_name);
    if (!pid) { printf("[-] Process not found.\n"); return 1; }
    printf("[+] PID: %u\n", pid);

    HANDLE dev = OpenDevice();
    if (dev == INVALID_HANDLE_VALUE) return 1;

    TD_RESOLVE_EXPORT_PARAMS p = {};
    p.target_pid = (UINT64)pid;

    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(dev, IOCTL_RESOLVE_EXPORT, &p, sizeof(p), &p, sizeof(p), &bytes, NULL);

    bool resolved = (ok &&
        bytes >= sizeof(TD_RESOLVE_EXPORT_PARAMS) &&
        p.status == 0 &&
        p.messageboxa_va != 0 &&
        p.sleepex_va != 0);

    if (ok && bytes >= sizeof(TD_RESOLVE_EXPORT_PARAMS))
    {
        printf("[+] Resolve export status: 0x%08llX\n", p.status);
        printf("    MessageBoxA VA: 0x%llX\n", p.messageboxa_va);
        printf("    SleepEx VA:     0x%llX\n", p.sleepex_va);
        if (!resolved)
            printf("[-] Resolve export returned incomplete result.\n");
    }
    else
    {
        printf("[-] IOCTL_RESOLVE_EXPORT failed (error %u)\n", GetLastError());
        printf("    Driver status: 0x%08llX\n", p.status);
    }

    CloseHandle(dev);
    return resolved ? 0 : 1;
}

// ---- usage ----

static void PrintUsage(const wchar_t* exe)
{
    printf("Ophion Test Tool\n\n");
    printf("Usage:\n");
    printf("  %ls inject [process]             Stealth inject (default: notepad.exe)\n", exe);
    printf("  %ls hook                         R0 EPT hook NtCreateFile (all processes)\n", exe);
    printf("  %ls unhook                       Remove R0 EPT hook\n", exe);
    printf("  %ls injectrw [process] [rw|wc|protect]  RW-alloc + EPT stealth inject\n", exe);
    printf("  %ls injectrwshadow [process] [rw|wc|protect]  RW-alloc + shadow CR3 inject (no EPT split)\n", exe);
    printf("  %ls allocmem <process> <size> [exec] [rw|wc|protect]  Allocate memory, optional shadow CR3 exec\n", exe);
    printf("  %ls freemem <process> <base> <size>  Free memory allocated by allocmem\n", exe);
    printf("  %ls shadowprotect <pid> <base> <size> <r|rw|x|rx|rwx|protect>  Protect via shadow CR3\n", exe);
    printf("  %ls shadowgaptest                 Patch/restore current ntdll code gap via shadow protect\n", exe);
    printf("  %ls triggerjump <pid> <trigger|0> <jump> [flags]  Trigger hook redirect\n", exe);
    printf("  %ls injectdll <process> <dllpath>  Manual-map DLL inject (no LoadLibrary)\n", exe);
    printf("  %ls hookr3 <pid> <va> <proxy> [type]  R3 EPT hook (per-process)\n", exe);
    printf("  %ls unhookr3 <pid> <va>                Remove R3 EPT hook\n", exe);
    printf("  %ls resolvetest [process]              Resolve MessageBoxA+SleepEx via driver\n", exe);
    printf("\n");
    printf("Hook types: 0=abs jump (14B), 1=VMCALL (3B), 2=INT3 (1B)\n");
}

// ---- main ----

int wmain(int argc, wchar_t* argv[])
{
    if (argc < 2)
    {
        //return CmdInjectRWShadow(L"PioneerGame.exe", PAGE_READWRITE);
        return CmdInjectRWShadow(L"notepad.exe", PAGE_READWRITE);

    }

    const wchar_t* cmd = argv[1];

    if (_wcsicmp(cmd, L"inject") == 0)
    {
        const wchar_t* target = (argc > 2) ? argv[2] : L"notepad.exe";
        return CmdInject(target);
    }
    else if (_wcsicmp(cmd, L"injectrw") == 0)
    {
        const wchar_t* target = (argc > 2) ? argv[2] : L"notepad.exe";
        DWORD protect = ParseRwProtect((argc > 3) ? argv[3] : L"rw");
        if (!protect) return 1;
        return CmdInjectRW(target, protect);
    }
    else if (_wcsicmp(cmd, L"injectrwshadow") == 0)
    {
        const wchar_t* target = (argc > 2) ? argv[2] : L"notepad.exe";
        DWORD protect = ParseRwProtect((argc > 3) ? argv[3] : L"rw");
        if (!protect) return 1;
        return CmdInjectRWShadow(target, protect);
    }
    else if (_wcsicmp(cmd, L"allocmem") == 0)
    {
        if (argc < 4) { printf("Usage: allocmem <process> <size> [exec] [rw|wc|protect]\n"); return 1; }
        UINT64 size = wcstoull(argv[3], NULL, 0);
        bool need_execute = (argc > 4) ? (wcstoull(argv[4], NULL, 0) != 0) : false;
        DWORD protect = ParseRwProtect((argc > 5) ? argv[5] : L"rw");
        if (!protect) return 1;
        return CmdAllocMem(argv[2], size, need_execute, protect);
    }
    else if (_wcsicmp(cmd, L"freemem") == 0)
    {
        if (argc < 5) { printf("Usage: freemem <process> <base_va> <size>\n"); return 1; }
        UINT64 base_va = wcstoull(argv[3], NULL, 0);
        UINT64 size = wcstoull(argv[4], NULL, 0);
        return CmdFreeMem(argv[2], base_va, size);
    }
    else if (_wcsicmp(cmd, L"shadowprotect") == 0)
    {
        if (argc < 6) { printf("Usage: shadowprotect <pid> <base_va> <size> <r|rw|x|rx|rwx|protect>\n"); return 1; }
        UINT64 pid = wcstoull(argv[2], NULL, 0);
        UINT64 base_va = wcstoull(argv[3], NULL, 0);
        UINT64 size = wcstoull(argv[4], NULL, 0);
        DWORD protect = ParseShadowProtect(argv[5]);
        if (!protect) return 1;
        if (!pid) { printf("[-] Invalid pid.\n"); return 1; }
        return CmdShadowProtect(pid, base_va, size, protect);
    }
    else if (_wcsicmp(cmd, L"shadowgaptest") == 0)
    {
        return CmdShadowGapTest();
    }
    else if (_wcsicmp(cmd, L"triggerjump") == 0)
    {
        if (argc < 5) { printf("Usage: triggerjump <pid> <trigger_va|0> <jump_to_va> [flags]\n"); return 1; }
        UINT64 pid = wcstoull(argv[2], NULL, 0);
        UINT64 trigger_va = wcstoull(argv[3], NULL, 0);
        UINT64 jump_to_va = wcstoull(argv[4], NULL, 0);
        UINT64 flags = (argc > 5) ? wcstoull(argv[5], NULL, 0) : 2;
        return CmdTriggerJump(pid, trigger_va, jump_to_va, flags);
    }
    else if (_wcsicmp(cmd, L"injectdll") == 0)
    {
        if (argc < 4) { printf("Usage: injectdll <process> <dllpath>\n"); return 1; }
        return CmdInjectDll(argv[2], argv[3]);
    }
    else if (_wcsicmp(cmd, L"hook") == 0)
    {
        return CmdHook();
    }
    else if (_wcsicmp(cmd, L"unhook") == 0)
    {
        return CmdUnhook();
    }
    else if (_wcsicmp(cmd, L"hookr3") == 0)
    {
        if (argc < 5) { printf("Usage: hookr3 <pid> <target_va> <proxy_va> [type]\n"); return 1; }
        UINT64 pid       = wcstoull(argv[2], NULL, 0);
        UINT64 target_va = wcstoull(argv[3], NULL, 16);
        UINT64 proxy_va  = wcstoull(argv[4], NULL, 16);
        UINT64 hook_type = (argc > 5) ? wcstoull(argv[5], NULL, 0) : 0;
        return CmdHookR3(pid, target_va, proxy_va, hook_type);
    }
    else if (_wcsicmp(cmd, L"unhookr3") == 0)
    {
        if (argc < 4) { printf("Usage: unhookr3 <pid> <target_va>\n"); return 1; }
        UINT64 pid       = wcstoull(argv[2], NULL, 0);
        UINT64 target_va = wcstoull(argv[3], NULL, 16);
        return CmdUnhookR3(pid, target_va);
    }
    else if (_wcsicmp(cmd, L"resolvetest") == 0)
    {
        const wchar_t* target = (argc > 2) ? argv[2] : L"notepad.exe";
        return CmdResolveExport(target);
    }
    else
    {
        printf("[-] Unknown command: %ls\n\n", cmd);
        PrintUsage(argv[0]);
        return 1;
    }
}

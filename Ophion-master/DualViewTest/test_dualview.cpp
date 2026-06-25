/*
*   test_dualview.cpp — DLL dual-view EPT test
*
*   flow:
*     1. load test_dll.dll (our "injected" DLL)
*     2. call IOCTL_DLL_DUALVIEW to hide it (read→legit DLL, exec→our code)
*     3. pause — user can inspect memory with x64dbg/Process Hacker
*     4. call ShowMessage() — should still work (EPT exec view has our code)
*
*   compile: cl /Fe:test_dualview.exe test_dualview.cpp
*   usage:   test_dualview.exe [legit_dll_path]
*            default legit: \SystemRoot\System32\version.dll
*/
#include <windows.h>
#include <stdio.h>

// ---- IOCTL (must match TestDriver) ----

#define TD_IOCTL_BASE     0x900
#define IOCTL_DLL_DUALVIEW CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 8, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 8)
typedef struct _TD_DLL_DUALVIEW_PARAMS {
    UINT64 target_pid;
    UINT64 dll_base;
    UINT64 dll_size;
    WCHAR  legit_path[260];
    UINT64 pages_hooked;
    UINT64 status;
} TD_DLL_DUALVIEW_PARAMS;
#pragma pack(pop)

typedef void (*fn_ShowMessage)(void);

int main(int argc, char* argv[])
{
    // --- 1. load test DLL ---
    printf("[*] Loading test_dll.dll...\n");

    HMODULE hDll = LoadLibraryA("test_dll.dll");
    if (!hDll)
    {
        printf("[-] LoadLibrary failed: %u\n", GetLastError());
        return 1;
    }

    fn_ShowMessage pShow = (fn_ShowMessage)GetProcAddress(hDll, "ShowMessage");
    if (!pShow)
    {
        printf("[-] GetProcAddress(ShowMessage) failed\n");
        FreeLibrary(hDll);
        return 1;
    }

    printf("[+] test_dll.dll loaded at 0x%p\n", hDll);
    printf("[+] ShowMessage at 0x%p\n", pShow);

    // --- 2. parse PE and save .text info BEFORE any EPT hook ---
    //    (after dualview, reading PE header → EPT → legit content → wrong layout)
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hDll;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((BYTE*)hDll + dos->e_lfanew);
    DWORD image_size = nt->OptionalHeader.SizeOfImage;

    BYTE* text_va = NULL;
    DWORD text_size = 0;
    {
        PIMAGE_SECTION_HEADER secs = IMAGE_FIRST_SECTION(nt);
        for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
        {
            if (secs[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
            {
                text_va = (BYTE*)hDll + secs[i].VirtualAddress;
                text_size = secs[i].Misc.VirtualSize;
                break;
            }
        }
    }

    printf("[+] .text at %p, size 0x%X\n", text_va, text_size);
    printf("[+] ShowMessage at %p (offset 0x%llX in .text)\n",
           pShow, (UINT64)pShow - (UINT64)text_va);

    // save .text content BEFORE dualview
    BYTE before_bytes[64] = {};
    if (text_va)
        memcpy(before_bytes, text_va, sizeof(before_bytes));

    // --- 3. print .text content, pause for x64dbg, then call ShowMessage ---
    printf("\n[*] .text BEFORE dualview at %p (first 32 bytes):\n    ", text_va);
    for (int i = 0; i < 32; i++) printf("%02X ", before_bytes[i]);
    printf("\n");
    printf("[*] ShowMessage at %p (first 16 bytes):\n    ", pShow);
    for (int i = 0; i < 16; i++) printf("%02X ", ((BYTE*)pShow)[i]);
    printf("\n\n");

    printf("=== BEFORE dualview — check in x64dbg, then press any key ===\n");
    system("pause");

    printf("[*] Calling ShowMessage BEFORE dualview...\n");
    pShow();
    printf("[+] Pre-hide call OK.\n");

    // --- 4. hide DLL via IOCTL_DLL_DUALVIEW ---
    HANDLE dev = CreateFileW(
        L"\\\\.\\OphionTest",
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL);

    if (dev == INVALID_HANDLE_VALUE)
    {
        printf("[-] Cannot open OphionTest device (error %u)\n", GetLastError());
        printf("    Make sure Ophion.sys and TestDriver.sys are loaded.\n");
        FreeLibrary(hDll);
        return 1;
    }

    const wchar_t* legit_path = L"\\SystemRoot\\System32\\version.dll";
    if (argc > 1)
    {
        static wchar_t wide_path[260];
        MultiByteToWideChar(CP_ACP, 0, argv[1], -1, wide_path, 260);
        legit_path = wide_path;
    }

    TD_DLL_DUALVIEW_PARAMS params = {};
    params.target_pid = (UINT64)GetCurrentProcessId();
    params.dll_base   = (UINT64)hDll;
    params.dll_size   = (UINT64)image_size;
    wcscpy_s(params.legit_path, 260, legit_path);

    printf("[*] Hiding DLL: base=0x%llX size=0x%X\n", params.dll_base, image_size);
    printf("[*] Legit DLL: %ls\n", params.legit_path);

    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(dev, IOCTL_DLL_DUALVIEW,
        &params, sizeof(params), &params, sizeof(params), &bytes, NULL);

    CloseHandle(dev);

    if (ok && params.status == 0)
    {
        printf("[+] DualView OK! %llu pages hooked.\n", params.pages_hooked);
    }
    else
    {
        printf("[-] DualView failed: ioctl=%u status=0x%llX pages=%llu\n",
               GetLastError(), params.status, params.pages_hooked);
        FreeLibrary(hDll);
        return 1;
    }

    printf("\n[*] .text BEFORE dualview at %p (first 32 bytes):\n    ", text_va);
    for (int i = 0; i < 32; i++) printf("%02X ", before_bytes[i]);
    printf("\n");

    // --- 5. read legit DLL from disk for comparison ---
    BYTE legit_text_bytes[64] = {};
    {
        // open the same legit DLL to get its .text content
        HANDLE hLegit = CreateFileW(
            L"C:\\Windows\\System32\\version.dll",
            GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hLegit != INVALID_HANDLE_VALUE)
        {
            DWORD file_size = GetFileSize(hLegit, NULL);
            BYTE* fbuf = (BYTE*)malloc(file_size);
            if (fbuf)
            {
                DWORD read = 0;
                ReadFile(hLegit, fbuf, file_size, &read, NULL);

                // parse legit PE to find .text raw offset
                IMAGE_DOS_HEADER* ldos = (IMAGE_DOS_HEADER*)fbuf;
                IMAGE_NT_HEADERS64* lnt = (IMAGE_NT_HEADERS64*)(fbuf + ldos->e_lfanew);
                IMAGE_SECTION_HEADER* lsecs = IMAGE_FIRST_SECTION(lnt);
                for (int i = 0; i < lnt->FileHeader.NumberOfSections; i++)
                {
                    if (lsecs[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
                    {
                        DWORD raw_off = lsecs[i].PointerToRawData;
                        DWORD copy_sz = sizeof(legit_text_bytes);
                        if (copy_sz > lsecs[i].SizeOfRawData) copy_sz = lsecs[i].SizeOfRawData;
                        memcpy(legit_text_bytes, fbuf + raw_off, copy_sz);
                        break;
                    }
                }
                free(fbuf);
            }
            CloseHandle(hLegit);
        }
    }

    printf("[*] Legit DLL .text (first 32 bytes from disk):\n    ");
    for (int i = 0; i < 32; i++) printf("%02X ", legit_text_bytes[i]);
    printf("\n");

    // --- 6. now read .text AFTER dualview ---
    BYTE after_bytes[64] = {};
    if (text_va)
        memcpy(after_bytes, text_va, sizeof(after_bytes));

    printf("[*] .text AFTER dualview at %p (first 32 bytes):\n    ", text_va);
    for (int i = 0; i < 32; i++) printf("%02X ", after_bytes[i]);
    printf("\n\n");

    // --- 7. verification ---
    BOOL content_changed = (memcmp(before_bytes, after_bytes, 32) != 0);
    BOOL matches_legit   = (memcmp(after_bytes, legit_text_bytes, 32) == 0);

    printf("=== VERIFICATION ===\n");
    printf("[%c] .text content changed after dualview\n",
           content_changed ? '+' : '-');
    printf("[%c] .text now matches legit DLL (version.dll)\n",
           matches_legit ? '+' : '-');

    if (content_changed && matches_legit)
        printf("[+] SUCCESS: read view shows legit DLL, our code is hidden!\n");
    else if (!content_changed)
        printf("[-] FAIL: .text content didn't change — EPT hook may not be working\n");
    else
        printf("[?] PARTIAL: content changed but doesn't match legit DLL\n");

    // --- 8. test execution still works ---
    printf("\nPress any key to call ShowMessage() (exec view test)...\n");
    system("pause");

    printf("[*] Calling ShowMessage AFTER dualview...\n");
    printf("[*] ShowMessage addr: %p (in hooked range: %s)\n",
           pShow,
           ((UINT64)pShow >= (UINT64)text_va &&
            (UINT64)pShow < (UINT64)text_va + text_size) ? "YES" : "NO");
    pShow();
    printf("[+] Post-hide call OK! Execution goes through EPT shadow.\n");

    printf("\nPress any key to exit...\n");
    system("pause");

    FreeLibrary(hDll);
    return 0;
}

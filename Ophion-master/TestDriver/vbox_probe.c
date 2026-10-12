/* vbox_probe.c - triggers the declined VBoxDrv open on this thread, then
 * reads the stored decline reason from \\Device\\VBoxDrvErrorInfo (same
 * thread + 60s window) via NtReadFile (buffered device).
 * Build: build_vbox_probe.bat
 */
#include <windows.h>
#include <stdio.h>
#include <winternl.h>

typedef struct _VP_UNI {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} VP_UNI;

typedef struct _VP_OA {
    ULONG  Length;
    HANDLE RootDirectory;
    VP_UNI *ObjectName;
    ULONG  Attributes;
    PVOID  SecurityQualityOf;
    PVOID  SecurityDescriptor;
} VP_OA;

typedef struct _VP_IOS {
    LONG  Status;          /* offset 0 */
    ULONG __Pad;           /* offset 4 (x64 alignment) */
    PVOID Information;     /* offset 8 - REAL IO_STATUS_BLOCK is 16 bytes! */
} VP_IOS;

typedef LONG (NTAPI *fn_NtCreateFile)(HANDLE *, ACCESS_MASK *, VP_OA *, VP_IOS *,
                                      LARGE_INTEGER *, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef VOID (NTAPI *fn_RtlInitUnicodeString)(VP_UNI *, PCWSTR);
typedef LONG (NTAPI *fn_NtClose)(HANDLE);
typedef LONG (NTAPI *fn_NtReadFile)(HANDLE, HANDLE, PVOID, PVOID, VP_IOS *,
                                    VOID *, ULONG, ULONG, PVOID);

static fn_NtCreateFile   g_NtCreateFile;
static fn_RtlInitUnicodeString g_RtlInit;
static fn_NtClose        g_NtClose;
static fn_NtReadFile     g_NtReadFile;

static HANDLE OpenDev(const wchar_t *pwszNt, unsigned long access, LONG *pSt)
{
    VP_UNI uni;
    VP_OA  oa;
    HANDLE h = NULL;
    VP_IOS ios;
    memset(&ios, 0, sizeof(ios));
    g_RtlInit(&uni, pwszNt);
    memset(&oa, 0, sizeof(oa));
    oa.Length = (ULONG)sizeof(oa);
    oa.ObjectName = &uni;
    oa.Attributes = OBJ_CASE_INSENSITIVE;
    *pSt = g_NtCreateFile(&h, (ACCESS_MASK)access, &oa, &ios, NULL, FILE_ATTRIBUTE_NORMAL,
                          FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
                          FILE_NON_DIRECTORY_FILE, NULL, 0);
    return *pSt >= 0 ? h : NULL;
}

int wmain(void)
{
    HMODULE hNt = GetModuleHandleW(L"ntdll.dll");
    g_NtCreateFile  = (fn_NtCreateFile)(void *)GetProcAddress(hNt, "NtCreateFile");
    g_RtlInit       = (fn_RtlInitUnicodeString)(void *)GetProcAddress(hNt, "RtlInitUnicodeString");
    g_NtClose       = (fn_NtClose)(void *)GetProcAddress(hNt, "NtClose");
    g_NtReadFile    = (fn_NtReadFile)(void *)GetProcAddress(hNt, "NtReadFile");
    if (!g_NtCreateFile || !g_RtlInit || !g_NtClose || !g_NtReadFile)
    {
        wprintf(L"ntdll resolution failed\n");
        return 2;
    }

    /* 1) trigger the declined unrestricted open ON THIS THREAD. */
    LONG st = 0;
    HANDLE hDrv = OpenDev(L"\\Device\\VBoxDrv", FILE_GENERIC_READ | FILE_GENERIC_WRITE, &st);
    wprintf(L"VBoxDrv open: st=%08lX handle=%p\n", (unsigned long)(unsigned)st, hDrv);
    if (hDrv)
    {
        wprintf(L"VBoxDrv OPENED - driver accepts this process!\n");
        g_NtClose(hDrv);
        return 0;
    }

    /* 2) same thread: read the stored decline text (60s window). */
    st = 0;
    HANDLE hErr = OpenDev(L"\\Device\\VBoxDrvErrorInfo", FILE_GENERIC_READ, &st);
    if (!hErr)
    {
        wprintf(L"ErrorInfo open: st=%08lX\n", (unsigned long)(unsigned)st);
        return 1;
    }
    char szText[8192];
    memset(szText, 0, sizeof(szText));
    VP_IOS iosR;
    memset(&iosR, 0, sizeof(iosR));
    LONG stR = g_NtReadFile(hErr, NULL, NULL, NULL, &iosR, szText, sizeof(szText) - 1,
                            NULL, NULL);
    ULONG got = (ULONG)iosR.Information;
    if (stR >= 0 || got)
    {
        szText[got] = 0;
        wprintf(L"ErrorInfo (%lu bytes):\n", got);
        printf("%s\n", szText);
    }
    else
        wprintf(L"ErrorInfo read failed: st=%08lX\n", (unsigned long)(unsigned)stR);
    g_NtClose(hErr);
    return 0;
}

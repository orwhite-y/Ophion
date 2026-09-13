#include <windows.h>
#include <winternl.h>
#include <stdio.h>

typedef NTSTATUS (NTAPI *NtOpenFile_t)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
    ULONG, ULONG);
typedef NTSTATUS (NTAPI *NtClose_t)(HANDLE);

static NtOpenFile_t pNtOpenFile;
static NtClose_t    pNtClose;

void try_nt(const char* label, const WCHAR* ntpath) {
    OBJECT_ATTRIBUTES oa; UNICODE_STRING un;
    RtlInitUnicodeString(&un, ntpath);
    InitializeObjectAttributes(&oa,&un,OBJ_CASE_INSENSITIVE,NULL,NULL);
    HANDLE h=NULL; IO_STATUS_BLOCK iosb;
    NTSTATUS st = pNtOpenFile(&h, GENERIC_READ|GENERIC_WRITE, &oa, &iosb, 0, FILE_SYNCHRONOUS_IO_NONALERT);
    printf("  [NtOpen] %-28s -> 0x%08X\n", label, (unsigned)st);
    if (h && pNtClose) pNtClose(h);
}

int main() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    pNtOpenFile = (NtOpenFile_t)GetProcAddress(ntdll, "NtOpenFile");
    pNtClose    = (NtClose_t)GetProcAddress(ntdll, "NtClose");
    printf("=== Device Diagnostic (PID=%lu) ===\n", GetCurrentProcessId());

    // direct device object
    try_nt("\Device\RMCoreTst", L"\Device\RMCoreTst");
    // global symlink namespace
    try_nt("\GLOBAL??\RMCoreTst", L"\GLOBAL??\RMCoreTst");
    try_nt("\BaseNamedObjects", L"\BaseNamedObjects");

    // user-mode CreateFile variants
    const wchar_t* cf[] = { L"\\.\RMCoreTst", L"\\??\RMCoreTst", L"\\.\RMCore" };
    for (int i=0;i<3;i++){
        HANDLE h = CreateFileW(cf[i], GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,0,NULL);
        wprintf(L"  [CreateFile] %-24s -> %s err=%lu\n", cf[i],
                h!=INVALID_HANDLE_VALUE?L"OK":L"FAIL", GetLastError());
        if (h!=INVALID_HANDLE_VALUE) CloseHandle(h);
    }
    printf("=== done ===\n");
    return 0;
}

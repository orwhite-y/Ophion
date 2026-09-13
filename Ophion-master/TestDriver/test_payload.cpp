// test_payload.cpp - Simple DLL for injection testing
#include <windows.h>
#include <stdio.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // Create a file as proof of injection
        {
            HANDLE hFile = CreateFileW(
                L"C:\\inject_success.txt",
                GENERIC_WRITE,
                0,
                NULL,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                NULL
            );
            if (hFile != INVALID_HANDLE_VALUE) {
                const char* msg = "DLL injected successfully via TestDriver IOCTL_INJECT_MEM_DLL\r\n";
                DWORD written;
                WriteFile(hFile, msg, (DWORD)strlen(msg), &written, NULL);
                CloseHandle(hFile);
            }
        }
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

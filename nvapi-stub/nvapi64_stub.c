#include <windows.h>

__declspec(dllexport) void* __stdcall nvapi_QueryInterface(unsigned int id)
{
    (void)id;
    return NULL;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)hinstDLL;
    (void)fdwReason;
    (void)lpvReserved;
    return TRUE;
}

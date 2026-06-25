/*
*   test_dll.cpp — test DLL with an exported function (MessageBox).
*   compile: cl /LD /Fe:test_dll.dll test_dll.cpp user32.lib
*/
#include <windows.h>

extern "C" __declspec(dllexport)
void ShowMessage(void)
{
    MessageBoxA(NULL, "Hello from hidden DLL!", "DualView Test", MB_OK);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(hModule);
    return TRUE;
}

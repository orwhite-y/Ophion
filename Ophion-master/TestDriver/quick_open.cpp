#include <windows.h>
int main() {
    HANDLE h = CreateFileW(L"\\.\RMCoreTst", GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
    if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); return 0; }
    return 1;
}

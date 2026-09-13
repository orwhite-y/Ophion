#include <windows.h>
#include <stdio.h>
int main(){
    // probe a few candidate names
    const wchar_t* names[] = {
        L"\\.\RMCoreTst",
        L"\\.\RMCoreTest",
        L"\DosDevices\RMCoreTst",
        L"\DosDevices\RMCoreTest",
    };
    for(int i=0;i<4;i++){
        HANDLE h = CreateFileW(names[i], GENERIC_READ|GENERIC_WRITE,0,0,OPEN_EXISTING,0,0);
        if(h!=INVALID_HANDLE_VALUE){
            printf("[FOUND] %ls -> handle %p\n", names[i], h);
            CloseHandle(h);
        } else {
            printf("[MISS]  %ls err=%lu\n", names[i], GetLastError());
        }
    }
    // check registry drivers may carry another name
    return 0;
}

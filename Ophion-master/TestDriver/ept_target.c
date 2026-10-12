/* ept_target.c - Guest-side test target for EPT hook verification.
 * Build: build_ept_target.bat
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

static volatile ULONG64 g_counter = 0;

__declspec(noinline)
static ULONG64 __fastcall TraceTarget(ULONG64 *p)
{
    ULONG64 v = *p;
    v = v + 1;
    *p = v;
    return v;
}

int wmain(int argc, wchar_t **argv)
{
    if (argc < 2)
    {
        wprintf(L"usage: ept_target write <addr_hex> <count>\n");
        return 2;
    }

    /* write: allocate page, report address, write N times */
    if (wcscmp(argv[1], L"write") == 0 && argc >= 4)
    {
        ULONG count = wcstoul(argv[3], NULL, 0);
        PVOID buf = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buf) { wprintf(L"VirtualAlloc failed %lu\n", GetLastError()); return 1; }
        memset(buf, 0xCC, 4096);

        wprintf(L"PID=%lu\n", GetCurrentProcessId());
        wprintf(L"BUF=%p\n", buf);
        wprintf(L"COUNT=%lu\n", count);

        ULONG64 *p64 = (ULONG64 *)buf;
        for (ULONG i = 0; i < count; i++)
        {
            p64[0] = 0xAAAABBBBCCCCDDDDULL + i;
            Sleep(10); /* 10ms between writes for BP test */
        }
        wprintf(L"WRITE_DONE count=%lu\n", count);
        VirtualFree(buf, 0, MEM_RELEASE);
        return 0;
    }

    /* loop: spin in a 3-instruction block for N seconds (for trace) */
    if (wcscmp(argv[1], L"loop") == 0 && argc >= 3)
    {
        ULONG secs = wcstoul(argv[2], NULL, 0);
        ULONG64 local = 0;
        ULONGLONG end = GetTickCount64() + (ULONGLONG)secs * 1000;
        wprintf(L"LOOP start pid=%lu\n", GetCurrentProcessId());
        while (GetTickCount64() < end)
            TraceTarget(&local);
        wprintf(L"LOOP done val=%llu\n", local);
        return 0;
    }

    wprintf(L"unknown mode: %ls\n", argv[1]);
    return 2;
}

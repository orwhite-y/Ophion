/* ept_probe_all.c — EPT Hook 全接口功能验收
 *
 * 自含式：本进程就是靶标，不需要第二个进程。
 * 编译: build_ept_probe.bat
 * 运行: ept_probe_all.exe  （Guest 内管理员运行，TestEptHook 驱动 RUNNING）
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

/* ===== IOCTL codes ===== */
#define TD_IOCTL_BASE   0x900
#define MYCTL(n) CTL_CODE(FILE_DEVICE_UNKNOWN, (TD_IOCTL_BASE + (n)), METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_HV_BP_SET         MYCTL(28)
#define IOCTL_HV_BP_CLEAR       MYCTL(29)
#define IOCTL_HV_BP_CLEAR_ALL   MYCTL(30)
#define IOCTL_HOOK_DIAG         MYCTL(36)
#define IOCTL_REMOTE_CALL       MYCTL(35)
#define IOCTL_HV_EVENT_READ     MYCTL(37)

/* ===== TD_MEMORY_BREAKPOINT_REQUEST (mirror td_common.h) ===== */
typedef struct _TD_BP_REQ {
    UINT64 breakpoint_id;
    UINT64 target_pid;
    UINT64 target_address;
    UINT32 size;
    UINT32 access;          /* 1=R 2=W 4=X */
    UINT32 flags;           /* 1=oneshot */
    UINT32 status;          /* out NTSTATUS */
} TD_BP_REQ;

/* ===== TD_HOOK_DIAG_PARAMS (mirror) ===== */
typedef struct _TD_DIAG {
    UINT64 GCPhys;
    UINT64 status;
    UINT64 vmm_rc;
    UINT64 au_entry[4];
    UINT32 f_present;
    UINT32 f_large;
    INT32  id_hook;
    UINT32 u_hook_state;
    UINT32 u_hook_mode;
    UINT32 u_hook_generation;
    UINT32 c_fires;
} TD_DIAG;

/* ===== TD_REMOTE_CALL_PARAMS (mirror) ===== */
typedef struct _TD_RC {
    UINT64 target_pid;
    UINT64 function_va;
    UINT64 wait_ms;
    UINT32 arg_count;
    UINT32 flags;
    UINT64 param_block_va;
    UINT64 trigger_va;
    UINT64 thread_exit_code;
    UINT64 vbox_status;
    UINT64 status;
    UINT64 arg[24];
} TD_RC;

/* ===== TD_HV_EVENT_READ (mirror) ===== */
typedef struct _TD_EVT {
    UINT32 cMaxEvents;
    UINT32 cEvents;
    UINT32 cDropped;
    UINT32 cRemaining;
    UINT32 cCpus;
    UINT32 status;
    UINT8  events[8][64];
} TD_EVT;

/* ===== Globals ===== */
static HANDLE g_hDev = INVALID_HANDLE_VALUE;
static int g_pass = 0, g_fail = 0;
static UINT64 g_bp_id = 0;

static int DoIO(DWORD code, void *buf, DWORD cb)
{
    DWORD ret = 0;
    return DeviceIoControl(g_hDev, code, buf, cb, buf, cb, &ret, NULL);
}

static void PR(const char *test, int pass, const char *detail)
{
    printf("  [%s] %s\n", pass ? "PASS" : "FAIL", test);
    if (detail) printf("         %s\n", detail);
    if (pass) g_pass++; else g_fail++;
}

int wmain(void)
{
    printf("==========================================\n");
    printf("  EPT Hook Interface Test\n");
    printf("  PID: %lu\n", GetCurrentProcessId());
    printf("==========================================\n\n");

    /* ===== Test 1: Open device ===== */
    printf("[TEST 1] Device open\n");
    g_hDev = CreateFileW(L"\\\\.\\RMCoreTst", GENERIC_READ | GENERIC_WRITE,
                         0, NULL, OPEN_EXISTING, 0, NULL);
    PR("DeviceOpen", g_hDev != INVALID_HANDLE_VALUE,
       g_hDev != INVALID_HANDLE_VALUE ? NULL : "open failed");

    if (g_hDev == INVALID_HANDLE_VALUE) goto done;

    /* ===== Test 2: DIAG_WALK ===== */
    printf("\n[TEST 2] DIAG_WALK (GPA=0x1000)\n");
    {
        TD_DIAG d;
        memset(&d, 0, sizeof(d));
        d.GCPhys = 0x1000;
        DWORD ret = 0;
        BOOL ok = DeviceIoControl(g_hDev, MYCTL(36), &d, sizeof(d),
                                  &d, sizeof(d), &ret, NULL);
        int pass = ok && d.status == 0;
        printf("  present=0x%08X id_hook=%d state=%u\n",
               d.f_present, d.id_hook, d.u_hook_state);
        printf("  PTE: %016llX %016llX %016llX %016llX\n",
               d.au_entry[0], d.au_entry[1], d.au_entry[2], d.au_entry[3]);
        PR("DIAG_WALK", pass, NULL);
    }

    /* ===== Test 3: BP_SET(W) on self ===== */
    printf("\n[TEST 3] BP_SET (W, self, persistent)\n");
    {
        static volatile ULONG64 watch_addr = 0;
        /* Allocate a page-aligned buffer */
        PVOID buf = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buf) { printf("  VirtualAlloc failed\n"); g_fail++; goto summary; }

        watch_addr = (UINT64)buf;

        TD_BP_REQ req;
        memset(&req, 0, sizeof(req));
        req.target_pid = GetCurrentProcessId();
        req.target_address = (UINT64)buf;
        req.size = 8;
        req.access = 2; /* W */
        req.flags = 0;  /* persistent */

        DWORD ret = 0;
        BOOL ok = DeviceIoControl(g_hDev, IOCTL_HV_BP_SET, &req, sizeof(req),
                                  &req, sizeof(req), &ret, NULL);
        int pass = ok && req.status == 0;
        g_bp_id = req.breakpoint_id;
        printf("  BP_SET: ok=%d status=0x%08X id=%llu addr=%p\n",
               ok, req.status, req.breakpoint_id, buf);
        PR("BP_SET(W)", pass, NULL);

        /* ===== Test 4: Write trigger ===== */
        printf("\n[TEST 4] BP-W trigger (5 writes, 20ms apart)\n");
        for (ULONG i = 0; i < 5; i++)
        {
            *(volatile ULONG64 *)buf = 0xDEAD0000 + i;
            Sleep(20);
        }
        printf("  wrote 5 times\n");
        PR("BP_W_trigger", 1, NULL); /* if we got here without crash, pass */

        /* ===== Test 5: EVENT_READ ===== */
        printf("\n[TEST 5] EVENT_READ\n");
        /* Use IOCTL_HV_EVENT_READ (+37) */
        {
            /* TD_HV_EVENT_READ_PARAMS mirror */
#pragma pack(push,1)
            struct {
                UINT32 cMax; UINT32 cGot; UINT32 cDrop; UINT32 cRem;
                UINT32 cCpu; UINT32 st;
                UINT8 ev[8][64];
            } evt;
#pragma pack(pop)
            memset(&evt, 0, sizeof(evt));
            evt.cMax = 8;

            ok = DeviceIoControl(g_hDev, MYCTL(37), &evt, sizeof(evt),
                                 &evt, sizeof(evt), &ret, NULL);
            printf("  ok=%d events=%u dropped=%u remaining=%u\n",
                   ok, evt.cGot, evt.cDrop, evt.cRem);
            int ev_pass = ok && evt.cGot > 0;
            PR("EVENT_READ", ev_pass, NULL);

            /* ===== Test 6: BP_CLEAR ===== */
            printf("\n[TEST 6] BP_CLEAR (id=%llu)\n", g_bp_id);
            memset(&req, 0, sizeof(req));
            req.breakpoint_id = g_bp_id;
            ok = DeviceIoControl(g_hDev, IOCTL_HV_BP_CLEAR, &req, sizeof(req),
                                 &req, sizeof(req), &ret, NULL);
            printf("  BP_CLEAR: ok=%d status=0x%08X\n", ok, req.status);
            PR("BP_CLEAR", ok && req.status == 0, NULL);

            /* ===== Test 7: REMOTE_CALL probe ===== */
            printf("\n[TEST 7] REMOTE_CALL (zero params)\n");
            TD_RC rc2;
            memset(&rc2, 0, sizeof(rc2));
            rc2.target_pid = GetCurrentProcessId();
            rc2.wait_ms = 5000;
            ok = DeviceIoControl(g_hDev, MYCTL(35), &rc2, sizeof(rc2),
                                 &rc2, sizeof(rc2), &ret, NULL);
            printf("  ok=%d status=0x%08llX vmm=0x%08llX\n", ok, rc2.status, rc2.vbox_status);
            /* Zero params → C000000D = correct rejection */
            PR("RemoteCall(probe)", ok && rc2.status == 0xC000000D, NULL);
        }

        VirtualFree(buf, 0, MEM_RELEASE);
    }

summary:
    printf("\n==========================================\n");
    printf("  RESULTS: PASS=%d  FAIL=%d\n", g_pass, g_fail);
    printf("==========================================\n");

done:
    if (g_hDev != INVALID_HANDLE_VALUE)
        CloseHandle(g_hDev);
    return (g_fail == 0) ? 0 : 1;
}

#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>
#include <vector>

#include "../include/trace_protocol.h"

#define TD_IOCTL_BASE 0x900
#define IOCTL_HV_TRACE_START CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 31, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_TRACE_STOP  CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 32, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_HV_TRACE_READ  CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 33, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_HV_TRACE_CLOSE CTL_CODE(FILE_DEVICE_UNKNOWN, TD_IOCTL_BASE + 34, METHOD_BUFFERED, FILE_ANY_ACCESS)

static volatile LONG g_stop_requested = 0;

static BOOL WINAPI ConsoleHandler(DWORD type)
{
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT)
    {
        InterlockedExchange(&g_stop_requested, 1);
        return TRUE;
    }
    return FALSE;
}

static bool NtSuccess(uint32_t status)
{
    return (int32_t)status >= 0;
}

static void PrintUsage()
{
    wprintf(L"Ophion VT instruction trace\n\n");
    wprintf(L"  trace_cli run   <r3-ept|r3-hwbp|r0-ept|r3-auto|r0-auto> <pid|0> <start> <end> <max> [--stack]\n");
    wprintf(L"  trace_cli start <mode> <pid|0> <start> <end> <max> [--stack]\n");
    wprintf(L"  trace_cli read  <session-id> [next-sequence] [count]\n");
    wprintf(L"  trace_cli stop  <session-id>\n");
    wprintf(L"  trace_cli close <session-id>\n\n");
    wprintf(L"Examples:\n");
    wprintf(L"  trace_cli run r3-ept 4242 0x7FF612341000 0x7FF612342000 500 --stack\n");
    wprintf(L"  trace_cli run r3-hwbp 4242 0x7FF612341120 0x7FF612341300 200 --stack\n");
    wprintf(L"  trace_cli run r0-ept 0 0xFFFFF80612341000 0xFFFFF80612342000 500\n");
}

static bool ParseMode(
    const wchar_t * text,
    OPHION_U32 * scope,
    OPHION_U32 * backend)
{
    if (_wcsicmp(text, L"r3-ept") == 0)
    {
        *scope = OPHION_TRACE_SCOPE_USER;
        *backend = OPHION_TRACE_BACKEND_EPT;
    }
    else if (_wcsicmp(text, L"r3-hwbp") == 0)
    {
        *scope = OPHION_TRACE_SCOPE_USER;
        *backend = OPHION_TRACE_BACKEND_HWBP;
    }
    else if (_wcsicmp(text, L"r0-ept") == 0)
    {
        *scope = OPHION_TRACE_SCOPE_KERNEL;
        *backend = OPHION_TRACE_BACKEND_EPT;
    }
    else if (_wcsicmp(text, L"r3-auto") == 0)
    {
        *scope = OPHION_TRACE_SCOPE_USER;
        *backend = OPHION_TRACE_BACKEND_AUTO;
    }
    else if (_wcsicmp(text, L"r0-auto") == 0)
    {
        *scope = OPHION_TRACE_SCOPE_KERNEL;
        *backend = OPHION_TRACE_BACKEND_AUTO;
    }
    else
    {
        return false;
    }
    return true;
}

static HANDLE OpenDevice()
{
    HANDLE device = CreateFileW(
        L"\\\\.\\RMCoreTst", GENERIC_READ | GENERIC_WRITE,
        0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (device == INVALID_HANDLE_VALUE)
        wprintf(L"open RMCoreTst failed: Win32=%lu\n", GetLastError());
    return device;
}

static bool StartTrace(
    HANDLE device,
    int argc,
    wchar_t ** argv,
    int first_arg,
    OPHION_TRACE_START_REQUEST * request)
{
    if (argc < first_arg + 5 ||
        !ParseMode(argv[first_arg], &request->scope, &request->backend))
        return false;

    request->version = OPHION_TRACE_ABI_VERSION;
    request->target_pid = _wcstoui64(argv[first_arg + 1], nullptr, 0);
    request->start_address = _wcstoui64(argv[first_arg + 2], nullptr, 0);
    request->end_address = _wcstoui64(argv[first_arg + 3], nullptr, 0);
    request->max_steps = _wcstoui64(argv[first_arg + 4], nullptr, 0);
    if (request->backend == OPHION_TRACE_BACKEND_HWBP ||
        request->backend == OPHION_TRACE_BACKEND_AUTO)
        request->flags |= OPHION_TRACE_FLAG_STOP_OUTSIDE_RANGE;

    for (int i = first_arg + 5; i < argc; ++i)
    {
        if (_wcsicmp(argv[i], L"--stack") == 0)
            request->flags |= OPHION_TRACE_FLAG_CAPTURE_STACK;
        else
            return false;
    }

    DWORD returned = 0;
    if (!DeviceIoControl(
            device, IOCTL_HV_TRACE_START,
            request, sizeof(*request), request, sizeof(*request),
            &returned, nullptr))
    {
        wprintf(L"TRACE_START failed: Win32=%lu\n", GetLastError());
        return false;
    }
    if (!NtSuccess(request->status))
    {
        wprintf(L"TRACE_START failed: NTSTATUS=0x%08X\n", request->status);
        return false;
    }

    wprintf(L"trace started: id=%llu scope=%s backend=%s range=[%llX,%llX) max=%llu\n",
        request->session_id,
        request->scope == OPHION_TRACE_SCOPE_USER ? L"R3" : L"R0",
        request->actual_backend == OPHION_TRACE_BACKEND_HWBP ? L"HWBP+MTF" : L"EPT-X",
        request->start_address, request->end_address, request->max_steps);
    return true;
}

static void PrintRecord(const OPHION_TRACE_RECORD & record)
{
    const wchar_t * event_name = L"EPT";
    if (record.event_type == OPHION_TRACE_EVENT_HWBP_ENTRY)
        event_name = L"HWBP";
    else if (record.event_type == OPHION_TRACE_EVENT_MTF_STEP)
        event_name = L"MTF";

    wprintf(L"#%lld tsc=%llX cpu=%u pid=%llu %s RIP=%016llX RSP=%016llX RFLAGS=%016llX\n",
        record.sequence, record.timestamp, record.cpu, record.process_id,
        event_name, record.rip, record.rsp, record.rflags);
    wprintf(L"  RAX=%016llX RBX=%016llX RCX=%016llX RDX=%016llX RSI=%016llX RDI=%016llX RBP=%016llX\n",
        record.rax, record.rbx, record.rcx, record.rdx,
        record.rsi, record.rdi, record.rbp);
    wprintf(L"  R8 =%016llX R9 =%016llX R10=%016llX R11=%016llX R12=%016llX R13=%016llX R14=%016llX R15=%016llX\n",
        record.r8, record.r9, record.r10, record.r11,
        record.r12, record.r13, record.r14, record.r15);
    if (record.stack_qwords)
    {
        wprintf(L"  STACK:");
        for (uint32_t i = 0; i < record.stack_qwords; ++i)
            wprintf(L" +%02X=%016llX", i * 8, record.stack[i]);
        wprintf(L"\n");
    }
}

static bool ReadTrace(
    HANDLE device,
    uint64_t session_id,
    uint64_t * cursor,
    uint32_t count,
    uint32_t * state)
{
    if (!count)
        count = 64;
    const DWORD output_size = OPHION_TRACE_READ_OUTPUT_HEADER_SIZE +
        count * (DWORD)sizeof(OPHION_TRACE_RECORD);
    std::vector<uint8_t> buffer(output_size);

    OPHION_TRACE_READ_REQUEST request = {};
    request.version = OPHION_TRACE_ABI_VERSION;
    request.max_records = count;
    request.session_id = session_id;
    request.next_sequence = *cursor;

    DWORD returned = 0;
    if (!DeviceIoControl(
            device, IOCTL_HV_TRACE_READ,
            &request, sizeof(request), buffer.data(), output_size,
            &returned, nullptr))
    {
        wprintf(L"TRACE_READ failed: Win32=%lu\n", GetLastError());
        return false;
    }

    OPHION_TRACE_READ_OUTPUT * output =
        reinterpret_cast<OPHION_TRACE_READ_OUTPUT *>(buffer.data());
    if (!NtSuccess(output->status))
    {
        wprintf(L"TRACE_READ failed: NTSTATUS=0x%08X\n", output->status);
        return false;
    }

    for (uint32_t i = 0; i < output->record_count; ++i)
        PrintRecord(output->records[i]);
    *cursor = output->next_sequence;
    *state = output->state;

    if (output->overwritten)
        wprintf(L"trace ring overwritten=%llu produced=%llu next=%llu\n",
            output->overwritten, output->produced, output->next_sequence);
    return true;
}

static bool ControlTrace(HANDLE device, DWORD code, uint64_t session_id)
{
    OPHION_TRACE_CONTROL_REQUEST request = {};
    request.version = OPHION_TRACE_ABI_VERSION;
    request.session_id = session_id;
    DWORD returned = 0;
    if (!DeviceIoControl(
            device, code, &request, sizeof(request),
            &request, sizeof(request), &returned, nullptr))
    {
        wprintf(L"trace control failed: Win32=%lu\n", GetLastError());
        return false;
    }
    if (!NtSuccess(request.status))
    {
        wprintf(L"trace control failed: NTSTATUS=0x%08X\n", request.status);
        return false;
    }
    return true;
}

int wmain(int argc, wchar_t ** argv)
{
    if (argc < 2)
    {
        PrintUsage();
        return 2;
    }

    HANDLE device = OpenDevice();
    if (device == INVALID_HANDLE_VALUE)
        return 1;

    int result = 0;
    if ((_wcsicmp(argv[1], L"start") == 0 ||
         _wcsicmp(argv[1], L"run") == 0))
    {
        OPHION_TRACE_START_REQUEST request = {};
        if (!StartTrace(device, argc, argv, 2, &request))
        {
            PrintUsage();
            result = 2;
        }
        else if (_wcsicmp(argv[1], L"run") == 0)
        {
            SetConsoleCtrlHandler(ConsoleHandler, TRUE);
            uint64_t cursor = 0;
            uint32_t state = OPHION_TRACE_STATE_RUNNING;
            while (!g_stop_requested && state == OPHION_TRACE_STATE_RUNNING)
            {
                if (!ReadTrace(device, request.session_id, &cursor, 64, &state))
                {
                    result = 1;
                    break;
                }
                Sleep(10);
            }

            if (g_stop_requested && state == OPHION_TRACE_STATE_RUNNING)
                ControlTrace(device, IOCTL_HV_TRACE_STOP, request.session_id);

            // Drain the last records before releasing the session.
            ReadTrace(device, request.session_id, &cursor, 1024, &state);
            if (!ControlTrace(device, IOCTL_HV_TRACE_CLOSE, request.session_id))
                result = 1;
        }
    }
    else if (_wcsicmp(argv[1], L"read") == 0 && argc >= 3 && argc <= 5)
    {
        uint64_t cursor = argc >= 4 ? _wcstoui64(argv[3], nullptr, 0) : 0;
        uint32_t count = argc >= 5 ? wcstoul(argv[4], nullptr, 0) : 64;
        uint32_t state = 0;
        if (!ReadTrace(device, _wcstoui64(argv[2], nullptr, 0),
                &cursor, count, &state))
            result = 1;
        else
            wprintf(L"next-sequence=%llu state=%u\n", cursor, state);
    }
    else if ((_wcsicmp(argv[1], L"stop") == 0 ||
              _wcsicmp(argv[1], L"close") == 0) && argc == 3)
    {
        DWORD code = _wcsicmp(argv[1], L"stop") == 0
            ? IOCTL_HV_TRACE_STOP : IOCTL_HV_TRACE_CLOSE;
        if (!ControlTrace(device, code, _wcstoui64(argv[2], nullptr, 0)))
            result = 1;
    }
    else
    {
        PrintUsage();
        result = 2;
    }

    CloseHandle(device);
    return result;
}

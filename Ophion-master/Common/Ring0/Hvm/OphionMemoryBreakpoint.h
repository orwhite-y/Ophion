#pragma once

#include <ntifs.h>

#define OPHION_BP_ACCESS_READ       0x01
#define OPHION_BP_ACCESS_WRITE      0x02
#define OPHION_BP_ACCESS_EXECUTE    0x04
#define OPHION_BP_FLAG_ONESHOT      0x01

VOID OphionMemoryBreakpointInitialize();
BOOLEAN OphionMemoryBreakpointAvailable();

NTSTATUS OphionMemoryBreakpointSet(
    ULONG target_pid,
    UINT64 target_address,
    UINT32 size,
    UINT8 access,
    UINT8 flags,
    UINT64* breakpoint_id,
    UINT64* target_cr3);

NTSTATUS OphionMemoryBreakpointClear(UINT64 breakpoint_id);
VOID OphionMemoryBreakpointCleanupAll(BOOLEAN issue_vmcalls);

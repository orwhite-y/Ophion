#pragma once

// Shared wire contract used by Ophion, TestDriver and trace_cli.
// Keep this header independent from WDK headers so the user-mode tool can
// include it directly.

typedef unsigned char      OPHION_U8;
typedef unsigned short     OPHION_U16;
typedef unsigned long      OPHION_U32;
typedef unsigned __int64   OPHION_U64;
typedef __int64            OPHION_I64;

#define OPHION_TRACE_ABI_VERSION       1u
#define OPHION_TRACE_SCOPE_USER        1u
#define OPHION_TRACE_SCOPE_KERNEL      2u
#define OPHION_TRACE_BACKEND_AUTO      0u
#define OPHION_TRACE_BACKEND_EPT       1u
#define OPHION_TRACE_BACKEND_HWBP      2u

#define OPHION_TRACE_FLAG_CAPTURE_STACK       0x00000001u
#define OPHION_TRACE_FLAG_STOP_OUTSIDE_RANGE  0x00000002u

#define OPHION_TRACE_STATE_CREATED     1u
#define OPHION_TRACE_STATE_RUNNING     2u
#define OPHION_TRACE_STATE_STOPPED     3u
#define OPHION_TRACE_STATE_COMPLETE    4u
#define OPHION_TRACE_STATE_CLOSED      5u

#define OPHION_TRACE_STOP_NONE         0u
#define OPHION_TRACE_STOP_REQUESTED    1u
#define OPHION_TRACE_STOP_LIMIT        2u
#define OPHION_TRACE_STOP_RANGE_EXIT   3u
#define OPHION_TRACE_STOP_PROCESS_EXIT 4u
#define OPHION_TRACE_STOP_OVERFLOW     5u
#define OPHION_TRACE_STOP_CONTEXT_EXIT 6u
#define OPHION_TRACE_STOP_HWBP_CONFLICT 7u

#define OPHION_TRACE_EVENT_EPT_EXECUTE 1u
#define OPHION_TRACE_EVENT_HWBP_ENTRY  2u
#define OPHION_TRACE_EVENT_MTF_STEP    3u

#pragma pack(push, 8)

typedef struct _OPHION_TRACE_START_REQUEST {
    OPHION_U32 version;
    OPHION_U32 scope;
    OPHION_U32 backend;
    OPHION_U32 flags;
    OPHION_U64 session_id;
    OPHION_U64 target_pid;
    OPHION_U64 start_address;
    OPHION_U64 end_address;       // exclusive
    OPHION_U64 max_steps;
    OPHION_U32 actual_backend;
    OPHION_U32 status;
} OPHION_TRACE_START_REQUEST;

typedef struct _OPHION_TRACE_CONTROL_REQUEST {
    OPHION_U32 version;
    OPHION_U32 reserved;
    OPHION_U64 session_id;
    OPHION_U32 status;
    OPHION_U32 state;
} OPHION_TRACE_CONTROL_REQUEST;

typedef struct _OPHION_TRACE_READ_REQUEST {
    OPHION_U32 version;
    OPHION_U32 max_records;
    OPHION_U64 session_id;
    OPHION_U64 next_sequence;     // 0 starts at the oldest retained record
} OPHION_TRACE_READ_REQUEST;

typedef struct _OPHION_TRACE_RECORD {
    // sequence is published last by VMX-root. A zero/mismatched value means
    // the slot is currently being written or has already been overwritten.
    volatile OPHION_I64 sequence;
    OPHION_U64 timestamp;
    OPHION_U64 session_id;
    OPHION_U64 process_id;
    OPHION_U64 cr3;
    OPHION_U64 rip;
    OPHION_U64 rsp;
    OPHION_U64 rflags;
    OPHION_U64 rax;
    OPHION_U64 rbx;
    OPHION_U64 rcx;
    OPHION_U64 rdx;
    OPHION_U64 rsi;
    OPHION_U64 rdi;
    OPHION_U64 rbp;
    OPHION_U64 r8;
    OPHION_U64 r9;
    OPHION_U64 r10;
    OPHION_U64 r11;
    OPHION_U64 r12;
    OPHION_U64 r13;
    OPHION_U64 r14;
    OPHION_U64 r15;
    OPHION_U64 stack[8];
    OPHION_U32 cpu;
    OPHION_U16 event_type;
    OPHION_U8  scope;
    OPHION_U8  backend;
    OPHION_U32 stack_qwords;
    OPHION_U32 reserved;
} OPHION_TRACE_RECORD;

typedef struct _OPHION_TRACE_READ_OUTPUT {
    OPHION_U32 version;
    OPHION_U32 status;
    OPHION_U32 state;
    OPHION_U32 stop_reason;
    OPHION_U32 record_count;
    OPHION_U32 actual_backend;
    OPHION_U64 next_sequence;
    OPHION_U64 produced;
    OPHION_U64 overwritten;
    OPHION_TRACE_RECORD records[1];
} OPHION_TRACE_READ_OUTPUT;

#pragma pack(pop)

#define OPHION_TRACE_READ_OUTPUT_HEADER_SIZE \
    ((OPHION_U32)(sizeof(OPHION_TRACE_READ_OUTPUT) - sizeof(OPHION_TRACE_RECORD)))

#if defined(__cplusplus)
static_assert(sizeof(OPHION_TRACE_START_REQUEST) == 64,
    "OPHION_TRACE_START_REQUEST ABI drift");
static_assert(sizeof(OPHION_TRACE_CONTROL_REQUEST) == 24,
    "OPHION_TRACE_CONTROL_REQUEST ABI drift");
static_assert(sizeof(OPHION_TRACE_READ_REQUEST) == 24,
    "OPHION_TRACE_READ_REQUEST ABI drift");
static_assert(sizeof(OPHION_TRACE_RECORD) == 264,
    "OPHION_TRACE_RECORD ABI drift");
static_assert(OPHION_TRACE_READ_OUTPUT_HEADER_SIZE == 48,
    "OPHION_TRACE_READ_OUTPUT header ABI drift");
#endif

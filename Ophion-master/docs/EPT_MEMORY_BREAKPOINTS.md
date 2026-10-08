# EPT memory breakpoints

The hypervisor now supports process-filtered EPT breakpoints for read, write,
and execute accesses. A breakpoint is either one-shot (`once`) or persistent
(`permanent`). Every matching exit is written to `C:\Windows\O.log` with the
faulting linear/physical address, CR3, all general-purpose registers, RIP,
RSP, RFLAGS, and 16 stack qwords.

## Build

Build both drivers normally, then build the small controller:

```bat
cd TestDriver
build_memory_breakpoint_cli.bat
```

## Commands

```text
memory_breakpoint_cli set <pid> <address> <size> <access> <once|permanent>
memory_breakpoint_cli clear <breakpoint-id>
memory_breakpoint_cli clear-all
```

`access` is any combination of `r`, `w`, and `x`.

```text
memory_breakpoint_cli set 4242 0x7FF612341000 8 rw permanent
memory_breakpoint_cli set 4242 0x7FF612342080 1 x once
memory_breakpoint_cli clear 1
```

The requested byte range must stay inside one 4 KB page. The TestDriver pins
that page until the breakpoint is cleared or the target process exits. Pages
already owned by the EPT hook or stealth-page engines are rejected to keep the
three permission state machines independent.

EPT permissions are page-granular. Accesses elsewhere on the same page are
filtered in VMX root, passed through for one instruction, and the page is
re-armed with Monitor Trap Flag (MTF).

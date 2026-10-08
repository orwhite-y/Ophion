# DbgkSys Ophion port

`DbgkSysWin10` and `DbgkSysWin11` are solution-level projects beside
`TestDriver`. Both depend on `Ophion` and emit their artifacts to
`build/bin/<Configuration>/`.

## Build

Use Visual Studio 2022 with the Windows Driver Kit installed:

```powershell
msbuild Ophion.sln /m /t:DbgkSysWin10 /p:Configuration=Debug /p:Platform=x64
msbuild Ophion.sln /m /t:DbgkSysWin11 /p:Configuration=Debug /p:Platform=x64
```

The projects link `Common/Ring0/SymbolicAccessKM.lib` and use SHA-256 for the
WDK test-signing step.

## Memory-breakpoint contract

The existing `IOCTL_SET_HARDWARE_BREAKPOINT` and `BREAKPOINT_RECORD` wire
layout remain compatible. Set these fields before sending the encrypted
record:

| Field | Value | Meaning |
| --- | ---: | --- |
| `command` | `15` | write access |
| `command` | `16` | read access |
| `command` | `17` | execute access |
| `LoopUserMode` | `0` | permanent breakpoint |
| `LoopUserMode` | `1` | one-shot breakpoint |
| `pid` | target PID | target address space |
| `Address` | target VA | first watched byte |
| `length` | `1..4096` | watched byte range; it must stay inside one page |

On success the driver returns the Ophion breakpoint identifier in `watchid`
and the resolved target CR3 in `cr3`. Pass the returned record to
`IOCTL_DEL_HARDWARE_BREAKPOINT` to clear it.

Ophion writes each hit with the `[ept-bp]` prefix. The hit report contains the
access type, mode, CPU, GLA/GPA/CR3, all general-purpose registers, RSP/RIP,
RFLAGS, and sixteen 64-bit stack entries when the guest stack is mapped.

The old VT_Driver software-breakpoint VMCALL values overlap unrelated Ophion
services. The port therefore blocks those legacy calls instead of forwarding
them. EPT memory breakpoints are the supported path.


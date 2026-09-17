# EPT lifecycle worklog

## Current objective
Close the cross-vCPU MTF / shadow-window race before any further test, build, or driver deployment.

## Scope
- Repo: `F:\winDriver\te\Ophion-master\Ophion-master`
- Branch: `test-from-9f8d515`
- HEAD: `4a56bde`
- Do not re-add `PROCESS.md` to git.
- Do not test, start, or deploy the driver until all static fixes are complete and the build passes.
- Driver lifecycle commands are restricted to:
  - `cmd /c manage_driver.bat build`
  - `cmd /c manage_driver.bat sign`
  - `cmd /c manage_driver.bat deploy`
  - `cmd /c manage_driver.bat start`
  - `cmd /c manage_driver.bat stop`

## Current state
- `VMCALL_SHADOW_ABORT_ALL` is patched:
  - drains pending shadow/MTF state
  - sets `vcpu->ept_state_quiesced = TRUE`
  - calls `ept_state_mark_drained(vcpu)`
- `VMCALL_EPT_UNHOOK_ALL` is patched:
  - drains current vCPU
  - requires all-vCPU drained at current epoch
  - returns `STATUS_RETRY` if any vCPU is not drained
- `VMCALL_STEALTH_FREE_ALL` is patched:
  - drains current vCPU
  - requires all-vCPU drained at current epoch before bulk free
  - returns `STATUS_RETRY` when any vCPU is not drained
- `VMCALL_STEALTH_FREE` is patched:
  - drains current vCPU
  - requires all-vCPU drained at current epoch before single free
  - restores host CR3 before returning `STATUS_RETRY`
  - preserves `free_req->result` and final status
- Quiesce guards are complete in `src/ept_hook.cpp` for:
  - `ept_handle_violation()`
  - `ept_handle_vmcall_hook()`
  - `ept_hook_handle_pf()`
- Quiesce guards are complete in `src/ept_stealth.cpp` for:
  - `ept_stealth_handle_pf()`
  - `ept_stealth_handle_violation()`
- Successful install paths now clear quiesce.

## Required design rule
Before any free of global EPT/stealth metadata, every launched vCPU must be quiesced and drained at the current epoch. After quiesce, no vCPU may arm a new MTF or open a new shadow-CR3 window until an install path clears quiesce.

## Execution plan
1. Patch `VMCALL_SHADOW_ABORT_ALL` only.
2. Patch `VMCALL_EPT_UNHOOK_ALL`.
3. Patch `VMCALL_STEALTH_FREE_ALL`.
4. Patch `VMCALL_STEALTH_FREE`.
5. Add quiesce guards to all MTF-arm points in `src/ept_hook.cpp`.
6. Add quiesce guards to all MTF/shadow-window points in `src/ept_stealth.cpp`.
7. Clear quiesce on successful install paths.
8. Static review.
9. Build only, no test.

## Checkpoint 5 record (completed)
- `ept_handle_violation()` now blocks all four MTF-arm paths while quiesced:
  - fake-page data access: installs a temporary RW data view, no pending pointer, no MTF, returns `TRUE`
  - target-page data access: restores original EPT view, no pending pointer, no MTF, returns `TRUE`
  - non-target CR3 execute: swaps to passthrough, no pending pointer, no MTF, returns `TRUE`
  - expected-TID mismatch: swaps to passthrough, no pending pointer, no MTF, returns `TRUE`
- `ept_hook_handle_pf()` now keeps the exec-PT view without recording `stealth_pf_swapped_hook` or arming MTF when quiesced.
- `ept_handle_vmcall_hook()` now restores the current vCPU EPT view and returns `TRUE` before proxy dispatch when quiesced.
- A pre-patch backup was saved as `src/ept_hook.cpp.bak_quiesce_checkpoint5` (untracked, not for commit).

## Checkpoint 6 record (completed)
- `ept_stealth_handle_pf()` now:
  - clears any stale shadow-CR3 window while quiesced
  - refuses to open a new shadow-CR3 window while quiesced
  - leaves fake-PT execution in a safe EPT view without recording `stealth_pf_swapped` or arming MTF
- `ept_stealth_handle_violation()` now blocks both MTF-arm paths while quiesced:
  - stealth target-page data access restores the original EPT view and returns `TRUE`
  - shared fake-PT data access restores the real PT EPT view and returns `TRUE`
- A pre-patch backup was saved as `src/ept_stealth.cpp.bak_quiesce_checkpoint6` (untracked, not for commit).

## Checkpoint 7 record (completed)
- `src/ept_hook.cpp`:
  - tracks `metadata_changed` for new function, primary-page, or secondary-page metadata
  - clears `vcpu->ept_state_quiesced` on successful primary install
  - advances the lifecycle epoch only when global hook metadata was created or linked
- `src/ept_hook_secondary.cpp`:
  - clears `vcpu->ept_state_quiesced` after successful secondary-CPU EPT install
  - does not advance the epoch because no global metadata is modified
- `src/ept_stealth.cpp`:
  - both already-installed secondary paths clear quiesce without advancing the epoch
  - both full-install success paths clear quiesce and advance the epoch
- `src/vmexit.cpp`:
  - already-installed and lost-interlock lazy paths clear quiesce without advancing the epoch
  - full-install success clears quiesce and advances the epoch
- Pre-patch backups exist as:
  - `src/ept_hook.cpp.bak_install_checkpoint7`
  - `src/ept_hook_secondary.cpp.bak_install_checkpoint7`
  - `src/ept_stealth.cpp.bak_install_checkpoint7`
  - `src/vmexit.cpp.bak_install_checkpoint7`
- `git diff --check` passed for the four modified core files.
- No build, sign, deploy, start, injection, or runtime test was performed.

## Checkpoint 8 record (completed)
- Audited every `MONITOR_TRAP_FLAG` arm site:
  - `ept_handle_violation()` arms are behind the quiesce early-return guards.
  - `ept_hook_handle_pf()` arms only inside `if (!vcpu->ept_state_quiesced)`.
  - `ept_handle_vmcall_hook()` returns before any MTF arm while quiesced.
  - `ept_stealth_handle_pf()` blocks both shadow-CR3 and fake-PT MTF arms while quiesced.
  - `ept_stealth_handle_violation()` blocks both stealth-page and shared-fake-PT MTF arms while quiesced.
- Added defensive all-vCPU drained guards directly inside global release paths:
  - `ept_unhook_all()`
  - `ept_stealth_free_all()`
  - `ept_stealth_uninstall()`
- Reordered `DriverUnload()`:
  - `broadcast_terminate_all()` now runs before `ept_stealth_free_all_broadcast()`.
  - Global stealth metadata is therefore released only after every launched vCPU has executed VMXOFF.
- Verified retry behavior:
  - `VMCALL_EPT_UNHOOK_ALL`, `VMCALL_STEALTH_FREE_ALL`, and `VMCALL_STEALTH_FREE` return `STATUS_RETRY` before any global metadata free.
  - `VMCALL_STEALTH_FREE` restores host CR3 before returning retry.
- Verified install lifecycle:
  - successful installs clear per-vCPU quiesce.
  - epoch advances only on full/global metadata creation or linkage.
  - secondary-CPU EPT-only installs do not advance the epoch.
- Verified `PROCESS.md` is not tracked and the git index is empty.
- `git diff --check` passed for all modified source files.
- Pre-static-fix backups exist as:
  - `src/ept_hook.cpp.bak_static_checkpoint8`
  - `src/ept_stealth.cpp.bak_static_checkpoint8`
  - `src/driver.cpp.bak_static_checkpoint8`
- No sign, deploy, start, stop, injection, or runtime test was performed.

## Checkpoint 9 record (completed)
- Executed only `cmd /c manage_driver.bat build`.
- Build result:
  - `build\bin\Debug\Ophion.sys` generated.
  - `build\bin\Debug\TestEptHook.sys` generated.
  - The integrated build/signing flow reported successful signing for both driver binaries.
- No deploy, start, stop, injection, or runtime test was performed in this checkpoint.
- Build warnings remain but do not block the build; they are mostly C4819 encoding warnings and existing deprecation/unused-function warnings.

## Checkpoint 10 record (completed)
- Runtime preflight completed:
  - `RMCore` and `RMCoreTst` are registered and currently stopped.
  - Service binaries point to `C:\Windows\System32\drivers\Ophion.sys` and `C:\Windows\System32\drivers\TestEptHook.sys`.
  - Deployed driver hashes do not match the newly built binaries, so runtime must use the new build after deployment.
  - Existing `_smoke_r3_auto.exe` is based on the known-good R3 path, but it calls `MessageBoxA` and can block on UI; use a non-interactive variant for automated validation.

## Checkpoint 11 record (completed)
- Executed `cmd /c manage_driver.bat deploy`.
- The script:
  - stopped and removed the old stopped services,
  - copied the new `Ophion.sys` and `TestEptHook.sys` into `C:\Windows\System32\drivers`,
  - re-registered `RMCore` and `RMCoreTst`.
- The ?Input redirection is not supported? lines came from the batch script?s `timeout` calls under redirected input; deployment itself completed successfully.

## Checkpoint 12 record (completed)
- Executed `cmd /c manage_driver.bat start`.
- Both `RMCore` and `RMCoreTst` are running.
- The ?Input redirection is not supported? lines are from the batch script?s `timeout` calls under redirected input and do not indicate a driver-start failure.

## Next action
Create and compile a non-interactive R3 EPT hook smoke test that does not rely on `MessageBoxA`.

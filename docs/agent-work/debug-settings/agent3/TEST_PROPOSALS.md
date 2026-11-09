# Test proposals for Agent 1

Submitted for **Agent 1 approval and execution only**. Agent 1 exclusively owns the one console and one Lua loader. Agent 3 performed no live tests, TCP 9026 connection, Chiaki access, probe, or reboot. These are specifications, not instructions to run automatically. No proposed test writes system configuration or attempts to create the Debug Settings entry.

The first gate is offline: obtain an authenticated, version-matched contract for the **actual Settings visibility decision** or a documented read-only service query. Without that, the saved 14.10 captures justify no configuration setter test. An on-screen entry in the native Settings application, recorded by Agent 1, would be the target observation; a game overlay, return code, or module name would not suffice.

## DS-0 — Offline interface and visibility inventory (recommended first)

- **Hypothesis:** Existing local, lawfully held 14.10 artifacts or documented SDK material identify the Settings application's visibility predicate and a version-matched service/query contract.
- **Required existing capability:** Offline repository/artifact reading only. Start from the game's module inventory ([42i](../../../../results/phase9_kaslr_defeat/42i_vmquery_20261016_070711.txt#L14-L47)); record artifact provenance and firmware version. No version-matched Settings contract has yet been identified.
- **Expected harmless behavior:** Search and document local files; make no console or network connection and modify no device state.
- **Success observation:** A specific Settings-side read of a named feature or service response is established in a version-matched artifact, with the caller contract, authorization requirements, and provenance recorded. A mere string, NID guess, or module filename is insufficient.
- **Failure observation:** No authenticated Settings image/contract is available, or the identified interface does not cover visibility. Record the exact negative scope; retain judgment C.
- **Possible system instability:** None; no console interaction.
- **Rollback/recovery:** None. Any scratch output stays local and may be deleted; original artifacts stay unchanged.
- **Agent 1 decision requested:** Approve the offline evidence gate. Any later on-console test requires a separate, concrete read-only API specification.

## DS-1 — Passive development-state return, conditional low-priority control

- **Hypothesis:** The already observed no-argument syscall 606 result is stable in the current game and may be useful as a passive state classifier. Its `is_development_mode` name is inherited from a 13.60 map; the 14.10 capture only proves a `0` return ([51b](../../../../results/51b_accessible_syscall_deep_20261016_214832.txt#L26)). This test does **not** hypothesize that the call toggles the menu.
- **Required existing capability:** Agent 1's existing Lua syscall wrapper and a healthy loader session. No new gadget, address, service handle, or privilege is needed.
- **Expected harmless behavior:** One no-argument read-like call with a self-PID control; log return values only. No loop, mutation, or inter-process call. Compare with the existing capture before interpreting it.
- **Success observation:** The call completes and returns a stable scalar in the same session; this supports only passive observability. If Agent 1 independently records the native Settings menu state, that correlation can be noted but is not causation.
- **Failure observation:** Error, changed return, timeout, or process loss; leave 14.10 semantics unresolved. Even a repeat `0` does not establish that 606 controls menu visibility.
- **Possible system instability:** Low expected, but every Lua probe carries the observed loader/game crash risk. Stop at one call if the canary or response is abnormal.
- **Rollback/recovery:** No state to roll back. If the game process exits, only Agent 1 may use the existing recovery procedure; no reboot is requested by this proposal.
- **Agent 1 decision requested:** Defer unless DS-0 finds a reason this passive flag is relevant. The old capture already answers simple reachability.

## DS-2 — Read-only DIP switch value, only after a predicate link is found

- **Hypothesis:** If DS-0 establishes that the genuine Settings visibility predicate reads a specific DIP switch value, a single read-only query of that **identified** value can establish what the game is permitted to observe. The current captures show a read-only open and read-like ioctl, but no setting semantics or menu link ([132a](../../../../results/phase21_kernel_leak/132a_srop_dipsw_dmem_20261021_223550.txt#L5-L9); [132c](../../../../results/phase21_kernel_leak/132c_srop_dipsw_write_20261021_223951.txt#L5-L29)).
- **Required existing capability:** Agent 1's existing O_RDONLY open and one previously measured read-like ioctl shape. DS-0 must supply the exact index/meaning; do not guess another one.
- **Expected harmless behavior:** Open `/dev/dipsw` read-only, make one known read-like request with a bounded output buffer and sentinel, log syscall return and changed bytes, then close. No O_RDWR, write-shaped ioctl, sweep, or device-state change.
- **Success observation:** The known query returns a bounded value and DS-0 independently ties that field to the Settings predicate. Success establishes observation, not influence.
- **Failure observation:** Open/query refuses, buffer unchanged, value is ambiguous, or no authenticated predicate link exists. In that case this test is not run or is non-informative.
- **Possible system instability:** Low for the previously measured read shape; nonzero because device ioctl behavior and loader stability are not guaranteed. The prior wide sweeps should not be repeated.
- **Rollback/recovery:** No persistent state expected. Close the descriptor; if the process fails, Agent 1 handles game recovery under the existing hardware protocol.
- **Agent 1 decision requested:** Hold until DS-0 identifies a specific field consumed by Settings.

## DS-3 — Version-matched service **query**, only with an authenticated contract

- **Hypothesis:** A documented, game-authorized, read-only service API in a loaded module can report the feature state that the native Settings application uses. Module presence alone ([42i](../../../../results/phase9_kaslr_defeat/42i_vmquery_20261016_070711.txt#L21-L47)) does not meet this hypothesis.
- **Required existing capability:** Existing game-native function invocation and module enumeration, **plus** a DS-0 result that supplies the exact 14.10 export/NID, signature, object/session setup, permission model, and read-only behavior. These details are not currently known; no function address or offset is supplied here.
- **Expected harmless behavior:** One documented query in the game process using its ordinary client library, a bounded output buffer, and an immediately checked error/status result. No setter or request to a system process based on guessed protocol bytes.
- **Success observation:** The service returns a documented success status and value; Agent 1 can compare the value with an independently observed native Settings baseline. This proves reachability of the query only; a separate authorized mutation would still be needed to show influence.
- **Failure observation:** Missing export, entitlement denial, no valid session, error status, or no correspondence with the documented predicate. Treat a syscall return of `0` with a failure word in the output as failure, as the [622](../../../../results/phase17_new_vectors/305a_sys622_unauth_20261022_120414.txt#L1-L8) and [532](../../../../results/phase17_new_vectors/307a_sys532_argument_map_20261022_120556.txt#L3-L28) captures require.
- **Possible system instability:** Moderate unknown until a real contract is found. The existing compositor and 622 experiments show that guessed service messages can disrupt or terminate a game session ([service record](../../../SYSTEM_SOCKETS_14_10.md#what-the-daemons-do-with-input); [stopped 622 capture](../../../../results/phase17_new_vectors/355c_sys622_data_20261022_165803.txt)). Do not approve an implementation lacking the DS-0 contract.
- **Rollback/recovery:** No persistent state is expected for a documented query. Close any session; if the game fails, Agent 1 handles recovery. No console reboot is part of this specification.
- **Agent 1 decision requested:** Keep pending; review the exact API specification produced by DS-0 before any console execution.

## Decision and stop criteria

There is currently **no justified state-changing on-console test** for menu visibility. Do not treat `debug_init(560)` success, `syscall 532` dispatch, a socket connect, or a `dipsw` zero readout as permission to write system state. Do not run command sweeps, send arbitrary `/system_tmp` messages, use the unstable 622 `0x400` path, or attempt Settings-process access. Agent 1 should stop any approved read-only test at the first unexpected failure and record the raw result, loader health, and whether the genuine Settings entry was actually observed.

The requested outcome remains a genuine entry in the native Settings application. These tests first determine whether a legitimate game-callable interface exists; they do not claim to enable it.

## Notes for Agent 1's existing queue

The staging branch's [Agent 1 queue](../agent1/TEST_QUEUE.md) and [status](../agent1/STATUS.md) contain a few claims to resolve before approval:

- Queue T-001 calls syscall 585 a possible PID discovery route. The corrected syscall label is `is_in_sandbox`, and the saved 14.10 call returned `1` ([name correction](../../../SYSCALL_MISLABEL_AUDIT_2026-10-19.md#L19-L25); [raw result](../../../../results/phase15_native_sysent/syscall_isolation_sweep_20261020_193825.txt#L16)). A process list would still not authorize access to Settings.
- The status says all syscall 532 commands return `-1`. The 14.10 [argument map](../../../../results/phase17_new_vectors/307a_sys532_argument_map_20261022_120556.txt#L3-L28) shows a limited reachable subset that returns output status errors/constants; no Settings operation or usable registered handle was established. This distinction matters when evaluating a documented query.
- The status says all sysctl writes fail. The [43f capture](../../../../results/43f_sysctl_write_20261016_180756.txt#L5-L21) contains one failed securelevel-labeled write; the other candidate writes were conditional and not reached. The existing [finding correction](../../../FINDINGS.md#finding-42-recorded-sysctl-operations-probe-43f) states that this is not a complete write survey.
- Public kernel-flag and ShellUI-patch implementations establish **known privileged routes** ([existing path review](../../../DEBUG_SETTINGS_14_10_PATH.md#finding)). They do not establish that every possible legitimate 14.10 service route is absent. Until the native Settings predicate is recovered, the visibility mechanism remains C (unknown), with B applying to the protected routes already tested.

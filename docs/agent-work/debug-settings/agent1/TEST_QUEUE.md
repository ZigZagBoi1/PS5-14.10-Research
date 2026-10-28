# Agent 1 — Test Queue

Last updated: 2026-10-24

## Approval Procedure

1. Every live test must have a written hypothesis, expected outcome, and failure condition
2. Check the full dead-ends list in CLAUDE.md before proposing a test
3. Crash-class assessment required: LOW / MODERATE / HIGH / RISKY
4. Only one test at a time on the PS5 — exclusive hardware access
5. Stop after any crash or unexpected state until reviewed
6. No test runs until explicitly approved by the project lead

## Pending (Awaiting Review)

### T-001: Enumerate Settings-related processes and their PIDs
- **Hypothesis:** `sysctl kern.proc` may reveal whether ShellUI or a Settings process is visible to the game process.
- **Expected:** PID list showing only the game process and its children. ShellUI likely in a different jail.
- **Failure:** Process kills on sysctl access (known safe — probe 43f already accessed kern.proc variants).
- **Crash class:** LOW
- **Status:** PENDING — needs review against existing kinfo_proc scan results
- **Duplicate check:** Probe 43f scanned sysctl, but not specifically for process enumeration across jails.
- **Correction (Agent 3):** T-001 previously referenced sys 585 as "PID discovery." The corrected label is `is_in_sandbox` (returned 1 on 14.10). A process list would not authorize Settings access regardless.

### T-002: sys 587 credential deep scan for Debug Settings bits
- **Hypothesis:** The 0x88-byte credential structure returned by sys 587 may contain bits that, if writable through a different syscall, could influence Debug Settings visibility.
- **Expected:** Read-only data. Only known value is +0x0C = 0x20000000 (capability word). The credential record is in kernel memory; writing it requires kernel R/W.
- **Failure:** Already tested (probe 55e) — returns 0x88 bytes, no kernel pointers.
- **Crash class:** LOW
- **Status:** LIKELY DUPLICATE — 55e already scanned this. Needs review of whether any bit maps to a settings-visibility flag.

### T-003: Notification subsystem message injection
- **Hypothesis:** The notification0-5 devices open from the game process. If a specific notification type or payload could trigger Settings to show Debug Settings, this would be a userland path.
- **Expected:** Notification devices reject custom messages or show only game-level notifications. Sony's notification protocol is not documented.
- **Failure:** Device rejects write / returns -1 / crash.
- **Crash class:** MODERATE — unknown protocol, could crash notification daemon
- **Status:** PENDING — notification devices confirmed open (34/76 /dev nodes), but no writes attempted
- **Prerequisite:** Document the notification device ioctl interface first (from existing ioctl sweep results)

## Approved

### DS-0: Offline interface and visibility inventory (Agent 3 proposal)
- **Hypothesis:** Existing local 14.10 artifacts or documented SDK material identify the Settings application's visibility predicate and a version-matched service/query contract.
- **Expected:** Search and document local files; no console interaction.
- **Success:** A specific Settings-side read of a named feature/service is established with caller contract and authorization requirements.
- **Failure:** No authenticated Settings image/contract available. Retain judgment C.
- **Crash class:** NONE (offline only)
- **Status:** COMPLETED — NEGATIVE RESULT (2026-10-24)
- **Agent 1 decision:** Approved and executed offline.
- **Result:** No version-matched Settings visibility contract identified in local artifacts. Searched: all kernel handler analyses, sysent name CSVs, SDK code (pup14/), Apollo kernel_offset.lua, webkit crossref docs, probe results for sys 532/591/606/619/622/643/649, dipsw captures, module enumeration (42i/56g2), and all 39 loaded module handles. The repository contains no Settings application binary, no ShellUI binary, no Settings-facing NID or export, and no documented service contract for menu visibility. DIP switches are all zero on retail. The kernel predicate `SblRcMgrIsAllowDebugMenuForSettings` (Agent 2, HIGH confidence) reads kernel `.data` flags, not a service API. Judgment remains **C**.

## Deferred (Blocked by DS-0 Negative Result)

### DS-1: Passive development-state return (Agent 3 proposal)
- **Hypothesis:** sys 606 result (`0` in saved capture under `is_development_mode` label) is stable and may classify system state. Not a setter.
- **Agent 1 decision:** CLOSED. DS-0 found no reason this flag is relevant to Settings. Existing capture (51b) already shows return=0. Re-running adds nothing.

### DS-2: Read-only DIP switch value (Agent 3 proposal)
- **Hypothesis:** If DS-0 identifies a specific DIP switch consumed by Settings, one read-only query can check what the game observes.
- **Agent 1 decision:** CLOSED. DS-0 did not identify any DIP switch consumed by Settings. All switches read as zero on retail (132c). No index to test.

### DS-3: Version-matched service query (Agent 3 proposal)
- **Hypothesis:** A documented, game-authorized, read-only service API in a loaded module can report the feature state that Settings uses.
- **Agent 1 decision:** CLOSED. DS-0 produced no export/NID, no service contract, no documented API. dlsym(591) fails for all handles. Module text is XO. No query to make.

## Completed

(None yet — agent just started)

## Rejected

### R-001: sys 643 chicken switches for Debug Settings
- **Reason:** Already exhaustively tested. Probe 55a: all 32 individual bits accepted, no effect on any gate. Probe 356a: `0xFFFFFFFF` OR'd in, no change to 585/618/646/532/mprotect. The field is process-local at `process+0xa34` and does not reach kernel globals or other processes.

### R-002: sys 560 debug_init
- **Reason:** Already tested (probes 257a/258a). `560(1)` returns 0 but produces zero observable changes to any system gate. Dead.

### R-003: mprotect(RWX) or W^X bypass for code injection into ShellUI
- **Reason:** W^X is enforced at hypervisor level. Probe 423a: bit 0x4 (execute) is the only one refused by mprotect. Probe 424a-c: mmap with PROT_EXEC maps but child threads fault on first instruction. Probe 54d/124a: sys 588 DMEM page attribute modify accepts RWX but PTE never gets execute bit. This wall cannot be bypassed from userland.

### R-004: kldstat/kldsym/kldnext for module analysis
- **Reason:** All killed or return -1 (probes 56k4/56k5, 171a, 353a/353b). The entire kld* family is dead on 14.10.

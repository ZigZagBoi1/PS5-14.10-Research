# kptr_hunt OBJECT-sourced copyout candidates — audit and closure

> **Date:** 2026-11-05. Closes TODO.md Priority 1 item "Review 17
> OBJECT-sourced copyout candidates". Input:
> `results/offline/kptr_hunt.json` (produced by
> `tools/offline/kptr_hunt.py` over the 13.60 capture). Verdict rule: a
> candidate is closed when live evidence (14.10 local or the 13.40
> community cross-check in issue #170) shows the copyout either never
> fires for a game process or carries only userland/scalar values.

## The 17 sites are 7 unique code locations

`kptr_hunt.py` walks each handler body independently, so shared helper
sites are counted once per handler. The 17 raw hits collapse to 7
unique `(rva, source)` sites:

| # | site (13.60 RVA) | source operand | handlers it appears in |
|---|---|---|---|
| 1 | `0x4f757f` | `[rax+0x88]` | 536 (`registry_ioctl`), 604 (`dl_get_metadata`) |
| 2 | `0x34b8e2` | `[r14+0x10]` | 593 (`dynlib_get_info`), 659 (`dynlib_get_info2`?) |
| 3 | `0x34c647` | `[r14+0x10]` | 656 (`dynlib_get_info_for_libdbg`) |
| 4 | `0x34bd8e` | `[r14+0x10]` | 660 (`dynlib_get_info_ex`-family) |
| 5 | `0xca1b8b` | `[r13+0x578]` | 601 (`mdbg_service`, cmd 0x12 read-back) |
| 6 | `0x3b018a` / `0x3b1612` | `[rbx+8]` / `[rbx+0x10]` | 661, 662, 663, 664, 668 (AIO family) |
| 7 | `0x3b1f6d` | `[rbx+0x18]` | 665, 666 (AIO family) |

(Count check: 2+2+1+1+1+5+2 = 14; the remaining 3 of the 17 are the
second occurrences of the two AIO sites inside 662/664/668 — same RVAs,
same sources.)

All sites call copyout (`0x2591d0`). Spot-verified against
`tools/offline/dis_rva.py`: `0x34b8e2` copies `0x160` bytes from the
filled module-record buffer; `0x4f757f` copies `rdx=r13` bytes from
`rsi=r15`; the AIO sites copy per-request status/result fields from the
in-flight AIO request object.

## Per-site verdicts

| site | verdict | evidence |
|---|---|---|
| `0x4f757f` (536, 604) | **CLOSED — gated off** | 14.10: both deny with rax=1 on every real-arg shape; issue #170 reproduces the denial on 13.40 ("caller gate rejects the context before any pid/handle work — zero qwords changed"). 536's reachable decode path is the checksum-gated forged-handle path (probes 429a–433a): registration table empty for a game process, all forged ids answer `0x800D0203`. |
| `0x34b8e2` (593, 659) | **CLOSED — userland-only** | 14.10 probe 54k: 593 returns userland module bases for 39 modules, zero kernel pointers. Issue #170: same region userland-only on 13.40; also covers the adjacent 598/649/672 family. Struct map confirms the copied `0x160`-byte record is filled from userland segment metadata (`docs/SYS_608_DYNLIB_GET_INFO_EX_13_60.md` for the _ex variant). |
| `0x34c647` (656) | **CLOSED — gated off** | 14.10 probes 1300a–D (PR #193): unit/firmware-class gate fails on retail; `docs/SYS_656_DYNLIB_GET_INFO_FOR_LIBDBG_13_60.md` decodes the gate chain and marks the site kptr-negative (source is a userland VA field). Issue #170: denied on 13.40, only touched qword is the `0x160` size prefix. |
| `0x34bd8e` (660) | **CLOSED — userland-only (kptr-negative anchor)** | Issue #170 is the strongest single result in the set: on 13.40 the call **fully succeeds** (rax=0) and fills the entire `0x160`-byte record — 44 qwords, every one a userland segment base or scalar, kernel-band count 0. The OBJECT member `[r14+0x10]` provably carries userland VAs. |
| `0xca1b8b` (601) | **CLOSED — paired read-back, never armed** | Static (verified this session, `docs/SYS_601_MDBG_SERVICE_LIMITS_13_60.md`): the site copies out the `+0x578` buffer that cmd 0x11 installs, then frees and zeroes it — a store/load pair, not a leak. Live 14.10 (PR #90, probes 322a–324a): cmd 0x12 returns -1 (no session installed); issue #170: only write in the whole 601 command set is the scalar `0x101` from cmd 0x00. |
| AIO `0x3b018a` / `0x3b1612` / `0x3b1f6d` (661–668) | **CLOSED — family inert/gated** | 14.10: submit path is behind a boot tunable that never opens (`docs/AIO_GATE_14_10.md`); 661 kills as the shared nosys trampoline (353a); the 65l "double-free" was double-status, retracted (PRs #187/#188). Batch calls 662/663/664 with the id-array shape return one `0x80020003` (unknown id) per slot — the copied object fields are Sony status codes, not pointers. Issue #170: independent 13.40 race testing also non-exploitable, family considered closed. |

## Cross-check completeness

The TODO item named handlers "536/593/601/604/656/659/660/661-668".
Every one of the 17 raw candidates is covered by at least one of:
14.10 local captures (54k, 83a/83c, 322a–324a, 1300a–D, 429a–433a,
AIO probes 760b–818a), the issue #170 13.40 cross-check, or a static
decode that bounds what the site can copy (601 paired read-back, 608/656
struct maps). No candidate remains in "untested contract" state.

## Standing caveat

These are 13.60-capture candidates cross-checked against 14.10 and
13.40 behavior. A handler whose 14.10 implementation diverged from the
13.60 body could in principle re-open a site; the 608 case argues this
is rare (14.10 matched the static struct map exactly, PR #193 probes
1198a/1198b). If a 14.10 kernel image lands, re-running
`tools/offline/kptr_hunt.py` against it is the definitive close-out.

# Offline assessment: probes 1407a / 1408a / 1409a (FreeBSD SA-26:48/51/54)

**Date:** 2026-11-17
**Scope:** static / source-scope only. No console was contacted. Every conclusion
is version-scope ("does the vulnerable code exist in the PS5 11.0.0-era fork"),
not a device measurement.

The three queued probes in `results/STATE.md` (`1407a` ktimer, `1408a` SysV sem,
`1409a` kevent) all restate 2026 FreeBSD advisories. The repo already triaged this
decade once (`docs/FREEBSD_CVE_TRIAGE_14_10.md` §0.1: the kernel is an 11.0.0 fork,
so 2024-2026 code is out of scope by construction). Each probe was written without
that filter. Verdicts:

| Probe | Advisory | CVE | Offline verdict |
|---|---|---|---|
| 1407a | SA-26:51.ktimer (CLOCK_TAI stack leak) | CVE-2026-58084 | DEAD — the clock id does not exist in the fork |
| 1408a | SA-26:54.sysvsem (GETALL/SETALL OOB) | CVE-2026-58087 | DEAD — SysV IPC subsystem absent (already recorded) |
| 1409a | SA-26:48.compat32 + SA-26:51 | CVE-2026-49425 + 58084 | DEAD — both halves out of scope for the fork |

---

## 1. 1407a — CLOCK_TAI leak (CVE-2026-58084) is unreachable

The advisory (`FreeBSD-SA-26:51.ktimer`) describes `timer_settime(2)` calling
`realtimer_gettime()` for a CLOCK_TAI timer; that read fails when no TAI offset is
configured, the error is not checked, and the uninitialized on-stack
`struct itimerspec oval` is copied to userland. The trigger is:

```
timer_create(CLOCK_TAI, ...) -> timer_settime(t, 0, &zero, &oval)  // oval = kernel stack
```

**CLOCK_TAI does not exist in the fork's clock table.** The constant was added to a
new header `sys/_clock_id.h` (copyright 2021 Netflix, present in 15.1 with
`#define CLOCK_TAI 16`). FreeBSD 11 does not have that header, and its
`sys/sys/time.h` clock list ends at `CLOCK_PROCESS_CPUTIME_ID = 15` with **no
CLOCK_TAI**: 0 REALTIME, 1 VIRTUAL, 2 PROF, 4 MONOTONIC, 5 UPTIME, 7 UPTIME_PRECISE,
8 UPTIME_FAST, 9 REALTIME_PRECISE, 10 REALTIME_FAST, 11 MONOTONIC_PRECISE,
12 MONOTONIC_FAST, 13 SECOND, 14 THREAD_CPUTIME_ID, 15 PROCESS_CPUTIME_ID.

CLOCK_TAI was introduced to FreeBSD in the 13.0 era (sub-second TAI/timecounter
rework), so a 2016-era 11.0.0 fork cannot contain the `realtimer_gettime(CLOCK_TAI)`
failure path the advisory patches. On a FreeBSD-11 kernel, `timer_create(16, ...)`
(any value 16..MAX) fails with EINVAL at the clock-id check, and every value the
kernel *does* accept is a clock for which `realtimer_gettime()` succeeds, so the
"error unchecked, oval uninitialized" shape never fires.

Secondary note: the probe also mislabels the clock ids anyway (its Section E table
calls 11 "MONOTONIC_FAST" and 12 "SECOND"; the FreeBSD values are 11 MONOTONIC_PRECISE,
12 MONOTONIC_FAST, 13 SECOND). That matters for the Section E sweep's output labels,
but it does not change the verdict either way — **the vulnerable clock value is
unreachable regardless**, so there is no point spending a console run on 1407a.

Sources:
- `FreeBSD-SA-26:51.ktimer.asc` (mechanism + scope wording)
- `https://cgit.freebsd.org/src/plain/sys/sys/_clock_id.h?h=releng/15.1` (CLOCK_TAI=16, 2021)
- `https://cgit.freebsd.org/src/plain/sys/sys/time.h?h=releng/11.4` (clock list, no CLOCK_TAI)
- `https://man.freebsd.org/cgi/man.cgi?query=clock_gettime&sektion=2&manpath=FreeBSD+11.4-RELEASE` (documents the same list; no CLOCK_TAI)

---

## 2. 1408a — SysV semaphore OOB (CVE-2026-58087) already closed

`SA-26:54.sysvsem` requires `semget()` to succeed so GETALL/SETALL can run against a
set whose slot is swapped under the sequence-wrap race. On 14.10 the entire SysV IPC
family is absent and this is already recorded:

- `525a` (`results/phase23_cve_2026/525a_sysv_ipc_presence_20261105_090149.txt`):
  `semget` -1 on every shape, `shmget` -1, `msgget` -1.
- `389h` / `184a` corroborate `semget=-1`, `shmget=-1`, `msgget=-1`.
- `docs/SYSENT_PRESENCE_14_10.md`: 221 `semget`, 222 `semop`, 510 `__semctl`,
  231 `shmget`, 225 `msgget` all recorded "kills" — an absent slot, per
  `docs/SYSCALL_ABSENT_VS_LETHAL.md` (an absent slot terminates the caller; a present
  handler returns -1). The "kills" rows in the presence map are absence, not hostility.
- `docs/DEAD_ENDS.md:168` already closes it: "SysV IPC completely absent (525a) …
  Sony removed the entire SysV IPC subsystem."

No new work. 1408a restates a dead end; do not burn a console run on it.

---

## 3. 1409a — kevent ext[] + ktimer leak (CVE-2026-49425 / 58084) out of scope

The probe bundles two unrelated advisories:

**Half A — SA-26:48.compat32 (CVE-2026-49425):** the compat32 `kevent()` handler
translates a 64-bit kevent into a stack `struct kevent32` without zeroing it. Two
reasons this does not map to the PS5 kernel: (1) advisory scope is FreeBSD 14.3/14.4/
15.0 — the compat32 kevent translation path post-dates the 11.0.0 fork; (2) the bug
lives in COMPAT_FREEBSD32, which requires the 32-bit compatibility layer and a 32-bit
binary to drive it — the PS5 Lua loader runs 64-bit Sony syscalls, not a compat32
binary. Neither precondition is reachable.

**Half B — the `ext[4]` scan:** the probe assumes a 64-byte `struct kevent`
(`ident 8, filter 2, flags 2, fflags 4, data 8, udata 8, ext[4] 32`). The `ext[4]`/
`kevent_data` extension was added in FreeBSD **12.0**, not 11: FreeBSD 11's
`struct kevent` is 32 bytes (ident, filter, flags, fflags, data, udata — no ext[]).
Scanning `+0x20..+0x3F` for leak bytes on a FreeBSD-11-shaped kernel reads past the
struct that an 11 fork would copy out. (Sony could in principle have backported the
struct, but the probe asserts a layout it has not re-established from the 13.60
artifacts, and its ktimer/TAI premise is dead per §1.)

The relevant prior measurements are already in the ledger and clean: `85h`/`85i`/`85j`
(kevent leak attempts), `56q` (kevent output scan). The kqueue locking is separately
proven solid (`271g`/`271h`/`271i`, DEAD_ENDS.md:155).

---

## Bottom line

All three probes are closed offline with no console cost:

- **1407a**: CLOCK_TAI absent from the 11.x clock table → the SA-26:51 leak path is
  unreachable by construction.
- **1408a**: already-closed dead end (SysV IPC absent); restates `525a`.
- **1409a**: both halves (compat32 kevent, FreeBSD-12 kevent struct) post-date the
  11.0.0 fork; prior kevent leak scans are already clean.

None should be re-investigated without first re-establishing, from the 13.60/14.10
artifacts, that the fork actually contains late-version code — the same filter
`docs/FREEBSD_CVE_TRIAGE_14_10.md` §0.1 already applies. Remove the three probe names
from STATE.md's `queued_probes`; they are not pending, they are dead.
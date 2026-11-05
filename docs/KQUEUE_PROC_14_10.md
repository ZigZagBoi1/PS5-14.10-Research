# kqueue / EVFILT_PROC on 14.10 — console panic 2026-10-28

Status: **open, not reproduced in four attempts** (2026-10-28). This note records one console-wide crash and the
sequence that produced it, so it is not lost and not re-run blindly.

## What happened

Two probes ran back to back on the same console session (the game process is
shared across TCP connections, established in `docs/PHASE17_FINDINGS.md`):

1. `probes/phase17_new_vectors/105a_evfilt_proc_kptr_leak.lua` —
   `results/phase17_new_vectors/105a_evfilt_proc_kptr_leak_20261028_191128.txt`.
   `kqueue()` → `kevent(EV_ADD, EVFILT_PROC, flags=EV_ADD|EV_ENABLE|EV_CLEAR,
   fflags=NOTE_EXIT|NOTE_FORK|NOTE_EXEC|**NOTE_TRACK** , ident=own pid)` →
   `ret=0x0`. Then individual notes (`0x80000000`, `0x40000000`, `0x20000000`,
   `0x1`) each `ret=0x0`. Script finished `COMPLETE`; the kqueue fd was never
   closed, so the registration outlives the connection.

2. `probes/phase16_thr_create_crash/78d_kevent_evfilt_proc.lua` —
   `results/phase16_thr_create_crash/78d_kevent_evfilt_proc_20261028_191208.txt`.
   Prints `[0] canary pid=85`, `[0] self_tid=101831`, `[0] kqueue fd=23`, then
   **nothing**. The next call is
   `kevent(kq=23, changelist=1, eventlist=NULL, nevents=0, timeout=NULL)` with
   `EVFILT_PROC`, `EV_ADD|EV_ENABLE|EV_CLEAR`,
   `fflags=NOTE_EXIT|NOTE_FORK|NOTE_EXEC` (no `NOTE_TRACK`), `ident=pid`.

3. The console then crashed entirely (user report, 2026-10-28). No process-level
   kill: the connection had already stopped producing output at step 2.

## What the two differ in

| | 105a (returned 0) | 78d (hung) |
|---|---|---|
| second registration in the same process | no | **yes**, same `ident` |
| `NOTE_TRACK` on the first | **yes** | n/a |
| `eventlist` | non-NULL, `nevents` set | NULL / 0 |
| timeout | zeroed timespec | NULL (blocking) |

Two candidate mechanisms, both consistent with the evidence:

- **A.** A second `EVFILT_PROC` knote for a process that already carries a
  `NOTE_TRACK` tracker deadlocks on the proc knlist (or the tracker's refcount),
  so the syscall never returns.
- **B.** `nevents=0` with `eventlist=NULL` is not treated as "no output" on this
  kernel and the call blocks; the panic follows the hang, not the registration.

`78d`'s own `thr_create` fault never ran — the `[A] [BEFORE] thr_create` line is
absent — so the earlier "EVFILT_PROC + thr_create" framing of that probe is not
what happened here.

## Isolation plan (do not run on a console that matters)

`probes/phase17_new_vectors/931a_kevent_proc_repeat.lua` — one connection, no
`NOTE_TRACK`:

- `[1]` kqueue A, register `EVFILT_PROC` self, close A, kqueue B, register self,
  close B, print, poll A.
- `[2]` only when `SECTION>=2`: the same but the first registration carries
  `NOTE_TRACK` — the suspected trigger.
- `[3]` only when `SECTION>=3`: register with `nevents=0, eventlist=NULL` and a
  zero timespec, the exact 78d shape.

Run `SECTION=1` first. It answers mechanism A without `NOTE_TRACK`; if it
survives, `SECTION=2` is the discriminating run.

## Why this is interesting

If A holds, the kqueue proc-tracking code has a locking/refcount defect reachable
from a plain page-free process with two syscalls, and it is *stateful across
connections* because the process is shared. That is a kernel-side bug class we
have not been able to reach since the aio family turned out to be inert.

## Reproduction attempts (all survived)

`probes/phase17_new_vectors/931a_kevent_proc_repeat.lua`, run on the relaunched
console against process pid 81:

| run | shape | result |
|---|---|---|
| SECTION 1 | two kqueues, plain `EVFILT_PROC`, zero timeout | both `rv=0`, poll 0 events |
| SECTION 2 | first registration `NOTE_TRACK`, second plain, both kqueues open across the second | both `rv=0` |
| SECTION 3 | `nevents=0`, `eventlist=NULL`, zero timespec | `rv=0` |
| SECTION 5 | 78d verbatim: `nevents=0`, `eventlist=NULL`, **`timeout=NULL`** | `rv=0` |
| 105a then 931a SECTION 1 | previous connection leaves a `NOTE_TRACK` kqueue open, next connection registers | `rv=0` |

So neither the `NOTE_TRACK` cross-connection state nor the NULL-timeout shape
reproduces the hang. `78d` also never printed its `=== SECTION A ===` banner,
which sits *before* the kevent call and after `memory.alloc` — so the stop may
not have been the `kevent` at all. Without a panic log there is no way to place
it more precisely; treat the 2026-10-28 console power-off as unexplained and do
not attribute it to EVFILT_PROC on the strength of one run.

## Cross-references

- `docs/KEVENT_TIMEOUT_VARIABLE.md` — earlier kevent timeout oddity (probe 30c).
- `docs/PHASE17_FINDINGS.md` — shared-process note (probes 887a-890a, same pid
  across four connections).
- `results/phase17_new_vectors/105a_…` and `results/phase16_thr_create_crash/78d_…`.

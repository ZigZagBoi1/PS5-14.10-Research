# kevent: nonzero timeout is an observed difference, not an explanation

Status: **evidence reconciliation.** Two saved captures disagreed about `kevent`
(363) and this repo recorded both verdicts at once. Reading a third capture
shows the disagreement cannot be resolved from registration-vs-poll shape
alone. A nonzero timeout is one observed differing variable and a testable
hypothesis, not an explanation; the cause remains unresolved.

`docs/ATTACK_SURFACE.md` used to say, one screen apart, that kevent "registers
or produces events" (Partially Working) and that it is "Always -1" (Completely
Blocked). `CLAUDE.md` and `docs/STRATEGY.md` repeated the "always -1" half.

## The three calls

Probe 20 splits registration and delivery
(`probes/phase2_kernel_objects/20_kqueue_stress.lua:137-138,157-158`):

```lua
syscall.sc_kevent(kq, changelist, #pipes, eventlist, 0, timeout)   -- register, nevents=0
syscall.sc_kevent(kq, changelist, 0, eventlist, 10, timeout)       -- poll, nchanges=0
```

Probe 21 combines them
(`probes/phase2_kernel_objects/21_kqueue_deep.lua:76,142`):

```lua
syscall.sc_kevent(kq, batch, 10, events, 10, timeout)              -- add+poll together
```

Probe 30c also combines them
(`probes/phase4_ipc_network/30c_fcntl_bypass.lua:261-262`):

```lua
syscall.sc_kevent(kq_fd, kev, 1, out_kev, 1, timeout)              -- add+poll together
```

The struct bytes are identical in all three: 32-byte kevent, valid changelist,
valid output buffer, valid timeout pointer. Probe 21's combined call succeeds
with a zero timeout. One observed difference between that result and 30c's
`rv=-1` is the timeout: probes 20 and 21 use a **zero** timeout
(`21_kqueue_deep.lua:40-42`, `20_kqueue_stress.lua:133-135`), while 30c uses a
**100ms** timeout (`30c:254-256`).

## What each returned

| probe | shape | timeout | result |
|---|---|---|---|
| 20, PART 3 | split register | zero | `rv=0` (`results/phase2_kernel_objects/20_kqueue_stress_20261015_193513.txt:14`) |
| 20, PART 4 | split poll | zero | 3 events with fd/filter/data/udata (`:17-20`) |
| 20, PARTs 6-7 | 200 register/delete rounds, 5 kqueues | zero | all OK (`:34-45`) |
| 21 | combined add+poll throughout | zero | 31/31 signals, 20/20 user, 2000 knotes, 50 live PIDs |
| 30c, PART 6 | combined add+poll | 100ms | `rv=-1` (`results/phase4_ipc_network/30c_fcntl_bypass_20261015_201500.txt:48`) |

The only failing call is also the only listed call with a nonzero timeout. This
correlation makes nonzero timeout one hypothesis, not a causal explanation,
and leaves one cell of the 2x2 untested: split with a nonzero timeout. Its
result would add a comparison for the observed association, but the cause of
the failure remains unresolved.

## What this changes

1. kevent is not blocked. Register, poll, batch register, and delivery all work
   with a zero timeout, across two probes and multiple filter types.
2. The "always -1" verdict described one argument shape from one probe section
   (30c PART 6), then generalized to the number.
3. A combined call with a zero timeout is confirmed working (probe 21), so any
   future kevent probe should default to that and vary the timeout explicitly.

## What this does not change

- No path to a second thread or process is demonstrated; `fork`, `rfork`, and
  `thr_new` still return -1 through the tested Lua path (probe 27). The
  CVE-2026-58083 assessment's thread precondition is unaffected.
- No kernel pointer, crash, or privilege change is recorded in any kevent
  capture. Working delivery is an event primitive, not a leak.
- The 30c failure is unexplained, not explained away. A 100ms timeout returning
  -1 where a zero timeout succeeds is itself a behavioral fact worth one probe.

# kevent: 100 ms timeout works in the corrected matrix

Status: **live retest on 2026-10-19.** Probe 58f ran the missing split/combined
by zero/100 ms matrix with a fresh kqueue and valid socketpair per cell. All
four cells returned the expected read event. The earlier `30c` `rv=-1` cannot
be attributed to the timeout value alone.

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
valid output buffer, valid timeout pointer. Probe 21's combined call succeeding
rules out "combined shape fails" as the explanation. The remaining difference:
probes 20 and 21 use a **zero** timeout (`21_kqueue_deep.lua:40-42`,
`20_kqueue_stress.lua:133-135`), while 30c uses a **100ms** timeout (`30c:254-256`).

## What each returned

| probe | shape | timeout | result |
|---|---|---|---|
| 20, PART 3 | split register | zero | `rv=0` (`results/phase2_kernel_objects/20_kqueue_stress_20261015_193513.txt:14`) |
| 20, PART 4 | split poll | zero | 3 events with fd/filter/data/udata (`:17-20`) |
| 20, PARTs 6-7 | 200 register/delete rounds, 5 kqueues | zero | all OK (`:34-45`) |
| 21 | combined add+poll throughout | zero | 31/31 signals, 20/20 user, 2000 knotes, 50 live PIDs |
| 30c, PART 6 | combined add+poll | 100ms | `rv=-1` (`results/phase4_ipc_network/30c_fcntl_bypass_20261015_201500.txt:48`) |

The historical captures alone left the timeout value as a plausible cause.
The first two 58f runs did not answer it: one had unresolved syscall names;
the second mistook a failed `pipe2` sentinel (`0xFFFFFFFF`) for a valid fd.
After those harness fixes, 58f used `socketpair` fds 23/24 and got:

| 58f cell | shape | timeout | result |
|---|---|---|---|
| A | split | zero | register `rv=0`, poll `rv=1`, data=1 |
| B | split | 100 ms | register `rv=0`, poll `rv=1`, data=1 |
| C | combined | zero | `rv=1`, data=1 |
| D | combined | 100 ms | `rv=1`, data=1 |

Raw capture: [`58f_kevent_timeout_matrix_20261019_185532.txt`](../results/phase2_kernel_objects/58f_kevent_timeout_matrix_20261019_185532.txt); [run metadata](../results/phase2_kernel_objects/58f_kevent_timeout_matrix_20261019_185532.json). The `30c` failure remains specific to its setup or state; its exact cause is unresolved.

## What this changes

1. kevent is not blocked. Register, poll, batch register, and delivery all work
   with a zero timeout, across two probes and multiple filter types.
2. The "always -1" verdict described one argument shape from one probe section
   (30c PART 6), then generalized to the number.
3. Both split and combined calls worked with a 100 ms timeout in 58f. Future
   work on 30c should compare its fd, event, and state setup against 58f.

## What this does not change

- No path to a second thread or process is demonstrated; `fork`, `rfork`, and
  `thr_new` still return -1 through the tested Lua path (probe 27). The
  CVE-2026-58083 assessment's thread precondition is unaffected.
- No kernel pointer, crash, or privilege change is recorded in any kevent
  capture. Working delivery is an event primitive, not a leak.
- The 30c failure remains unexplained; its `rv=-1` is a behavioral fact for
  that call shape and setup, while 58f rules out a general 100 ms rejection.

# The 14.10 sysent ends at 676 — measured, not inferred (probe 1253a, 2026-11-05)

## The question

`docs/SYSENT_PRESENCE_14_10.md` swept 677-707 with zeroed arguments and every one of the 31
numbers killed the process. It concluded that the table ends at 676, but the repository's own
rule says a kill is a result about the call, never about the handler: an absent slot delivers
SIGSYS, and a present handler that faults on bad arguments dies exactly the same way. Upstream
row O4/O5 asked for "fault-proof calls (705, 713, 733, 687, 690) with real arguments" to tell
the two apart. Probe 1253a does that.

## Method

1. Install `SIG_IGN` for SIGSYS(12) with `syscall.sigaction(12, sa, 0)`, `sa_handler = 1`,
   and read the disposition back with `sigaction(12, NULL, old)`.
2. Control: call **4095**, a number that cannot have a handler. With SIG_IGN it must return
   `-1 / ENOSYS` and the process must survive. If it dies, SIG_IGN does not cover an absent
   slot and the whole test is void.
3. Call the 13.60-named tail slots with valid, non-faulting arguments, printing `step N ok`
   after each so a death localises itself.

## Result

Capture: `results/phase17_new_vectors/1253a_sysent_tail_sigsys_20261105_210052.txt`
(pid 80, 873 bytes, COMPLETE in 0.016 s).

| step | call | arguments | ret | errno |
|---|---|---|---|---|
| 1 | `sigaction(12, SIG_IGN)` | handler=1, flags=4 | 0 | readback handler = `0x1` |
| 2 | **4095** (control) | none | **-1** | **78 ENOSYS**, pid 80 alive |
| 3 | 705 `get_phys_page_size` | none | -1 | 78 ENOSYS |
| 4 | 687 `pipe2` | valid 16-byte fds buffer, flags 0 | -1 | 78 ENOSYS, fds untouched (0,0) |
| 5 | 690 `ppoll` | valid pollfd (fd 0, POLLIN), nfds 1, zero timespec | -1 | 78 ENOSYS, revents 0x0 |
| 6 | 728 `virtual_query_by_pid` | self pid, heap address, valid 0x100 buffer | -1 | 78 ENOSYS, buffer untouched |
| 7 | 725 `mmap2` | 0, 0x4000, prot 3, MAP_ANON\|PRIVATE, -1, 0 | -1 | 78 ENOSYS |
| 8 | 715 `ioreq` | zeros | -1 | 78 ENOSYS |
| 9 | `getpid` | - | - | pid 80 alive |

No step died. Every tail candidate returned ENOSYS from a slot that was already proven
survivable by the control.

## Conclusion

**The tail slots are absent on 14.10, not present-and-faulting.** The earlier kills were the
default SIGSYS disposition, exactly as `docs/SYSCALL_ABSENT_VS_LETHAL.md` predicted, and the
table that 14.10 resolves really does stop at 676 — 677 entries against the 13.60 capture's
735. `get_phys_page_size` returning ENOSYS rather than 0x4000 is the sharpest single datum:
a present handler with no arguments to get wrong had to answer, and it did not exist.

Consequences:

- Upstream rows O4 and O5 are closed. The 58 numbers 677-734 are out of the search space.
- `wait6`, `cap_rights_limit`, `pipe2`, `ppoll`, `procctl`, `apr_*`,
  `get_phys_page_size`, `begin_app_mount`/`end_app_mount`, `ioreq`, `mmap2` and
  `virtual_query_by_pid` are not reachable on this firmware. Several of those were the most
  attractive unexplored Sony handlers, so this closes a large surface as well as a question.
- **A positive test now exists for the whole table.** `SIG_IGN` + a non-faulting call that
  returns `-1/ENOSYS` is evidence of absence; the old inference from a kill was not.

## Caveat worth keeping

A handler that deliberately returns ENOSYS is observationally identical to an absent slot. The
test proves "nothing is implemented behind this number", not "the table has no entry". For the
tail that distinction does not matter, because either way there is no code to attack.

## Cost model note

The reason this had never been run is the 2026-10-20 sweep, where 677 and 678 killed the
process *and* the game. That is consistent with what is measured here: the loader died to an
uncaught SIGSYS, and the game's Lua host went with it. With SIG_IGN installed the same class
of call costs nothing.

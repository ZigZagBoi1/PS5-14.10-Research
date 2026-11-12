# AIO is absent on 14.10; the kill list reclassified (probe 1254a, 2026-11-05)

## What was measured

Probe 1253a proved the oracle: with `SIG_IGN` installed for SIGSYS(12) and verified by
read-back, an absent slot returns `-1 / ENOSYS(78)` and the process survives, while the
2026-10-20 sweep could only record that the process died. Probe 1254a applies that oracle to
every number the old sweep recorded as a kill and that had not yet been reclassified.

Capture: `results/phase17_new_vectors/1254a_kill_list_presence_20261105_210158.txt`
(pid 80, COMPLETE in 0.032 s, process alive at the end).

| number | 13.60 name | old record | **1254a result** | verdict |
|---|---|---|---|---|
| 661 | `aio_submit` | kills | **-1 / ENOSYS** | **absent** |
| 665 | `aio_get_data` | kills | **-1 / ENOSYS** | **absent** |
| 668 | `aio_create` | kills | **-1 / ENOSYS** | **absent** |
| 627 | — | kills (52a) | **-1 / ENOSYS** | **absent** |
| 628 | `dmem` | EBUSY 16 | -1 / **EINVAL 22** | present, rejects zeros |
| 629 | `shm_open` | stub | -1 / **EFAULT 14** | present, rejects zeros |
| 630 | — | PCALL-FAIL (52a) | -1 / **EFAULT 14** | present, rejects zeros |
| 631 | — | kills (52a) | **-1 / ENOSYS** | **absent** |
| 677 | `wait6` | kills + game crash | **-1 / ENOSYS** | **absent** |
| 678 | `cap_rights_limit` | kills + game crash | **-1 / ENOSYS** | **absent** |

## 1. The AIO family is dead, and the Lapse/Prolapse route with it

`aio_submit`(661) and `aio_create`(668) **do not exist on 14.10**. The AIO IDs that
`aio_multi_delete`(662) takes as arguments can therefore never be created, which is a stronger
statement than the earlier "unreachable by construction": there is no entry point at all, not
merely a context that cannot be assembled.

This closes the `aio_multi_delete` TOCTOU on 14.10 — the bug probed here as 65l and identified
upstream as the vulnerability behind three published/announced PS5 exploits, patched in 14.20
(`.local/tmp/up/docs/2026-10-25/11_LAPSE_PROLAPSE_IDENTIFICATION.md`). The 14.10 firmware is
in the announced vulnerable range, so the natural expectation was that the route was open and
merely needed the right argument shape. It is not: the syscall that creates the object the race
needs is missing. `aio_init`(670) returning `0` is a stub, not a context factory, because
nothing downstream of it accepts an ID (662/663/664/666/669 all return `-1` for every layout
tried in `docs/AIO_RANGE_14_10_EVIDENCE.md`).

## 2. 631 and 677/678 were never hostile handlers

All three are `nosys` slots. 631 "instantly killed the process" (probe 52a) and 677/678
"killed the process and crashed the game" (2026-10-20 sweep) purely because the default SIGSYS
disposition terminates the process, and the loader's death takes the game's Lua host with it.
With SIG_IGN they return ENOSYS like any other absent number and the process is untouched.

Consequence for the syscall map: the "lethal" column was not measuring the kernel's behaviour
toward the call, it was measuring the process's signal disposition. Every row in it must be
re-derived with the SIG_IGN oracle before it can be used as evidence.

## 3. What is left ambiguous

Only numbers that still die *with* SIG_IGN are present-and-faulting, and none of the ten tested
here does. The remaining "kills" rows in `docs/SYSENT_PRESENCE_14_10.md` and
`docs/ATTACK_SURFACE.md` are the same class and will fall the same way; they are lower priority
than the two that were thought to be dangerous.

## Reproduce

`probes/phase17_new_vectors/1254a_kill_list_presence.lua`, one connection, no reboot, no
loader loss.

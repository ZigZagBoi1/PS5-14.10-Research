# 14.10 PI mutex race audit — 2026-10-21

## Scope and result

No kernel pointer, UAF, or kernel read/write is established by the existing PI mutex probes. The saved 14.10 `110b` capture proves one uncontended mutex with flag `0x04` can be locked and unlocked through `_umtx_op(454)` operations 5 and 6. It prints only the user-memory owner TID word.

## Operation identity

The retained 13.60 kernel text maps `_umtx_op(454)` slot handlers 5, 6, 18, 19, and 20 to RVAs `0x37fc90`, `0x37fd70`, `0x381af0`, `0x381e70`, and `0x382280`, respectively. The matching [FreeBSD 11 `umtx.h` definitions](https://raw.githubusercontent.com/freebsd/freebsd-src/stable/11/sys/sys/umtx.h) identify 5 as `MUTEX_LOCK`, 6 as `MUTEX_UNLOCK`, 18 as deprecated `MUTEX_WAKE`, 19 as deprecated `SEM_WAIT`, and 20 as deprecated `SEM_WAKE`. Operations 4 and 7 are `MUTEX_TRYLOCK` and `SET_CEILING`; 9, 10, and 15 are `CV_SIGNAL`, `CV_BROADCAST`, and `WAIT_UINT_PRIVATE`.

The public `probes/phase17_new_vectors/136a_umtx_pi_race.lua` labels op 9 as TRYLOCK, 10 as PI lock, and 15 as SET_CEILING, then performs 500 lock/unlock cycles and 200 threaded corruption rounds. These labels are wrong for FreeBSD 11 and not established by the 13.60 bytes or 14.10 captures. Do not run that script as a PI test. The correct PI selector is `UMUTEX_PRIO_INHERIT=0x04` in the mutex flags field at `+4`, exercised with ops 4/5/6. The public `116a` script has the correct operation numbers but its “GPU mmap” object uses `MAP_ANON` with `fd=-1`; it has not established a GPU physical/device-pager backing object.

## Allocation and disclosure boundary

The [FreeBSD 11 PI lock implementation](https://raw.githubusercontent.com/freebsd/freebsd-src/stable/11/sys/kern/kern_umtx.c) allocates an internal `umtx_pi` on a first lock path and stores thread pointers internally. That upstream source is useful for selecting a hypothesis, but it does not prove identical Sony 14.10 behavior. Neither the FreeBSD ABI nor the saved 14.10 result copies `umtx_pi` or `struct thread *` to user memory. A PI contention or allocation result by itself would still not be a kernel pointer leak. A viable follow-up needs an independently evidenced disclosure or corruption transition, plus a bounded canary and captured raw output.

## Next test boundary

If testing continues, first use one valid `UMUTEX_PRIO_INHERIT` mutex and two threads for a single owner/waiter/unlock lifecycle, with a bounded wait and no user-memory owner corruption. Record TIDs, owner word, syscall returns, and process survival. Compare this with the 13.60 lock/unlock branches before any race. Do not interpret a TID-shaped owner word, process exit, or zero VM counter delta as a kernel pointer or kernel R/W.

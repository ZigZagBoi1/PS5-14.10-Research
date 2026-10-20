# An absent syscall slot terminates the caller (14.10)

## The measurement

`make_syscall(4095)` with six zero `uint64` arguments terminated the process inside the
call. 4095 is past the end of any sysent table this kernel can have, so no handler exists
for it.

Capture: `results/phase17_new_vectors/173a_unimplemented_syscall_slot_20261020_184436.txt`,
probe `probes/phase17_new_vectors/173a_unimplemented_syscall_slot.lua`.

## Why this matters for every earlier "lethal" verdict

A real FreeBSD stub returns `ENOSYS`; it cannot terminate its caller. The numbers that have
killed this process are:

| syscall | what it is | why the slot is plausible absent |
|---|---|---|
| 307 | `kldnext` | host-side module loader, meaningless on a console |
| 308 | `kldstat` | same |
| 337 | `kldsym` | same |
| 570 | `sysctlbyname` | the console keeps `sysctl` (202) but not the by-name entry |
| 661 | AIO submit | AIO compiled out |
| 665 | `nosys` stub in the 13.60 capture | literally labeled absent there |
| 668 | `nosys` stub in the 13.60 capture | same |
| 4095 | past the end of the table | absent by construction |

One rule explains all eight: a slot that is not present terminates the process. The
alternative — eight unrelated handlers each choosing to kill a caller that a normal kernel
would answer with `ENOSYS` — has no mechanism behind it.

## What the statuses mean now

- **KILLED_IN_CALL** — the slot is absent on 14.10. It is not a hostile handler and it is
  not exploit surface. The process death is the dispatcher's response to a missing entry.
- **RETURNED with `-1`** — the slot exists and rejected these arguments. This is a positive
  result: it proves the handler is present and reachable, which is where bug surface lives.
- **RETURNED with `0` or a value** — the slot exists and accepted the arguments.

The earlier reading treated `-1` as failure and a kill as the interesting case. It is the
other way round: `-1` means the handler is there, and a kill means it is not.

## Consequences for recorded verdicts

- The "AIO 661-670 hard wall" was 661 (and 665, 668) being absent, not hostile. The six
  numbers that returned `-1` — 662, 663, 664, 666, 667, 669 — are **present handlers** that
  rejected six zero arguments. That is the part of the range worth attacking with real
  structures, and it was written off as dead.
- `kldsym` (171a), `kldstat`/`kldnext` (56k4/56k5) and `sysctlbyname` (172a) are not
  "lethal Sony guards"; the console simply does not have them. No further argument shapes
  need testing on those numbers.
- The 13.60/14.10 "stub-path divergence" question disappears: 665 and 668 are absent in both.

## Rule for future sweeps

Before calling any number hostile, check whether it is absent: a call that returns anything
at all proves presence, and presence is required for a handler to be exploitable. A sweep
record whose only evidence is a kill carries no information about the handler, because
there is none.

## Present but gated: 662-669 (174a, 175a, 2026-10-20)

The six surviving numbers in 661-670 are present, and 162 calls say so:

- `174a` gave 662, 663, 664, 666, 667 and 669 a zeroed 0x400 page in `RDI` and `0x400` in
  `RSI`. All six returned `-1` and wrote nothing.
- `175a` swept selectors 0-8 in each of the first three argument positions, 27 calls per
  number, 162 in total. Every call returned `-1`.

Rejection is therefore independent of argument layout and of the buffer. The remaining
explanation is a state gate: an AIO context must exist, and the number that would create
one (661) is an absent slot. The range is unreachable by construction, which is a stronger
statement than "returns -1".

`175a`'s first run printed 162 "hits" because the probe compared the return against the Lua
number `-1` while `get_hi_lo` returns the low dword unsigned (`4294967295`). The comparison
now uses `0xFFFFFFFF`; the corrected run is the one recorded here.

## The death is process-wide, so the map costs a relaunch per gap (176a, 2026-10-20)

`176a` spawned a `thr_create` child with `RAX = 4095` at `syscall_address`, parked on a
`jmp $` slot, and busylooped the main thread on `getpid`. The capture ends at
`[1] spawning thread RAX=4095`: the print that follows `thr_create` never ran, so the child's
absent-slot call took the whole process with it.

The killer is not confined to the calling thread, which means a child thread cannot be used
to probe slots cheaply. Mapping an absent number always costs one game relaunch: the sweep
stops there, and the numbers after it need a fresh process.

## Correction: the game restarts the loader by itself (2026-10-20)

Earlier entries said an absent slot costs a game relaunch. It does not. A kill still takes
the whole process, but the game brings the loader straight back:

    before: PID 292  SW 0x807584B57
    call 4095 (absent)  -> connection dropped
    waited 9.31s        -> port 9026 accepting again
    after:  PID 299  SW 0x818C90B57

A new pid and a new module base, so this is a fresh process rather than a surviving one, and
nobody touched the console. The same thing happened during the 572-600 sweep: numbers 573, 589,
590 and 597 killed the process and the sweep continued without help, because
`--wait-for-loader` simply waited about nine seconds.

The relaunch prompts in the earlier entries were a measurement artefact: the sweeps aborted on
the first `CONNECT_FAILED` and never sat long enough to observe the recovery. The lesson is
that "the port refused" is not "the console needs a human" - poll before concluding.

## Not every kill recovers in nine seconds (2026-10-20)

The nine-second restart above is what happens when the loader process dies and the game
is still running. Some low numbers take more than the process with them:

    sys 1  exit        -> port refused, still down after 150s
    sys 8  compat.creat -> port refused, still down after 150s
    sys 9  munmap      -> port refused, still down after 240s (sweep of 9-537 aborted there)

Against 4095, which only ends the loader, the wait was 9.31s every time. The difference is
consistent with `exit` and the two copies that fault on a null argument doing more than
ending a thread: they end the game, so nothing is left to spawn a new loader. Treat a kill
that outlives four minutes as needing a human, and keep `--wait-for-loader` as the fast path
for the loader-only case rather than a guarantee.

## A positive return is the strongest evidence (2026-10-20)

The sweep ran 104-537 and 238 of the 328 numbers it reached returned something. Most of those
returned the all-ones value the loader prints as `-1`, but six returned a small positive number:
`125` -> 4, `141` -> 22, `310` -> 54, `330` -> 1, `362` -> 22 and `429` -> 14. Those are FreeBSD
errno values (EINTR, EINVAL, ECONNRESET, EPERM, EFAULT), which the kernel returns in `RAX` on
the error path; libc translates them to `-1` for ordinary programs, and a direct `syscall`
instruction sees the number itself.

That makes the three readings distinguishable for the first time:

| Return | What it shows |
|---|---|
| a positive errno | the handler ran, parsed the arguments and rejected them |
| `0` | the handler ran and accepted six zeros |
| `-1` | the handler refused, or Sony's filter refused before it; the sweep cannot separate the two |
| nothing | the loader died or stopped answering; says nothing about the handler |

Capture `results/phase15_native_sysent/syscall_isolation_sweep_20261020_213026.json`.

## The port coming back is not the loader coming back (2026-10-20)

Syscall 94 is labelled with the shared `nosys` stub in the 13.60 capture, and the 10-537 sweep
stopped on it: two probes connected, sent and received nothing, then the port refused
connections. A second run did the same at 95. That looked like a parked thread on a syscall
that should not be able to park anything.

`probes/phase17_new_vectors/188a_sys94_repeat.lua` (capture
`results/phase17_new_vectors/188a_sys94_repeat_20261020_210214.txt`) on a fresh loader settles
it. Three rounds of `(0,0,0,0,0,0)`, then fds 1, 2, 0 and 3, then `0x1000` in every slot, with
`getpid` between every call: every 94 call returns `-1`, every `getpid` after it returns
`0x334`, and the script reaches its last line. 94 neither parks nor kills; it refuses.

What did happen is a loader state the wait could not see. After 93's kill the listener accepted
again while the Lua thread never answered: probes were accepted, produced no output at all, and
the console stayed in that state for minutes across several sends. Only a relaunch cleared it.

`loader_is_up()` checks the socket, `loader_answers()` checks that a `print` comes back, and
both drivers now resume only on the second (`c9865fb`). A listener without a thread therefore
reaches a relaunch prompt instead of being swept into. The cost is that this state cannot be
waited out: the sweep stops with the loader open but silent.

## A kill does not prove the slot is absent (2026-10-20)

The rule above was written after 4095 showed that an unimplemented slot kills the process. It
is a one-way implication and it was read as two: an absent slot kills, therefore a kill means
an absent slot. The 601-660 sweep supplies the counterexample.

`622 ipmimgr_call` kills the process when called with six zero arguments. It cannot be absent:
`55c` called it through `make_syscall(622)` with `(cmd, 0, buf, buf, 0x100)` for 400+ command
values and got `ret=0` with `buf[0]=0x800E0001` every time. So a present handler took the
process down on zeros and worked on a real request.

The same ambiguity covers every "absent" reading taken from a zero-argument sweep: 561
`suspend_process`, 562 `resume_process`, 573 `mdbg_call`, 589 `dynlib_dlopen`, 590
`dynlib_dlclose`, 597 `dynlib_prepare_dlclose`, 609, 614, 621, 631, 650, 651 - and 661, 665,
668. All of them have a real handler RVA in the 13.60 capture (`docs/sysent-names-13.60.csv`),
none is the `nosys` stub at `0x265760`.

What survives: 4095 has no handler in any version and kills, so a kill is what an absent slot
looks like. What does not survive: concluding absence from a kill. The honest status is
"kills with zeros", and the follow-up is a probe with plausible arguments - a path string for
`dynlib_dlopen`, a pid for `suspend_process`, a command for `mdbg_call`.

The distinction matters for exploit work in both directions. A kill was being filed as "no
handler, nothing here", which discards the four AIO handlers and every dlopen-style call
without looking. And a `-1` was being read as "dead", when it means the opposite: the handler
ran and checked its arguments, which is the more interesting of the two answers.

## What the tail sweep adds (2026-10-20)

The 677-734 sweep is the first block where every number kills: 677 through 707, thirty-one
in a row, then the loader took more than two minutes to return. Thirty-one consecutive kills
is not thirty-one hostile handlers - the parsimonious reading is that those numbers are past
the end of the table, which is the same shape as 4095.

So there are three readings a kill can have and observation alone cannot separate them:

1. the slot is not implemented (4095, and 677+);
2. the slot is implemented and the zero arguments fault it (622 returns `0` to a real request);
3. the slot is implemented and the kernel kills the caller on purpose.

Case 3 is not hypothetical for this platform: a console kernel that kills on unimplemented
numbers is doing exactly that, and the same policy applied to a privileged call would look
identical from the outside. The practical consequence is the same for all three: a kill is a
result about the *call*, never a result about the *handler*.

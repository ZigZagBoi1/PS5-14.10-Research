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

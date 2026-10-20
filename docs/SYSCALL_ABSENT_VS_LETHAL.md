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

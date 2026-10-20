# Sysent presence map (14.10)

A kill means the slot is absent (`docs/SYSCALL_ABSENT_VS_LETHAL.md`), so a sweep that
records the return value also records which handlers exist. `-1` is a positive result: the
handler ran and rejected six zero arguments.

Every entry below comes from `tools/syscall_isolation_sweep.py` with six zero `uint64`
arguments, one connection per number.

## Measured

| range | present | absent |
|---|---|---|
| 538-560 | all 23 (`548` returns `0`, the rest `-1`) | none |
| 561-600 | not yet measured | 561, 562 |
| 661-670 | 662, 663, 664, 666, 667, 669 (`-1`), 670 (`0`) | 661, 665, 668 |
| host facilities | none | 307 (`kldnext`), 308 (`kldstat`), 337 (`kldsym`), 570 (`sysctlbyname`) |
| past the table | none | 4095 |

Captures: `results/phase15_native_sysent/syscall_isolation_sweep_20261020_185359.txt`
(538-560), `..._185415.txt` (561 stopped the sweep), `..._190003.txt` (562 stopped the
next one — 561 and 562 are both absent, so each costs a relaunch).

## How to read it

- Present handlers are the only ones that can contain a bug worth reaching, and a `-1`
  means the handler is there but gated on arguments, credentials or state.
- The gate is the interesting part. 662-669 reject every argument layout tried (162 calls)
  because the context they need can never exist (`661` is absent). 561 and the host
  facilities cannot be called at all.
- An absent number costs a relaunch to discover, because the kill takes the whole process.
  Sweep in ascending order and stop at the first kill keeps that cost to one relaunch per
  absent slot.

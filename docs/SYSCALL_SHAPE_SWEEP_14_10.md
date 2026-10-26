# Shape Sweep Over Every Reachable Syscall (14.10)

Date: 2026-10-24. Console: firmware 14.10, loader on TCP 9026.
Driver: `tools/fuzz_shapes_sweep.py`, one connection per number, resumable.

## Method

Each connection installs `SIG_IGN` for SIGSYS (syscall 416, signal 12) so an
absent slot returns `-1` instead of killing the process, maps a zeroed 16 KiB
page, and calls one syscall number with six argument shapes:

| shape | arguments |
|---|---|
| `zeros` | `(0,0,0,0,0,0)` |
| `buf` | `(BUF,4096,0,0,0,0)` |
| `three` | `(BUF,16,BUF+2048,16,BUF+4096,16)` |
| `ones` | `(0xFFFFFFFF × 6)` |
| `counts` | `(BUF,1,2,3,4,5)` |
| `mixed` | `(1,BUF,2,BUF+1024,3,BUF+2048)` |

Every call prints its return value; a completed number prints `SWEEP-OK`.
The number that kills the process is therefore named by the last line it
printed. This is a shape sweep, not a fuzzer: it finds handlers that mishandle
degenerate arguments, not handlers that break on well-formed ones.

## Result: 145 numbers, one death

Numbers 532 through 676 were swept. Every number returned cleanly for all six
shapes **except 622**, which killed the process on the first shape,
`622(0,0,0,0,0,0)`.

622 is already known to be gated (`docs/ATTACK_SURFACE.md:180-235`), and the
13.60 body explains the death: the wrapper reads `uap[0x10]` (argument 3) as a
status out-pointer, and checks `uap[0x20]` (argument 5) as a size. With
`arg5 > 0x40` it `copyout`s the `0x800E0001` status to `arg3`; with
`arg5 <= 0x40` it enters the dispatch, where command `0` dereferences
argument 2 without checking it. `622(cmd, 0, …)` with command 0 is therefore a
NULL dereference, which is what killed the sweep. It is a missing argument
check in a command path the process is not permitted to complete, not a
memory-safety bug.

```
8b19cd62 mov rax,[rsi+0x10]      ; arg3 = status out pointer
8b19cd66 mov r14d,[rsi]          ; arg1 = command
8b19cd69 mov r15d,[rsi+8]        ; arg2
8b19cd6d mov r13,[rsi+0x18]      ; arg4
8b19cd71 mov r12,[rsi+0x20]      ; arg5 = size
8b19cd85 cmp r12,0x40
8b19cd89 jbe 0x8b19cdf5          ; size <= 0x40 -> dispatch
8b19cd8b mov dword [rbp-0x74],0x800e0001
8b19cdb2 call copyout            ; size > 0x40 -> status only
```

## Numbers that return 0 for at least one degenerate shape

`587 588 596 643 657 659 662 664 666 675`

`656a` called each of these with three shapes and dumped the pages afterwards:

| number | what a zero return leaves behind |
|---|---|
| 587 | `p1+0x08 = 0x4000000000000000` (the single capability bit; matches probe 55e) |
| 588 | nothing |
| 596 | nothing, for all three shapes and all six sweep shapes |
| 643 | nothing (chicken switches, probe 55a) |
| 657 | nothing (blockpool is `-1` without a pool context) |
| 659 | `p1+0x00 = 0x1300000000`, `p1+0x08 = 0x14`, `p2+0x00 = 0x03` |
| 675 | nothing (global reset, probe 55e) |

No kernel-shaped value (high half in `0xFFFF8000`-`0xFFFFFFFF`) appeared in any
page for any call. The sweep adds no KASLR source.

## What this does and does not show

- Does show: no reachable number in 532-676 dies on degenerate arguments
  except 622's unchecked command-0 path, and none of them writes a kernel
  pointer into a caller page under those shapes.
- Does not show: that the handlers are safe for well-formed arguments. The
  shapes do not construct valid descriptors for the structured calls
  (`662`, `669`, `601`, `622`, `653`-`657`), which the dedicated probes cover.
- The sweep ran with SIGSYS ignored. A number that is absent on 14.10 returns
  `-1` here; `docs/SYSCALL_ABSENT_VS_LETHAL.md` explains why that is not proof
  of presence.

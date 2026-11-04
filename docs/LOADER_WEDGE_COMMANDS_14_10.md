# Commands that wedge the console: 637's middle range and 601 command 0x08

Two syscalls measured on 14.10 block forever inside the kernel, taking the whole Lua loader with
them. Both are reachable from a game process, both need no credential, and neither can be recovered
from on the console side. This note collects them, the detection pair that identifies them, and the
rule for probing command spaces that contain them.

## The two known wedges

| surface | shape | what happens |
|---|---|---|
| syscall `637` `set_phys_fmem_limit` | `637(pid=0, limit)` with `limit` in `[17, 0x40000000)` | never returns. `limit <= 16` is `EINVAL` (22) and `limit >= 0x40000000` returns 0, so the wedge sits in the middle of the argument range that otherwise works. First hit by `339a` on 2026-10-22 (capture ends after `637(0, 0x10) = -1`) and never diagnosed; measured again by `1162a`. See [the 637 note](PROC_LOCK_WEDGE_637_14_10.md). |
| syscall `601` `mdbg_service` | `601(0x08, buf, 0x4000, 0, 0, 0)` | never returns. Every command below it answers (`0x00` writes 8 bytes, `0x01/0x02/0x05/0x06` = -1, `0x07` = 0 and writes nothing), so the stop is localised exactly. Measured by `1170a`. |

| syscall `601` `mdbg_service` | `601(0x0C, buf, 0x4000, 0, 0, 0)` | parks like `0x08`: the capture stops after the previous command's line and `port_witness` answers `LOADER-STUCK`. Measured by `1172a`, which had already returned `0x09` = 0, `0x0A` = -1, `0x0B` = 0 with nothing written. |
| syscall `601` `mdbg_service` | `601(0x1C, mapped struct, mapped out-pointer, 0, 0, 0)` | kills the process: `port_witness` answers `LOADER-DEAD connect refused`. With `arg3 = 0` the same command only returns EFAULT(14), and it returns EFAULT even with a mapped zeroed struct, so it dereferences a field inside the struct. Measured 1194e, 2026-11-04 18:18. |
| syscall `601` `mdbg_service` | `601(0x27, buf, 0x4000, 0, 0, 0)` | kills the loader outright (connection refused afterwards, `LOADER-DEAD`), so it is a different failure from the three wedges above - a fault, not a park. The console itself stayed up: the user confirmed a plain loader relaunch was enough, so `0x27` kills the loader process without panicking the kernel. Measured by the first `601_arm_bruteforce` run after `0x28`..`0x2f` all returned -1. |

| syscall `600` `sandbox_path` | `600(buf, 0, 0, 0, 0)` with `buf` a mapped 0x200 buffer of `0xA5A5A5A5` | kills the process before it can print a single result line: `1197a` emitted only its banner and `port_witness` then answered `LOADER-DEAD connect refused`. `sandbox_path` takes a path string, so an unterminated 0xA5 buffer is very likely walked past its end. Retry the census with 600 excluded. Measured 2026-11-04 19:00. |

Both are *one call from userland*, they need no arguments that we cannot satisfy, and they are not
panics: the kernel stays alive and keeps completing TCP handshakes.

## Detecting one without guessing

```
python tools/send_probe.py --ip 192.168.1.121 --save probes/<phase>/<name>.lua
python tools/port_witness.py --ip 192.168.1.121
```

The pair is:

* `send_probe` ends with `Status: IDLE_TIMEOUT` and the capture has no `=== DONE` — it *stopped*.
* `port_witness` then prints **`LOADER-STUCK accepted, no reply`** with exit code 3.

`LOADER-DEAD connect refused` is the other case (process or console gone, loader gone with it);
`LOADER-STUCK` means the kernel accepted the socket and the loader process will never read it again.
Recovery is a manual relaunch — reboot if the relaunch cannot be done from the app. Nothing on the
console side resumes it, and probing further over the same connection is impossible because the Lua
VM is inside the blocked syscall.

Do not retry a wedge: it costs the same relaunch every time. Record it and move the sweep past it.

## Why the 601 wedge is more interesting than a DoS

`637`'s wedge is a lock cycle: it takes the process lock at `0x148` and calls `0x8aefaa10(p)` while
holding it, and that helper never returns. That is a bug we cannot use.

`601` command `0x08` blocks *without* the console dying, which is the signature of a **wait**: the
handler is parked on an event that only a debugger on the other end would post. Two consequences
worth recording:

1. If the wait is interruptible, then a second thread in the same process would stay in-kernel while
   the main thread continues — a parked thread inside the debug subsystem, holding whatever the wait
   holds. `thr_create(430)` is the only way we have to make a second thread (documented gates in
   `CLAUDE.md`), and the thread that enters the wait would end in `thr_exit(431)` only if the wait
   returned, so the cost of being wrong is one relaunch per attempt, exactly as measured. Not
   attempted; recorded as a hypothesis, not a result.
2. A debug *wait* implies a debug *event source*: some other command in the same table must be able
   to raise an event (attach, set state, break). If `0x08` is the wait half of that pair, the pair is
   a userland-usable synchronisation primitive between two processes, which is new machinery even
   without a memory primitive.

Neither is measured. What is measured is that the command blocks and that the console needs a
relaunch.

## Rule for probing a command space that contains blockers

`1170a` swept `601` ascending in one process and lost everything after `0x08`. The corrected
pattern, already used for the 622 arm (`tools/622_arm_bruteforce.py`), is now
`tools/601_arm_bruteforce.py`:

* one command per TCP connection, i.e. one fresh process per command;
* the command number is patched into a template probe's `CMD_SELECT` line, so the probe body is
  written and reviewed once;
* every result is checkpointed to `.local/601_cmd_state.json` **before** the next command runs;
* a `=== DONE` marker distinguishes "survived" from "died or blocked"; a missing marker plus
  `LOADER-STUCK` records the command as a blocker instead of losing the sweep;
* `--wait N` polls `port_witness` so a relaunch resumes the walk by itself.

Descending order (`0x2f` down to `0x09`) is the default: the low commands hold the two known
panicking ones (`0x03`/`0x04`), the known blocker (`0x08`), and the six already measured, so the
unknown tail is sampled first.

## Status

* `637`: closed as a hazard. The usable part of the range is `limit >= 0x40000000` (returns 0, writes
  a caller-chosen qword to `child+0x280`) and the cross-process path is bit-62 gated.
* `601`: eleven of `0x00..0x2f` measured, none returned text. The unprivileged log drain of
  `docs/HANDLER_SHAPE_HUNT_14_10.md` finding 1 is **still unfound**, and no capture in this repo has
  ever contained the string `mDBG:`. Resume at `0x09` with the driver above.

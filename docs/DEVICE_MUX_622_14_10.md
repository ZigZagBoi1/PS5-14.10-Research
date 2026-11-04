# Syscall 622 — the device multiplexer's argument block and gate map

Recovered from `results/kernel_handlers/decompiled/sys_622_deep.c` (RVA `0x7dcd40`,
`deep_622.bin` SHA256 `aa174830…db258` over a raw window; external bodies and data outside the
window are absent). Measurements are from probes 1039a, 1040a, 1072a and 1074a.

## The uap is read as a struct, not as six independent arguments

```c
uVar6 = *param_2;                       /* +0x00  u32   command          */
uVar2 = param_2[2];                     /* +0x08  u32                   */
uVar3 = *(undefined8 *)(param_2 + 4);   /* +0x10  u64   copyout target   */
uVar4 = *(undefined8 *)(param_2 + 6);   /* +0x18  u64                   */
uVar9 = *(ulong *)(param_2 + 8);        /* +0x20  u64   size             */
```

`param_2` is the syscall argument block, so this is the ordinary register encoding:

| syscall arg | offset | role |
|---|---|---|
| `arg0` | `+0x00` | command, read as `u32` |
| `arg1` | `+0x08` | `u32` operand |
| `arg2` | `+0x10` | **destination of the 4-byte status copyout** |
| `arg3` | `+0x18` | 64-bit operand |
| `arg4` | `+0x20` | size, must satisfy `size < 0x41` |

The whole body sits behind one size test:

```c
uVar8 = 0x800e0001;                 /* "no device context" default */
if (uVar9 < 0x41) { … dispatch … }
… tail: copyout(&local_7c /* uVar8 */, uVar3, 4)
```

So **any call with `arg4 >= 0x41` skips every arm and returns `0x800E0001`.** That is the
explanation for probe 55c's "400+ commands all return `0x800E0001`": it placed the command in
`arg1` (so `arg0` was 0) and did not control `arg4`, which landed at or above `0x41`. The sweep
measured the size gate, not the command space.

If the copyout does not return 4 **and** `*(int *)(td + 0x398) != 0`, the handler calls
`invalidInstructionException()` and does not return. Our process has that thread flag set, which
is why a failing arm kills rather than returning an error.

## Gate map below `0x134`

`uVar1 = command - 0x100`, and for `uVar1 < 0x34` two 64-bit masks select the predicate:

```c
if ((0xf8fff000000d5 >> (uVar1 & 0x3f) & 1) == 0) {
    if ((0x600000000000 >> (uVar1 & 0x3f) & 1) != 0)  -> func_0x00609110, then func_0x006090d0
} else                                                -> func_0x00609110, then func_0x00609040
```

Set bits give `uVar1 ∈ {0,2,4,6,7} ∪ {32…43,47} ∪ {48…51}` for the first mask and
`uVar1 ∈ {45,46}` for the second. A predicate returning 1 fails the gate and yields
`uVar8 = 0x8002004e` (EACCES). Every other command in `0x100..0x133` reaches the dispatch table
without a predicate.

## Dispatch

Four arms, each an indirect jump through a table of 32-bit offsets relative to the table base:

| condition | table |
|---|---|
| `command < 0x134` | `0x178057c` |
| `command - 0x201 < 0x71` | `0x1780a4c` |
| `command - 0x302 < 0x1f` | `0x1780c10` |
| `command - 0x400 < 0x94` | `0x1780c8c` |

All four tables lie above RVA `0x1780000`; the captured `docs/dumps_13.60/kernel_data.bin` covers
`0x1000000..0x1400000`, so **no arm body is recoverable locally**. Special cases handled inline:
`0x271`, `0x372`, `0x473` (predicate pair, then `func_0x0026d0a0`), `0x372` again
(`sub_007ddbb0` + `func_0x00c02050`), and `0x520` (`func_0x0029a570`).

## Measured

| call | result |
|---|---|
| `622(0x100, 0, buf, 0, 0)` | `rv=0`, status `0x8002004E` — predicate failure |
| `622(0x200, 0, buf, 0, 0)` | `rv=0`, status `0xFFFFFFFF` — no arm matches, default reached |
| `622(0x300, 0, buf, 0, 0)`, `0x301` | `rv=0`, status `0xFFFFFFFF` |
| `622(0x302, 0, buf, 0, 0)` | **process dies before the status prints** |
| `622(0x302, 0, buf, user_page, 0, 0)` | dies identically |
| `622(0x302, 0, buf, 0xFFFFFFFF9C800000, 0, 0)` | dies identically |
| `622(0x400, 0, buf, 0, 0)` | dies before the status prints (sweep stopped at its first entry) |

Because a user page and a mapped supervisor page in `arg3` die the same way, **`arg3` is not
dereferenced**; the death comes from the arm body or from the tail's `invalidInstructionException`
path. The `0x302` and `0x400` arms cannot be distinguished from "table entry points at a body
that needs a device context we do not have" without a kernel read.

## What would unlock it

`0x8002004E` proves the predicates exist and that our credential fails them. `probes/phase17_new_vectors/1068a_sys587_foreign_pid.lua`
shows pids 1-7 hold capability **bit 62**, which our process does not; the `0x100`-arm predicates
are the same family of checks. Nothing measured so far provides a device context, and every
node that might supply one either refuses `open()` or returns `-1` from `read()`
(`docs/DEVFS_NAMESPACE_14_10.md`).

## Why a brute sweep does not work

`probes/phase17_new_vectors/1074a_622_shape_sweep_full.lua` ordered the four arms cheapest-last
and died on **`0x400`, the first command of the first arm**, before any status printed. An arm's
table entry is a 32-bit self-relative offset; an entry for an unimplemented command presumably
resolves to something that does not execute as intended, and the tail then reaches
`invalidInstructionException()` because `td + 0x398` is set. One command per connection is the only
survivable form, and most of the ~460 commands in the four arms are expected to die, so the sweep
is not a viable discovery method without a kernel read.

## Measurement record

`results/phase17_new_vectors/1039a_622_shape_sweep_20261103_182423.txt`,
`…/1040a_622_cmd302_ptr_20261103_093743.txt`,
`…/1072a_622_cmd302_kaddr_20261104_100535.txt`,
`…/1074a_622_shape_sweep_full_20261104_100958.txt`.

## The slot-0 sweep, measured (1074a, 2026-11-04)

The sentinel had to be fixed twice before this sweep meant anything. `0xFFFFFFFFFFFFFFFF` is a
Lua number literal above 2^53; `uint64.lua:44-45` turns it into `h = 4294967296, l = 0`, so the
first version filled its buffer with zero and an exact all-ones test could never match.

The second failure was subtler and the first fix did not catch it: filling with all-ones makes
a write of `0xFFFFFFFF` **indistinguishable from no write**, and `0xFFFFFFFF` is exactly what the
neighbouring commands write. The capture from that version reports `C 200 rv=0
buf0=FFFFFFFF_FFFFFFFF` and cannot say whether the arm wrote or stayed silent. Re-filling with
`0xA5A5A5A5` and counting differing dwords over the whole buffer resolves it, and the answer
inverts the earlier reading.

With the sentinel proven (`[V] sentinel A5A5A5A5 dirty=0 CLEAN`), arm `0x134`-`0x200` measured as
**205 commands, every one `rv=0` with exactly one dword changed at offset `+0`, the new value
being `0xFFFFFFFF`** — `q0 = A5A5A5A5_FFFFFFFF`, `touched=1 first=+0` on all 205. That is the
shared *unrecognised command* arm writing its status, not silence.

| range | reply | buffer |
|---|---|---|
| `0x100`-`0x133` | `rv=0` | `0x8002004E` (EACCES) written at `+0` |
| `0x134`-`0x200` | `rv=0` | `0xFFFFFFFF` written at `+0`, nothing else touched |
| `0x201` | **kills the game** — the loader stopped accepting connections | - |
| `0x202` | **kills the game** on the first command of its arm | - |
| `0x300`, `0x301` | `rv=0` | `0xFFFFFFFF` written |
| `0x302` | dies at any shape | - |
| `0x303` | **kills the game** on the first command of its arm | - |
| `0x400` | dies on its first command | - |

The handler returns 0 through every one of these and reports the real outcome through the status
dword in slot 2, so `rv` alone carries no information — only the buffer does. That is why the
all-ones fill produced a confident wrong answer.

`0x201` and `0x303` are stronger failures than `0x302` and `0x400`: those killed the probe process and left
the loader serving, while `0x201` took the game down with it. The boundary between `0x200`
(returns the default status) and `0x201` is therefore the entrance to an arm that does not return.

**Conclusion: 622 is a status-dword writer and a process killer, not a read primitive.**

### The 0x302-0x320 arm

`0x302` kills at every shape tested (1039a with three arguments, 1040a with a user page, 1072a
with a mapped supervisor page). Its neighbour `0x303` — the first command of the `0x303`-`0x320`
arm — killed the game on its first call (`results/phase17_new_vectors/1074a_622_shape_sweep_full_20261104_102943.txt`
ends at `> 303`, 197 bytes, loader refusing afterwards). Two adjacent commands at the head of one
arm both take the game down, so this arm is not a surface: a command that does not return cannot
be interrogated.

The commands below the boundary are fully classified (`0x134`-`0x200`, default status) and the
ones already measured above it (`0x300`, `0x301`, same default status). The unmeasured remainder
is `0x202`-`0x271`, `0x304`-`0x320` and `0x401`-`0x493`; each killer costs a game restart, and
every arm that has returned at all has returned the same `0xFFFFFFFF` default, so the expected
yield does not cover the restarts. Recorded as a deliberate stop, not as coverage.

### Does a real handle save the 0x201 arm? No.

`probes/phase17_new_vectors/1078a_622_arm_handle.lua` (capture
`results/phase17_new_vectors/1078a_622_arm_handle_20261104_104443.txt`) created an evf
(`538(name,0x100)` -> `16901(g2/s517)`), ran a control `622(0x300, handle, out, 0, 0, 0)` which
returned `rv=0 out=0xFFFFFFFF`, then called `622(0x202, handle, out, 0, 0, 0)` and died with no
line after `[C] risky:`.

The control rules out a broken probe and shows the handle argument is ignored by the default arm,
so the death is inside the `0x201`-`0x271` arm body. Passing a live per-process object id does not
change it, which leaves two readings: the arm wants an object class other than the per-process
table's (the helper looks up `0x8001`), or the arm is fatal for every argument shape we can form.
Neither is testable from here — the class is chosen by kernel code we cannot see, and each guess
costs a game restart.

### The `0x201`-`0x271` arm is not uniformly fatal

`tools/622_arm_bruteforce.py` runs one command from that arm per connection and stops at the first
death, so a relaunch only costs the commands already tried. First descent (`0x271`, `0x261`,
`0x251`):

| command | rv | status dword | outcome |
|---|---|---|---|
| `0x271` | 0 | **`0x8002004E`** | survived |
| `0x261` | 0 | `0xFFFFFFFF` | survived |
| `0x251` | - | - | killed the game |

`0x8002004E` is EACCES - the predicate gate on the low-command mask (`0xf8fff000000d5` /
`0x600000000000`) - so at least one command in the arm reaches real logic instead of dying. The arm
is therefore a mix of gated, default and lethal commands, and the lethal ones are not its head.

Full descent of the arm so far (`0x271` down to `0x253`), one command per connection:

| range | rv | status dword | reading |
|---|---|---|---|
| `0x271` | 0 | `0x8002004E` | predicate gate reached, EACCES |
| `0x256`-`0x270` | 0 | `0xFFFFFFFF` | unrecognised-command path |
| `0x253`-`0x255` | **-1** | **untouched** | early return, no status write |
| `0x251`-`0x252` | - | - | kills the game |

Three distinct outcomes inside one jump-table arm, so the arm is data-dependent rather than a
single body: the `-1`/untouched group is the only shape that never writes the status dword, which
means it leaves the handler before the copyout tail at `LAB_007dcd8e`.

Second descent (`0x250` -> `0x244`) returned the default status on every command, and `0x243` killed
the game. Lethal commands recorded so far: `0x201`, `0x202`, `0x243`, `0x251`, `0x252`; early-return
group `0x253`-`0x255`; the only non-default status in the arm is `0x271` -> `0x8002004E`.

### The whole `0x201`-`0x271` arm, mapped (113 commands, one per connection)

| outcome | commands | count |
|---|---|---|
| kills the game | `0x201`, `0x202`, `0x232`, `0x241`, `0x242`, `0x243`, `0x251`, `0x252` | 8 |
| `rv=-1`, status untouched | `0x212`, `0x222`, `0x253`, `0x254`, `0x255` | 5 |
| `rv=0`, status `0x8002004E` (EACCES) | `0x271` | 1 |
| `rv=0`, status `0xFFFFFFFF` (default) | everything else | 99 |

Every surviving command writes only the 4-byte status dword. None of the 105 survivors touched any
other byte of a 0x100 buffer painted `0xA5A5A5A5`, so the arm carries no write primitive reachable
from this process - and per the provenance audit the stride index it would use is kernel state, not
attacker input.

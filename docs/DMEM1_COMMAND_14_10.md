# `/dev/dmem1`: one ioctl, `0x80108017`, panics the kernel

Status: measured on 14.10 on 2026-10-23. Captures under
`results/phase17_new_vectors/476a*`, `477*`, `478*`.

## The trigger

`_IOW(0x80, 0x17, 0x10)` = `0x80108017`, a single `ioctl` call on `/dev/dmem1`
opened `O_RDWR`, with a zeroed 0x100-byte argument page. Nothing else. The
process never returns, the screen goes black, the console powers off, and the
next boot runs the storage consistency check — a kernel panic.

`probes/phase17_new_vectors/478n_cmd17.lua` is that call and nothing else. The
sweep that found it ran each command of the group in its own connection;
`0x80108000` … `0x80108016` all returned `-1` and completed, `0x80108017`
stopped answering and took the console with it.

The contents of the argument do not matter. `478p` builds a coherent struct —
qword 0 = its own page address, dword at +8 = `0x10`, dword at +12 = 0, and
prints the readback `110BE420 00000003 00000010 00000000` — then issues the same
command. The console panicked again with the identical signature: the capture
(`results/phase17_new_vectors/478p_dmem1_cmd17_padded_20261023_154002.txt`,
8818 bytes) ends at that readback, the client saw nothing for 30 s, and the
console went black and powered off. This matches 13.60, where the callee
overwrites `rdi`/`rsi` before `ud2` and the three argument words are never read.

## What 13.60 says

`0x80108017` has exactly one call site in the 13.60 text
(`docs/dumps_13.60/kernel_text.bin`), in the dmem dispatch at `0x3d1ec9`:

```
3d20ff  mov  eax, 0x80108017
3d2104  cmp  rbx, rax
3d2107  jne  0x3d2635            ; EINVAL path
3d210d  mov  rdi, [r14]          ; argument +0x0
3d2110  mov  esi, [r14+8]        ; argument +0x8
3d2114  mov  edx, [r14+0xc]      ; argument +0xc
3d211b  call 0x3f4c60
```

and `0x3f4c60` is a straight-line stub with no branch:

```
3f4c60  push rbp / mov rbp, rsp
3f4c64  call 0x7f1950            ; timestamp (rdmsr 0x1dd)
3f4c69  lea  rdi, [rip-0x10]
3f4c70  call 0x7f1810            ; timestamp (rdmsr 0x1dd/0x1de)
3f4c75  lea  rsi, [rip+0xf07ad8] ; format string
3f4c7c  mov  edi, 0x2f
3f4c81  xor  eax, eax
3f4c83  call 0xc9aa10            ; variadic print (saves rdx/rcx/r8/r9)
3f4c88  ud2
```

The three values the dispatcher passes are dead: the stub overwrites `rdi` and
`rsi` before the print. So on 13.60 this command is an unimplemented one whose
handler is `panic`, and its argument cannot change the outcome.

That matches the 14.10 measurement: the same all-zero argument that every other
command in the group accepts or refuses is fatal for this one.

## The earlier "pair" reading is withdrawn

477b walks the group in one connection and its capture ends mid-line at
`[13] ret=-`, which was read as the killer being `0x80108013` and needing a
`0x80108012` prefix. Both were wrong, and the mechanisms are worth recording:

- **The truncation is buffered output.** 477b dies at `0x17`, four iterations
  after `0x13`; the loader's partial last line is whatever had been flushed, not
  the command that killed it. `478m` replays 477b byte-for-byte up to and
  including the `[13]` line — process completes.
- **`0x80108013` is inert.** `478b` (four argument shapes), `478f` (200 tight
  calls), `478g` (page dumped after every call) and `478m` all return `-1` with
  nothing written. `478a` also tried non-zero structs `{page,0x10,0}`,
  `{page,0x1000,0}`, `{0x150000000,0x10,0}` and `{page+0x40,0x10,1}` — all `-1`,
  no damage.
- **The prefix arming theory is dead.** `478i`'s ladder, `478j`/`478k`'s
  fresh-process rungs `0x00`…`0x12` followed by `0x13`, and `478d`'s 19
  interleaved pairs all survive. Nothing the prefix does matters, because the
  prefix was never the cause.

The lesson is mechanical: a capture cut mid-line names the last command whose
output reached the socket, not the command that faulted. Only one command per
connection settles it.

## The rest of the group

`0x4008800A` = `_IOR(0x80,0x0A,8)` is the readable half (`477a`):

| node | ret | bytes |
|---|---|---|
| `/dev/dmem1` | `0` | `50 00 00 00 00 00 00 01` = `0x0000000150000000`, constant over three page fills and three repeats |
| `/dev/dmem2` | `0` | zeros |
| `/dev/dmem0` | `-1` | page untouched |

The value is not in the 674-region VM map and cannot be dereferenced from the
process.

## A read-only handle blocks instead of panicking

`480c` opens `/dev/dmem1` `O_RDONLY` — which succeeds as fd 22 — and issues the
same `0x80108017`. The call never returns:

| run | wait | result |
|---|---|---|
| 1 | 30 s | `[1] open(...)=22`, `[2] calling …`, then nothing |
| 2 | 180 s | identical; still nothing after 180 s |

The wait is not the process being wedged. While the first run was blocking, a
plain `print` probe ran on a fresh connection in 16 ms, so the loader was still
serving and the console was still up. The game did not panic at the call.

The console went down later anyway. Both runs left a call outstanding; a few
minutes after the second one, TCP 9026 stopped answering at all (connect
timeout, not refused) and stayed that way. `480d`, which would have asked the
same question of `/dev/dmem0`, could not run.

So the command has three outcomes, all reachable from the game process:

| node | open mode | outcome |
|---|---|---|
| `/dev/dmem1` | `O_RDWR` | panic within a second — black screen, power off, storage check |
| `/dev/dmem1` | `O_RDONLY` | never returns; console alive for minutes, then goes down |
| `/dev/dmem2` | `O_RDWR` | never returns; console alive for minutes, then goes down |

Each of these ended in the same observed death: black screen, the console
powers itself off, and the next boot runs the storage check. Only the delay
differs, so the read-only and `dmem2` paths are the same panic reached later,
not a hang.

`/dev/dmem0` does not share the dispatcher. `480d` opens it (`fd 22`) and the
same command returns `-1` immediately — 78 ms, capture intact. That matches the
readable half, which `dmem0` also refuses: the node is a different cdev from
`dmem1`/`dmem2`.

## The same command on `/dev/dmem2` blocks

`tools/ioctl_isolation_sweep.py --device /dev/dmem2 --commands 0x17` connects,
sends, and then receives nothing at all: the connection stops answering while
the console stays up. A follow-up connection is accepted by the kernel and also
executes nothing, so the loader thread is parked inside the call rather than
dead. Minutes later the console went black, powered itself off and ran the
storage check — the same panic as `dmem1`, delayed.

The open is not what waits: `probes/phase17_new_vectors/480b_dmem2_open_only.lua`
opens the node and ends, and completes in 16 ms with
`open(O_RDWR)=22`, `open(O_RDONLY)=23`. `480a`'s stage markers could not show
this because the loader buffers its output: only its 57-byte header arrived, so
a probe that blocks or panics loses every line after the last flush. The
practical rule is one connection per question, and a script that ends, which
flushes.

## The rest of the group needs a device address

`481a` (`probes/phase17_new_vectors/481a_dmem_arg_matrix.lua`) measured the
commands that are not stubs, on both nodes, with five argument shapes each.
`0x4008800A` answers `0` for every shape. `0x80108002`, `0x80108015` and
`0xC010801A` answer `0` **only** when the whole argument page is zero, and `-1`
as soon as q0 holds a heap page. `0x80108006`, `0xC030801E`, `0x40048023` and
`0x80048022` answer `-1` for every shape tested.

The 13.60 body at `0x3d2213` explains the split: q0 is accepted only when
`q0 + 0xffffffdb00000000 < 0x58000001`, i.e. q0 in
`[0x2500000000, 0x2558000001)`, and the callee `0x3c4e40` additionally requires
q0 and q1 to be 16 KB aligned with q1 non-zero. The zero-argument success is the
empty range: `min(0x5000000000 - 0, 0) == 0`, so nothing is walked.

That callee is a range walk over a `vm_map` rooted at `[ctx + 0x48]`, with
entries compared at `+0x48`/`+0x50`, lookup through `0x3c3ff0`, locks at
`0x4c6a00`/`0x4c6fa0`, and `0x6b7af0` for wakeups. The context is selected from
an 11-entry table of `0x138`-byte records by `(q0 - 0x2500000000) >> 27`, so the
command inserts a range into a **device address space**, not the caller's. Both
argument words are a device address and a length; no user pointer is involved.

## mmap can reach the window

`482b` walked all 316 regions of the process map (`sys 674`) and found none
intersecting the window; its own read of the unmapped window start ended that
run, so the region walk is the only result it produced.

`482c` then asked `mmap` for hints inside it. All were honoured: `0x2500000000`,
`0x2520000000`, `0x2550000000` and `0x2500400000` landed at or just above the
requested address, while an unhinted `mmap` landed at `0x3108D4000`. So both the
range test in the handler and the alignment rules in the callee can be satisfied
from a game process.

## `0x80108002` with a real window range takes the console down

Four runs, all with a legal 16 KB-aligned range, all on `/dev/dmem1`:

| probe | argument | what happened |
|---|---|---|
| `482d` | `{0x2500000000, 0x4000}` and three siblings | `0` — but the argument page sat outside the mapping that `mmap` actually placed (`0x2500140000`), so the writes were dropped and the kernel saw a zeroed argument: this is the empty-range no-op, not a window call |
| `482e` | `{0x2520000000, 0x4000}`, nothing mapped | console died at the call |
| `482f` | `{0x2500000000, 0x4000}`, placement not printed | console died at the call |
| `482g` | `{0x2500000000, 0x4000}`, placement printed as exactly `0x2500000000` | returned `0`, then the console died while the probe was still printing, before the next step |

The `482d` row is a correction: its `0`s came from an argument of zeros, which
is why it looked like a successful window call and why the mapped/unmapped
reading did not survive `482f`.

What the four runs establish: `0x80108002` returns `0` for an empty range and
does nothing, and for any legal non-empty range inside the window it takes the
console down — synchronously when the address is not mapped, and immediately
after a successful return when it is.

Not established: the faulting instruction, whether the mapped case dies inside
the device service or in a later walk, what backs the inserted range, and
whether a correct argument exists that the firmware accepts.

## Not established

- **Why the argument is ignored without crashing in the copy.** A coherent
  non-zero struct panics exactly like the zeroed one, but the 14.10 handler has
  not been disassembled, so the read that would fault on a bad pointer (if any)
  is unobserved.
- **Whether other nodes expose the same command.** `dmem2` shares the readable
  half; the write group has not been swept there.
- **What the read-only path waits on.** `O_RDONLY` never returns and does not
  panic at the call, but the console still goes down minutes later; the thread
  state and the object the call blocks against are unobserved.
- **Whether a retail game sees the node.** All of this ran inside the game
  process on this console; whether `/dev/dmem1` exists in the same form for
  every title or only for this environment is unobserved.
- **What the delayed path waits on before the panic fires.** The panic is the
  same one; why the read-only and `dmem2` calls reach it minutes late is
  unobserved.
- **The faulting instruction.** The blank screen, power-off and storage check
  say panic; 13.60 says `ud2`; the 14.10 instruction is unobserved.
- the faulting path behind `0x80108002` with a legal window range, and whether
  any argument makes it return without taking the console down;
- what backs a range inserted into the device map, and whether it is shared with
  the firmware service the gic command talks to;
- whether the device window accepts a mapping at every address in it, or only
  the ones tested (`0x2500000000`, `0x2520000000`, `0x2550000000`).

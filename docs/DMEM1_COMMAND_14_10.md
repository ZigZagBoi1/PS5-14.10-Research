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

## Not established

- **Whether the argument is truly ignored on 14.10.** 13.60's stub overwrites
  the registers, but the 14.10 handler has not been disassembled (no 14.10
  image exists here), so a non-zero argument has not been shown to be equally
  fatal. Only the all-zero page is measured.
- **Whether other nodes expose the same command.** `dmem2` shares the readable
  half; the write group has not been swept there.
- **Whether a non-`O_RDWR` open reaches it.** Every run used `O_RDWR`.
- **The faulting instruction.** The blank screen, power-off and storage check
  say panic; 13.60 says `ud2`; the 14.10 instruction is unobserved.

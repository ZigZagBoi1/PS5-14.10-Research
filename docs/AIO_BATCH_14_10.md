# The AIO batch entry works on 14.10

Syscall 661 (`aio_submit`) kills the process on every argument shape tried: two
in 54c/54f, and again with a complete `aiocb` and a real file descriptor in 266a.
That result was carried for three days as "AIO is dead" (`docs/ATTACK_SURFACE.md`
row 76, `CLAUDE.md` dead ends).

It was the wrong conclusion from the right measurement. 661 is one entry in the
family. 669 is another, and it accepts a *batch* of descriptors through a
different path. Called with the contract its 13.60 dossier names, 669 works,
662/664/666/662 drive a request to completion, and the bytes really move.

## The shape

The recovered contract (`results/kernel_handlers/analysis/sys_669_deep.md`) is
five slots:

```
669(cmd, user_reqs, count, class, user_ids)
```

- `cmd` selects the operation: **1 is a read, 2 is a write**, 3 and above are
  refused with `-1` at the entry. `0` is refused too, so the selector really is
  two values out of the range the dossier describes.
- `user_reqs` points at an array of descriptors, stride `0x28`:
  `+0x00` signed offset, `+0x08` byte count, `+0x10` destination/source pointer,
  `+0x18` result pointer, `+0x20` file descriptor, `+0x24` padding.
- `count` is 1..128 (0 and 129 both refuse).
- `class` is 1..3 (0 and 4 both refuse).
- `user_ids` receives one 32-bit identifier per submitted request.

All four permutations of the first four slots that move `cmd` out of position
return `-1`, so the order above is measured, not assumed.

## What a completed request looks like

Reading 16 bytes of `/dev/urandom` three times in one process (352f):

```
669(cmd=1) = 0   id=0x0209   664 state=0x3   data=A1D83E05 6BDBE557…  result=0x00000010
669(cmd=1) = 0   id=0x2209   664 state=0x3   data=29D90C63 D7CB2120…  result=0x00000010
669(cmd=1) = 0   id=0x4209   664 state=0x3   data=AC944EB5 965B78EC…  result=0x00000010
```

`result[0]` is the number of bytes transferred. The data is different on every
read, so the copy is real and not a stale buffer.

The identifier is a slot number with a generation tag: 24 requests issued
without deleting anything returned `0x4205, 0x0206, 0x0207 … 0x021C`, and after
deleting four and submitting four more, the same four slots came back with a
different high word (`0x4205 → 0x6205`, `0x0206 → 0x2206`). Polling a deleted
identifier afterwards returns `0` with the request's last state rather than
addressing whatever now owns the slot.

`664` reports `state = 0x3` for a completed request, and `0x10003` for the same
id on a second poll - the "first observation" flag the dossier describes.

## Failures are in the result word, not the return value

`669` returns `0` whether or not it actually queued anything. When the slot
table is exhausted the refusal appears only in `result[0]`:

```
[A] 16 bytes into a 4 KiB buffer      result=0x80020005
[B] 0x14000 bytes into a 4 KiB buffer result=0x80020005
[C] data = unmapped 0x1000            result=0x80020005
[D] data = 0xFFFF8000_00000000        result=0x80020005
```

This is why `352e` and `352g` look like "every destination is refused": a control
that had worked earlier also answers `0x80020005` there. Every later probe
submits a plain control immediately after each hostile case.

## The destination is range-checked

With a healthy queue (352j), each hostile case followed by a control that
succeeds:

| case | result word |
|---|---|
| `data = 0x1000`, not mapped | `0x8002000E` (EFAULT) |
| `data = 0xFFFF8000_00000000` | `0x8002000E` |
| `result = 0xFFFF8000_00000000` | nothing written to our buffer; control follows at `0x10` |

A kernel-half destination is refused exactly like an unmapped one, so the check
is a user-range test (`useracc`-style), not a page walk. There is no privileged
write through this path.

## The write path checks its source the same way

`/dev/null` cannot show this: its write routine discards the data without
touching the buffer, so a kernel-half source still reported `0x10` bytes moved.
A socketpair does consume the bytes, and there the check is visible (352n):

```
[A] write 16 bytes of ours        result=0x00000010   peer read 16: CCCCCCCC CCCCCCCC CCCCCCCC CCCCCCCC
[B] source = 0x1000 (unmapped)    result=0x8002000E   peer read -1
[C] source = 0xFFFF8000_00000000  result=0x8002000E   peer read -1
[D] write 16 bytes of ours        result=0x00000010   peer read 16: CCCCCCCC CCCCCCCC CCCCCCCC CCCCCCCC
```

An unmapped source and a kernel-half source are refused identically, and the
control after each still completes, so the refusal belongs to the case and not
to a spent queue. Both directions of the copy are range-checked.

(A file under `/savedata0` is not an option for this test: opening one for
writing returns `-1`.)

## The identifier generation is three bits, and it is checked

Cycling one slot through twenty submit/delete pairs shows the field above the
slot taking exactly eight values before repeating (352o):

```
0x2205  0x4205  0x6205  0x8205  0xA205  0xC205  0xE205  0x0205  0x2205 ...
```

So the generation is bits 13-15 and an identifier from eight requests ago is
byte-identical to a current one. That would matter if only the slot were used.
It is not: bumping the generation by one gives an identifier the kernel refuses
with `0x80020003`, both for delete and for poll, and the live request is still
there afterwards (352p).

```
[A] submit id=0xA205; delete 0xC205 (bumped) -> 0x80020003; poll 0xA205 -> state 0x3
[B] submit id=0x0206; poll   0x2206 (bumped) -> 0x80020003
[C] poll 0x0206 -> state 0x3; delete 0x0206 -> 0
```

The wrap is therefore an aliasing window, not an unchecked index: the caller has
to reproduce the exact identifier, and then it names the request that is really
in that slot.

## The byte count is not clamped to the buffer

Passing `count = 0x14000` with a 4 KiB destination killed the process: the
kernel wrote the whole requested count through the process heap and the loader
faulted (352i). The destination only has to be mapped; the caller is trusted to
size it. That is self-corruption inside our own address space, not a boundary
break, but it is worth knowing before passing large counts anywhere.

## Other targets through the same queue

`/dev/dmem0` opens, and a read queued through 669 comes back `0x80020013` - the
same refusal the node gives every other access path - while `/dev/zero` in the
same process completes normally (352o). The queue does not bypass a node's own
read routine.

## What this does not give

No pointer, no length confusion, no write outside the caller's own address
space, and no way to name a request that was not submitted by this process.
The surface is a working, validated file-I/O path.

What it does change is the record. The AIO family was written off because its
single-submit entry kills on touch. The batch entry has a different argument
path and runs, which means "661 kills" says nothing about 662-670, and the same
mistake is worth checking for elsewhere: an entry that dies on a shape is not a
family that does not exist.

## Reproducing

```
python tools/send_probe.py probes/phase17_new_vectors/352a_aio_batch.lua --ip <console>
python tools/send_probe.py probes/phase17_new_vectors/352f_aio_repeat.lua --ip <console>
python tools/send_probe.py probes/phase17_new_vectors/352h_aio_slots.lua --ip <console>
python tools/send_probe.py probes/phase17_new_vectors/352j_aio_hostile.lua --ip <console>
python tools/send_probe.py probes/phase17_new_vectors/352k_aio_commands.lua --ip <console>
```

Each probe runs on a fresh console process; requests left queued by one probe
make the next one answer `0x80020005` until the console relaunches.

## 661 is the nosys trampoline, not a hidden entry

Probe 353a settled why 661 killed: with SIGSYS ignored (`sigaction(12, SIG_IGN)`, syscall
416) the call returns `-1` instead of ending the process, and the 13.60 body for 661 is the
shared `nosys` trampoline that raises signal 12. So the single submit does not exist on this
firmware, 669 is the only way into the queue, and every earlier argument about "the path
that kills" was about an absent slot. See PR #99 and `docs/SYSCALL_ABSENT_VS_LETHAL.md`.

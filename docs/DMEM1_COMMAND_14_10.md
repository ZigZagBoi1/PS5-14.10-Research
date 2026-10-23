# `/dev/dmem1` command `0x80108013` powers the console off

Status: measured on 14.10 on 2026-10-23. Two consoles deaths from two runs.
Captures: `results/phase17_new_vectors/476a_unswept_node_sweep_20261023_150014.txt`
and `results/phase17_new_vectors/477b_dmem1_write_group_20261023_150640.txt`.

## What is established

A game process that opens `/dev/dmem1` and issues one ioctl —
`0x80108013`, `_IOW(0x80, 0x13, 0x10)`, a zeroed 16-byte argument — takes the
whole console down. TCP to 9026 stops answering (timeout, not refusal), the
screen goes black, and the next boot runs the storage check.

The command was found by the encoding sweep in `probes/phase17_new_vectors/476a_unswept_node_sweep.lua`.
That run completed `/dev/ajm` (three framework returns) and skipped
`/dev/encdec`, `/dev/uvd_dec` and `/dev/physhm0` (none open), then died inside
`/dev/dmem1` after the progress line `cmd=0x80107FFF`, so the lethal call was in
`[0x80108000, 0x8010BFFF)`.

`probes/phase17_new_vectors/477b_dmem1_write_group.lua` then walked group `0x80`
one command at a time, printing the number before the call. The capture ends:

```
[12] cmd=0x80108012
[12] ret=-1  page=00000000 00000000 00000000 00000000
[13] cmd=0x80108013
[13] ret=-
```

`0x00`–`0x12` all return `-1` and leave the argument page untouched. The call at
`0x13` never returned its line.

## The rest of the group

`0x4008800A` = `_IOR(0x80, 0x0A, 8)` is the readable half of the same driver
interface (`probes/phase17_new_vectors/477a_dmem1_read_command.lua`):

| node | ret | bytes |
|---|---|---|
| `/dev/dmem1` | `0` | `50 00 00 00 00 00 00 01` = `0x0000000150000000`, constant over repeats and independent of the page fill |
| `/dev/dmem2` | `0` | zeros |
| `/dev/dmem0` | `-1` | page untouched |

So the node reports a base value (`0x150000000`, 5.25 GiB) that is not in the
674-region VM map and cannot be dereferenced from the process.

## What 13.60 says

The 13.60 text contains a dispatch for this node family at `0x3d1ec9`. Its
comparison chain handles `0x4008800A` (branch `0x3d2391`: `call 0x3c52b0`, store
the qword at `[r14]`), `0x80108002`, `0x80108015`, `0x80108017` (branch
`0x3d210d`: `call 0x3f4c60([r14], [r14+8], [r14+0xc])`), `0x80188007`,
`0x80188008`, `0x8018801F`, `0x80188025`, `0xC010801A`, `0xC0108026`,
`0xC030801E`, `0x40048023` and `0x80048022`; an unmatched command falls to
`0x3d2635` with `r12d = 0x16` (`EINVAL`).

`0x80108013` does not appear anywhere in the 13.60 text, and no compare in that
dispatch selects it. On the 13.60 build it would take the `EINVAL` path. Its
handler in 14.10 is therefore either new or reachable only through a path the
13.60 dump does not contain.

## What is not established

- **The cause.** From outside, a kernel panic, a protection trip and a watchdog
  cut are indistinguishable: the console powers off in all three. The evidence
  says a single ioctl with a zeroed argument is sufficient; it does not name the
  faulting instruction.
- **The argument layout.** The command reads 16 bytes. Every other command in
  the group that takes 16 bytes reads a qword and two dwords, so
  `{u64 addr; u32 size; u32 flags}` is the plausible shape, but a zeroed struct
  dies before anything can be observed, and no non-zero shape has been tried.
- **Whether `dmem0` or `dmem2` accept the command.** `dmem2` answered the read
  command and `dmem0` refused it; neither has been given `0x80108013`.
- **Impact beyond the shutdown.** No memory is read or written by anything
  measured here.

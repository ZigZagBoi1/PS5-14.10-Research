# `/dev/dmem1`: `0x80108012` then `0x80108013` panics the kernel

Status: measured on 14.10 on 2026-10-23. Three console panics from three runs of
the identical file, with byte-identical captures. Captures under
`results/phase17_new_vectors/476a*`, `477*`, `478*`.

## What happens

`probes/phase17_new_vectors/477b_dmem1_write_group.lua` opens `/dev/dmem1`,
walks the IOC_IN group `0x80` one command at a time over a zeroed 0x100-byte
page, and prints the command number before the call and the result after it.
Three runs produced the same 1504 bytes, all ending:

```
[12] cmd=0x80108012
[12] ret=-1  page=00000000 00000000 00000000 00000000
[13] cmd=0x80108013
[13] ret=-
```

The line is cut in the middle of the result field, so the process died inside
its own output write, one syscall after the ioctl.

The console is gone with it: black screen, power off, storage consistency check
on the next boot. That is a kernel panic, not a killed game process.

`0x00`-`0x12` all return `-1` and leave the page untouched. `0x80108013` is
`_IOW(0x80, 0x13, 0x10)`.

## What does not reproduce it

| probe | shape | result |
|---|---|---|
| 478b | `0x80108013` alone, four shapes `{1,0x10}`, `{page,0}`, `{0,0x10}`, `{0,0}` | `-1` each, no damage |
| 478c | prefix `0x00`-`0x12` alone, then a read-command canary | all `-1`, canary still `0x150000000` |
| 478d | each prefix command followed by `0x13`, 19 pairs | all `-1`, no damage |
| 478e | 477a's nine-read sequence on `dmem1`/`dmem0`/`dmem2`, then `0x13` | `-1`, no damage |
| 478f | 200 tight `0x80108013` calls after a 200-call read control | both loops `-1` ×200, no damage |
| 478g | prefix with the whole 0x100-byte page dumped after every call, then `0x13` | 256 bytes zero throughout, `-1`, no damage |
| 478h | tight prefix, a ~0.1 s busy loop, then `0x13`, five rounds | `-1` ×5, no damage |

## What that leaves

The call is refused by the driver in every shape tested, including the exact
all-zero argument the fatal run used, and the prefix is harmless by itself. The
argument page carries no state: 478g dumps all 256 bytes after every prefix
command and they stay zero.

Rate is out (478f: 200 tight calls of the very command are refused), so the
death is not the driver falling behind.

What is left is a short-lived condition that the prefix — or its last command,
`0x80108012` — creates and that expires quickly, which `0x80108013` must arrive
inside. Every variant that puts anything between the two survives: 64 dword
writes in 478d, a busy loop in 478h, a full page dump in 478g. 477b has only a
print there, and dies 3/3.

`probes/phase17_new_vectors/478i_dmem1_ladder.lua` shortens the prefix from the
front — `0x12` then `0x13`, then `0x11..0x12` then `0x13`, and so on — to find
the shortest fatal sequence. If `0x80108012` then `0x80108013` dies, the fatal
pair is two ioctls and the prefix is irrelevant.

## The rest of the group

`0x4008800A` = `_IOR(0x80, 0x0A, 8)` is the readable half (`477a`):

| node | ret | bytes |
|---|---|---|
| `/dev/dmem1` | `0` | `50 00 00 00 00 00 00 01` = `0x0000000150000000`, constant over three page fills and three repeats |
| `/dev/dmem2` | `0` | zeros |
| `/dev/dmem0` | `-1` | page untouched |

The value is not in the 674-region VM map and cannot be dereferenced from the
process.

## What 13.60 says

The 13.60 text contains a dispatch for this node family at `0x3d1ec9`. Its
comparison chain handles `0x4008800A` (branch `0x3d2391`: `call 0x3c52b0`, store
the qword at `[r14]`), `0x80108002`, `0x80108015`, `0x80108017` (branch
`0x3d210d`: `call 0x3f4c60([r14], [r14+8], [r14+0xc])`), `0x80188007`,
`0x80188008`, `0x8018801F`, `0x80188025`, `0xC010801A`, `0xC0108026`,
`0xC030801E`, `0x40048023` and `0x80048022`; an unmatched command falls to
`0x3d2635` with `r12d = 0x16` (`EINVAL`).

`0x80108013` does not occur anywhere in the 13.60 text and no compare in that
dispatch selects it, so on 13.60 it would take the `EINVAL` path — which is what
14.10 returns whenever the call is made alone.

## Not established

- **The faulting instruction.** The console behaviour says kernel panic (black
  screen, power off, storage check on the next boot) and the truncation inside
  the process's own write syscall says the kernel died between the ioctl and
  that write. Neither says which instruction faulted.
- **Why `0x80108013` is refused alone but not after the prefix.** The driver has
  a state the prefix creates; nothing here reads it.
- **The argument layout.** `{u64 addr; u32 arg; u32 status}` is inferred from
  the sibling commands, not from a successful call.
- **Whether `dmem0`/`dmem2` behave the same.** Neither has had the burst.
- **Whether the trigger survives a firmware patch.** Nothing here is tested
  against another build.

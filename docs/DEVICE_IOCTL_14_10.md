# The device ioctl surface on 14.10

The syscall table is closed: 683 numbers measured, the table ends at 676, and
every family that creates a kernel object either has no name lookup, is
reference-counted, or kills the process when touched. A device driver is the
one other place where a game process hands a pointer to code that was written
to accept one, so this is where the search moved.

The question this round answers is narrow: **does any driver expose a command a
game process can call, and does that command do anything with our bytes?**

## What a game process can open

`docs/ATTACK_SURFACE.md` records the inventory from probes 259a-263a: 34 of the
76 nodes in `/dev` open, and the rest are refused at open time. Opening is
gated by credentials, not by path, so a refused node cannot be reached by
guessing another name - `273a` checked the obvious aliases for the update
devices (`pup_update0`, `pup_update`, `sbl_srv`, `encdec`, `uvd_dec`, `update`,
`upd`) and all of them return `-1` for both `O_RDONLY` and `O_RDWR`.

## How the commands are encoded

FreeBSD ioctl numbers pack four fields:

```
bits 30-31   direction   0x40000000 = out, 0x80000000 = in, 0xC0000000 = in/out
bits 16-29   argument length in bytes
bits  8-15   group
bits  0-7    command
```

The file layer answers any number whose command byte names one of its own
operations: `FIOCLEX` (`0x20006601`), `FIONCLEX` (`0x20006602`), `FIODTYPE`
(`0x4004667A`). These return `0` on every node, so they are not evidence of a
driver.

Everything else belongs to the driver's `d_ioctl`, and the driver compares the
whole 32-bit number against its table. A command declared with the wrong length
or direction is not recognised at all, so the search has to cover the space
rather than guess command numbers.

That is why the first sweeps missed two thirds of the table below: they fixed
the length field to `0, 4, 8, 0x10, 0x20, 0x40, 0x100`, and the graphics driver
declares commands at `0x18`, `0x28`, `0x30`, `0x48` and `0x888`.

## The sweeps

| probe | space | calls | result |
|---|---|---|---|
| 274a | `/dev/dce`, commands `0x0000..0xFFFF`, three argument shapes | 196 608 | none |
| 275a | `/dev/dce`, 5 directions x 9 lengths x `0x0000..0xFFFF` | 2 949 120 | 4 |
| 278a | 31 nodes, `0x0000..0xFFFF` | 2 031 616 | none |
| 279a | 10 nodes, 4 directions x 5 lengths x `0x0000..0xFFFF` | 1 310 720 per node | `/dev/gc` only |
| 280a | `/dev/gc` group `0x81`, 4 directions x 7 lengths | 7 168 | 20 |
| 284a | `/dev/gc` group `0x81`, lengths `0..0x7FF`, four directions | 2 097 152 | 22 |
| 286a | `/dev/gc` lengths `5..0x7FF` in/out and `0x800..0x3FFF` elsewhere | 11 533 056 | 25 total |

The 278a sweep is the important negative one: thirty-one nodes, the whole 16-bit
command space, and not one number outside the file layer answered. Whatever a
driver implements, it does not live in the low command numbers.

## `/dev/dce`

Four numbers answer the full 32-bit sweep, and `276a` separates them by calling
each on seven different descriptors:

| command | dce | other nodes | behaviour |
|---|---|---|---|
| `0x20006601` FIOCLEX | 0 | 0 | file layer |
| `0x20006602` FIONCLEX | 0 | 0 | file layer |
| `0x4004667A` FIODTYPE | 0 | 0 (device), -1 (socket) | file layer, zeroes the 4-byte out buffer |
| `0x80088209` | 0 | -1 everywhere else | driver |

`0x80088209` is the decoder's own command. `277a` measures its shape: it copies
in exactly 8 bytes (a null pointer, a kernel-shaped pointer and an unmapped user
pointer all return `-1`; a valid page returns `0`), the length must be exactly
8 (`0x80008209`, `0x80048209`, `0x80108209` and the `0x40`/`0xC0` direction
variants are all `-1`), and the content is ignored - zero, one, `0x1000`,
`0xFFFFFFFF` and a pointer to itself all return `0`. It is repeatable and has no
observable side effect.

It is recognised and inert: an 8-byte message with no reply.

## `/dev/gc`

The graphic-core driver is the only node with a command table. Twenty-five
commands answered across the whole sweep:

| command | length | writes |
|---|---|---|
| `0x40048135` | 4 | `[0] = 0x00000101` |
| `0x4004813A` | 4 | `[0] = 0`, `1` on a later run |
| `0x40088137` | 8 | zeros |
| `0x8004813C` | 4 | nothing |
| `0x80888123` | 0x888 | nothing |
| `0xC0048113` | 4 | `[0] = 3` |
| `0xC0048114` | 4 | nothing |
| `0xC0048115` | 4 | `[0] = 0` |
| `0xC0048116` | 4 | nothing |
| `0xC0048117` | 4 | nothing |
| `0xC004811D` | 4 | `0` in one run, `-1` in another |
| `0xC004811F` | 4 | `[0] = 0` |
| `0xC0048125` | 4 | does not return |
| `0xC004812E` | 4 | `[0] = 0` |
| `0xC0088101` | 8 | nothing |
| `0xC0088111` | 8 | nothing |
| `0xC008811B` | 8 | `[0] = 0x80000000`, `[4] = 0x0C` |
| `0xC0088133` | 8 | `[4] = 0x5C` |
| `0xC010810B` | 0x10 | `0x10` in four dwords |
| `0xC0108120` | 0x10 | `[0] = 0` |
| `0xC0108139` | 0x10 | `[0]`, `[8]`, `[0xC] = 0` |
| `0xC0188132` | 0x18 | `[0x10] = 0x5C` |
| `0xC0288130` | 0x28 | nothing |
| `0xC030811E` | 0x30 | nothing |
| `0xC0488131` | 0x48 | `[0x40] = 0x5C` |

Every one of them returns `-1` for a null pointer, so the argument is genuinely
read by the driver, and every one writes at most the length its command number
declares - measured across the whole page, not inferred from the number.

Three questions decide whether any of this is a primitive, and all three were
measured:

**Does the driver follow an address inside the struct?** `283a` sets the first
qword of the argument page to the address of a second user page and watches that
page. Nothing follows the pointer: all eighteen commands tested leave the
second page untouched.

**Does the content change what the driver does?** `285a` and `287a` call each
command with a `0xAA`-filled struct and with a zero-filled struct. The return
values and the written fields are identical, so the fields are not used as
values. `0x80888123`, the only command with a large input, behaves the same at
both contents and writes nothing back.

**Is the write bounded by the declared length?** Yes in every case, including
the four struct commands, whose writes land at `+0x10` and `+0x40` inside their
own structures.

## The one defect: a command that blocks

`0xC0048125` did not return in 281a or 282a, and in 284a it hung again. In 280a,
called before `0x80888123` had ever run, the same command returned `0`. The
argument bytes are not what decides it - 281a, 282a and 284a all passed a
`0xAA` page.

What the caller sees is not a dead process. The console keeps rendering, the
loader keeps accepting connections, and a later connection gets zero bytes
because the Lua thread is parked in the ioctl. Closing the app then fails: the
screen goes black for a few seconds and the system reports that the game went
wrong. So the process is healthy everywhere except the thread that entered the
driver, and the teardown of that thread faults.

That is a driver bug with a consequence we can reproduce on demand, and it is
the only kernel-side defect this round produced. It denies service; it does not
corrupt anything the caller can observe, and it hands back no address.

## What this means

No information leak: every value written back is a small constant - `0x101`,
`3`, `0x80000000`, `0x0C`, `0x5C`, `0x10`, `0` - and none of them changes
between calls in a way that would reveal a kernel or GPU address.

No dereference primitive: a driver that followed an address from our buffer
would show up in `283a` as a change in the watched page, and none did.

No overflow: the write length matches the declared length for all twenty-five
commands, and the four struct commands write inside their own structures.

The device surface is real and reachable - a game process can call twenty-five
graphics-driver commands with structures it controls, including one of 2184
bytes - but they are struct fillers. The driver copies in a fixed number of
bytes, ignores what they contain, and writes constants back.

This route is closed for the same reason the syscall families closed: it needs
a bug in code we cannot read. What would reopen it is a 14.10 kernel image, in
which the driver's `d_ioctl` table and its copyin sites could be audited
directly instead of probed from the outside.

## Reproduction

```bash
export PYTHONIOENCODING=utf-8
python tools/send_probe.py --save probes/phase17_new_vectors/273a_pup_device_reach.lua
python tools/send_probe.py --save probes/phase17_new_vectors/275a_dce_ioctl_encoding.lua
python tools/send_probe.py --save probes/phase17_new_vectors/278a_node_ioctl_sweep.lua
python tools/send_probe.py --save probes/phase17_new_vectors/280a_gc_command_table.lua
python tools/send_probe.py --save probes/phase17_new_vectors/286a_gc_sweep_remainder.lua
python tools/send_probe.py --save probes/phase17_new_vectors/287a_gc_struct_commands.lua
```

`sentinel` is the default address; pass `--ip` for a console on another host.
Each probe runs in one connection, and the loader process persists across
connections, so a probe that wedges the Lua thread ends the session for every
later probe until the game is relaunched.

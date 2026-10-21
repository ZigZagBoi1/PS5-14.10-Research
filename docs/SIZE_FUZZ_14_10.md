# Declared-size fuzz of the Sony handlers (574-660), 14.10

Question: does any handler of the `574`-`660` block copy more, or something other, than the
buffer its arguments describe? The earlier sweeps only measured whether a handler answered;
this one hands each handler a canary-filled page and a declared size, then counts what changed
inside that size and outside it.

Run: `python tools/bounds_fuzz.py --ps5-ip 192.168.1.121 --range 574-660 --layouts a1_buf_size
--sizes 0,0x100 --save`. 174 probes (87 numbers, two sizes, one layout: buffer in the second
argument, size in the third), 625 s. Capture `results/phase17_new_vectors/bounds_fuzz_20261020_223442.txt`,
journal `results/phase17_new_vectors/bounds_fuzz_coarse.jsonl`.

## Result

| Class | Count |
|---|---|
| returned without writing anything | 150 |
| killed the process | 20 (the ten numbers below) |
| wrote into the buffer | 4 (587, 601, 615, 638) |
| wrote a kernel-shaped qword | 0 |

## The four writers ignore the declared size

Each of them writes the same payload whether the size argument is `0` or `0x100`, so the
size is not a bound they honour:

| Syscall | Bytes written | First dwords | 13.60 name |
|---|---|---|---|
| 587 | 0x88 (34 dwords) | `0, 0, 0, 0x20000000` | `get_credential_metadata` |
| 601 | 8 | `0x100, 0` | `process_control` |
| 615 | 8 | `0xC42, 0` | `get_resident_fmem_count` |
| 638 | 8 | `0xE10, 0` | `utc_to_localtime` |

`587` is the one the earlier probe already knew about: a fixed 0x88-byte credential struct
whose only non-zero word is `0x20000000` at `+0x0C`. The other three write a single value and a
zero. All four write into the buffer the caller supplied, so what overflows is our own address
space.

That is the point worth stating plainly: a copyout that ignores the declared size is the right
*shape* for a kernel leak, and this fuzz would have flagged it, because it checks every changed
dword against the next one for a `0xFFFF8xxx_xxxxxxxx` shape. None of the four carries a
pointer, and none of the 150 silent handlers wrote anything at all.

## The ten numbers that die

`589`, `590`, `597`, `609`, `614`, `621`, `622`, `631`, `650`, `651` kill the process in both
sizes. That matches the zero-argument sweep, and `622` remains the exception that keeps the
reading honest: it kills here, yet probe 55c calls it with `(cmd, 0, buf, buf, 0x100)` and gets
`ret=0` with `buf[0]=0x800E0001` across 400+ commands. Dying inside a call is not evidence that
the slot is a stub.

## What is left unmeasured

Sizes above `0x1000` and the other two argument layouts were not run: four of 87 numbers write
anything, and none of them writes a pointer, so the remaining layouts can only find the same
struct in a different argument slot. The next pass on this driver should be aimed at a handler
whose output is variable length, not at this block.

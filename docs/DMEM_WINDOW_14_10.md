# `/dev/dmem0` — a writable device window whose low pages are reproduced with the same content on 14.10

Status as of 2026-11-09: **measured surface, not yet a primitive.** Every measured row below
carries its capture; the two rows that carry an interpretation rather than a measurement say so.
Nothing here reads or writes kernel memory.

## Why this exists

`docs/DEAD_ENDS.md` carries the line "GPU device mappings — all read/write paths dead
(376a-381a)", which came from probes that mapped the GPU *addresses* found in the sys
674 VM map and read them. Those mappings are execute-only-device pages and a read kills
the process. `/dev/dmem0` is a different object: it is a **character device whose
`mmap` installs ordinary writable pages**, and it was never exercised with a working
argument shape until now. 1395a found the shape by accident while looking for an offset
wrap, and 1396b-1397l characterised it.

## How to open and map it

```lua
local fd = mk(5)(uint64(str_addr("/dev/dmem0")), uint64(0x4002), ...)  -- O_RDWR|O_NONBLOCK? 0x4002
local va = mk(477)(uint64(0), uint64(0x1000), uint64(3), uint64(1), uint64(fd), uint64(offset))
```

`open` needs the path built with `write_byte` into an allocated buffer — passing a Lua
string to `uint64()` raises `uint64:new: invalid decimal string for uint64 (/dev/dmem0)`.

`prot = 3` is required for stores; `prot = 1` maps and reads but **a store into it kills
the process** (1397c). `flags = 1` (`MAP_SHARED`) works. 547 on the result reports
protection 3 over 4 KiB ranges.

## What the window is

| fact | value | capture |
|---|---|---|
| offsets that map | **0 … 0x11000FFFF, edge at 0x110010000** (bisected at 0x4000 in 1547a; `L in [0x110010000, 0x110011000)`), plus one 16 KiB rung at 0x1000000000 that maps read-only. The earlier "0 … 0x11FFFFFFF" and the 0x120000000 / 0x140000000 first-refusal figures were 256 MiB and 1 GiB grids — see §6 | 1397d, 1410a, 1411a, **1547a** |
| single-mapping length | up to 0x80000000 (2 GiB) | 1397d |
| rung size | 0x1000, contiguous: a marker at rung 0x2000 appears at a second mapping's +0x1000 | 1397e |
| populated pages in the first 1 MiB | 12 of 256: 0x000 (header), 0x001-0x004 (our markers), 0x00F, 0x011-0x016 | 1397f |
| populated 16 MiB rungs in 4 GiB | 1 of 256 (offset 0) | 1397f |
| holes | reading page 0x17000 faults even inside a mapping that spans it — the pager backs only populated pages | 1397g |
| descriptors | `/dev/dmem0` and `/dev/dmem1` are two descriptors on one backing store **within one process**: a store through dmem0 at offset 0x1000 is visible through a second dmem0 mapping and through dmem1; cross-process sharing is not measured | 1396b |
| `/dev/gc` | same two offsets map, every dword reads `FFFFFFFF`, a store reads back unchanged, page 0 all-FF | 1396b, 1397e |
| lifetime | the tested writes do not survive a pid change (markers written before a loader restart came back zero) and page 0x00F's word comes back as its original value; whether the backing is per process or re-initialised at each new process's first mapping is **not** measured, and no allocation-identity field was ever read | 1454a, 1455a |
| liveness | 0 of 23 pages changed their checksum across a 1.5 s `nanosleep` | 1397i |
| writability | page 0 and page 0x16 accept stores that survive 500 ms and are visible through a fresh mapping; the populated records are otherwise untouched | 1397j |

**The noun and the overlap (2026-11-10).** The rungs in the table above are `0x1000` **device byte
offsets**, not kernel pages — the kernel page is `0x4000` (`1544a`: one `0x40000` mmap is one 547
record and sixteen addresses at `0x4000` stride each read a distinct sentinel). Two consequences:

1. Counts written as "pages" ("12 of 256", "0 of 23 pages", "64 pages") are offset counts. The
   measurements stand; only the noun was wrong.
2. A `len = 0x1000` device mmap rounds up to a `0x4000` vm_map entry — measured, not assumed:
   `1441a` mapped device offset `0x01000000000` with `len 0x1000` at VA `0x311db8000` and its 547
   answered `w0=0x11DB8000 w8=0x11DBC000`, a span of `0x4000`
   (`results/phase36_realargs/1441a_mprotect_device_window_20261109_165212.txt` lines 3 and 10).
   So the mapping starting at device offset X covers device bytes `[X, X+0x4000)`, adjacent
   `0x1000` rungs overlap by `0xC000`, and they are not independent pages. That overlap is exactly
   why the "rung size" cross-read above works, and it means a probe that compares two `0x1000`
   rungs as if they were disjoint is comparing overlapping windows.

`mmap` of this device needs no capability beyond opening the node, and it returns writable
pages. Which kernel path writes the low pages is not identified; the surface is interesting
because it is memory a game process maps RW that it did not allocate and cannot otherwise read.

## What is in it

**Offset 0 — the header page.** Not a flat register array (1397d):

- `0x000`-`: C0012800 80000000 80000000 C0001200 00000000 C0055800 2EC47FC0 FFFFFFFF`
- `0x300`-`0x520`: triples such as `(C0017600, 00000216, FFFFFFFF)`
- `0x800`-`0xBB0`: **48** records, stride 0x14 (1397k — the last non-zero index is 47):
  `(C0038000, E0000C00, 0000000F, 00000100, N)` with N = 0, 0x400, 0x800 … 0xB400
- `0xBC0`-`0xFFF`: zero

**Offset 0xF000 — a Sony structure block** (1397g):

- `BEEB03FF 00000003 7E000280 5E000100 BF800000 F8001C0F 00000000 BF810000`, then ASCII
  `SbrO` / `hdr`
- at `0x103C0` the string **`COrbisMemory ONION`**
- from `0x11000` a stride-0x80 record array with a stable 32-byte body
  (`00000002 00000002 00000002 00000000 00000010 0000000F 00000002 03000000` /
  `00080001 000C011B 03100100 03180200 00200101 00240201 00280002 0010000F`), a run of
  `AFAFAFAF`, and counters `0210FD30, 0210FD32, 0210FD34…`
- at `0x10080` pairs `(00FD0060, 2), (00FD0070, 2) …` stepping 0x10

## What it is not

The 0x800 record table looks exactly like a page table — 48 descriptors of 0x400 bytes
whose base is the GPU-side address of this allocation — and it is **descriptive only**:

- rewriting `record[0].addr` from `C0038000` to `C0039000` and munmap/mmap changes nothing
  at window offset 0x000 (1397k);
- rewriting it to `0x00000000` and remapping still reads the original content (1397l);
- pointing `record[63]` at another chunk changes nothing at 0xFC00 (1397k).

So the table in the window is descriptive, not the pager's actual map.

## Open questions this creates

1. The record base `C0038000` is presumably the GPU-side address of the allocation. If
   so, a game process can now *learn the physical/GPU address of its own buffer* — an
   asset for any future primitive that takes an address (a physical copy, a GPU
   submission). Unverified: no independent measurement of that address exists.
2. Whether any kernel path re-reads the 0x800 table or the 0xF000 block after the first
   mapping. Nothing in the four steering experiments says it does, but nothing rules out
   a consumer on close, on GPU submission, or on a suspend/resume path.
3. What the 0xF000 block is. The `BEEB03FF` header and the `0x80`-stride records with
   `AFAFAFAF` padding look like GPU memory-management metadata, and the `ONION` name
   appears next to `UC ONION NV` / `WT ONION NV` strings in the 13.60 kernel data, which
   are GPU cache-attribute names.

## Capture table

| probe | capture | result |
|---|---|---|
| 1395a | `results/phase35_dead_end_reruns/1395a_dev_mmap_offset_wrap_20261109_141742.txt` | dmem0/dmem1 map at offsets 0 and 0x1000; reads the GPU register block |
| 1396b | `results/phase36_realargs/1396b_dev_map_writable_20261109_142603.txt` | store lands; dmem0 and dmem1 share one backing store |
| 1397b | `results/phase36_realargs/1397b_dmem_offset_ladder_20261109_142645.txt` | every offset to 0x10000000 maps with prot 1 and 3 |
| 1397c | `results/phase36_realargs/1397c_dmem_ladder_contents_20261109_142729.txt` | prot=1 store kills the process |
| 1397d | `results/phase36_realargs/1397d_dmem_extent_regs_20261109_142819.txt` | 4 GiB range, EACCES above; page 0 is a structured table |
| 1397e | `results/phase36_realargs/1397e_dmem_page0_liveness_20261109_142921.txt` | contiguous rungs; page 0 static |
| 1397f | `results/phase36_realargs/1397f_dmem_content_map_20261109_143000.txt` | 12 of 256 pages populated; 1 of 256 rungs |
| 1397g | `results/phase36_realargs/1397g_dmem_f000_dump_20261109_143115.txt` | the 0xF000 block and the ONION string |
| 1397i | `results/phase36_realargs/1397i_dmem_block_checksum_20261109_143254.txt` | 0 of 23 pages change over 1.5 s |
| 1397j | `results/phase36_realargs/1397j_dmem_page0_write_20261109_143351.txt` | page 0 is writable RAM |
| 1397k | `results/phase36_realargs/1397k_dmem_record_steer_20261109_143442.txt` | records do not steer offset 0 |
| 1397l | `results/phase36_realargs/1397l_dmem_steer_f000_20261109_143526.txt` | records do not steer 0xF000 either |

1397h is void: it died in its own diff loop (`attempt to index field '?' (a number value)`)
before producing a comparison, and is only cited for the observation that the loader
process had changed pid by then.

## 6. The device frame rounds the offset DOWN, so the ACL cannot be crossed (1547a, 2026-11-10)

`results/phase36_realargs/1547a_dmem_frame_straddle_20261110_165645.txt`, COMPLETE 0.032 s, pid 242, ledger
grade **M**. The question was whether a page-sized request that respects the aperture's `offset + length`
test could still produce a mapping covering device address space past the limit, because the vm_map entry
rounds a `len = 0x1000` request up to `0x4000`. It cannot, and the reason is structural.

**Three measured facts.**

1. **A `len = 0x1000` device mmap produces a `0x4000` vm_map entry, and the entry can start BELOW the
   mapping's own VA.** `mmap(off = 0x1000, len = 0x1000)` returned VA `0x3115E9000`; 547 reported
   `start = 0x3115E8000 end = 0x3115EC000 len = 0x4000 prot = 0x3 flags = 0x10020`, and `[A2]` confirmed
   that `0x3115E9000`, `0x3115EA000` and `0x3115EB000` are all inside that one entry while
   `0x3115EC000` is outside. So the VA returned is `entry_base + (off mod 0x4000)`, and the entry covers
   the whole `0x4000` frame.
   `flags = 0x10020` is specific to a `/dev/dmem0` mapping and **is not a device-versus-anonymous
   test**: `1533a` records `flags = 0x610020` for anonymous regions *and* for the `SceGnmTrapData`
   device window (`docs/VM_LAYER_14_10.md:588`), so the dmem value is the outlier. Use frame content,
   not this field, to tell what is behind an entry.
2. **Device frames are byte-addressed and round the offset DOWN to the frame.** `[B]` anchored on device
   offset 0 (`C0012800`, the GPU registers) and read `A0+0x1000 = 0x00000000` and `A1+0 = 0x00000000`
   for the map at device offset `0x1000`, and `A0+0x2000 = 0` against `A2+0 = 0` — the SLIDE model, in
   which a map at device offset X shows device offset X at VA + 0. Combined with fact 1, the frame
   covering device offset `off` is `[off & ~0x3fff, (off & ~0x3fff) + 0x4000)`: **rounded down**.
3. **The aperture edge is `0x110010000`, not the 4 GiB / 5 GiB the coarse ladders suggested.** `[C]` on
   an 18-rung ladder gave one accepted-to-refused transition (`0x100000000` maps, `0x120000000` is
   `EACCES(13)`), and `[D]` bisected at `0x4000` to `LIMIT = 0x110010000`. `1410a`'s "first refusal at
   `0x140000000`" and `1411a`'s "`0x120000000`" were both 1 GiB and 256 MiB grids; the true edge is
   `0x110010000` and the residual slack is `L in [0x110010000, 0x110011000)`.

**Why the straddle cannot exist.** With round-down frames, any accepted request `off` maps the frame
`[off & ~0x3fff, ... + 0x4000)`, whose end is at most `(off & ~0x3fff) + 0x4000 <= off + 0x4000`. The
aperture test accepts `off` only when `off + len <= L`, with `len >= 0x1000`. The frame's end exceeds `L`
only if `(off & ~0x3fff) + 0x4000 > L`. But `off & ~0x3fff > L - 0x4000` implies `off > L - 0x4000`, and
`off + 0x1000 > L + 0x1000 - 0x4000 = L - 0x3000`, which does not by itself exceed `L` — so the boundary
case has to be measured, and it was:

| rung | request | result |
|---|---|---|
| `[E0]` | `off = LIMIT - 0x4000, len = 0x4000` | **accepted**, entry `0x3115E8000..0x3115EC000` |
| `[E]` | `off = LIMIT - 0x1000, len = 0x1000` | **accepted**, VA `0x3115EB000`, entry `0x3115E8000..0x3115EC000` |
| `[E1]` | `off = LIMIT - 0x1000, len = 0x4000` | **`EACCES(13)`**, `off + len = LIMIT + 0x3000` |

`[E]`'s entry is `0x3115E8000..0x3115EC000` with the VA at `+0x3000`, so it covers device offsets
`[0x11000C000, 0x110010000)` — the frame rounds `LIMIT - 0x1000` down to `LIMIT - 0x4000` and therefore
**ends exactly at the limit**. `547` at `LIMIT` itself is refused, `[G]`'s read of the in-window
sub-block (`0x11000F000`) returned `0x00000000`, and `[E1]` proves the ACL's own size stops at `LIMIT`
rather than past it. There is no overhang in either direction.

**The general statement, which the single-point measurement only instantiates.** For any accepted
request, `off + len <= L`. The entry a request produces is
`[off & ~0x3fff, round_up(off + len, 0x4000))`, and because `L` is `0x4000`-aligned — the measured
bracket is `[0x110010000, 0x110011000)`, which contains exactly one frame-aligned value, `0x110010000`
— `round_up(x) <= L` whenever `x <= L`. So **no accepted request can
produce an entry that ends past `L`, for any `off` and any `len`** — the boundary case in the table is
the one that decides it, and it lands on the safe side. A frame that reaches past the aperture is not
constructible from the ACL's own accepted set.

**Consequence.** The dmem ACL is correct for every shape reachable from a game process, and the
"rounding buys a bypass" composition is closed. The probe's `[F]` verdict printed NO STRADDLE before any
dereference, so the negative is not an artefact of a fault. Note also what fact 1 implies on its own:
a `len = 0x1000` request grants read/write over the entire `0x4000` frame that contains it, i.e. `0x3000`
bytes *below* the requested offset as well. That is an over-grant of up to `0x3fff` device bytes in the
low direction, bounded by the same frame alignment, and it adds no address space outside the aperture.

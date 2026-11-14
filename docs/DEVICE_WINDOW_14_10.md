# Device windows on 14.10: 548 is a real protection rewrite, and what it exposes

Scope: what syscall 548 op 2 actually does, the protection matrix, the two kill vectors it
introduced, and the complete content survey of the device memory it makes reachable. Every
number here has a capture; the capture table is at the bottom. No claim in this document is a
kernel primitive — nothing below reads or writes kernel memory, and no kernel pointer was found
in any of it.

## 1. Why 548 matters

`548` is `sceKernelBatchMap2`. The repo spent a year calling it a dead end because `55b` passed
the opcode in arg 1 and got `-1` for everything. The contract, decoded from the 13.60 body
(`0xffffffff8b47be60`) and confirmed on 14.10, is:

```
548(arg1_ignored, flags, entry_array, count, processed_out, 0)
```

- `flags` is a mask compared against `0xe0bffb6f + (byte[proc+0xc81] ? 0x20000000 : 0)`; `0` and
  `0x10000000` pass, `0x1`, `0x1000`, `0x20000000` and `0xFFFFFFFF` give `EINVAL`.
- `entry_array` is a packed array of **0x20-byte** `SceKernelBatchMapEntry` records:
  `+0x00 start`, `+0x08 offset`, `+0x10 length`, `+0x18 protection`, `+0x1C op`.
- `count` is the number of entries; `processed_out` receives a dword per call.
- `arg1` is ignored entirely — `0`, `1`, `0x310000000` and `0xFFFFFFFFC1000000` all return `0`.

Two gates killed every early attempt, and neither is documented anywhere in the repo:

1. **`length` must be 16 KiB aligned** (`test r12d,0x3fff`). `0x1000` and `0x2000` give `EINVAL`
   with `processed=0`; `0x4000` and `0x8000` succeed. This is why `1479c`/`1479d` reported a
   uniform negative and were read as "no op accepts a real range".
2. **`op` 2 is a real `vm_map_protect`**, not a stub. The case at `0x8b47c0b0` does
   `test esi,0x3fff`, `test edx,0x3fff`, `and ecx,8; jne EINVAL`, `add rdx,rsi; jb EINVAL`,
   `shr ecx,1; and ecx,0xffffffc1; or ecx,edi`, then calls `vm_map_protect` at `0x8ac8bdb0`.

The consequence: `548` op 2 changes a protection that `547` then reads back changed. `mprotect(2)`
on this platform returns `0` and does nothing (`56k`), so **`548` is the only working protection
primitive a game process has.**

## 2. The protection matrix

`1481g`, on an anonymous page and on a device page, one entry per call:

| requested prot | anonymous page | device page |
|---|---|---|
| `0x0` `0x1` `0x2` `0x3` | `rv=0` | `rv=0` |
| `0x4` `0x5` `0x6` `0x7` | `rv=-1` | `rv=-1` |
| `0x8` `0x9` `0xA` `0xC` `0xF` | `rv=-1` | `rv=-1` |
| `0x10` `0x20` `0x33` | **kills the thread** | `rv=0`, `547` reads 16/32/51 |

Three results worth carrying:

- **`PROT_EXEC` is refused by a filter inside 548**, not by `max_prot` — the values are rejected
  before the map is touched, with `processed=0`.
- **`prot 0x2` is silently upgraded to `3`.** The kernel applies write-implies-read
  (`shr ecx,1; and ecx,0xffffffc1; or ecx,edi`), so `547` reports `3` after a request of `2`.
- **`prot 0x10` on an anonymous page hangs or kills the process.** It is fine on a device page.
  This is a new probe-killer; do not request it on an ordinary mapping.

## 3. What it exposes

`1480c` walked the 674 map, found the 56 entries whose protection is not `0/1/2/3/5`, and
protected them. **19 moved from `0x33` to `3` and then read normally** — the same windows that
`376a`/`380a` recorded as read-fatal:

| window | address | first dword after the move |
|---|---|---|
| `(NoName)eboot.bin` | `0xC80000000` | `00000000` |
| `SceGnmTrapCode` | `0xF00000000` | `BF800001` |
| `SceGnmTrapData` | `0xF00004000` | `00144000` |
| `SceAgcDdid` | `0xF00008000` | — |
| `SceGnmEopFifo` | `0xF00104000` | — |
| `SceGnmShadowRegInfo` | `0xF00140000` | — |
| `SceGnmCwsr` | `0xF00144000` (16 MiB) | zero |
| `SceGnmMisc` | `0xF01144000` | — |
| `SceGnmACQRB` | `0xF01148000` (1.9 MiB) | zero |
| `SceGnmDriver` | `0xFE0000000` | `C0012800` |
| `SceGnmDingDong` | `0xFE0200000` | `FFFFFFFF` |

`1485a` closed the obvious next question: **an execute-only entry cannot be lowered.** All 38
`prot 4` entries — every `.sprx` text segment and `sigtramp_alias` at `0x800000000` — answer
`EACCES(13)` for a request of `3`, `2` or `1`. `max_prot` for module text is execute-only, so
module text stays unreadable and the oldest wall in this repo holds.

`1486a` then protected every pre-existing GPU pool entry with a **single call each**, including a
`0xFE190000` (3.9 GB) entry. So a 4 GB `0x33` mapping that used to kill on touch is now an
ordinary read/write region.

## 4. What is in it: nothing useful

- **`SceGnmDriver` (64 KiB) is the same table as `dmem0` page 0**, byte for byte in the first 0x20:
  `C0012800 80000000 80000000 C0001200 … C0055800 2EC47FC0 FFFFFFFF`. It is a GPU register-init
  list — pairs of `(register, value)` with runs like `C0027600` at `0x08 0x48 0xC8 0x108 0x148` —
  not live MMIO. `1397j` already proved the `dmem0` copy is ordinary RAM that accepts stores, so
  the `0xFE0000000` window is a RAM mirror.
- **`SceGnmTrapCode`** is 2442 of 4096 non-zero dwords of shader ISA (`BEF20300 BEF7037F …`).
- **`(NoName)eboot.bin` at `0xF0000000`** has 93 of 4096 dwords non-zero, also shader-shaped.
- **`SceGnmDumpArea`** (1 MiB) holds exactly two dwords at `+0xB6440`: `00000E10`, `00000040`.
- **`SceGnmCwsr`, `SceGnmACQRB`, `SceGnmMisc`, `SceGnmShadowRegInfo`** are all zero across their
  full extents.
- **`SceGnmDingDong`** is `0xFFFFFFFF` everywhere and a store there does not stick.
- **The pool is empty.** 4372 sampled 1 MiB rungs across all six pool entries: 3 non-zero, and
  all three are the first rung of an entry, holding allocation headers
  (`00010006 FFFFFFFF FFFFFFFF …`, `… 00000523 …`, `00840000 00000002` pairs at `+0x10` stride).
- **`SceKernelInternalMemory`** (16 MiB, `0x880AD0000`) is zero at all 256 sampled 64 KiB rungs.

The `0xFFFFFFFF2EC47FC0`-shaped qwords a naive scan reports are register pairs from the init
table, not kernel pointers: the low dword is below `0x80000000` and the whole value is far below
this boot's image at `0xFFFFFFFFCC800000`.

## 5. What this does and does not give

Does:

- A working protection rewrite for any entry whose `max_prot` allows the target — the only one on
  the platform, and the reason `376a`/`380a` are superseded.
- Reads and writes of device memory the process does not own, verified by write-restore in
  `1481b` (6 of 6 landed).
- A method to make the `0x33` pool entries readable, including a 4 GB entry in one call.

Does not:

- Reach kernel memory. Every entry is in our own `vm_map`.
- Break W^X. `548` refuses any protection carrying bit `0x4`, and `max_prot` refuses lowering an
  execute-only entry.
- Drive the GPU. The device windows are RAM mirrors of an init table and an empty pool, so
  writing them does not program hardware; every GPU ioctl is refused (`docs/DEVICE_IOCTL_14_10.md`).

## 6. Open questions

1. `548` op 0 returns `EBUSY(16)` for a 16 KiB-aligned **unmapped** address and `rv=0` for a
   mapped one, which is not what a map op should do. Ops 0/1/3/4 dispatch and validate but change
   nothing measurable (`547` identical, markers intact).
2. `548` sets `td+0x116 = 1` for the duration of the call. `vm_map_protect` reads that byte but
   still takes `map+0x170`/`map+0x1a8` unconditionally, so it is not a lock bypass; what the flag
   is for is unknown.
3. The `0x33` protection on the pool entries is accepted by `548` for a device page and refused
   for an anonymous page, so `max_prot` there is wider than the anonymous default. Nothing found
   uses that.

## 7. What each batch op does (measured 2026-11-09)

The five ops are now identified. `1488b` swept ops 0-4 twice, once with a fixed 16 KiB hole and
once with `start = 0`, and carried `/dev/dmem0`, `/dev/dmem1`, `/dev/gc`, `/dev/zero` and a
`-1` descriptor in the entry's `+0x08` field.

| op | return | processed | effect |
|---|---|---|---|
| 0 | `-1` EINVAL(22) | 0 | nothing, for every descriptor tried |
| 1 | `0` | 1 | nothing - the commit/flush case |
| 2 | `0` | 1 | `vm_map_protect` on the entry covering `start` |
| 3 | **the address** (`0x311220000`) | 1 | maps anonymous memory at `start` (kernel picks when `start = 0`); `547` then shows `start..start+len` at the requested protection |
| 4 | `-1` EOPNOTSUPP(45) | 0 | nothing on a live entry |

Only op 0 reads `entry+0x08` as anything other than a flag word. In the 13.60 body its case
(`0xffffffff8b47bff3`, RVA `0xabbe60`) is the one that gates on `[proc+0x1c9] >= 2`,
`![proc+0x464] & 2`, `!(entry[+0x08] & 0x400)` and `[proc+0x5d4] >= 0x2500000` before calling
`0x8b47d540`, which resolves a descriptor out of the fd table with `0x8b142a80` - the only
descriptor-taking map path in the syscall. On 14.10 it answers EINVAL for every descriptor
including the three device nodes, so one of those four gates is closed for a game process.

op 3 ignores `entry+0x08` as a descriptor entirely: the case at `0xffffffff8b47c11e` forces
`fd = -1` and `offset = 0` and passes `entry[+0x08] | 0x1000` as the map flags, which is why all
five descriptor rows of `1488b` return the same address. So op 3 is `mmap(MAP_ANON)` with a caller
chosen flag word, nothing more.

Consequence: 548 is a protection changer (op 2) plus an anonymous allocator (op 3). It has no
reachable path that binds a device, vnode or physical object into the address space.

## 8. Captures

| probe | capture | shows |
|---|---|---|
| `1479e` | `results/phase36_realargs/1479e_sys548_prot_matrix_20261109_195636.txt` | 16 KiB alignment is the gate; prot really changes |
| `1480a` | `.../1480a_sys548_eboot_rwx_20261109_200355.txt` | prot 1/3 round-trip; 5/7 EACCES |
| `1480b` | `.../1480b_sys548_low_map_20261109_200449.txt` | ops 0/3/4 change nothing; unmapped → EBUSY. **Corrected 2026-11-10: the line labelled `op=1` in this capture never called op 1** - its entry buffer still held `set_entry(A,0,0x4000,3,2)`, so it repeated op 2 on A. Not evidence about op 1. |
| `1480c` | `.../1480c_sys548_device_prot_20261109_200528.txt` | 19 device windows 0x33 → 3 and read |
| `1481a` | `.../1481a_gpu_windows_scan_20261109_200632.txt` | the persist is visible in 674 |
| `1481b` | `.../1481b_gpu_windows_write_20261109_201732.txt` | 6 of 6 stores land and restore |
| `1481c` | `.../1481c_gpu_region_content_20261109_201653.txt` | bulk read: no kernel data |
| `1481e` | `.../1481e_device_alias_test_20261109_201808.txt` | not an alias of executable memory |
| `1481f` | `.../1481f_full_map_dump_20261109_201845.txt` | 336 records, 279 readable, 38 with prot 4 |
| `1481g` | `.../1481g_sys548_prot_full_matrix_20261109_202102.txt` | the protection matrix |
| `1483a` | `.../1483a_driver_window_content_20261109_203533.txt` | the init table, the shader body, the empty windows |
| `1485a` | `.../1485a_protect_exec_only_entry_20261109_203825.txt` | XO cannot be lowered |
| `1486a` | `.../1486a_gpu_pool_scan_20261109_203940.txt` | 4 GB in one call; the pool is empty |
| `1487a` | `.../1487a_physhm_548_20261109_214646.txt` | physhm installs no vm_map entry at all |
| `1488b` | `.../1488b_sys548_map_desc_20261109_215258.txt` | the op map; op 0 takes a descriptor and refuses every one |

## 9. op 3 with MAP_FIXED places a page anywhere (measured 2026-11-09)

`1492a` and `1493a` concluded that op 3's `start` field was a hint, because every call they made
into an occupied address came back with a different address. That was a missing flag, not a
missing capability. `548` arg2 bit `0x10` is `MAP_FIXED` for this op, and no other bit in the
`0xe0bffb6f` batch mask covers it.

### The contract

```
548(arg1_ignored, flags, entry_array, count, processed_out, 0)
entry[0x00] qword start   entry[0x08] qword flags-for-the-inner-mapper (op 3)
entry[0x10] qword length  entry[0x18] dword protection
entry[0x1C] byte  opcode   -- 3 = anonymous map
```

With `flags = 0x10` the call returns **exactly the requested address** and `processed = 1`.
Without it the address is only a hint and an occupied range pushes the result to the next hole
(`1508a`: asked for `0x31106C000`, got `0x311070000`).

### What it does, measured

| probe | call | result |
|---|---|---|
| `1508a` [B] | op 3, flags `0x0`, onto a live anon page | `rv = V+0x4000`, marker `11223344` intact |
| `1508a` [C] | op 3, flags `0x10`, same address | `rv = V`, marker `00000000` — **entry replaced** |
| `1508a` [D] | op 3, flags `0x10`, onto a 16 KiB hole | landed exactly at the requested `0x311074000`, writable |
| `1508a` [E] | op 3, flags `0x10`, over `SceGnmTrapCode` `0xF00000000` | landed, and the window then read `00000000` where it had read `01 00 80 BF`; **no panic** |
| `1509b` | op 3, flags `0x10`, prot 0..7 | every call landed; the protection is **stripped, not refused** |
| `1510a` | op 3, flags `0x10`, at `0x4000`/`0x10000`/`0x100000`/`0x1000000` | all landed, all writable |
| `1510a` | op 3, flags `0x10`, at `0x0` | `rv = -1`, `processed = 0` |

So `op 3 + 0x10` **deletes the `vm_map_entry` covering the range and installs a fresh anonymous
one, at any 16 KiB-aligned address from `0x4000` up to the same ceiling `mmap` has**, with no
ownership test, no overlap test and no reference to who created the old entry. Plain
`mmap(MAP_ANON|MAP_FIXED)` at `0x0` fails too, so the `0x4000` floor is the true user map floor
and `548` simply does not re-check it.

It is **not** a W^X bypass. `op 3` handles an exec request differently from `op 2` — op 2 answers
`EACCES(13)`, op 3 accepts and silently drops bit `0x4`, then applies write-implies-read:

| requested | `547` reports |
|---|---|
| 0 | 0 |
| 1 | 1 (a store faults) |
| 2 | 3 |
| 3 | 3 |
| 4 | 0 |
| 5 | 1 |
| 6 | 3 |
| 7 | 3 |

(`1509b`; the stray binary on stdout in the prot-1 and prot-5 rows is the loader's own SIGSEGV
dump from the calibration store into a read-only page, and the process survived it.)

### What it is and is not good for

It is a **placement** primitive, not a read. Replacing a device window does not reveal the device
object's contents — the VA simply becomes a zero page, which is why `[E]` matters as a
*destruction* result and not as a disclosure.

The one property worth chasing is that the kernel's own view of a VA can now be swapped for
memory we own:

- **graft.** Replace one page inside a region the kernel or a driver still believes it owns and
  watch for bytes appearing in it. `1509a` is that experiment; it is written but every run so far
  is void (see its ledger rows — the first two decoded the 674 name field with a dword read and
  the third grafted at 32-bit-truncated addresses and killed the loader).
- **a low page.** `0x4000` is mappable and page 0 is not, so a kernel dereference of a value read
  out of caller bytes only becomes survivable if the resulting address lands in the second page.
  That is narrow, but it is the difference between a kill and a datum for the 601 cmd `0x11` and
  622 low-command shapes.
- **destruction.** A device window can be deleted from our own map without a panic, which drops
  that `vm_object`'s reference. Whether the driver's own reference keeps the object alive is
  unmeasured.

### Open questions

1. Does deleting a device entry free the `vm_object` while the driver still holds a pointer to it?
   `1508a` [E] shows the delete is survivable but says nothing about the object's lifetime.
2. Does anything kernel-side write into a grafted page? `1509a` is the instrument.
3. What happens to the *old* physical pages — are they returned to the free list, and are they
   reachable again through a second mapping of the same device offset?

### Captures

| probe | capture | shows |
|---|---|---|
| `1508a` | `results/phase36_realargs/1508a_sys548_map_fixed_20261109_224934.txt` | MAP_FIXED replaces a live entry, lands on a hole, replaces a device window |
| `1509b` | `.../1509b_sys548_op3_exec_20261109_225307.txt` | op 3 strips exec instead of refusing it |
| `1510a` | `.../1510a_low_address_ladder_20261109_225354.txt` | 0x4000 is the floor; page 0 refused |
| `1509a` | (void — see the ledger) | the graft experiment, not yet run cleanly |

## 10. op 3 SPLITS the entry it lands in (measured 2026-11-09)

Section 9 said op 3 "deletes the `vm_map_entry` covering the range". That is true but imprecise:
it is `vm_map_delete(range)` followed by `vm_map_insert()`, and `vm_map_delete` on a range in the
*interior* of an entry runs `vm_map_clip_start` and `vm_map_clip_end` first. So one call does not
destroy an entry — it clones it twice and replaces only the middle. `1512a` measured it directly:

```
before  one entry   0x3110AC000 .. 0x3120AC000   len 0x1000000   prot 3
carve   op 3 MAP_FIXED at 0x3110B0000, len 0x4000, prot 3
after   three entries
        0x3110AC000 .. 0x3110B0000   len 0x4000    prot 3   (head, markers intact)
        0x3110B0000 .. 0x3110B4000   len 0x4000    prot 3   (the carve, reads zero)
        0x3110B4000 .. 0x3120AC000   len 0xFF8000  prot 3   (tail, markers intact)
```

A second carve at `+0x800000` split the tail the same way, and `munmap(base, 0x1000000)` then
removed all three fragments. Every marker outside the carved page survived, so the head and tail
keep their object and their pages; only the middle is replaced.

### The clippers and the object type they touch

In the 13.60 dump both clippers carry a special case guarded by `cmp byte [obj+0x9d], 2` and
`cmp qword [entry+0x70], 0` — `vm_map_clip_start` at `0xffffffff8ac8b564` and `vm_map_clip_end`
at `0xffffffff8ac8b7e5` — which writes `[obj+0x1a0] = entry->[0x70]` and
`[obj+0x1a8] = entry->end - entry->start`. Object type 2 is `OBJT_VNODE`, so a **file mapping is
the one entry kind the clipper mutates in place**, and a vnode mapping's object is the vnode's
page-cache object, shared by every mapping of that file. That made a shared-object corruption
plausible enough to measure. It does not happen:

| probe | object | result |
|---|---|---|
| `1513a` | `MAP_SHARED` vnode (`/app0/eboot.bin`, prot 1), mapped **twice** | carve landed exactly at `A+0x10000`; the carve page read zero while mapping B read the real file bytes at the same offset; B stayed `start/end/len/prot` identical and byte-identical at `+0`, `+0x8000`, `+0x30000`; a second carve on A after unmapping B was also clean; the file on disk read back unchanged |
| `1514a` | `MAP_SHARED` POSIX shm, mapped **twice** | the two mappings really were one object first (a write through A appeared through B and back). After the carve, propagation still worked in both directions, a 0x40000 sweep of B found **0 dwords** that were neither written by us nor zero, and a second carve on B itself was also clean |

So a quiescent clip is correct for both a shared file object and a shared shm object: the head and
tail fragments keep a valid reference and no page is lost. Note `1514a`'s summary line reports
"1 of 3 checks lost" — that is a bug in the probe's own expectation table (it checked `+0x0000`
against a sentinel that was written at `+0x8000`), not a lost page; the two real checks and the
full sweep are both clean.

### The one case that kills: a fault in flight

`1515a` raced op 3 against a Lua thread reading the same page. 200 serial control rounds were
perfect (0 non-zero reads, 0 replacement failures); the moment a reader thread ran, the process
died — the capture stops at `spawn = OK` and the loader then answers `CONNECTION_REFUSED`.

That result is **not** evidence of a kernel bug, and must not be cited as one. op 3 is delete
then insert, so between the two the address is genuinely unmapped and a *user* read there takes an
honest `SIGSEGV`. The design cannot separate a signal from a kernel fault, which is why
`1516a` replaces the racing party: it has a thread call `write(fd, V+0x1000, 4)` so the page is
faulted in **inside `copyin`**, where an unmapped source returns `EFAULT` to the caller and cannot
deliver a signal. In that design a process death is attributable to the kernel, and a survival is
a clean negative. `1516a` is written and syntax-clean; it has not been run.

### Captures

| probe | capture | shows |
|---|---|---|
| `1512a` | `results/phase36_realargs/1512a_sys548_op3_split_20261109_230244.txt` | one carve splits a 16 MiB entry into head / carve / tail; two carves; markers outside survive |
| `1513a` | `.../1513a_sys548_op3_vnode_clip_20261109_230353.txt` | a vnode clip leaves a second mapping of the same file untouched and the file unmodified |
| `1514a` | `.../1514a_sys548_op3_shm_clip_20261109_230444.txt` | a shared shm object still propagates writes both ways after the clip; 0 odd dwords |
| `1515a` | `.../1515a_sys548_op3_fault_race_20261109_230554.txt` | a user-space reader racing the carve kills the process; ambiguous, see above |

## 11. What op 3 is worth (consolidated, measured 2026-11-09)

Stripped of the detail above, the whole capability is one sentence: **a game process can delete
the `vm_map` entry covering any 16 KiB-aligned address at or above `0x4000` and install a fresh
anonymous RW page in its place, with no ownership, overlap, ceiling-below-`0x4000`, or max_prot
test.** That is `vm_map_clip_start` + `vm_map_clip_end` + `vm_map_delete` + `vm_map_insert` with a
caller-chosen range. It is real, it is reachable with four arguments, and it is the first VM-layer
write this project has ever had.

What it does **not** give, each of these measured:

| attempted use | probe | result |
|---|---|---|
| read the device memory behind a device window | `1508a` | replacing the entry makes the window read **zero**: the device pages are unmapped, not re-pointed |
| make a kernel or driver object write into our page | `1509a` | five grafts at `SceGnmTrapData`, `/AOSharedState`, a GPU pool page, `SceNpGlobalHeap`, `SceKernelInternalMemory`; **0 changed dwords** across three rounds of syscall driving |
| attack a device object's lifetime | `1511a` | 200 rounds of mmap-then-replace: `bad=0`; the descriptor still maps and round-trips after every round |
| corrupt a shared vnode object | `1513a` | a second mapping of the same file keeps its bytes, its extent and its protection |
| corrupt a shared shm object | `1514a` | write propagation both ways still works after the carve; a full sweep found 0 odd dwords |
| race a fault against the delete/insert window | `1515a`, `1516a`, `1517a` | **untested, not negative** — see below |
| grant execute | `1509b`/`1496a` | op 3 **strips** bit `0x4` then applies write-implies-read (0→0, 2→3, 4→0, 6→3); no protection it installs is executable |

The race is untested because the instrument was wrong, not because the answer is no. `1517a`'s
`[C]` ran 200 000 `write()` calls in a spawned Lua thread with **no op 3 call anywhere in the
phase** and the loader still died, and `1518a` reproduced it with a `/dev/zero` destination and a
single closure. **A spawned Lua thread that runs a syscall loop takes the whole process down**, so
the racy side of `1515a` and `1516a` proves nothing. A valid race needs a native child
(`thr_new(455)` plus a hand-built ROP chain), which has not been built.

Two smaller facts worth keeping from the same campaign: `/dev/zero`'s `write` never touches the
source pointer (an unmapped source returns `4`, not `EFAULT`), so it cannot be used as a fault
generator; and a 548 call that returns `rv=0 processed=1` is **not** proof a range exists —
`1487a` got that answer on a physhm address that `547` says was never mapped.

### Captures

| probe | capture | shows |
|---|---|---|
| `1508a` | `results/phase36_realargs/1508a_sys548_map_fixed_20261109_224934.txt` | MAP_FIXED honoured exactly; device window reads zero after replacement |
| `1509a` | `.../1509a_graft_kernel_pages_20261109_225814.txt` | 5/5 grafts landed exactly, 0 changed dwords |
| `1509b` | `.../1509b_sys548_op3_exec_20261109_225307.txt` | op 3 strips bit 0x4 and applies write-implies-read |
| `1510a` | `.../1510a_low_address_ladder_20261109_225354.txt` | placement works from 0x4000; 0x0 refused |
| `1511a` | `.../1511a_device_entry_churn_20261109_225908.txt` | 200 replace rounds, device object undamaged |
| `1517a` | `.../1517a_sys548_op3_race_bisect_20261109_231611.txt` | the child-thread control: a Lua thread dies on its own |
| `1518a` | `.../1518a_child_thread_stability_20261109_232028.txt` | same, with no socket and one closure; `/dev/zero` ignores its source pointer |

## 12. op 3 is bounded by the map, so a kernel-half graft is impossible (static, 2026-11-10)

The one composition that would have turned op 3 into ring 0 is this: there is no
KPTI on this console, so the process page tables hold the kernel mappings. If the
user `vm_map` would accept an entry at a kernel virtual address, the graft would
install a user-writable page at that VA, and the kernel - which fetches and
dereferences those VAs at CPL0 through the same tables - would read our bytes.

It cannot. The MAP_FIXED branch of op 3 checks both map bounds before inserting:

```asm
0x8b47d7c4  (MAP_FIXED branch: r11b & 0x10)
0x8b47d7d7  cmp  qword ptr [rsi + 0x20], r12   ; map->min_offset vs start
0x8b47d7de  seta cl
0x8b47d7e1  add  r8, qword ptr [rbp - 0x48]    ; end = start + length
0x8b47d7e5  setb r9b                           ; carry -> overflow
0x8b47d7e9  or   r9b, cl
0x8b47d7ec  mov  ecx, 0x16                     ; EINVAL
0x8b47d7f1  jne  fail                          ; start < min  OR  wrap
0x8b47d7f7  cmp  qword ptr [rsi + 0x28], r8    ; map->max_offset vs end
0x8b47d7fb  jb   fail                          ; end > max
```

`[map+0x20]` is `min_offset`, `[map+0x28]` is `max_offset` - the same pair
`vm_map_protect` clamps to. So the "no ownership check" in op 3 means "any address
inside this process's own map", not "any address in the address space". The
kernel's own user limit is 2^47: `copyin`/`copyout` compare against
`0x800000000000` and mask with `0x7fffffffffff` (`0x8ac191f8`, `0x8ac1921d`).

This also explains the two measured edges without needing a ladder run: `0x4000`
lands and `0x0` is refused because `min_offset` is one page, and `0xF00000000`
lands because it is below `max_offset`.

**Consequence: op 3 is a placement primitive inside the process's own user map and
nothing more.** The remaining lever that could change that is syscall 637, which
writes a caller-chosen qword into `[map+0x280]` with no capability check when the
pid argument is 0 - if that field were `max_offset` the story would be different,
but `max_offset` is at `+0x28`, 0x258 bytes earlier, and the write is preceded by
`mtx_lock(map + 0x278)`, so `+0x278`/`+0x280` is a Sony lock-and-field pair, not
the bound. Identifying that field is the open question.

## 13. What syscall 637 actually writes, and why it is inert (static, 2026-11-10)

637 is named `set_phys_fmem_limit` in `docs/sysent-names-13.60.csv:639`, and the
field matches the name. The store is `0xffffffff8b47da0c mov qword [r12+0x280], rax`
with `r12 = [[gs:0]+8]+0x200` and `rax = uap[1]` verbatim; the only gate is
`0xffffffff8b47d93e cmp qword [rsi+8],0x11; jl` (reject values below 17). The
mutex at `+0x278` is taken around the store and released at `0x8b47da14`, before
the consumer runs.

**There is exactly one reader in the whole corpus**, `0xffffffff8b051919`:

```asm
0x8b051900  mov rax, [r14 + 0x1d8]   ; accounting object
0x8b051907  mov rcx, [r14 + 0x230]   ; bytes in use
0x8b05190e  mov rax, [rax + 0x50]    ; capacity in bytes
0x8b051912  sar rcx, 0xe             ; >> 14  -> pages
0x8b051916  sub rax, rcx             ; free pages
0x8b051919  cmp qword [r14 + 0x280], rax
0x8b051920  jg  0xffffffff8b051c35   ; limit >= free -> return
```

Below the free count it walks the entry ring from `[r14+8]`, skips
`test dword [rax+0x60], 0x40102`, and pages out through `0x8ae21b20`,
`0x8b5497f0`, `0x8b2a6110`. Nothing else in the corpus reads a qword at `+0x280`
on this object - `sys_667`'s `0x4a4552` and `sys_650`'s `0x561ad9`/`0x561b3e` are
the same displacement on unrelated structures (a list head with payload byte
`+1`, and a dword on an object carrying `+0xe0` proc and `+0x560` lock).

So `[MAP+0x280]` is a **per-process physical-fmem page limit, consumed as a
SIZE by a single signed compare**. It is never dereferenced, never scaled into an
index, never compared with `nentries`, never copied out, and never reaches
`vm_map_find`/`vm_map_insert`. Writing it steers no allocation. Its only
observable is the reclaim loop: at or above the free count the `jg` returns
immediately - which is the measured `ret 0` for every value >= 0x40000000 - and
below it the loop has no exit for a live process, which is the measured
permanent wedge at value 17 that also takes the shared parent with it.

**637 is therefore a real unprivileged write to a real kernel field that is not a
lever.** It cannot corrupt a bound, cannot redirect a pointer, and cannot be read
back through 615, 642 or 733. The earlier hope that `+0x280` might be `pmap` or
`max_offset` is dead: `max_offset` is `+0x28`, and a garbage `pmap` would fault on
the next `vm_map_insert` - `346b` wrote `0xFFFFFFFF` there and mapped three
chunks without incident.


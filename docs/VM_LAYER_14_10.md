# The VM layer on 14.10: what munmap actually removes, and the sys 673 contract

Status: measured on 2026-11-09 against firmware 14.10 (console 192.168.1.121, loader pid 432).
Nothing here is a kernel read/write primitive. It records four measurements that change how
probes must be built, plus one contract that closes a dead end properly instead of by a
single -1.

---

## 1. munmap removes the whole entry, not the requested range

> **CORRECTION 2026-11-10 — this section's conclusion is wrong, and the paragraph below explains
> why.** This kernel uses **16 KiB pages (0x4000)**. `mmap(0, 0x4000, ...)` therefore maps *one*
> page, and the four addresses 1450a calls "pages 0-3" (`base`, `base+0x1000`, `base+0x2000`,
> `base+0x3000`) are all inside that same 16 KiB page. So `munmap(base+0x3000, 0x1000)` asks to
> remove part of the only page in the mapping, the handler rounds the range to `[base, base+0x4000)`
> exactly as the 13.60 body does (`start = addr & ~0x3fff`, `end = round_page(addr+len)`), and the
> whole mapping goes. Nothing in 1450a tested a *multi-page* entry, so "entry-scoped" was never
> measured; it was an artifact of printing addresses 0x1000 apart and calling them pages. 1446d's
> independent fault at `base` is explained the same way: `base` is in the page that was just
> removed.
>
> The claim therefore reverts to the default and is **unverified**: whether `73` splits a
> multi-page entry or deletes it whole is an open question. `548` op 1 demonstrably splits a
> 256 KiB entry (1537b), and `probes/phase36_realargs/1544a_munmap_pte_scope.lua` tests `73` the
> same way on a sixteen-page mapping. Until it runs, nothing in this repository may cite
> "munmap is entry-scoped".
>
> The "costs" list below is retracted with it: a guard page *can* be built with `munmap`, by
> unmapping one 16 KiB page of a multi-page mapping — which is precisely what `1446e` was doing
> when it used a short copy length instead.
>
> **RESOLVED 2026-11-10 by `1544a` — `73` splits, and the 16 KiB page size is now measured
> directly.** `results/phase36_realargs/1544a_munmap_pte_scope_20261110_162901.txt`: a
> `477(0, 0x40000, 3, 0x1002, -1, 0)` mapping produced **one** `547` record
> `0x310AB0000-0x310AF0000` (exactly `0x40000`) and all sixteen addresses at `0x4000` stride read
> back their own sentinel `0xA0000000..0xA000000F`, so sixteen 16 KiB pages exist inside that one
> entry — that is the page size, measured rather than inferred from an alignment mask. Then
> `73(base + 0x10000, 0x4000)` returned `0`, and `547` afterwards gave `0x3` for pages
> `0,1,2,3,5,14,15` with **page 4 unmapped**. So `73` removes exactly the aligned span it is given
> and leaves the rest of the entry as two entries: **`73` and `548` op 1 agree**, and "munmap is
> entry-scoped" is dead for good. The heading above is kept only so the retraction stays legible.


Capture: `results/phase36_realargs/1450a_munmap_semantics_20261109_172529.txt` (grade M).

`mmap(0, 0x4000, 3, 0x1002, -1, 0)` → one entry. Then one `munmap` of a single page:

| block | munmap argument | pages 0-3 afterwards |
|---|---|---|
| A | `(base, 0x1000)` — first page | all four unmapped |
| B | `(base+0x3000, 0x1000)` — last page | all four unmapped |
| C | `(base+0x1000, 0x1000)` — middle page | all four unmapped |
| D | `(D1+0x2000, 0x1000)`, second region D2 untouched | D1 all four unmapped, **D2 still mapped** |

"Unmapped" is `sys 547` (query_memory_protection) answering `-1` for that VA — it does not
dereference the address, so the question can be asked safely. The result is not an artefact
of 547: `results/phase36_realargs/1446d_instrument_selftest_20261109_171122.txt` independently
read page 0 after `munmap(base+0x3000, 0x1000)` and faulted.

So on 14.10 the operation is **entry-scoped**: the handler finds the `vm_map_entry` that
contains `addr` and removes it whole, whatever `addr`'s offset inside it and whatever `len`
say. Neighbouring entries are unaffected.

The 13.60 body (`0xffffffff8b478bb0`) computes the range the FreeBSD way — `start = addr &
~0x3fff`, `end = round_page(addr + len)` with the page offset folded in, both clamped to
`[map->min, map->max]` — and then calls the map-remove helper. The range arithmetic is
correct at the syscall boundary; the collapse happens below it.

### What this costs and what it buys

* **Cost:** a guard page cannot be built with `munmap`. `1446b` and `1446c` both tried and both
  produced invalid instruments (captures graded V). Any probe that needs "page N is unmapped
  while page N±1 is mapped" must use a short copy length as the boundary instead, the way
  `1446e` did.
* **Cost:** `munmap` is not a way to free *part* of a mapping. Mapping 0x8000 and unmapping the
  middle 0x1000 frees all 0x8000.
* **Not measured:** whether the page-table teardown and any object unref cover the same range.
  The `vm_map_entry` and the page tables both go (547 says no entry, the read faults), which is
  consistent, so no stale mapping was produced in these four shapes. A device or shared object
  with a refcount could still be unref'd by a different amount than the entry it removed; that
  is the one shape worth testing if a device object ever becomes interesting again.

---

## 2. sys 673: a 64 KiB block move inside a type-11 vm_object

Capture: `results/phase36_realargs/1451a_sys673_object_type_20261109_172818.txt` and
`..._172829.txt` (grade M). Body `0xffffffff8b36b1f0`, thunk `0x265f88`, 13.60 name
`blockpool_move`.

The gate chain, decoded from the dump:

```
rbx = vm_map = [proc + 0x200]
r14 = uap[0]   must be >= map->min and 0x10000-aligned
r15 = uap[1]   must be >= map->min and 0x10000-aligned
r12 = uap[2]   must be 0x10000-aligned
      uap[3]   must be 0
vm_map_lookup_entry(map, uap[0], &entry)                 [0x8ac86c40]
entry->flags bit 1 must be clear                         test byte [entry+0x60], 2
entry->object ([entry+0x50]) must be non-NULL
cmp byte [obj + 0x9d], 0xb   ; else EINVAL               <-- object type must be 11
```

On success it shifts three of the values right by 16 (64 KiB units) and calls
`0x8b36b370(map, ..., old_lo>>16, old_hi>>16, new>>16)`. Every rejection returns EINVAL(22),
so the syscall cannot report which gate it failed.

Measured with all four arguments at 64 KiB alignment, six shapes per mapping
(`addr/addr+0x10000/new`, `addr/addr+0x20000/new`, self-move, zero target, length reading,
degenerate):

| mapping flavour | shapes | result |
|---|---|---|
| anonymous `0x1002` 0x80000 | 6 | all `-1` EINVAL |
| `/dev/zero` 0x80000 | 6 | all `-1` EINVAL |
| `/dev/gc` 0x80000 | — | does not map at that length at all |
| `/dev/dmem0` 0x80000 prot 3 | 6 | all `-1` EINVAL |

So the type-11 gate is not satisfied by an anonymous object, the zero device, or the GPU
aperture window. A scan of all 5,343,048 instructions in the 13.60 text for a store of the
constant `0xb` to `[obj + 0x9d]` found **none**: the 26 instructions that mention both are all
`cmp`. Whatever allocates a type-11 object does not do it with a constant store inside the
dumped text, which is consistent with the GPU driver living outside it.

Verdict: 673 is not a page-remap primitive on 14.10 for anything a game process can map. The
earlier `docs/DEAD_ENDS.md` entry ("GPU mmap backing object isn't type 11") was right about the
outcome and had tried one shape; this table is the wider version, and it also fixes the name —
the 13.60 symbol is `blockpool_move`, not a page remap.

---

## 3. The sysarch family is bounded (sys 165, not 166)

Capture: `results/phase36_realargs/1449a_sysarch_xfpustate_20261109_172134.txt` (grade M).
`1448a` (grade V) is the correction that produced it: it called **166**, which is `rtprio`,
with a struct pointer as the pid, and the process died on the first call. `165` is `sysarch`
(`docs/sysent-names-13.60.csv`).

Measured on 165:

| command | shape | result |
|---|---|---|
| 128 GET_FSBASE | `(128, parms)` | rv=0, writes nothing |
| 128 | `(128, NULL)` | EFAULT(14) |
| 132 GET_XFPUSTATE | `(132, BUF)` — buffer used as the parms pointer | EINVAL(22) |
| 132 | `(132, {BUF, 0x40})` | rv=0, 16 of 16 dwords written, head `0x00000007` |
| 132 | `(132, {BUF, 0x200})` | rv=0, 128 of 128 dwords written |
| 132 | `(132, {BUF, 0x240})` and above | EINVAL, nothing written |
| 133-140 | `(n, BUF)` | EINVAL |
| 131 SET_GSBASE | `(131, BUF)` | rv=0 (accepts a user address) |
| 130 GET_GSBASE | `(130, parms)` after 131 | writes `0x1085E000` into parms[0] |

So 132 is `{user_addr, len}` and the length is capped at 0x200 — the x87/SSE/AVX state, no
over-read and no kernel disclosure. The fp-state leak hypothesis is dead. 131 accepting a
user address and 130 echoing it is consistent with a per-thread GS base and gives nothing new.

---

## 4. select/pselect do not clamp nfds

Capture: `results/phase36_realargs/1446e_select_fdset_span_20261109_171239.txt` (grade M).

FreeBSD clamps `nfds` to `FD_SETSIZE` before copying fd_sets (`if (nd > FD_SETSIZE) nd =
FD_SETSIZE`). On 14.10 that clamp is absent: in a 64 KiB region every `nfds` up to 524288
(where the implied copy is exactly the region size) returns 0, and `nfds = 1048576` — one byte
past it — returns EFAULT. In a 4 MiB region `nfds` up to 8388608 (implied 1 MiB) all return 0.
`pselect(522)` behaves identically.

No overflow follows: the copy length is derived from `nfds` at every size, and the only
limits that appear are the mapped extent of the buffer. The unclamped value is a *contract*
fact, not a bug — the missing clamp would only matter if a downstream object had a fixed
fd_set size, and no such object was reachable.

---

## 5. The instrument lesson

Three probes were wasted learning that 14.10 cannot express "unmapped page next to a mapped
one":

* `1446b`/`1446c` (V) built the guard hole with `munmap` and measured the hole itself.
* `1446d` (M) found the entry-scoped behaviour by self-testing the instrument first.
* `1446e` (M) then used copy length alone and produced the result.

Self-testing the instrument before using it is what turned three void captures into one
correct measurement, and it is why section 1 exists.

---

## Captures

| probe | capture | grade |
|---|---|---|
| 1446d | `results/phase36_realargs/1446d_instrument_selftest_20261109_171122.txt` | M |
| 1446e | `results/phase36_realargs/1446e_select_fdset_span_20261109_171239.txt` | M |
| 1448a | `results/phase36_realargs/1448a_sysarch_family_20261109_171956.txt` | V |
| 1449a | `results/phase36_realargs/1449a_sysarch_xfpustate_20261109_172134.txt` | M |
| 1450a | `results/phase36_realargs/1450a_munmap_semantics_20261109_172529.txt` | M |
| 1451a | `results/phase36_realargs/1451a_sys673_object_type_20261109_172829.txt` | M |

---

## 6. sys 548 is sceKernelBatchMap2, and op 2 is vm_map_protect (2026-11-09)

`55b` called 548 with the opcode in arg1 and recorded "every operation returns -1, processed=0".
That shape was wrong, and the conclusion was wrong with it. The 13.60 body is at
`0xffffffff8b47be60` (`results/kernel_handlers/asm/sys_548.asm` PART B, thunk `0x265d60:
JMP 0xabbe60`), and it is a **batch** call:

| arg | meaning | evidence (13.60 VA) |
|---|---|---|
| arg1 | descriptor (loaded, then discarded by the op-0 path) | `0x8b47bffa mov esi,[rbx]`, overwritten at `0x8b47c04c` |
| arg2 | flag mask, tested against `0xe0bffb6f + (byte[proc+0xc81] ? 0x20000000 : 0)` | `0x8b47be94-0x8b47beac` |
| arg3 | entry array | `0x8b47bf68 mov r12,[rbx+0x10]` |
| arg4 | entry count | `0x8b47be85 mov r13d,[rsi+0x18]` |
| arg5 | `int *processed` | `0x8b47c355 mov rdi,[rbx+0x20]`, written at `0x8b47c35e` |

Each entry is 0x20 bytes (`0x8b47bf7e add r12,r14` with `r14 = index * 0x20`, then
`0x8b47bf86 mov edx,0x20 / call copyin`), and the opcode is at entry+0x1C
(`0x8b47bfa2 mov ecx,[rbp-0x7c]`, `0x8b47bfd8 cmp ecx,4 / ja`). That is byte-for-byte
`SceKernelBatchMapEntry`:

```
+0x00 start (qword)   +0x08 offset (qword)   +0x10 length (qword)
+0x18 protection (dword)                     +0x1C op (byte)
```

Measured on 14.10 (`1479a`, `1479b`): count 0 → rv 0, processed 0; count 1 with an all-zero
entry and op 2 → **rv 0, processed 1**; ops 0/1/3/4/5 with the same entry → EINVAL(22);
arg2 `0x1`/`0x1000`/`0x20000000`/`0xFFFFFFFF` → EINVAL while `0x0` and `0x10000000` → 0, which
is the `0xe0bffb6f` mask with bit 28 clear and bits 29-31 set; **arg1 is ignored**; and a
single-byte sweep with op=2 fixed shows +0x00/+0x01 and +0x10/+0x11 refused, +0x02..+0x0F and
+0x12 inert, and **+0x13 = 0xFF kills the caller**. 0xFF and 0xFF00 are not 4 KiB aligned while
0xFF0000 is, so the refused bytes are the low half of the two aligned qwords.

### op 2

`0xffffffff8b47c0b0`:

```
test esi,0x3fff ; jne EINVAL      ; start, low 32 bits only
test edx,0x3fff ; jne EINVAL      ; length, low 32 bits only
movzx edi,byte [rbp-0x80]         ; protection byte
and  ecx,8 ; jne EINVAL           ; protection bit 0x8 refused
add  rdx,rsi ; jb EINVAL          ; end = start + length, carry checked
shr  ecx,1 ; and ecx,0xffffffc1 ; or ecx,edi   ; WRITE implies READ
rdi = proc->vm_map ; xor r8d,r8d
call 0xffffffff8ac8bdb0           ; vm_map_protect(map, start, end, prot)
```

A start equal to the length-zero end is `KERN_SUCCESS`, which is exactly why the all-zero
entry returns 0 with processed=1.

Consequences that matter:

* This is `mprotect` without `mprotect(2)`. The syscall itself refuses any request whose
  `PROT_EXEC` bit is set (probe `423a`: "bit 2 is the only one refused"), and this path does
  not carry that check -- it hands `prot` straight to `vm_map_protect`, whose only limit is the
  entry's `max_protection`. Whether the pmap then installs the bit is a separate question the
  hypervisor answers, but **the vm_map's own view of the protection can be changed here**,
  which is what sys 547 reports.
* The alignment tests use 32-bit registers (`test esi,0x3fff`), so only the low half of each
  qword is checked. That is not a hole by itself -- every 64-bit value whose low 32 bits are
  page-aligned is page-aligned -- but it does mean the range end is computed from the full
  qwords, and `add rdx,rsi; jb` is the only overflow guard.
* Protection bit `0x8` is refused at the entry, before `vm_map_protect` is reached. The
  meaning of bit 3 in Sony's protection word is unmeasured.
* The other four ops queue or act through helpers at `0x8b478430`, `0x8b47d540` and
  `0x8b478bb0` (the last is the same routine `munmap` calls). The dispatch table sits at
  `0xffffffff8c29bf54`, **outside every dumped region**, so the op-to-case mapping has to be
  measured rather than read; only op 2 is pinned so far.

### What is still unmeasured

1. Whether op 2 moves the protection of a range the caller owns (`1479c` [A] is the positive
   control).
2. Whether it can make an executable page -- eboot text, a module's `.text` -- writable, i.e.
   whether `max_protection` admits `PROT_WRITE` for those mappings. If it can, the loader's own
   code can be edited in place and restored, which is code execution that never asks the pmap
   for an executable page.
3. What ops 0, 1, 3 and 4 do with a valid entry, since `1479a` only ever gave them a zero one.
4. Whether the queue/flush path (`0x8b47c3b0`, which ultimately calls `0x8ac8dc10` with the
   whole list) has its own validation, and which op feeds it.

`1479c` and `1479d` are written for (1)-(3) and are gated on a positive control so that a
refusal cannot be mistaken for a measurement.

| probe | capture | grade |
|---|---|---|
| 1479a | `results/phase36_realargs/1479a_sys548_batch_contract_20261109_192503.txt` | M |
| 1479b | `results/phase36_realargs/1479b_sys548_field_map_20261109_192622.txt` | M |

## 7. The two fault-in-flight races are closed, with validated oracles (2026-11-10)

Both experiments ask the same question in different places: **does a kernel copy
that is in flight survive the vm_map entry under it being deleted and
re-inserted?** `548` op 3 does exactly that delete/insert pair, so it is the only
lever a game process has for moving an entry while a copy is running.

A race is worthless without a *discriminating* oracle. The first version of each
probe was graded **V**, not because the console died but because the oracle could
not have seen the event it was built for:

- `1529b` filled the victim page with zeros. Op 3 installs a *zeroed* anon page,
  so a stale read and a fresh page are byte-identical. **Fixed** by filling the
  page with `0x41` before the one replacement, starting the child after that
  replacement, and scanning only the log bytes past the recorded offset. Any
  `0x41` after that point is a copy out of released memory.
- `1530a` refilled the object with a constant `0x41`. A page freed by an earlier
  shrink still holds our own `0x41`, so again the oracle could only ever see
  memory from *outside* the object. **Fixed** with a per-round fill byte and a
  `0x42` stamp written before every sample: a sample still holding `0x42` means
  the child was not delivering, and a byte that is neither this round's fill nor
  `0x00` is foreign.

### 7.1 copyin vs op 3 — `1529b`

Native child (`thr_new` 455, one ROP stack) calls `write(shmfd, V, 0x100)`
100,000 times while main replaces V's entry 20,000 times. Result
(`results/phase36_realargs/1529b_copyin_race_shm_20261110_110638.txt`):

| measurement | value |
|---|---|
| bytes scanned of the shm destination | 25,608,192 |
| `0x41` found after the replacement | **0** |
| child liveness (`lseek` SEEK_CUR shared offset) | 25,600,000 = `ITERS * CHUNK` exactly |
| placements that did not echo the requested address | 0 of 20,000 |
| `processed` word | 1 every round |

The liveness counter is load-bearing: without it a child that died after ten
writes produces the identical all-zero scan.

### 7.2 read vs ftruncate — `1530a`

Child does `lseek(fd,0,SEEK_SET); read(fd,V,0x1000)` forever; main does 3,000
cycles of `ftruncate(fd,0)` / `ftruncate(fd,0x10000)` / refill with a per-round
byte. Result (`..._1530a_shm_truncate_race_20261110_110919.txt`):

| measurement | value |
|---|---|
| samples | 3,000 |
| stale (sample still held our `0x42`) | **2** (0.07%) |
| foreign bytes in the 2,998 live samples | **0** |
| chain integrity (first and tail qword) | both match the expected gadgets |

### 7.3 Superseded: the first two runs measured a 2.5% overlap

Both runs above were then instrumented with mid-loop liveness sampling, and the
sampling invalidated them:

| probe | mid-loop samples | what it showed |
|---|---|---|
| `1529b` | `child_offset=25600068` at rounds 5000 / 10000 / 15000 / 20000 | the child finished **all 100,000 writes by round 500 of 20,000** |
| `1530a` | 2,815 of 3,000 samples still held the `0x42` stamp in the run before the per-round byte | the child had stopped delivering long before the loop ended |

The old check (final offset `== ITERS * CHUNK`) was satisfied by a child that
finished early, so it proved the child had run, never that it had run *during*
the replacements. **97.5% of the 1529b replacements and ~94% of the 1530a cycles
raced nothing.** A clean scan from them is a clean scan of an idle window.

A second reviewer (`Rev1530a2`) found two further defects in `1530a`:

- the `0x42` stamp was written **after** the refill and immediately before the
  sample, so the sample window excluded the truncate entirely and the stamp
  erased whatever the child had copied during it — `foreign=0` could not be read
  as "no leak";
- `pop rsp; chain_start` is arithmetically correct but **memory-unsafe**. The C
  syscall stub is entered at q6 with `RSP = A(q7)`, so its own pushes land on
  q6, q5 and **q4 — a live code pointer**. A linear chain never re-reads those
  slots, but a restart does, and that is exactly the `RIP=0` death with
  `err/trap 0x140e`: `RSP=0x312C86038`, `chain_start=0x312C63FF8`, i.e. 1,243
  complete iterations plus q0…q4 of iteration 1,244, with the `ret` inside
  `g_rdx` popping q4 after it had been overwritten. First/tail checks are blind
  to a single hole.

### 7.4 The rewritten instruments, and what they measured

Both probes use **bounded laps instead of a restart**: the chain emits `LAPS`
copies of `(lseek(...); <writes or reads>)` and then `thr_exit(431)`. One lap
rewinds, so the file never grows past one lap-sized window and the chain is
finite — no slot is executed twice. Sizing follows the measured rate of about
200 child syscalls per main round.

**`1529b`** (`results/phase36_realargs/1529b_copyin_race_shm_20261110_114359.txt`):
`LAPS=60`, `WRITES=2048`, `ROUNDS=500`. Liveness is the shared file offset
taking **at least three distinct values** across five mid-loop samples.

| measurement | value |
|---|---|
| placements that did not echo the requested address | 0 of 500 |
| rounds where the victim page was unmapped or non-zero | 0 |
| bytes scanned of the shm destination | 524,288 |
| bytes carrying the `0x41` the released page held | **0** |
| child offset at the five samples | 206,848 / 388,096 / 265,728 / 137,216 / 337,920 (5 distinct) |

The distinct offsets are the load-bearing part: the child was still writing at
round 500, so every one of the 500 replacements happened while a `copyin` was in
flight.

**`1530a`** (`results/phase36_realargs/1530a_shm_truncate_race_20261110_114527.txt`)
needed two corrections before its oracle meant anything, and the history is
worth keeping:

1. a second 4 KiB read after `lseek(0)` lands **inside page 0**, not in page 1,
   because the page size is `0x4000`. The first run with two destinations
   reported `0x62 0x62 0x62 0x62 0x62` — round 1's liveness byte — as "foreign
   bytes in the release target". The chain now seeks to `0x4000` explicitly.
2. clearing the oracle buffer only at the start of the race is not enough: a
   legitimate read of the still-live marker page leaves `0x41` in it, and a later
   round reads that as a leak. `W` is now cleared **after** the truncate
   releases the page and **before** the regrow recreates it, so the only way a
   `0x41` reaches it is a read that returned pre-truncate content from a page
   the kernel had already freed.

| measurement | value |
|---|---|
| samples (60 rounds × 2 cycles) | 120 |
| samples where the child delivered no live byte | **0** |
| child delivered per quarter | 30 / 30 / 30 / 30 |
| foreign bytes in the release target | **0** |

### 7.5 What these results mean

Deleting and re-inserting a `vm_map_entry` is serialised against the page faults
that a kernel `copyin` needs, and shrinking a shm object does not leave a page
the pager still hands out: no stale byte was read in 524,288 bytes copied out of
a replaced page or in 120 `ftruncate`-release cycles. Neither path is a UAF
surface reachable this way.

The earlier runs in §7.1 and §7.2 measured only the frames their child was
active for (2.5% and ~6% of their loops) and are **superseded**; the numbers
above are the ones to cite, with ledger rows `1529b` and `1530a`, both **M**.

### 7.6 The same race against a filesystem pager (MLFS), and the two instruments it needed

`1531a` (`results/phase36_realargs/1531a_mlfs_truncate_race_20261110_115112.txt`,
ledger **M**) repeats the read-vs-truncate race against a file on
`/av_contents/content_tmp/`, a writable MLFS path (947a) whose pages live in a
Sony zone rather than the shm object. 947b had only tested the serial case
(write, truncate through a second descriptor, read back zero); this is the
concurrent one.

| measurement | value |
|---|---|
| samples (60 rounds × 2 cycles) | 120 |
| samples where the child delivered no live byte | **0** |
| child delivered per quarter | 30 / 30 / 30 / 30 |
| control reads of the regrown page taken by the main thread | 120 |
| of those, non-zero (and therefore skipped) | **0** |
| foreign bytes in the read destination | **0** |

Three instrument bugs had to be fixed before those numbers meant anything, and
each one first produced a plausible-looking false positive:

1. **the child shared a file descriptor with the writer.** File offsets are per
   open file description, so `arm()`'s `lseek(0x4000)` landed between the
   child's `lseek(0)` and its `read`, and the child read the marker page into
   the liveness channel. Fixed by opening a second descriptor for the child.
2. **the liveness channel was wiped by the same truncate it was measuring.**
   With `ftruncate(0)` both pages are released, so after the regrow page 0 no
   longer held the round byte and 64 of 65 samples read "dead" — the probe raced
   nothing. Fixed by truncating to **one page** (`0x4000`), which releases the
   marker page and leaves the liveness page alive.
3. **MLFS does not reliably clear pages across a full truncate-then-grow.** With
   `ftruncate(0)` the marker page came back holding `0x41` in 55 of 120 cycles,
   and the main thread's own read proved it. Every sample is now gated on the
   main thread first reading the regrown page and getting zeros; a cycle that
   fails the gate is counted as skipped, not as clean.

The gate is the load-bearing change: without it the probe reported 3380 foreign
bytes that were the file's own surviving content, not a page served out of the
free list.

**What it adds.** `vm_map` delete/insert (1529b), the shm pager (1530a) and a
filesystem pager (1531a) all refuse to hand a read a page the kernel has already
released. Three different release paths, three validated oracles, one answer.

### 7.7 Third round of instrument fixes (2026-11-10, after `RevRace2`)

Three more defects, each of which could have turned a real leak into a clean
result, and each fixed before the rows above were re-recorded:

1. **`1529b` scanned the destination once, at the end.** The child rewinds and
   rewrites the same 512 KiB window every lap, so a stale byte from an early lap
   is overwritten within milliseconds and the final scan can only see the last
   lap — of a race that ran ~50 laps. The window is now scanned **every round**.
   Result: `stale_during_loop=0` over all 500 rounds, which is a claim about the
   whole loop rather than its last frame.
2. **`1529b` never installed its fake TCB.** The chain wrote one and never
   referenced it, so a placement that left the victim unmapped made the child's
   `write` return `EFAULT`, the libkernel stub stored errno through `%fs:0`, and
   the child died silently while the loop kept counting placements. The
   `sysarch(165, 129)` preamble is now part of the chain, and liveness also
   requires the **last two** offset samples to differ, so a child that died after
   the third mark cannot pass.
3. **`1530a` and `1531a` discarded every `ftruncate` return value.** A failed
   shrink leaves the marker page live and produces a false `FOREIGN BYTES`; a
   failed grow leaves the page beyond EOF and produces a false clean. Both
   probes now capture all three calls per cycle, and the verdict is `VOID` when
   any failed. Both also now require `dead == 0` for a clean verdict instead of
   tolerating 10% dead samples.

Final numbers, all three runs on pid 186, all ledger **M**:

| probe | samples | dead | instrument failures | foreign bytes |
|---|---|---|---|---|
| `1529b` (`..._115537.txt`) | 500 rounds | — | `bad_place=0 bad_prot=0` | **0** in-loop and 0 in the final scan |
| `1530a` (`..._115645.txt`) | 120 | 0 | `truncate_fail=0` | **0** |
| `1531a` (`..._115707.txt`) | 120 | 0 | `truncate_fail=0 gate_skipped=0` | **0** |

With that, three release paths — a `vm_map` delete/insert, the shm pager, and a
filesystem pager — each refuse to hand a read a page the kernel has already
released, measured with instruments that abort rather than report when their own
preconditions fail.


### 7.8 The MLFS content-preservation caveat is not an allocation leak

Section 7.6 records that a full `ftruncate(0)` followed by a grow returns the
file's previous content in 55 of 120 cycles. That is the page cache keeping
pages attached to the **same vnode** across a truncate; the security question is
whether those pages can later be handed to a *different* object.

`947b` already answers it: `[B]` unlinks the file, reopens the same name and
reads `0` — "new empty inode, >0 => old data resurrected", so a recreated file
does **not** inherit the released pages — and `[C]` truncates through a second
descriptor and reads `0` through the first, so both descriptors see the
truncate. Capture:
`results/phase17_new_vectors/947b_mlfs_inode_lifetime_20261028_214857.txt`.

So MLFS preserves content only within one inode lifetime, which is why the gate
in 7.6 has to exist at all (the child would otherwise legitimately read live
marker bytes) and why it costs nothing: nothing outside the file ever sees them.

## 8. op 2 measured end to end: a real mprotect, gated on 16 KiB alignment (2026-11-10)

The op-2 rows that said "548 refuses a real range" were probe bugs. The 13.60
body tests alignment of **both** the start and the length before it dispatches:

```asm
0x8b47c0b7  test esi, 0x3fff      ; start % 0x4000
0x8b47c0bd  jne  0x8b47c2b8       ; EINVAL(22)
0x8b47c0ca  test edx, 0x3fff      ; length % 0x4000
0x8b47c0d0  jne  0x8b47c2b8       ; EINVAL(22)
0x8b47c0d6  movzx edi, [rbp-0x80] ; protection byte
0x8b47c0dc  and  ecx, 8; jne EINVAL ; prot bit 0x8 refused
0x8b47c0e5  add  rdx, rsi; jb EINVAL ; end = start + len
0x8b47c0f5  shr  ecx, 1; and ecx, 0xffffffc1; or ecx, edi  ; WRITE implies READ
0x8b47c10c  call 0xffffffff8ac8bdb0  ; vm_map_protect(map, start, end, prot, set_max=0)
```

`1479c`, `1479d` and the anon rungs of `1481g` all passed `len = 0x1000`, so each
of those answered EINVAL at `0x8b47c0d0` and never reached the call. The
corroboration had been in the ledger all along: `1479b`'s single-byte poison sweep
saw `+0x12 = 0xFF` (length `0xFF000000`, aligned) **kill the process**, which only
happens if the call runs and walks the whole map.

`1533a` supplied the missing measurement on two anonymous pages and one device
window:

| Rung | Result |
|---|---|
| anon prot 3 -> 1 | `rv=0 processed=1`, 547 reads `0x1` |
| anon prot 1 -> 2 | `rv=0 processed=1`, 547 reads **`0x3`** - WRITE implies READ |
| anon prot 3 -> 0 | `rv=0 processed=1`, 547 reads `0x0` |
| anon prot -> 7 | **`rv=-1 13 Permission denied`** - max_prot excludes X |
| start misaligned (`P+0x2000`) | `rv=-1 22 Invalid argument` |
| length misaligned (`0x2000`) | `rv=-1 22 Invalid argument` |
| prot `0x18` | `rv=-1 22 Invalid argument` |
| count 2, both prot 3 | `rv=0 processed=2`, both entries applied |
| device `SceGnmTrapData` `0x33 -> 1 -> 0x33` | all three taken, window restored |

Four consequences:

1. **op 2 is not a W^X bypass.** PROT_EXEC is refused with EACCES, not EINVAL, so
   the refusal is `vm_map_protect`'s subset-of-max_prot check and the anon page's
   `max_prot` does not carry X. This is a second, independent confirmation of the
   W^X wall: `mprotect(2)` refuses X at its own entry (`423a`), and 548 op 2
   refuses it one layer down at the map.
2. **The alignment constant is `0x4000`, not `0x1000`.** Any future 548 probe that
   uses 4 KiB ranges is void by construction; the whole `SceKernelBatchMapEntry`
   family is built on the console's 16 KiB page size.
3. **`count` really is a batch.** `processed=2` with both protections visible in
   547 means the loop applies every entry, so a 128-entry batch is 128 vm
   operations per syscall.
4. **547's flags word is `0x610020` for every region tested** - anon, device
   window, and both anon pages - so it is not a per-region attribute. Record it
   as a constant of the record, not of the mapping.

Still open: op 0 and op 1 have never succeeded. The case at `0x8b47bff3` is gated
on four per-process fields before it builds its argument block
(`cmp byte [map+0x1c9],2`, `test byte [proc+0x464],2`, `test ecx,0x400`,
`cmp dword [proc+0x5d4],0x2500000`), and `0x5d4` is compared against three
different size constants in seven other places, so committing memory may satisfy
it. `1534a` tests exactly that.

Capture: `results/phase36_realargs/1533a_sys548_16k_alignment_20261110_134214.txt`.

## 9. The op 0/1 "gate" is a path selector, not a refusal (2026-11-10)

The dispatcher's four-field test was previously read as an accept/refuse gate on op 0 and op 1:

```asm
0x8b47c00e  cmp   byte  [r8 + 0x1c9], 2      ; r8 = proc->vmspace (map)
0x8b47c016  jb    0xffffffff8b47c1c5
0x8b47c01c  test  byte  [rdi + 0x464], 2
0x8b47c023  jne   0xffffffff8b47c1c5
0x8b47c029  test  ecx, 0x400                 ; ecx = uap[2], the flag word
0x8b47c02f  jne   0xffffffff8b47c1c5
0x8b47c035  cmp   dword [rdi + 0x5d4], 0x2500000
0x8b47c03f  jb    0xffffffff8b47c1c5
```

It is not. **Every one of those branches lands on `0x8b47c1c5`, which is a second, complete map path**, not an
error block. It re-validates the same entry and then builds a request and calls a helper:

```asm
0x8b47c1cc  test  edi, 0x3fff            ; start % 0x4000
0x8b47c1d2  jne   0xffffffff8b47c2b8     ; EINVAL
0x8b47c1df  test  r8d, 0x3fff            ; length % 0x4000
0x8b47c1e6  jne   0xffffffff8b47c2b8     ; EINVAL
0x8b47c1fd  test  r9, 0x8000000000003fff ; length < 2^47 and 16 KiB aligned
0x8b47c200  jne   0xffffffff8b47c2b8     ; EINVAL
0x8b47c20d  and   r10d, 8 ; jne EINVAL   ; protection bit 0x8 refused
0x8b47c213  or    ecx, 1
0x8b47c216  mov   [rbp-0x68], rdi        ; request+0x00 = start
0x8b47c21a  mov   [rbp-0x60], r8         ; request+0x08 = length
0x8b47c21e  mov   [rbp-0x58], edx        ; request+0x10 = protection
0x8b47c221  mov   [rbp-0x50], ecx        ; request+0x18 = arg2 | 1
0x8b47c224  mov   qword [rbp-0x48], 0    ; request+0x20 = 0
0x8b47c22c  mov   [rbp-0x40], esi        ; request+0x28 = fd, from uap[0] (mov esi,[rbx] at 0x8b47bffa)
0x8b47c22f  mov   [rbp-0x38], r9         ; request+0x30 = position, from entry+0x08
0x8b47c23e  call  0xffffffff8b478430
```

`0xffffffff8b478430` is the same helper op 3 reaches. So a failed selector does not refuse the entry; it runs
the **descriptor-backed** map (the fd comes from `uap[1]`, the entry's `+0x08` is the file position, and
`uap[2]` is the flag word) instead of the anonymous one. This retires the whole "op 0/1 are credential-gated"
reading, and it explains why `test ecx, 0x400` sits in the selector: `ecx` is `uap[2]`, not an entry field.

`0xffffffff8b478430` itself returns `0x16` (EINVAL) from eight distinct checks, in order: the offset field's bit 1
(`0x8b4786b1 and edi,3 / cmp edi,3` with `setne` combined against `request+0x20 < 4`), `request+0x28 != -1`
together with a nonzero length when offset bits `0x1100` are set, `request+0x28 != -1` again when offset bit `0x400`
is set, offset bits `0x1000c` when the process flag `proc+0xc81` is set, `offset & 0x88000 != 0`, a signed
compare against a **VM-entry quota** `proc+0x5e0 > 0xc3567` (800,103 entries) when the length is zero, and a
`test sil,1 / cmp r8d,0xf / ja EINVAL` for odd lengths. A 16 KiB-aligned length with offset 0 passes all of them:
`0x8b478712 and edx,0x3fff` is zero, so `0x8b47871b xor rcx, 0xffffffffffffbfff` leaves a huge `rcx` that
`0x8b478722 cmp rcx,rsi / jae` compares favourably against the length.

So op 0 is a descriptor mmap with a 16 KiB file position, and every previous measurement of it used a
non-aligned position or a non-aligned length. That is what `probes/phase36_realargs/1534b_sys548_op0_descriptor_map.lua`
tests. The point of the run is not memory growth - it is whether this second map entry point backs a descriptor
that 477 cannot, which matters for `/dev/dmem0` past its `0x120000000` boundary (1478a) and for the physhm
descriptor (629) that 477 maps and that kills on first touch (321a).

A reading caveat carried over from `Review1534a`: the earlier header for this work labelled `0x8b47c035` a quota
gate on committed memory, and that is wrong on both counts - it selects the anonymous path rather than refusing,
and `proc+0x5d4` is a per-process configuration value that process init zeroes
(`0xffffffff8aefba5e mov qword [rbx+0x5d4], 0`), so it is never the thing that decides acceptance.

The request is therefore `{start, length, protection, arg2|1, 0, fd, position}`: `arg1` is a descriptor, `arg2` is a
flag word, and the entry's `+0x08` is a **file position**, not a VA offset. Every earlier measurement of op 0 or op 1
passed a position that was not 16 KiB aligned, so each one answered EINVAL at `0x8b47c1ec` and never reached the
descriptor at all - including `1488b`'s "op 0 returns EINVAL for every fd", which was really EINVAL for every
position.

## 10. op 0 measured with a legal position: EBUSY at a free address (2026-11-10)

Section 9 predicted that `1534b` would be the first clean measurement of op 0, because every earlier rung had
failed the 16 KiB position check before the descriptor was touched. It was sent, and the prediction holds for the
entry checks only. `results/phase36_realargs/1534b_sys548_op0_descriptor_map_20261110_141234.txt`, COMPLETE,
0.844 s, pid 207, `674` reporting 316 records and `TARGET = 0x500000000` confirmed unmapped by `547`:

| rung | result |
|---|---|
| `/dev/zero` pos 0 | `rv=-1 EBUSY(16)`, `processed=0` |
| bogus fd `0xFFFFFFFF` pos 0 | `rv=-1 EBUSY(16)` - identical |
| `/app0/eboot.bin` pos 0 | `EBUSY(16)` |
| `/app0/eboot.bin` pos 0x4000 | `EBUSY(16)` |
| `/dev/dmem0` pos 0 | `EBUSY(16)` |
| `/dev/dmem0` pos `0x120000000` | **`EACCES(13)`** |
| `/dev/gc` pos 0 | `EBUSY(16)` |
| position `0x1000` (misaligned) | `EINVAL(22)` |
| `arg2 = 0x400` | `EINVAL(22)` |
| `op 3` at the same TARGET | **`rv = 0x500000000`**, `547` prot 3 afterwards |

Three conclusions follow, and one of them retires part of section 9.

1. **The entry checks run and the descriptor is consumed.** A misaligned position and `arg2` bit `0x400` both stop
   at `EINVAL` exactly where the listing puts them. A bogus descriptor cannot produce `/dev/dmem0`'s own
   `EACCES(13)` for a position above `0x120000000` - the same refusal `477` gives for that offset in `1478a` - so
   the fd reaches the device. The bogus fd and the valid ones answering identically means `EBUSY` is raised
   *before* the descriptor is validated, not because of it.
2. **`EBUSY` is not an address conflict.** op 3 mapped `TARGET` successfully in the same run and `547` read it back
   at prot 3, so the address was free and usable. Whatever refuses op 0 is not "something is already there".
3. **op 0 is therefore not a map that creates a range at a chosen address.** Together with `1480b`, where op 0
   returned `0` with `processed=1` on page A that the probe already owned (and `547` showed A unchanged, prot 3,
   before and after), the consistent reading is that op 0 acts on a range that already exists. That is what
   `probes/phase36_realargs/1534c_sys548_op0_on_live_range.lua` tests.

### Where `EBUSY` comes from

The mmap helper `0xffffffff8b478430` does not return errno values directly for every failure. Its tail,
`0xffffffff8b478b20`..`0xffffffff8b478ba0`, is a transcoder:

```asm
0x8b478b3d  mov rax, [rdi + 8]            ; td -> proc
0x8b478b47  mov rdi, [rax + 0x200]        ; the vm_map
0x8b478b4e  mov eax, 0x101
0x8b478b53  bextr r8d, r8d, eax
0x8b478b58  call 0xffffffff8ac8f830       ; the vm_map_find core
0x8b478b5d  cmp eax, 5
0x8b478b60  ja  0x8b478b95                ; -> EINVAL(22)
0x8b478b64  lea rdx, [rip + 0xe23365]     ; table at 0x8c29bed0, 6 entries
0x8b478b72  jmp rcx
0x8b478b7d  cmp byte [rax + 0xc81], 0
0x8b478b84  mov eax, 0xc                  ; ENOMEM(12)
0x8b478b89  cmove eax, ecx                ; or EINVAL(22) when proc+0xc81 is clear
0x8b478b8e  mov eax, 0x10                 ; EBUSY(16)
```

So `EBUSY` is one arm of a mapped internal status, chosen by a table that sits at `0x8c29bed0` - outside every
13.60 dump, exactly like the op table. Two of the arms are readable: one returns ENOMEM or EINVAL depending on
`proc+0xc81` (the same process flag that appears in op 0's offset validation), and one returns EBUSY. Which
`vm_map_find` status lands on the EBUSY arm cannot be read from the corpus, and it does not need to be: the
measured fact is that a free, mappable, 16 KiB-aligned address with a consumed descriptor is answered with
`EBUSY`, while the same address is mappable through op 3.

### The unmap helper, and the ops that do not reach it

`0xffffffff8b478bb0` is `munmap`'s kernel side: it rounds `start` down and `start+len` up to `0x4000`, bounds them
against `[map+0x20]` and `[map+0x28]`, then calls `vm_map_lock` (`0x8ac86480`) and `0x8ac89370`, which is
`vm_map_delete` - it compares `start` against `end`, takes the map lock, calls `vm_map_lookup_entry`
(`0x8ac86c40`), and tests `[entry+0x50]` object plus `cmp byte [entry+0x9d], 0xb` (the same type-11 test as 654
and 673). Its transcoder maps to ENOMEM(12), EACCES(13) and EINVAL(22).

The 548 body at `0xffffffff8b47c185` builds exactly `{start, len}` and calls that helper, so one of the five
opcodes is munmap. Neither op 1 nor op 4 is it: `1480b` re-read with `rv`-checked `547` shows page A still mapped
at prot 3 after the op 4 rung and page D still mapped and still holding `0x33334444` after the op 1 rung. The
op-to-case table at `0xffffffff8e29bf54` is outside the dump, so which opcode reaches `0x8b47c185` remains open,
and with it whether that arm is reachable at all.

One more measured asymmetry, for the same table: **op 3 returns `0` at an address that is already mapped**
(`1480b`) and **the mapped address at a free one** (`1534b`). op 0 does the opposite - `0` when the range exists,
`EBUSY` when it does not. Whatever the two opcodes are, they are not two spellings of the same call.

## 11. op 0 on a live range, op 1's effect, and W^X closed on the device window (2026-11-10)

Two runs, both `M`, and between them they retire the last two shapes that could have turned a batch-map opcode into
an executable mapping.

### 11.1 `1534c` - op 0 refuses a live range too

`results/phase36_realargs/1534c_sys548_op0_on_live_range_20261110_142452.txt`, COMPLETE, pid 207. The probe created
its own range with op 3 (`U = 0x500004000`, `547` prot `0x3`, sentinel `0xAABBCCDD` readable) and then called op 0
on that range with every descriptor it had:

| rung | result |
|---|---|
| `/app0/eboot.bin` pos 0, prot R | `EBUSY(16)`, `processed=0`, U unchanged |
| `/dev/zero` pos 0, prot RW | `EBUSY(16)`, U unchanged |
| `/dev/dmem0` pos 0 | `EBUSY(16)` |
| `/dev/dmem0` pos `0x120000000` | `EACCES(13)` |
| physhm fd from `629(1,2,0,0)` | `EBUSY(16)` |
| fd 0 and fd `0xFFFFFFFF` on a second op-3 range | `EBUSY(16)`, sentinel intact |
| free slot `0x600000000`, `arg2` `0x12` / `0x20` / `0x40` | `EINVAL(22)`, `processed` left as the `0xEEEEEEEE` sentinel |
| free slot, `arg2` `0x10` | `EBUSY(16)` |

`674`'s record count went `318 -> 318` across every `[A2]` and `[A3]` rung, so nothing was mapped anywhere, not
merely at a different address. The `dmem0` ACL word is still the one fact that proves the descriptor is consumed: a
bogus fd cannot produce a device-specific `EACCES` for a position above `0x120000000`.

So op 0 is not a map at a chosen address (`1534b`), and not an object attach to an existing range either. It answers
`EBUSY` for a legal 16 KiB range backed by a descriptor, on an entry the caller owns, with all four flag words the
descriptor path can be given. Together with `1480b`'s one success - fd 0, `arg2` 0, on a page created by `477`,
returning `0` with `processed=1` and changing nothing - the only reading left is that op 0 succeeds on ranges whose
object it already recognises and does something inert with them. It is not a primitive.

### 11.2 op 1: measured, and deliberately not concluded

> **Superseded 2026-11-10 by §14.** `1537a` measured op 1 on four ranges through `547` and a fresh `674` sweep
> and the record was gone every time: op 1 is munmap. The paragraph below is kept only so the earlier reading is
> not silently rewritten; its `1480b` clause is also void (§12.4 - that rung never called op 1).

`op 1` on `U` returned `rv = 0`, `processed = 1`, and the very next read of `U` faulted - the capture ends in the
loader's ucontext dump. That is the measurement. **It is not evidence that op 1 removed the mapping**, and this note
exists so the next reader does not treat it as such: `547` was never re-read between the call and the read, and
`1480b` has op 1 on a `477`-created page leaving it mapped, at prot 3, and still holding `0x33334444`. The
difference may be the mapping's origin, the object it points at, or the fault may be a page-level failure inside a
still-present entry. Splitting those costs one probe with a `547` check before the read, which is what any future
op-1 work must do.

**Probe rule this run paid for:** never dereference a range after a `548` opcode without a `v`-checked `547` first.
`Review1534c` flagged exactly this pattern as D3 elsewhere in the same probe and it was applied there; it was not
applied to `[G]`, and that is what ended the run.

### 11.3 `1535a` - the device window's max_prot excludes EXEC

`results/phase36_realargs/1535a_gpu_window_exec_via_548_20261110_143418.txt`, COMPLETE, 2.203 s, pid 214. `674`
named `SceGnmTrapData` at `0xF00004000..0xF00008000`, `547` reading prot `0x33`. The probe saved the 8 bytes at
`+0x100`, wrote `48 89 07 EB FE` (`mov [rdi],rax; jmp $`) and read them back - so the window is writable, which
`1481b` had already shown - then asked op 2 for an executable protection:

| protection asked | result | `547` afterwards |
|---|---|---|
| `0x37` (R\|W\|X plus both attribute bits) | `rv=-1 EACCES(13)`, `processed=0` | `0x33` |
| `0x7` (R\|W\|X) | `rv=-1 EACCES(13)`, `processed=0` | `0x33` |
| `0x5` (R\|X) | `rv=-1 EACCES(13)`, `processed=0` | `0x33` |
| `0x33` (its own value, as a control) | `rv=0 processed=1` | `0x33` |

`0x37` keeps both attribute bits and adds only `0x4`, and it is refused; `0x33`, which differs from it by exactly
that bit, is accepted. So the refusal is the EXEC bit and not a dropped attribute, which is the confound that made
`1481g`'s `0x33` result look like an executable state. `[E]` and `[F]` were skipped by design because no accepted
value carried `0x4`, the original protection was re-applied, and the original bytes were written back.

**Consequence.** The 14.10 `vm_map_entry` that backs a GPU device window has a `max_prot` without EXECUTE, exactly
like an anonymous page (`1533a`) and like every `477` mapping (`424a-424c`). `mprotect(2)` and `548` op 2 both
refuse it, and there is no third entry point to `vm_map_protect` that a game process can reach. No mapping this
process can own will ever be executable, so no kernel code execution can begin from userland memory - the remaining
route to kernel R/W is a kernel memory-safety bug, not a W^X bypass.

## 12. The five 548 op cases, in order (2026-11-10)

> **Correction, 2026-11-10 (after `1537a`).** The clause below - "the two measured
> ops pin the order" - is not sound. It reads ascending addresses as op order, and
> `1537a` measured op 1 at `0x8b47c185`, which is the *highest* of the five. So
> ascending address order is false and the two unmeasured bodies cannot be
> assigned that way. What survives is an assignment by **elimination**: op 0 is
> `0x8b47bff3`, op 2 is `0x8b47c0b0`, op 3 is `0x8b47c11e` and op 1 is
> `0x8b47c185`, all measured, so the only body left - `0x8b47c088`, the queueing
> case - is **op 4**. `probes/phase36_realargs/1537b_sys548_op4_and_op0_semantics.lua`
> tests it.


The dispatch table at `0xffffffff8e29bf54` is outside every dump, so which case
belongs to which op had to be inferred. It can be settled without the table:
the five case bodies sit at strictly ascending addresses, and the two ops that
have been measured pin the order.

| op | case body | what it does |
|---|---|---|
| 0 | `0x8b47bff3` | four gates (`[map+0x1c9] >= 2`, `[proc+0x464] & 2` clear, entry `offset & 0x400` clear, `[proc+0x5d4] >= 0x2500000`) then the elevated helper `0x8b47d540`; otherwise falls to the descriptor path at `0x8b47c1c5` |
| 1 | `0x8b47c088` | **does not touch the map**: normalises the protection byte (WRITE implies READ), updates the processed counter, then jumps to `0x8b47bf1a` and appends the entry to a pending list |
| 2 | `0x8b47c0b0` | alignment checks, then `vm_map_protect` (`0x8ac8bdb0`) |
| 3 | `0x8b47c11e` | alignment checks, builds `{start, length, prot, flags|0x1000, fd = -1, offset = 0}`, maps |
| 4 | `0x8b47c185` | alignment checks, then the munmap helper `0x8b478bb0` in-line |

ops 2 and 3 are the measured ones (`1533a`, `1534b`), and they land on the
protect and map cases exactly as the ascending order predicts, so the remaining
three follow.

### 12.1 op 1 is a queue, and the queue has its own applier

The per-entry loop copies exactly `0x20` bytes from `entries + index*0x20`
(`0x8b47bf68`..`0x8b47bf95`, `call 0x8ac19280`), then dispatches on the op byte
at entry `+0x1C` (`0x8b47bfa2 mov ecx,[rbp-0x7c]`). Before dispatching a
**non-4** entry it flushes the pending list (`0x8b47bfaa`..`0x8b47bfb9`,
`call 0x8b47c3b0`); `cmp ecx,4 / je 0x8b47bfd3` is the one case that skips that
pre-flush. So:

* An op 1 entry does nothing when it is copied. It is `malloc`ed into a node
  (`0x8b47bf1a`..`0x8b47bf54`, `call 0x8adfb880` then `call 0x8ac19be0`) and
  linked. A lone op 1 batch is only applied when the loop ends and flushes.
* The apply goes through `0x8b47c3b0` to the bulk applier `0x8ac8dc10`, **not**
  through `vm_map_protect`. That is a second, independent validator over the
  same protection byte.
* `0x8ac8dc10` validates `cmp byte [node+0x21], 0xa` and `test r12b,0xae` on the
  protection before it touches the map, and takes `map+0x170` or the mutex at
  `map+0x1a8` depending on `byte [map+0x244] & 0x10` — a different lock
  discriminator from the one `vm_map_protect` uses.

### 12.2 What that makes testable

Three questions follow, and none needs a load:

1. **Does op 4 remove?** The listing says its case calls the munmap helper
   directly, but `1480b` measured a `477` page still mapped after op 4. One of
   those is wrong.
2. **What does the queued apply do to a range?** `1534c` read a page right after
   op 1 returned `rv=0 processed=1` and the read faulted; the ledger row that
   called that "removed" was corrected to grade I because `547` was never
   re-read. If the queued applier leaves a range present but unusable, op 1 and
   op 2 disagree about what a protection means, and that disagreement is the
   interesting surface.
3. **Does the queued applier enforce the same protection limits as op 2?**
   op 2 returns `EACCES(13)` for any protection carrying bit 4 because the map's
   `max_prot` excludes EXEC (`1533a` on anonymous memory, `1535a` on the one
   device window a game process can reach). The applier's own `test r12b,0xae`
   is a different test over the same byte. If it accepts 5 or 7 and `547` reads
   the value back, the deferral is a W^X bypass that the direct path does not
   have. Nothing has to execute to answer that, and if it does not, the answer
   costs one run.

`probes/phase36_realargs/1537a_sys548_op1_removal_check.lua` asks all three
through `674` (the map table) and `547` (the per-range record), so no outcome
can turn a fault into a false "removed" reading.

## 13. The VM-map race is not buildable from Lua (2026-11-10)

Every 548 measurement so far has been sequential, so "the map lock holds" is an
untested assumption, and a protect racing a map or an unmap is the one bug class
over this syscall that a sequential contract cannot reach. A probe was designed
to contend it (`548` op 2 and op 3 from one thread, `547` from another) and then
abandoned before it was sent, because **the thread facilities this process has
cannot express the experiment**:

* `run_lua_code_in_new_thread` is not reentrant - six gated threads issuing no
  syscall at all die (`496c`), and the death lands at the **second** spawn while
  the first is parked (`496d`). One helper, not two.
* That one helper does not survive a syscall loop. Three shapes against the same
  200 000-iteration loop - a `SOCK_DGRAM` socketpair, `/dev/zero`, and a single
  closure - each spawned, ran, and then took the connection down (`1517a`,
  `1518a`). So the contending side cannot be a loop of `548` calls.
* A death in the helper **kills the whole process**, so a helper death and a
  genuine map anomaly produce the same capture. The oracle cannot separate the
  thing being tested for from the instrument.

The remaining option is a `thr_new(455)` child running a ROP chain of `548`
calls, which is expressible (the child-RoP catalogue gives `pop rax/rdi/rsi/rdx/
rcx/r8`, and `fn_addr` is the stub). It was rejected on measurement value rather
than on safety: a child chain of thirty syscalls completes in microseconds
against a Lua-side `547` loop that is thousands of times slower, so the overlap
window would be a rounding error, and both contended paths take a map lock by
construction (`vm_map_protect` `0x8ac8bdb0` takes `vm_map_lock`; the bulk
applier `0x8ac8dc10` takes `map+0x170` or `map+0x1a8`).

Consequence for the record: **the concurrency axis over the VM layer is closed
as unmeasurable, not as clean.** Nothing in this repository may cite a clean
race result for `548`, because none was run.

### 13.1 Correction (2026-11-10): the third ground is wrong — a sustained native loop exists

The paragraph above rejects the `thr_new(455)` child on the grounds that "a child
chain of thirty syscalls completes in microseconds". That measures a *chain*, not
a *loop*, and the corpus already contains a working loop.

`results/phase17_new_vectors/157a_syscall_loop_thread_20261020_172245.txt`
(parent pid 110) does exactly this:

```
[0] syscall_address=0x00000008_09D6CB57 wrapper(mov rax,116)=0x00000008_09D6CB50
[0] stack=0x00000003_10F40000 slots=131072
[1] child: RIP=0x00000008_09D6CB50 RSP=0x00000003_10F40000 RDI=0x00000003_10DDC000
[1] thr_create: ok=true rv=0 tid=0x00000000_00018D04
[2] after 40 ms: timeval sec=1792513365 usec=199514 624 delta=0 thr_kill(tid,0) rv=0
[2] 20 ms later:  timeval sec=1792513365 usec=220516
[3] *** CHILD LOOPED IN THE KERNEL: timeval advanced ***
[4] final canary: ok=true pid=110
```

The child re-enters the libkernel wrapper every ~21 µs (the 20 ms gap between
the two samples is 21 002 µs of `gettimeofday` time), the parent reads a live
`timeval` page while it runs, and the process survives. `157a`'s own header
explains the trick: `syscall.syscall_address` is the *gettimeofday* wrapper
`+ 7`, so `syscall_address - 7` is `mov rax,116; mov r10,rcx; syscall; ret`, and
a stack of nothing but that address re-enters it on every `ret`.

So the instrument exists: a native child that issues tens of thousands of
syscalls per second for as long as the parent needs, with the parent free to run
the slow side in Lua. What `§13`'s other two bullets still hold — the Lua helper
thread is not reentrant and its death kills the process — and they are the reason
the *second* actor must be native rather than a second Lua thread.

What §13's conclusion therefore becomes: the VM-concurrency axis is
**unmeasured**, not unexpressible, and a probe of the kind §13 described can be
written with `157a`'s loop on the contending side. The oracle still has to
survive the instrument: the parent's `547` must be `rv`-checked before any load,
because a load from a range the child unmapped is a clean SIGSEGV that kills the
process (the rule `1534c` paid for).

### 12.3 The flush is not privilege-gated for a game process

The flush helper `0x8b47c3b0` opens with two capability tests on `[td+0x140]`:

```asm
0x8b47c3e5  call 0xffffffff8afc9560   ; ([+0x6f] & 0x40) && ([+0x82] & 0x80)
0x8b47c3ea  mov  r15d, 1
0x8b47c3f0  test eax, eax
0x8b47c3f2  jne  0xffffffff8b47c4e4   ; nonzero -> return 1, nothing applied
0x8b47c3ff  call 0xffffffff8afc95a0   ; ([+0x6f] & 0x40) && ([+0x82] & 0x40)
```

`0x8afc9560` and `0x8afc95a0` are four instructions each: two `test`/`jne`
pairs, returning 1 only when **both** bits are set. A game process has them
clear, so both calls return 0 and the flush continues. The per-node validator is
not a privilege check either - `0x8ad833e0` is `cmp edi,0x15 / setb al`, applied
to the *sign-extended second byte* of the protection dword (`movsx edi, byte
[rbx+0x21]`, node+8 being the copied entry), so it only rejects a protection
whose byte 1 is at least `0x15`, which no value below `0x100` can be. Nodes are
also rejected when bit `0x8` of protection byte 0 is set (`0x8b47c45e`), matching
the direct path's refusal of that bit.

So the flush should run, and `1537a` `[I]` tests that directly by queueing
`prot 0` and reading the protection back: if the applier ran, `547` must report
0; if it did not, `547` still reports 3. `1480b` recorded exactly the second
shape (`op 1 prot 0` on a live `477` range, `rv=0 processed=1`, range still prot
3 and still readable), which is why the question is worth one run rather than an
inference.

### 12.4 1480b was never an op-1 observation

`1480b` has been cited (including in §11.2 of this file) as evidence that
`548` op 1 leaves a range mapped: its capture prints a line labelled
`op=1 prot=0 len=0x4000 on D` and then `[D after op=1] 547 prot=3`.

That line does not describe an op-1 call. The probe writes the entry buffer only
inside `set_entry`, and the last call before that rung is
`set_entry(A, 0, 0x4000, 3, 2)` - op **2**, with A's address still in the entry.
The rung therefore repeated `vm_map_protect` on A. The capture is consistent with
that and with nothing else: A reports prot 3 afterwards, D is never touched, and
D still holds its `33334444` sentinel because nothing ever wrote to it.

So the corpus contains exactly **one** op-1 measurement - `1534c`, the run that
faulted on the next read - and no run that shows op 1 leaving a range alone. Any
earlier sentence in this repository that treats `1480b` as an op-1 control is
withdrawn. `probes/phase36_realargs/1537a_sys548_op1_removal_check.lua` is the
replacement, and it also fixes the citation: the capture is
`results/phase36_realargs/1480b_sys548_low_map_20261109_200449.txt`, not
`..._eboot_rwx_...`.

## 14. op 1 is munmap, measured on three ranges (2026-11-10)

`results/phase36_realargs/1537a_sys548_op1_removal_check_20261110_150521.txt`,
COMPLETE 2.219 s, pid 214. Every op-1 call was built as a single 32-byte entry
`{start, 0, 0x4000, 3, 1}`, and each was judged by asking `547` and a fresh `674`
sweep afterwards, never by touching the range.

| range | how it was created | call | rv | processed | 547 after | 674 after |
|---|---|---|---|---|---|---|
| U1 `0x310B34000` | `477` anon | op 1 prot 3 len `0x4000` | 0 | 1 | no record | no record |
| U2 `0x500000000` | op 3 | op 1 prot 3 len `0x4000` | 0 | 1 | no record | no record |
| U3 `0x310D3C000` | `477` anon | op 1 prot 3 len `0x4000` | 0 | 1 | no record | no record |
| U4 `0x310D3C000` | `477` anon | op 1 prot 3 len `0x4000`, **offset `0x1000`** | 0 | 1 | no record | no record |

Baselines before each call were exact: `547` returned `U..U+0x4000` at
`prot=0x3` and `674` carried a record covering the same span with the same name
suffix (`anon:00002ef2599e`).

Four consequences.

1. **op 1 removes the range.** This is the control `1480b` never provided
   (see 12.4) and it settles the question §11.2 left open: `1534c`'s read fault
   after `rv=0 processed=1` was not an artefact of an unverified call, it was a
   load from memory that had just been unmapped. The old reading is withdrawn in
   both directions - op 1 does not leave a range mapped, and the fault was
   correct behaviour.
2. **The offset field is ignored by op 1.** U4 passed `offset = 0x1000` with an
   otherwise identical entry and removed exactly like the others. `1479d`'s
   EINVAL rows for offset shapes were all *misaligned entries*, which is a
   different rejection (the `0x4000` gate), so the offset field had never been
   varied on an aligned entry before this run.
3. **A removed range's address is reusable, so "547 fails" is only valid
   immediately.** At teardown - after `[D]`, `[E2]`, `[G]` had run - `547` at
   `0x310B34000` answered again with a span of `0x310B34000-0x310B44000`, four
   pages, because the loader had grown its own arena into the hole. The probe
   therefore prints `not ours (record covers ..., not ...)` and declines to
   unmap it. Any probe that checks removal must do so before the next allocation.
4. **`[H]` and `[I]` were unreachable by construction.** Both ask what the
   deferred applier does with a protection it is given on an existing range;
   `[F]` had already removed U3, so `547` failed and both skipped. Question 12.3
   opened - whether op 1 queues protection changes to `0x8ac8dc10` - is
   therefore still open, and it is now implausible: an op that deletes its
   entry has nothing left to apply a protection to.

Still unmeasured: **op 4** (`[E2]` skipped because both candidate ranges had
been removed by `[C]` and `[E]`), and **op 0**, which answers `0` on an existing
range and `EBUSY(16)` on a free one (1534b, 1534c) while consuming the
descriptor - `/dev/dmem0` at position `0x120000000` returns that device's own
`EACCES(13)`.

## 15. op 0 and op 4 are stubs; op 1 is precise - 548 is fully mapped (2026-11-10)

`results/phase36_realargs/1537b_sys548_op4_and_op0_semantics_20261110_151410.txt`,
COMPLETE 0.578 s, pid 214.

### 15.1 op 1 splits

`477` returned `0x310E54000` and `547` confirmed one exact entry of `0x40000`
(256 KiB). `548` op 1 on the **middle** 16 KiB page, `{start = BIG+0x20000,
offset 0, length 0x4000, prot 3, op 1}`, returned `rv=0 processed=1` and the
after-state is three facts:

| probe point | 547 after the call |
|---|---|
| `BIG` (first half) | `0x310E54000-0x310E74000` prot 3 |
| `BIG+0x20000` (the page asked for) | no record |
| `BIG+0x24000` (second half) | `0x310E78000-0x310E94000` prot 3 |
| `BIG+0x3C000` (last page) | same record |

So op 1 removes exactly the aligned span it is given and leaves the rest of the
entry as two entries. It is a precise unmap, not a whole-entry delete.

That contradicts the way `73` is described in `docs/DEAD_ENDS.md` ("munmap
removes the whole containing vm_map entry", from `1450a`/`1446d`/`1469a`). The
two are not necessarily the same call - op 1 runs through a different helper
(`0x8b47c185` inline) than syscall 73 does - but the discrepancy has not been
measured directly. Anyone who needs it should run `73` on the middle page of a
256 KiB entry before citing either statement.

**Correction (2026-11-10):** the `73` side of that contradiction is almost
certainly not real. `1450a` mapped `0x4000`, which is *one* 16 KiB page on this
kernel, and then printed four "pages" 0x1000 apart - all addresses inside that
same page. `mmap(0x8000)` plus `munmap(base+0x1000, 0x1000)` has never been run,
so "73 removes the whole entry" was never measured. See the correction at the
top of §1. `probes/phase36_realargs/1544a_munmap_pte_scope.lua` runs the missing
experiment on a sixteen-page mapping and also tests whether the surviving pages
keep live PTEs, which is the only way this stops being bookkeeping and becomes a
memory-safety question.

**Resolved (2026-11-10).** `1544a` ran that experiment and `73` split the sixteen-page entry
exactly as op 1 split the 256 KiB one: `73(base+0x10000, 0x4000)` → `0`, and `547` afterwards
reported `0x3` for pages `0,1,2,3,5,14,15` with page 4 the only unmapped one. The two calls agree,
the contradiction is closed, and the `docs/DEAD_ENDS.md` row is corrected.

The second half of that probe — whether a survivor keeps a live translation — did not produce a
load result, because the child faulted at the munmapped page and **took the connection down with
it** (the capture ends in a ucontext dump after the spawn line, with none of the parent's stamps
printed). That is a containment result in its own right and it is surprising: `1331a` spawned 512
children that each faulted on a *kernel* VA and finished `spawned=512 failed=0 alive`. A
`run_lua_code_in_new_thread` child that faults on an ordinary *unmapped user* page is therefore
not contained the same way, and no future probe should rely on catching a user-address fault in a
Lua child. It did not cost the question anything: `[D]` already shows pages 0-3 and 5-15 still
mapped at prot `0x3`, so there is no "entry unlinked, PTE alive" state on this mapping to find.


### 15.2 op 4 is `ENOTSUP`

| entry | call | rv | processed | 547 after |
|---|---|---|---|---|
| `{B4, 0, 0x4000, 3, 4}` | op 4 prot 3 | `-1` **45 Operation not supported** | 0 | unchanged, prot 3 |
| `{B4b, 0, 0x4000, 1, 4}` | op 4 prot 1 | `-1` **45 Operation not supported** | 0 | unchanged, prot 3 |

`processed=0` is the decisive part: every working op reports `processed=1`, so
the entry never reached an op body. op 4 short-circuits and answers `ENOTSUP`
regardless of the protection, which also means the deferred-applier hypothesis
of §12 - that op 4 queues entries for `0x8ac8dc10` - is **not** what a game
process reaches. That applier's `test r12b,0xae` mask forbidding WRITE and EXEC
stays a static reading about a path nothing here can drive.

### 15.3 op 0 is `EBUSY`, with a real descriptor

Earlier op-0 runs either passed `fd = 0` or a bogus descriptor, so "the
descriptor is consumed" rested on one `EACCES` outlier. This run passed real
ones: `/dev/dmem0` gave fd `23`, and `629(1,2,0,0)` gave the physhm descriptor
`22`.

| entry | descriptor | position | rv | processed |
|---|---|---|---|---|
| `{D, 0, 0x4000, 3, 0}` | physhm `22` | 0 | `-1` **16 Device busy** | 0 |
| `{C, 0, 0x4000, 3, 0}` | dmem0 `23` | 0 | `-1` **16 Device busy** | 0 |

Both left the range mapped at prot 3, under the same 547 shape and the same 674
record. With `processed=0` this is the same short-circuit as op 4: the op never
dispatches. `EBUSY` therefore does not mean "the range already exists" - it is
op 0's fixed answer - and `1534c`'s `EACCES(13)` for dmem0 at position
`0x120000000` is the device ACL being evaluated **before** that answer, which is
why it is the only op-0 rung that ever differed.

### 15.4 The five ops, complete

| op | behaviour | evidence |
|---|---|---|
| 0 | `EBUSY(16)`, `processed=0`, unchanged map | 1534b, 1534c, 1537b |
| 1 | **munmap**, precise to the aligned span | 1537a, 1537b |
| 2 | `vm_map_protect`, refuses EXEC with `EACCES` | 1479e, 1480a, 1533a, 1535a |
| 3 | anonymous map, answers the mapped address | 1534b, 1534c, 1537a |
| 4 | `ENOTSUP(45)`, `processed=0`, unchanged map | 1537b |

Only op 2 touches a protection word, and it enforces the same `max_prot` that
`mprotect(2)` does, so 548 offers no W^X bypass, no descriptor mapping and no
deferred apply. **The batch-map syscall is exhausted as a primitive.**

## 16. The 16 KiB page size invalidates four more claims (audit, 2026-11-10)

§1 and §15.1 correct the claims that motivated the page-size measurement. A sweep of the rest of the
tree for 4 KiB arithmetic turned up four more, all now recorded as corrections rather than silently
edited, because each one had already been cited downstream.

| # | Claim as recorded | What the 0x4000 page makes it |
|---|---|---|
| 1 | `mincore(78)` is a **residency oracle** over the dmem pager: "16 of 64 pages resident at phys 0" (`1503a`, ledger 4146) | **Inverted.** `0x40000 / 0x4000 = 16`, so the call wrote 16 bytes and all 16 read `0x0B` resident; bytes 16-63 were never written by the kernel. mincore reports every mapped page resident here and cannot find a hole. Row `1503a-correction` |
| 2 | "the **1024 resident pages** of that 16 MiB are all zeros" (`1504a`, ledger 4147) | `0x1000000 / 0x4000 = 1024` is the *whole* map, all resident; the "3072 skipped" was bookkeeping. `[C]` read base+0..base+0x3FF000 — the first **4 MiB** of 16 — so the zero result describes 4 MiB. Row `1504a-correction` |
| 3 | fault oracle "edge resolution at **4 KB**", "**512 pages** in the last 2 MB", "**8 pages** below image start" | 2 MB / 0x4000 = **128** pages and the 512 samples are four per page, so the real resolution is 16 KiB; 8 KiB is **2** pages. Conclusions survive because a present/absent fault is uniform across a page. `docs/FAULT_ORACLE_KASLR_14_10.md` corrected in place |
| 4 | AIO bounds "both came back bounded": `count=0x400` and a `count=4` write ending 4 bytes before a page boundary | **Neither measured a bounds question.** `0x400` is outside the 1..128 count gate so it returned `-1` before any pointer was read; the `count=4` buffer came from `memory.alloc(0x1000)` at `0x310f95f60`, which is not page-aligned, so the write ended `0x1FA4` bytes short of the 16 KiB page end. `docs/AIO_RANGE_14_10_EVIDENCE.md` corrected in place |

Two secondary fixes from the same audit: `docs/FINDINGS.md:403` reads `vec=0x1F` as "5 consecutive
pages resident" when the call asked about one 16 KiB page, so `0x1F` is that page's flag byte; and the
"Heap R/W (256+ pages)" headline in `CLAUDE.md` and `README.md` — `41c` scanned 256 steps of `0x1000`,
which is 1 MiB, i.e. **64** pages of 16 KiB.

**The general lesson, worth applying to any future page claim:** a probe that maps `len` and then asks
about `len / 0x1000` pages is not measuring anything. Either divide by `0x4000`, or stride reads at
`0x4000` and index residency as `p // 4`, and treat "all resident" as a real answer rather than a
failure of the oracle.

## 17. The W^X wall is one AND instruction, and it is applied to the object's max protection (2026-11-10)

`1547a` closed the device-offset straddle, and the follow-up question was the one left open by `1535a`:
the `SceGnmTrapData` window refused `0x37`/`0x7`/`0x5` but accepted its own `0x33`, which is consistent
with either "the EXEC bit is refused" or "the attribute bits were dropped". The batch-map core answers
it. The helper every op 0/op 3 request funnels into is `0xffffffff8b478430`, disassembled from
`.local/ktext_ins.pkl`, and the region that decides the protection is:

```
0xffffffff8b47896c  call 0xffffffff8b0ee150     ; resolve the descriptor -> object in [rbp-0x68]
0xffffffff8b4789aa  movzx r9d, word [rbp-0x72]  ; the object's own max-protection word
0xffffffff8b4789be  and   r9d, 0x3f3            ; <-- bits 0x4 (EXEC) and 0x8 stripped here
0xffffffff8b4789d5  call 0xffffffff8b47ea20     ; the real vm_map_find, given r9d as max_prot
```

(Offsets within the helper `0xffffffff8b478430` are `+0x53c`, `+0x57a`, `+0x58e` and `+0x5a5`; the
absolute VAs above are the ones to grep for.)

`0x3f3` is `0b1111110011`: bit 2 (`0x4`, PROT_EXEC) and bit 3 (`0x8`) are cleared, everything else is
kept. So **no file or device mapping can ever present a max protection carrying EXEC**, whatever its
driver declares, and no requested protection can survive the check that follows. That is the same wall
`548` op 2 hits from the other side (it refuses `0x7` at `vm_map_protect` and accepts exactly the value
the entry already had), and it explains `1535a` without needing the attribute confound: `0x37` was
refused because `0x37 & 0x3f3` drops bits the request insisted on, not because an attribute bit was
missing.

Anonymous mappings take the other branch (`+0x479 test r9d, 0x1000` -> `call 0xffffffff8b479f60`) and
are measured at max_prot 3 (`1480a` asked 7 at a fresh anonymous map and got EACCES). Executable
entries - eboot text, `prot 5` - already carry X in their max protection and never carry W. There is no
entry any game process can own whose max protection holds both, so `mprotect`-shaped and `548`-shaped
requests can never make one page simultaneously writable and executable. **W^X is enforced by a
single mask on the object's declared maximum, not by a policy check that a missing credential could
skip.**

Two follow-on facts from the same listing, both useful later:

- A **zero-length** request is a legal path, not an error. `+0x174 cmp qword [rcx+8], 0` sends it
  through a quota gate (`+0x17b cmp dword [rax+0x5e0], 0xc3567` -> EINVAL above 800,103 live entries)
  and then `+0x444 test r14, r14` short-circuits to the success tail when the rounded span is zero.
  The span is `round_up(length + (position & 0x3fff), 0x4000)`, so `len = 0` at a 0x4000-aligned
  position creates nothing at all, while `len = 0` at `off = L - 0x1000` rounds to one full frame -
  which still lands on `[L - 0x4000, L)` and does not cross `L`. This is the same round-down bound
  `1547a` proved, reached from the length-zero side, and it does not open a second door.
- `+0x625 mov qword [rbx + 0x408], start + (position & 0x3fff)` records the last mapped address in the
  thread structure. It is a bookkeeping store, not a primitive: the value is derived from the caller's
  own arguments.

## 18. `548` op 3 MAP_FIXED over a device-backed entry is a correct split (2026-11-10)

The composition worth testing after §17 was a reference-count error: carving an anonymous page into the
middle of a *device-backed* entry forces `vm_map` to clip the device entry into pieces that share the
pager object, then release the reference held by the page it removed. If the release were wrong, the
surviving neighbours would be sitting on a freed object — the first real kernel-memory bug the lab
could reach from userland. `1548a` ran it.

`results/phase36_realargs/1548a_map_fixed_over_device_entry_20261110_173458.txt` (COMPLETE, 0.047 s,
pid 242, ledger **M**). Seventeen seconds of setup, one clean negative:

- `[A]` `/dev/dmem0` at offset 0, length `0x40000` → `D = 0x3115E8000`, **one** 547 record
  `3115E8000-311628000 prot 3 flags 10020`, and `[D] = 0xC0012800` — the register page, so the
  mapping is device-backed and identifiable by content.
- `[B]` eight `548 op 3` MAP_FIXED carves at `ORDER = {8, 4, 12, 2, 6, 10, 14, 1}` (page index within
  the 0x40000 entry). The first seven are **interior** splits with device neighbours on both sides; the
  eighth is an end clip. **attempted 8, accepted 8, boundary-ok 8**: every `rv` equalled the requested
  carve address, and after every carve `547(at + 0x4000)` started exactly at `at + 0x4000`.
- `[C]` the sixteen pages alternate perfectly: `0,3,5,7,9,11,13,15` at `flags 10020` (device),
  `1,2,4,6,8,10,12,14` at `flags 610020` (carved anonymous), `absent 0`, `other 0`.
- `[D]` carved page 8 reads `00000000`; the uncarved control page 0 still reads `C0012800`.
- `[E]` a fresh 0x1000 mapping at `0x311628000` — exactly where the old entry ended — is accepted,
  covers prot 3 and reads `C0012800`, so the device object was **not** freed.
- `[F]` teardown munmap returned 0.

**Conclusion: no reference-count error, no stale PTE, no object reuse.** The device-pager version of the
carve is as correct as the vnode version `1513a` already recorded, and those two results together close
the "MAP_FIXED over a foreign object" family on this firmware.

Two facts earned along the way belong in the record:

- The 547 `flags` word is **not** an object-type test. `/dev/dmem0` entries report `0x10020`, while
  anonymous regions (`1533a`) *and* the `SceGnmTrapData` device window (`docs/VM_LAYER_14_10.md:588`)
  both report `0x610020` — and both the vnode entry (`1513a`) and the carved pages here also report
  `0x610020`. Only the dmem aperture carries `0x10020`. Use frame content, never this field, to decide
  what is behind an entry.
- `op 3` returns the **requested address** when MAP_FIXED is honoured (`rv == at` for all eight
  carves), which is the discriminator that separates a real carve from the silent no-op recorded at
  §9's `686-687`. Any future op-3 probe should assert `rv == at` before concluding anything.

## 19. `vm_map_protect` takes the map lock once: there is no retry window

The standing hypothesis after §8 was that `548` op 2 could be raced against `73` munmap, on the theory
that FreeBSD's `vm_map_protect` drops the map lock to call `pmap_protect` and then re-looks-up the
entry — the classic revalidation window. **The 13.60 body does not do that.**

`0xffffffff8ac8bdb0` was read out of `.local/ktext_ins.pkl` end to end: one contiguous body from
`0x8ac8bdb0` to the single `ret` at `0x8ac8d0fa`, 354 instructions, with the lock taken once and never
released until the epilogue:

```
8ac8be04  movzx eax, byte [rdi + 0x244]
8ac8be1b  test  al, 0x10
8ac8be1d  jne   0x8ac8be49                  ; the rw-lock arm
8ac8be35  lea   rdi, [rbx + 0x170]
8ac8be42  call  0xffffffff8b60bb20          ; mtx_lock(map + 0x170)
8ac8be65  inc   dword [rbx + 0x1c0]
8ac8be6e  lock add dword [rbx + 0x1c4], 1   ; timestamp bump
8ac8bea0  call  0xffffffff8ac86b10          ; clip / prepare
8ac8beb9  call  0xffffffff8ac86c40          ; vm_map_lookup_entry
```

Two checks were run on the listing, and only the second is load-bearing. **No backward branch anywhere in
`0x8ac8bdb0`-`0x8ac8d300` targets an address at or below `0x8ac8be70`** — a `Retry:` loop, which is what
the race hypothesis needs, has to jump back into that region, so its absence is decisive. **There is
exactly one call to the mutex helper `0x8b60bb20`**, and the rw arm at `0x8ac8be60` is the only other
acquisition site; the *release* is not an outward call in this body (it is inlined or reached through a
helper this dump does not name), so the single-lock count corroborates the branch evidence rather than
proving it on its own.

The entry walk itself revalidates nothing because it never gives the lock up: it holds `rbx = map`,
steps `r12` through the entry list (`8ac8bf55 mov rcx, [r12 + 0x20]` / `8ac8bf5a cmp rcx, r14`), and
tests each entry's object at `[r12+0x50]` with the same `cmp byte [rax+0x9d], 0xb` type-11 test that
`654`/`673` use. The protection arithmetic is the one already recorded: `r9d = 0x3f3` is the mask
applied to max protection, and `and r11d, 0xfc0f` splits the caller's value into the flag bits that
survive (`8ac8bf2a`).

Two smaller facts fall out of the same body and are worth keeping:

- `8ac8bdf5 cmp r13, r12 / 8ac8bdf8 je 0x8ac8d0d9` is the empty-range early success, which is why a
zero-length entry returns 0 (§8, `1479b`).
- The failure path is a single exit at `0x8ac8d0b3` with `r15d` holding the status: `4` (ENOMEM on a
wiring failure), `2`, `1`, `6`, and `0x16` (EINVAL) from the eight validation checks.

**Consequence: the protect-versus-munmap race is closed statically, not by a failed probe.** Nothing
in this tree should spend a console run on it. The general lesson is the one §17 recorded: on this
kernel the VM layer's answers are set by declared maxima and a single map mutex, and the remaining
doors are memory-safety bugs in code that runs *outside* that lock — pagers, drivers and the network
stack — none of which a game process has been able to reach with a malformed request.


## 20. op 2 on a COW entry: WRITE is granted and COW still breaks (2026-11-10)

`1552a` asked the question every op-2 measurement to date had avoided. All prior
op-2 targets were anonymous entries, the `SceGnmTrapData` window, or a carve
produced by op 3 — none of them carries `MAP_ENTRY_NEEDS_COPY`. A `MAP_PRIVATE`
mapping of a vnode is the one entry where granting `VM_PROT_WRITE` without
breaking COW would turn any store into a write into the page cache, visible to
every other mapping of the same file.

Capture: `results/phase36_realargs/1552a_cow_break_via_548_op2_20261110_190131.txt`
(pid 24x, COMPLETE, 0.032 s). Our own MLFS file
`/av_contents/content_tmp/r1552.bin` (`ftruncate 0x8000`, marker `COW0` at 0x00,
`0x11` at 0x10), opened **O_RDWR twice** and mapped twice with
`477(hint 0, 0x8000, prot 1, flags 0x2 = MAP_PRIVATE, fd, 0)`.

Four vacuity controls all passed before the verdict meant anything:

| control | result |
|---|---|
| `[C]` both mappings read the file | `V1[0..3] = 43 4F 57 30`, `V2[0..3] = 43 4F 57 30` |
| `[C2]` a byte written **through fd2** appears in V2 | wrote `0xA7` at file offset 0x10, `V2[0x10] = 0xA7` — **the two mappings really do share the page-cache page** |
| `[D]` the entry starts read-only | `547` reports `prot=1` |
| `[F]` the store lands | `V1[0x10] = 0x5C` after the write |

Then the measurement:

```
[D] V1 before: prot=1 start=0x1084C000 end=0x10854000
[E] 548 op2 start=0x31084C000 len=0x4000 prot=3 ...
[E] rv=0 processed=1
[E] V1 after : prot=3  <<< WRITE GRANTED
[F] store 0x5C at V1+0x10 (0x31084C010) ...
[F] V1[0x10] after = 0x5C (store landed)
[F] V2[0x10] after = 0xA7
[G] V3[0x10] = 167 (0x5C would mean the cache is corrupt)
```

**`548` op 2 does grant `VM_PROT_WRITE` on a `MAP_PRIVATE` vnode entry, and
`vm_map_protect` breaks COW correctly.** The store landed in V1, the second
mapping of the same file still read the page-cache byte `0xA7`, and a **third**
mapping created after the store and faulted fresh also read `0xA7`. Nothing
reached the page cache.

Three things this settles:

1. **A vnode entry's `max_prot` does carry W** when the descriptor was opened
   O_RDWR, so §8's EACCES results were about EXEC, not about file mappings being
   read-only. (The `[D]` line also re-confirms the 32-bit truncation of 547's
   own record: `start=0x1084C000` for a mapping at `0x31084C000`.)
2. **`vm_map_protect` keeps `MAP_ENTRY_NEEDS_COPY`** when it adds W — it sets the
   entry protection and lets the next store take a COW fault. That is the
   correct behaviour and it is now measured rather than assumed.
3. **The COW write-through idea (the top entry in
   `docs/CREATIVE_IDEAS_2026-11-10.md`) is dead.** There is no version of it that
   survives this capture: the private copy is made before the store becomes
   visible to anyone else, and the page cache is intact afterwards.

The remaining variant — granting W to a `MAP_SHARED` entry — is not a bug either,
because writing through a shared mapping is exactly what `MAP_SHARED` means. The
op-2 axis is therefore closed: it refuses EXEC (§8, §17, `1535a`), it honours the
entry's `max_prot`, and it does not disturb COW.

## 21. Delete versus a live store: measured, no stale PTE (2026-11-10)

`1557a` (`results/phase36_realargs/1557a_unmap_pte_removal_20261110_192806.txt`,
grade M) is the first race probe in this tree whose **death is the result**.  The
protocol, forced by `1556a`:

* `[A]` a control with no child — `548 op1` on `Q=0x3109A8000` returned
  `rv=0 processed=1`, `547` afterwards answered `-1`, and the process printed the
  next line.  So a death in `[B]` cannot be blamed on `op 1`.
* `[B]` a `thr_create(430)` child walked an 8 MiB stack filled with the 6-slot
  cycle `{Pv, STORE, POP_RDI, Hv, STORE, POP_RDI}` (`RIP = POP_RDI`, `RSP = base`),
  so it stored into `P` and into a heartbeat page `H` alternately and never ran out
  of slots before the unmap.  The arm check was zero-then-read on both pages:
  `P = H = 0x11223344556677`, i.e. the child was looping when the unmap was issued.
* The interpretation was printed **before** the lethal call, then `op 1`, then the
  `rv`.  The capture ends immediately after the banner with the loader's fault
  dump.

**The dump**: `RIP = 0x1A792C67` (the `mov [rdi],rax; ret` gadget), `RDI =
0x3109A8000` (= P), `RAX = 0x11223344556677` (the marker), `CS = 0x43`, `SS =
0x3B`, `RSP = 0x310C3D9F0` — 1.2 MB into the 8 MiB fill, i.e. roughly 25,000
store periods **after** the arm check.  The child was alive, storing, and its
next store to `P` faulted.

**Conclusion.** `vm_map_delete` does not leave a PTE that a racing user store can
reach.  The store that arrives after the unmap faults, which is what the
invariant requires.  Combined with `1534c-pte` (same result sequentially, with no
concurrency at all), the delete-versus-store axis is **closed**.

Three things this does not cover, stated so they are not read into the result:

1. **The fault-versus-delete window is a different lock user.**  This probe's
   store hits a *resident* PTE, so `vm_fault` is never entered.  A first-touch
   fault takes the map lock, drops it, and calls `pmap_enter` afterwards — the
   dangerous window is there, not here (`1554a` is built for it and has not run).
2. **A stale PTE would not have been visible as a heartbeat anyway** unless the
   child survived; the probe is asymmetric by construction, and the negative
   branch is the one that costs a relaunch.
3. **`pmap_remove_all` on free** is the reason §7 (`1529b`/`1530a`/`1531a`) came
   out clean after a `MAP_FIXED` replacement.  Nothing in this section changes
   that reading.

**Probe-design rule bought with two relaunches.**  Every VM race has the losing
child fault, and `1556a` measured that a user-space fault ends the entire run.  So
a race probe must print its interpretation and every prerequisite *before* the
lethal call, and must treat a capture that stops there as the positive result.
`1553a` was graded **V** precisely because it printed its verdict after the call.

## 22. A sub-range cannot leak max_prot (2026-11-10)

`1535a` closed W^X on the whole-window request: `548 op 2` on `SceGnmTrapData`
with `0x37`/`0x7`/`0x5` answers `EACCES(13)`.  The remaining way a batch call
could reopen it is a **split**: `vm_map_protect` breaks an entry when the range
covers only part of it, and the batch applier (`0x8ac8dc10`) re-looks-up per
entry after dropping the map lock.  If a split entry inherited the wrong
`max_prot`, or the applier validated only the first entry of a multi-entry
range, a 16 KiB request could succeed where the whole-window request failed.

`1562a` (`results/phase36_realargs/1562a_sys548_subrange_maxprot_20261110_194204.txt`,
grade M) measured both shapes:

| rung | call | result |
|---|---|---|
| `[B]` | `op2(0xF00008000, 0x4000, 0x33)` — one page, its own protection | `rv=0 processed=1`, `547=51` |
| `[C]` | `op2(0xF00008000, 0x4000, 0x37)` — the same page, +EXEC | `rv=-1 processed=0`, `547=51` |
| `[D]` | `op3` MAP_FIXED carves `0xF0000C000` | anon, `547` prot 3, record `[0xF0000C000,0xF00010000)` |
| `[E]` | `op2(0xF0000C000, 0x4000, 0x7)` on the carved anon page | `rv=-1 processed=0`, `547=3` |
| `[F]` | restore | `rv=0 processed=1`, `547=51` |

`[B]` first proves the sub-range path is reachable at all — without it, `[C]`'s
refusal would be indistinguishable from "sub-ranges are always rejected".  With
it, `[C]` shows the max_prot check is per entry, and `[E]` shows a freshly
carved entry does not inherit the device window's protection word.  So the
split is not a lever: **the only entries with EXEC in `max_prot` are the ones
that never have WRITE in it**, and no op can change that.

Note for anyone re-reading the run: `674` did not name the window in this
process, so the probe fell back to the documented `0xF00004000`, and the
`[B]`/`[C]` page (`0xF00008000`) sits one page past the record `547` returned
for that fallback.  Both are device pages at prot `0x33`, so the comparison
stands, but a future probe should locate the window through `674` and assert
that the record it gets covers the page it is about to modify.

## 23. Syscall 674 writes `min(entries, arg3) * arg2` bytes and never learns the buffer size (2026-11-10)

Every GPU-window probe in this tree enumerates the map with

```lua
sc674(buf, 72, MAXR, countp, 0x40000000, 0)
```

and always sizes `buf` as `MAXR * 72`.  `1563a`
(`results/phase36_realargs/1563a_sys674_record_bound_20261110_194414.txt`, grade M)
measured what happens when the buffer is **not** sized that way: the syscall has
no buffer-length argument at all, so the kernel writes one `arg2`-byte record per
map entry up to `arg3`.

| rung | call | bytes actually written |
|---|---|---|
| `[A]` | `674(buf, 72, 400, cnt)` on a 0x10000 region | 316 records, furthest offset `0x58DC` (= `0x58E0` of record data) |
| `[B]` limit 8 / 1 / 0 | same, `arg3` = 8 / 1 / 0 | `0x240` / `0x48` / nothing |
| `[C]` | `674(buf, 72, 4000, cnt)` | same `0x58DC` — the map size stops it, not the limit |

So `arg3` truncates exactly, the map size caps it, and a caller who offers less
than `min(entries, arg3) * arg2` bytes loses whatever follows its buffer.  That is
an API property of a `sceKernelVirtualQuery`-shaped call, not a kernel bug:
`copyout` rejects any destination above `0x800000000000`, and a destination page
without write permission yields `EFAULT` through the `onfault` handler rather than
a write, so the only memory this can corrupt is user memory the caller could
already write.  **No primitive.**

Probe defect worth recording: `[D]` filled `countp` with `0xEEEEEEEE` and then
measured it with `span()`, which looks for the `0xA5A5A5A5` sentinel — every dword
"differed", so that rung says nothing.  A sentinel scanner must take the sentinel
as a parameter.

### 23.1 The missing length kills a caller that gets it wrong (2026-11-10)

`1563a` measured the property; `1564a` demonstrated it by accident.  Its `674`
call used `memory.alloc(0x4000)` for the record buffer with a limit of 400
records, and the map answered 316 records — `316 * 72 = 22752` bytes into a
16384-byte block.  The capture
(`results/phase36_realargs/1564a_sys548_map_fixed_boundary_20261110_194737.txt`,
grade V) prints `[0] pid=312` and nothing else; `9026` then answers
`CONNECTION_REFUSED`.  So the overrun is real, it lands in the Lua heap, and it
takes the loader with it.

Rule for every future probe: size the `674` buffer as `0x48 * limit` **and** keep
the limit below the number of map entries times one, or the enumeration itself is
the crash.  `1481f`'s `CAP` is the right pattern; a `memory.alloc(0x4000)` with
`limit = 400` is the wrong one.

## 24. A MAP_FIXED range that spans two entries replaces both (2026-11-10)

`1548a` carved inside one device entry; the remaining question was whether a
`MAP_FIXED` range spanning **two entries with different backing objects** clips
both or reuses one entry's object for the new mapping — which would be a pager
object confusion readable from userland.

`1564a` (`results/phase36_realargs/1564a_sys548_map_fixed_boundary_20261110_195243.txt`,
grade M) built the adjacency and then crossed it:

| rung | call | result |
|---|---|---|
| `[A]` | `674(buf, 72, 400, cnt, 0x40000000, 0)` | 316 records, named `SceGnmTrapData` at `0xF00004000`, record `[0xF00004000,0xF00008000)` prot `51` |
| `[C]` | `op3` MAP_FIXED anon at `0xF00008000` (the page after the window) | landed, prot 3, store `0x11111111` read back; the device window still read `0xF00144000` |
| `[D]` | `op3` MAP_FIXED `0x8000` at `0xF00000000`, spanning the device entry | `rv = 0xF00000000`, `547(START)` prot 3, one record `[0xF00000000,0xF00008000)` |
| `[E]` | store `0xCAFEBABE` to both pages | both read back `0xCAFEBABE` |
| `[F]` | `547` both pages | one record covering both |

Both entries were deleted and one fresh anonymous entry was inserted: the page
that used to be the device window took an ordinary store, and no `0xF00144xxx`
value survived anywhere in the range.  So the multi-entry delete path in
`vm_map_find` is clean too — **the VM layer has no composition left that I can
name**, and the file's remaining open questions are about *other* subsystems.

Note: `[A]`'s 674 buffer is 0x8000 for a 400-record limit, which is the fix for
the overrun described in §23.1.

## 25. 674's copyout cannot write into a read-only code page (2026-11-10)

§23 showed 674 writes records to any address the caller names with no buffer length.  The obvious follow-up was whether that write path honours the page's write permission — if it did not, the destination could be eboot's RX text and the syscall would be a code-page write, i.e. the W^X bypass this project has been hunting.

`1565a` (`results/phase36_realargs/1565a_sys674_writebit_bypass_20261110_195359.txt`, grade M) measured it:

| rung | call | result |
|---|---|---|
| `[A]` | `674(buf, 72, 400, cnt, 0x40000000, 0)` | 315 records; largest prot-5 range is named `executable`, `[0x78420000,0x788B4000)` |
| `[B]` | read 64 bytes at `T = 0x7866A000` | `C0FFFBD1 F875FB85 0F6696EB 0000441F` — readable |
| `[C]` | `674(T, 72, 1, cnt, 0x40000000, 0)` | `rv = -1` |
| `[D]` | read the same 64 bytes | **0 of 16 dwords changed** |

So `copyout` faults on the missing write bit and reports failure through its `onfault` handler, exactly as `0x8ac191d0`'s prologue implies.  The executable code page cannot be written through 674, and the syscall stops being interesting: its over-write can only reach memory the caller could already write.

Probe gap to fix in any re-run: `[C]` records `rv` but not `errno`, so "EFAULT(14)" is inferred from the assembly rather than read from the capture.  A follow-up should print `errno()` after the call.

## 26. The fault-time map race is closed by construction (2026-11-10)

Three probes measured a clean result against a mapping being torn down underneath a
running thread — `1552a` (COW + `op2`), `1554a` (first-touch store + `op1`), `1557a`
(resident store + `op1`) — and the reason is in `vm_fault_hold`, not in luck.

Decoded from `.local/ktext_ins.pkl` (all VAs):

| symbol | VA | note |
|---|---|---|
| `vm_fault` | `0x8b0c69e0` | policy wrapper only; no lock, no lookup, no `pmap_enter` |
| `vm_fault_hold` | `0x8b0c6b40` | size `0x1e3f`; `__func__` "vm_fault_hold" at `0x8bc6ca9c` |
| `RetryFault` | `0x8b0c6c18` | 16 in-branches; a full `vm_map_lookup` each pass |
| `pmap_enter` | `0x8b2a2760` | called from exactly two sites (below) |

The lock choreography is four instructions long and has no gap:

```asm
8b0c75ab  call 0x8ac92a70   ; DROP  vm_map_lookup_done  (only while [rbp-0x78]==1)
8b0c7e76  call 0x8ac868e0   ; RELOCK _sx_try_slock(&map+0x170) -- does NOT bump +0x1c0
8b0c7e97  cmp dword ptr [rax+0x1c0], ecx   ; map->timestamp vs the value saved at 0x8b0c6cc0
8b0c7e9d  je  0x8b0c85ec    ; unchanged -> the old entry is still valid
8b0c7ecc  call 0x8ac92990   ; changed   -> SECOND vm_map_lookup, overwrites [rbp-0x80]
8b0c802f  cmp rax, [rbp-0x98]              ; new object vs first_object
8b0c803f  cmp rax, [rbp-0x90]              ; new pindex vs first_m
```

`0x8b0c86f8: call 0x8b2a2760` (the PTE install) is reachable only through the three
validated continuations `0x8b0c7e65` (lock never dropped), `0x8b0c7e9d` (timestamp
unchanged) and `0x8b0c8050` (re-lookup landed on the same object and pindex).  The other
`pmap_enter` at `0x8b0c6f8c` is the wired fast path, which runs before any drop.

The deleter cannot win: `vm_map_delete 0x8ac89370` does not lock itself — every one of its
17 call sites brackets it with `vm_map_lock`/`vm_map_unlock` (e.g. the munmap helper
`0x8b478bb0`: `0x8b478c1d lock` → `0x8b478c2b delete` → `0x8b478c92 unlock`) — and
`vm_map_lock` bumps the generation at **`0x8ac864cc: inc dword ptr [rbx+0x1c0]`**.  So an
exclusive holder in the unlocked window always shows up in the `0x8b0c7e97` compare, and
the fault re-looks-up instead of installing a PTE for a corpse.

Two limits of the mechanism, both fail-safe rather than holes:

* it never compares the saved **entry pointer** and never re-reads `wired_count` after the
  drop; entry identity rests entirely on `timestamp` or on `object ∧ pindex`;
* a failed try-lock (`0x8b0c7e7d je 0x8b0c7f81`) releases the page
  (`0x8b0c800e call 0x8b0c8df0`) and restarts at `RetryFault`, which takes the lock
  blocking.

Consequence for this project: **there is no stale-PTE race to widen.**  The three clean
measurements are the expected behaviour of a correct re-validation, not a probe that failed
to hit a window, so no further time should go into unmap/fault interleavings.

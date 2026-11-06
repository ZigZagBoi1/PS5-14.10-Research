# Sys 611 / 613 / 615 statistics family — 13.60 contract decodes

**Date:** 2026-11-06. Static decode of the 13.60 capture only (`docs/dumps_13.60/`,
`tools/offline/handler_extract.py`, `dis_rva.py`). No console was contacted.
Live 14.10 status for all three: `-1` on every shape tried (1300a, 198a/199a),
so these are untested contracts, not verdicts — the same rule the repo applies
to every six-zero `-1` row.

The three are one family: all gate on the same credential predicate, all resolve
an owner object the same way, all walk a per-owner linked map, and all copy a
small fixed record out to the caller. 613 is the minimal member and the cleanest
contract to test.

## Shared entry shape

All three handlers start the same way:

- Sysent metadata: `narg=3`. The `args` block is read as `{ id (dword, used),
  out_ptr1, out_ptr2 }`; only the low 32 bits of slot 0 are consumed.
- **Credential gate:** `call 0x608f90(*(thread+0x140))` and bail when it returns
  zero. The helper's body (`0x608f90-0x608fa0`) is exactly
  `(credential.qword[+0x60] >> 62) & 1` — capability **bit 62**, the same single
  test behind 618/641/642/646/671. Missing bit → `611` returns `1`, `613`
  returns `1`, `615` returns `1` (611/613) or the family's early-exit value.
  This is the gate that closes all three on 14.10 for a game process
  (`cred+0x60` is zero for a game process; probe 332a/333a, 55e).
- **Owner resolution:** `call 0x53c170(id)`. The helper hashes `id` into a
  global table (`movsxd rcx, r14d; and rcx, [mask]; mov rax, [table + rcx*8]`)
  and walks the bucket comparing `[rbx+0xbc]` against the id — a pid-style
  lookup, the same helper 641/642 use. Null → return `3`. **615 is the
  exception in the family:** it short-circuits `id = 0` and self-pid before
  the gate, so its self path does not need bit 62 — see its section.
- **Map walk:** the owner carries the map at `owner+0x200`, a lock-like object
  at `owner+0x148`, a hold count at `owner+0x358`, and a flags word at
  `owner+0xb0` (bit `0x2000` = closing; bit `0x10000000` selects an auxiliary
  call). Entries are the `+0x20 start / +0x28 end / +0x08 next` linked nodes
  shared with the 674 `virtual_query_all` region records.
- **Copyout:** `0x2591d0` (the standard copyout) per output, 8 bytes each.

## 613 `get_resident_count` — the minimal contract

Handler RVA `0xabca10`, 483 bytes, fully decoded:

1. Gate (bit 62). `id = *(dword*)args`; `owner = 0x53c170(id)`; null → `3`.
2. `owner+0xb0 & 0x2000` (closing) → unlock-and-return `3`.
3. `owner+0x358++`; if `owner+0xb0 & 0x10000000` is clear, `0x53aa10(owner)`
   (auxiliary refcount).
4. Lock `owner+0x148`, then `owner+0x200`.
5. `total = 0`; for each map entry:
   `total += (entry.end - entry.start) >> 0xE` — i.e. **sum of mapped range
   sizes in 16 KiB pages**. (`0xE` = log2(0x4000), the 16 KB page size.)
   Separately `other = *(owner+0x200 + 0x338)` via the one-instruction helper
   `0x2c6e90` (a second precomputed counter the map object already maintains;
   its exact meaning is not established by the bytes — likely a resident or
   wired count maintained on map operations).
6. Unlock, `owner+0x358--`, wake if it hit zero under the closing flag.
7. `copyout(&other, args[1], 8)` then `copyout(&total, args[2], 8)`; first
   copyout error wins (`errno` propagated), then return.

**Contract:** `613(id, &a, &b)` → `a = map's maintained counter`, `b = total
mapped size in 16 KiB pages` for the process whose id resolves. `id = getpid()`
for self. Errors: `1` (no credential bit 62), `3` (bad id / closing), copyout
errno.

**Why 14.10's `-1` is uninformative:** 1300a passed `(757, out, 0)` and
`(0, out, 0)`. With the bit-62 gate first in the body, *every* argument shape
from a game process returns the gate failure before any lookup runs — so `-1`
says nothing about id handling, the map walk, or the copyouts. A discriminating
probe needs the gate to pass, which a game process cannot do. The only live
question a game process can answer is already answered: the gate is first and
absolute.

## 611 `get_paging_stats_of_all_threads` — larger, same gate

Handler RVA `0xa36bc0`, ~2.8 KB. Same gate (bit 62, return `1`), then builds a
request block on the stack (`{ id = args[0], selector dword args+8, count=1,
… }`), takes the global list at `[rip+0x2b53234]`, and walks it under the
same `+0x148` lock protocol, filtering nodes with `dword[node+0xb8] == 1`. Per
accepted node it calls a stats helper (via `0x4c6a00`-family locks) with
`rdx = 0x102` and a format string pointer at `[rip+0x21c5424]`, accumulating
per-thread paging counters into the caller's buffer region described by the
request block. The size and the `0x102` selector bound the per-node record.

**Contract (bounded):** `611(id, out, arg2)` writes per-thread paging stats for
the resolved owner into `out`; record selection is fixed (`0x102`), not
caller-chosen. Same errors as 613. The full per-node record layout needs the
stats helper (`0xa36…` internals) decoded further — marked as limits of
evidence here; the entry contract (args, gate, walk, fixed selector) is what a
probe needs and is fully established.

## 615 `get_resident_fmem_count` — the richest of the three

Handler RVA `0xabcc00` is a thin front end; the body is `0xabccc0`, fully
decoded:

1. **Self short-circuit:** if `id != 0`, compare it against the caller's own
   pid at `gs:[0]+8 +0xbc` and bail to the gate path only when it differs; `id
   = 0` or self goes straight to the walk with `owner = current process`. The
   bit-62 gate at `0xabcfa2` is only reached for **foreign** pids (returns `1`
   without the bit, `3` for an unresolvable id via the same `0x53c170` lookup).
   **Consequence: `615(0, &a, &b)` and `615(self_pid, …)` do NOT need the
   credential bit at all on 13.60.** 1300a's `-1` for `615(0, out, 0)` on
   14.10 is therefore *not* explained by the bit-62 gate — either the gate
   moved in 14.10, or the `-1` came from the null second output pointer
   (`out2 = 0`; the two copyouts at `0xabcc5d`/`0xabcc93` would fault on the
   second). A `615(0, &a, &b)` retest with two valid pointers is a live
   discriminator (see below).
2. **Walk:** lock `owner+0x148`, then map `owner+0x200`; for each map entry:
   skip entries with `flags +0x60 & 2`; take the backing object at
   `entry+0x50`, skip when null; require `backing+0x9d` (object **type** byte)
   ≤ 8 and in the bitmask `0x187` (`bt 0x187, type` — types {0,1,2,7,8}). Then:
   - `count[entry.type_class] += (entry.end - entry.start) >> 0xE` where
     `entry.type_class = signext(byte [entry+0x14c]) << 4` — a per-class array
     of 16-byte slots in the 0xB0-byte output block (class index × 16, count
     at +8 of the slot). Range sizes are summed in **16 KiB pages**, same as
     613.
   - Walk the backing pager list (`0xb897f0` iterator over pages past
     `entry+0x58` up to `entry.end`, in 16 KiB steps): for each resident page
     whose object offset `[page+0x28]` lies below the entry end, increment
     `slot[0]` of the same class slot — a **resident-page count** beside the
     mapped-page count.
   - A watchdog: `rdtsc` sampled per entry; past `0x27101` cycles it drops the
     map lock, logs via `0xc06830`, re-locks, and re-validates
     `map+0x1c0` (a generation counter — if the map changed, re-lookup the
     current entry by address via `0x2c6c40`).
3. **Copyout:** `0xB0` bytes zeroed at `rbp-0xD0` (via `0x258ff0`), filled as
   per-class `{ resident_count, mapped_count }` pairs, then
   `copyout(buf+0x00, args[1], 8)` and `copyout(buf+0x08, args[2], 8)` — **the
   two user pointers receive the first class slot only** (class 0's resident
   and mapped counts); the remaining classes stay kernel-side. Errors: `1`
   (foreign pid without bit 62), `3` (bad id / closing), copyout errno.

**Contract:** `615(id_or_0, &resident, &mapped)` → resident-page count and
mapped-page count (16 KiB units) for class-0 (type-0-backed) ranges of the
resolved process. `id = 0` or self: no credential bit needed on 13.60. This is
the family's one handler whose self path is open in principle to a game
process — which makes its 14.10 `-1` the family's one genuinely unexplained
result, and the only one worth a real-args retest.

**Discriminating retest (console, low cost):** `615(0, &a, &b)` with two valid
mapped output pointers. If it returns `0` and `b` equals the sum of mapped
16 KiB pages (cross-check against the 674 region walk), the 14.10 handler
matches 13.60 and 1300a's `-1` was the null second pointer; if it still
returns `-1` with both pointers valid, 14.10 added a gate on the self path and
the family closes for good. Either answer is one call.

## What this family cannot give a game process

- 611 and 613 gate on bit 62 of `cred+0x60`, zero for a game process and not
  settable by any reachable call (643's chicken-switch OR targets `proc+0xa34`,
  a different word), so they stay closed on 14.10 exactly like 618/641/642/646.
  **615 is the exception:** its `id = 0` / self-pid path skips the gate on
  13.60, so its 14.10 `-1` is unexplained by the gate and is the family's one
  open question (the retest above).
- Even with the gate passed, the outputs are **counts and page totals**, not
  pointers. No kernel address appears in any copyout path of 613 (the only
  pointer-shaped value, the map's `+0x338` counter, is a count maintained by
  the map object, and 611/615's outputs are the same class of statistic). This
  is not a KASLR surface; it is a side-channel surface at best (per-process
  page totals of *other* pids — but the id lookup is constrained by the same
  credential environment, and self-totals are already available through 674's
  region records).

## Discriminating probe proposal (console, for the 14.10 bench)

Only worth running if a future path ever sets bit 62. Until then the family is
fully described by "gate first, absolute, counted outputs". If the bit were
somehow set, the discriminator for 613 is: `613(self_pid, &a, &b)` with two
different mmap sizes — `b` should move by exactly `size >> 14` per 16 KiB page
mapped, `a` should track the map's own counter. That distinguishes a live
handler from a stub in one call, and pins the `0x2c6e90` counter's meaning by
differencing against a `munmap`.

## Sources

- `tools/offline/handler_extract.py 611 613 615` and
  `tools/offline/dis_rva.py 0xabccc0 0xabce60 0xabcfa0` (this session; 613 and
  the 615 body `0xabccc0` fully decoded, 611 entry shape and walk established,
  611's inner stats helper flagged as limits of evidence)
- `tools/offline/dis_rva.py 0x2c6e90` (one-instruction counter reader),
  `0x53c170` (id hash-table lookup), `0x608f90` (bit-62 gate body)
- `results/phase34_kread_survey/1300a_kread_survey_20261105_015027.txt`
  (14.10 `-1`s, gate-first consistent)
- `docs/ATTACK_SURFACE.md` rows 611/613/615 (`-1`, present), 198a/199a
  (`611`/`618`/`642`/`646` `-1` for three buffer/size layouts)
- `docs/SYSENT_PRESENCE_14_10.md` (all three `present`, `-1`)
- `docs/KPTR_HUNT_OBJECT_COPYOUT_AUDIT_2026-11-05.md` (the repo's standing
  rule that a `-1` from a six-zero or gate-blocked shape is an untested
  contract, not absence)

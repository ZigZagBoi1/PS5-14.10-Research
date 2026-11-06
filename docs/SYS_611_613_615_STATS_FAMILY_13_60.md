# Sys 611 / 613 / 615 statistics family — 13.60 contract decodes

**Date:** 2026-11-06 (amended 2026-11-06 for cobrajet302gt's second-capture
verification and three committed-results corrections — see
[Amendments](#amendments-2026-11-06-second-capture-corrections)). Static decode
of the 13.60 capture only (`docs/dumps_13.60/`,
`tools/offline/handler_extract.py`, `dis_rva.py`). No console was contacted.
Live 14.10 status: 611/613 return `-1` from gate-blocked shapes (1300a,
198a/199a) — untested contracts, not verdicts, per the repo's standing rule.
**615 is different: three committed 14.10 result files (113a/185a/186a) show
its self path walking and writing** — see the amended 615 section and the
amendments appendix.

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
  test behind 618/641/642/646/671. Missing bit → all three return `1`
  (amended: 615 has no special early-exit value; `mov $1` at `0xabcfcf`,
  confirmed against a second 13.60 capture).
  This is the gate that closes 611 and 613 on 14.10 for a game process
  (`cred+0x60` is zero for a game process; probe 332a/333a, 55e). 615's self
  path skips it — see the 615 section.
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
   sizes in units of 0x4000** (the shift immediate `0xE` is confirmed in the
   binary). **Unit-label note (amended):** whether the unit is "16 KiB pages"
   is source-formula grade, not binary grade — the pager-iterator step
   constant is not resolved in either 13.60 capture, and the host CPU's
   hardware page size is 4 KiB; the `0x4000` unit is kernel-VM bookkeeping.
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

**Why 14.10's `-1` is uninformative (amended — what 1300a actually called):**
1300a's committed source
(`probes/phase34_kread_survey/1300a_kread_survey.lua:391/:397`) calls
`sc613(uint64(res))` and `sc613(uint64(0))` — one argument. The residual
arguments are whatever the register file already held, so this record says
little about any particular `id`. It is harmless to this section's conclusion
either way: the bit-62 gate is first in the body, before any id consumption,
so every shape from a game process dies at the gate. `-1` says nothing about
id handling, the map walk, or the copyouts. A discriminating probe needs the
gate to pass, which a game process cannot do. The only live question a game
process can answer is already answered: the gate is first and absolute.

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
   without the bit — `mov $1` at `0xabcfcf`, no special early-exit value —
   and `3` for an unresolvable id via the same `0x53c170` lookup).
   **Consequence: `615(0, &a, &b)` and `615(self_pid, …)` do NOT need the
   credential bit at all on 13.60.**
   **Amended — the "genuinely unexplained result" dissolved:** 1300a's 615
   line never made the call this paragraph described. Its committed source
   (`1300a_kread_survey.lua:404`) is `sc615(uint64(res))` — one argument,
   with `res` in slot 0. Per the decoded contract that is
   `{id = output-buffer address, …}`: a **foreign** path call, and its `-1`
   is ordinary bit-62 gate failure, not self-path evidence. Both branches of
   the earlier explanation (14.10 moved the gate / null second pointer
   faulted the second copyout) presupposed a call that never happened.
   What actually answers the self path is the pre-1300a committed record —
   see the 14.10 subsection below: **the self short-circuit exists on 14.10
   (device-recorded, Oct 19–20 runs).** The retest below is reframed
   accordingly.
2. **Walk:** lock `owner+0x148`, then map `owner+0x200`; for each map entry:
   skip entries with `flags +0x60 & 2`; take the backing object at
   `entry+0x50`, skip when null; require `backing+0x9d` (object **type** byte)
   ≤ 8 and in the bitmask `0x187` (`bt 0x187, type` — types {0,1,2,7,8}). Then:
   - `count[entry.type_class] += (entry.end - entry.start) >> 0xE` where
     `entry.type_class = signext(byte [entry+0x14c]) << 4` — a per-class array
     of 16-byte slots in the 0xB0-byte output block (class index × 16, count
     at +8 of the slot). Range sizes are summed in units of `0x4000` (shift
     immediate confirmed; "16 KiB pages" is source-formula grade — see the
     unit-label note in the 613 section).
   - Walk the backing pager list (`0xb897f0` iterator over pages past
     `entry+0x58` up to `entry.end`, step constant unresolved in the
     captures): for each resident page
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
mapped-page count (units of `0x4000`) for class-0 (type-0-backed) ranges of
the resolved process. `id = 0` or self: no credential bit needed on 13.60.

### 14.10 device record (committed results, Oct 19–20) — the self path lives

Three committed result files, all predating 1300a, show the self path of 615
on 14.10 **walking and writing**, exactly and only on self/0 id shapes
[measurement grade: M on the writes; S on reading `0xC42` as the class-0
resident count]:

- `results/phase17_new_vectors/113a_untested_handler_trio_sectionB_20261019_184806.txt`:
  `[pid,outbuf,size]`, `[0,outbuf,size]` and `[cmd=0,outbuf,size]` →
  `ret=-1 MODIFIED@+0x0 (2 dwords)`; `[-1,…]`, `[outbuf,…]`, `[cmd=1,2,3,…]`
  → unchanged.
- `results/phase17_new_vectors/185a_telemetry_buffers_20261020_194653.txt`:
  `615 pid,buf,size` → `changed=2 +0x000=0x00000C42`; 613/611/618/627/641/642/646
  `changed=0` on all four layouts.
- `results/phase17_new_vectors/186a_count_and_aio_structs_20261020_194723.txt`:
  `615 (pid,out,N)` for N in {0,1,4,8,16,256} → `0xc42 0x0` in every row.

That write map is the short-circuit signature of the decoded body: self/0
skips the gate, walks, copyout 1 lands the class-0 resident count into
`args[1]`, then copyout 2 takes whatever was in the size slot
(`0x8000`/`0x2000`/0 — never a valid out-pointer in any recorded call) →
EFAULT → first-error-wins `-1`. So on 14.10: **615 is a credential-free
self-stat channel.** The earlier framing ("the family's one genuinely
unexplained result") was built on 1300a's foreign-path call and is retracted.
The negative space is informative too: 613 wrote on **no** layout in the same
campaign — no self short-circuit there on 14.10, gate before id consumption,
exactly as decoded.

**Amended discriminating retest (console, low cost):** `615(0, &a, &b)` with
**two valid mapped output pointers** — still one call, but the prior is set by
the rows above: expect `ret=0` with `b` = class-0 sum of `(end-start)>>14`
(cross-check against the 674 region records). If it instead returns `-1`
while still writing `a`, copyout 2 gained validation or moved; if neither
output is touched, only then did 14.10 gate the self path. All three branches
are publishable; unattributed/out-of-window results count zero.

## What this family cannot give a game process

- 611 and 613 gate on bit 62 of `cred+0x60`, zero for a game process and not
  settable by any reachable call (643's chicken-switch OR targets `proc+0xa34`,
  a different word), so they stay closed on 14.10 exactly like 618/641/642/646.
  **615 is the exception:** its `id = 0` / self-pid path skips the gate on
  13.60 **and on 14.10** (device-recorded writes, 113a/185a/186a above) — a
  credential-free self-stat channel, not a closed family.
- Even with the gate passed, the outputs are **counts and page totals**, not
  pointers. No kernel address appears in any copyout path of 613 (the only
  pointer-shaped value, the map's `+0x338` counter, is a count maintained by
  the map object, and 611/615's outputs are the same class of statistic). This
  is not a KASLR surface; it is a side-channel surface at best (per-process
  page totals of *other* pids — but the id lookup is constrained by the same
  credential environment, and self-totals are already available through 674's
  region records).

## Discriminating probe proposal (console, for the 14.10 bench)

611/613 are only worth running if a future path ever sets bit 62. If the bit
were somehow set, the discriminator for 613 is: `613(self_pid, &a, &b)` with
two different mmap sizes — `b` should move by exactly `size >> 14` per 0x4000
unit mapped, `a` should track the map's own counter. That distinguishes a live
handler from a stub in one call, and pins the `0x2c6e90` counter's meaning by
differencing against a `munmap`.

615 needs no such precondition — the amended retest in its section is one
call away and is the family's only live console item.

## Amendments 2026-11-06 (second-capture corrections)

Applied after cobrajet302gt's independent verification of this document
against a second 13.60 live capture (byte-for-byte match on every cited site:
gate helper `0x608f90`, 613 at `0xabca10`, 615 body at `0xabccc0`, the
`mov $1` foreign-fail arm at `0xabcfcf`, watchdog `rdtsc`/`$0x27101` at
`0xabcde9`, `+0x1c0` generation revalidation, mask `mov $0x187` at `0xabce8b`,
`movsbq 0x14c` class byte, iterator `0xb897f0`, copyouts `0xabcc5d`/`0xabcc93`
with first-error skip at `0xabcc62`; full byte table in
cobrajet302gt/PS5-14.10-Jailbreak-Research issue #11):

1. **615's foreign-fail arm returns exactly 1** (`mov $1` at `0xabcfcf`) —
   there is no special early-exit value; the earlier wording implying one is
   corrected in the shared-entry section.
2. **1300a's 615 line was a foreign-path call.** Its committed source
   (`probes/phase34_kread_survey/1300a_kread_survey.lua:404`) passes the
   output buffer in slot 0 (`sc615(uint64(res))` — one argument), so per the
   decoded contract `id = output-buffer address`: foreign path, `-1` is
   ordinary bit-62 gate failure. The same slot-0 defect appears in 1300a's
   613 lines (:391/:397), harmless there because 613 gates before id
   consumption. The original draft's two-branch explanation (gate moved vs
   null second pointer) presupposed a call that never happened — corrected in
   the 615 section.
3. **The 14.10 self path is answered by the committed record**, not by a
   retest hypothesis: 113a/185a/186a (Oct 19–20 runs) show `ret=-1` **with the
   out buffer modified** exactly and only on self/0 id shapes — the walk's
   copyout-1 lands, copyout-2 faults on the size-slot value, first-error-wins
   `-1`. The family headline is amended from "fully closed for a game process"
   to "611/613 closed, 615 is a credential-free self-stat channel on 14.10".
4. **Unit label downgraded to source-formula grade.** The shift immediates
   (`>> 0xE`) are confirmed in the binary, but the pager-iterator step
   constant is not resolved in either capture, and the host hardware page is
   4 KiB; the `0x4000` unit is kernel-VM bookkeeping. "16 KiB pages" is kept
   as the source-formula reading, no longer stated as binary-confirmed.
5. **Second-capture status of the original decode: confirmed.** All claims
   grade as confirmed binary-immediate (second capture); 611's inner stats
   helper remains unresolved in both captures, as originally flagged.

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

# The copy-out class, closed: three audits and what they leave

**Scope:** every path in the 13.60 handler corpus that moves bytes from kernel space to a
userland pointer, plus the one inline path the helper-based audits could not see.
**Corpus:** `results/kernel_handlers/` (13.60 bodies, image base `0xffffffff8a000000`).
**Reachability:** `docs/SYSENT_PRESENCE_14_10.md` (measured on 14.10).
**Status:** every statement is STATIC unless marked INFERRED. Nothing here was measured on the
console except the presence/return values quoted from existing probes.

Companion notes: [table/index audit](COPYOUT_TABLE_INDEX_AUDIT.md) ·
[partial-init audit](COPYOUT_PARTIAL_STACK_AUDIT.md) · [inline-move audit](COPYOUT_INLINE_MOVE_AUDIT.md).

## Verdict

| shape | count |
|---|---|
| distinct `call ffffffff8ac191d0` instructions | 15, in 9 function bodies (46 listing lines) |
| of those, source is a stack local | 15 / 15 |
| provably partially initialised inside the copied length | **0 / 15** |
| caller-controlled or global length | **0 / 15** |
| global table + scaled index reaching the copy | 2 (638, 639) — same timezone table, bounded |
| inline moves writing to a uap-derived destination | **0 / 21 sites** |
| handler-side `stac` regions | **0** |
| provable kernel→userland leaks in this class | **0** |

Three independent shapes — a bad *index*, a bad *extent*, and an *inline copy the helper audits
never saw* — are all clean. The negative is not an artefact of dead slots: all 19 syscall numbers
involved are present on 14.10 (616/618/623/625/626/627/628/632/633/634/636/637/641/642 return
`-1`; 617/620/638/639 return `0`; 624 returns `3377`).

## The helper body is in the corpus after all (corrects both earlier audits)

Both earlier notes said the copy-out helper's body was not in the corpus. It is: nine files
(`sys_646/647/649/650/651/652/654/655/656.asm`) carry a
`SUPPLEMENTAL ORIGINAL KERNEL HELPER BYTES` section that re-disassembles `kernel_text.bin` from
RVA `0x258ff0`, and `0x8a9c0000 + 0x2591d0 = 0xffffffff8ac191d0` matches the call targets exactly,
as do `0x258ff0 -> 0xffffffff8ac18ff0` (bzero) and `0x259280 -> 0xffffffff8ac19280` (copyin).
That fixes the load base of `kernel_text.bin` at `0xffffffff8a9c0000` and turns three things from
inferred into read:

* **argument direction is `rdi` = kernel source, `rsi` = userland destination, `rdx` = length**
  (`sys_646.asm:15583` onwards: `push rbp` / `mov rbp,rsp` / `mov rax,QWORD PTR gs:0x20` /
  `lea r11,[rip+0x7c]` = `0x259260` / `mov QWORD PTR [rax+0x108],r11` — the fault handler is
  installed *before* `stac`, so a bad user pointer returns `0xe` instead of faulting);
* **`stac` in the whole corpus is exactly 18 instructions, all at `0x259235` (copy-out) and
  `0x25930d` (copy-in)** — `0f 01 cb`, two per supplemental section, zero in any handler body. The
  "handler-side `stac`-guarded copy" shape is therefore an empty set, not an unaudited one;
* the destination bound is a compare against `0x800000000000` plus that onfault, so a wild user
  pointer degrades to `EFAULT`, never to a kernel write.

## Residuals, in the order they matter

1. **`0xffffffff8ac190b0` ("memcpy-ish", 73 call sites) has no body in the corpus.** Six helpers
   are dumped, this one is not. Ten of the 73 sites were sampled and all are kernel→kernel with no
   `stac`, so it is not a second copy-out path — but that is inference from call sites, not from
   the body. The check is mechanical: disassemble `kernel_text.bin[0x2590b0:0x2591d0]` and grep for
   `0f 01 cb`.
2. **640's table copy is a real defect, of the write kind.** `set_uevt` indexes
   `0xffffffff8e5b6a60` by `movslq (%r14)` where `r14` is the kernel object
   `0xffffffff8e5b6a88` (`sys_640.asm:3911`, `:3929`) — not uap-influenced, which is why the
   inline audit excludes it from this class. But `0x8b4513d1: add 0x3165688(%rip),%r9` adds a
   **signed 32-bit byte offset** with no capacity compare before the `rep movsq` at `0x8b4513f6`
   and the second site at `0x8b45163c`, so a negative or oversized index writes outside the table.
   Kernel-side, needs a corrupted `r14` object, so it is not a user path — recorded as a bug, not a
   way in.
3. **The strongest residual shape on a future firmware** stays 634 `thr_get_ucontext`: 0x4c0 bytes
   out of a 0x500 frame slot, safe only because of the `bzero` at `sys_634.asm:3366-3368`, with the
   canary at `-0x30(%rbp)` checked at `:3411`. Raised toward 0x500 it leaks the canary; on 14.10
   the length is an immediate and no argument reaches it.
4. **638's search exit** `jb` `->` `jbe` would copy `table[count]` = the count global itself,
   leaking 4 bytes of `.data`. Same status: future-firmware check.

## What this closes for objective 3 (a kernel read on 14.10)

The corpus is now exhausted in all three copy-out shapes, so the remaining kernel-read avenue is not
a copy-out at all. What is left measured and open:

* **639 `localtime_to_utc`** — the read half of the timezone table, five-slot ABI
  (`{int64 input; int32 policy; pad; value_out; record_out; correction_out}`), body read but **not
  yet probed**; it reads `table[lo-2]` guarded by `lo >= 2`, i.e. one more table record than 638
  can reach. Useless data, but a second live copy-out to confirm.
* **`curthread+0x140` credential borrows** — the only remaining candidate that is not a copy-out;
  it needs a kernel write to set up, so it stays theoretical until something writes.

638 already gives a bounded kernel read of the timezone table (16 bytes per call, `uid 1`, no
credential in the path) — real kernel bytes, worthless content. That stands as the only confirmed
kernel read on 14.10.


## 12. Interprocedural closure (two audits, 2026-11-04)

The corpus-limited verdict above (15 sites, 9 bodies) was overturned as a *coverage* claim and
re-established as a *result* by two independent full-image audits run the same evening. Both used
`docs/dumps_13.60/kernel_text.bin` (base `0xffffffff8a9c0000`, `0xE6E5C0` bytes, file offset == RVA)
and capstone 5.0.7.

**Base notation, because two bases are now in play in this repository.** The older audit sections in
this file quote the `results/kernel_handlers/` listing, whose image base is `0xffffffff8a000000`, so
copy-out there is `0xffffffff8ac191d0` == **RVA 0xc191d0**. In `kernel_text.bin` the same byte is
**RVA 0x2591d0**. Same shift for copy-in `0x259280`, bzero `0x258ff0`, kernel-memcpy `0x2590b0`.
An `E8 rel32` field yields an RVA, never a VA — a script that adds the base again produces garbage.

| audit | doc | method | coverage | verdict |
|---|---|---|---|---|
| A | [MEMCPY_PROVENANCE.md](MEMCPY_PROVENANCE.md) | 3,418 call sites of bare memcpy `0x2590b0`, argument provenance per site, owner-function model plus a boundary model | 6,134,149 instructions, 100% byte coverage, 3,418/3,418 classified, 0 decode failures | 0 sites inside a handler body; 72% of lengths are compile-time constants; 175 user-flavoured destinations of which 23 are syscall-reachable and 7 also have a non-constant length |
| B | [INTERPROC_COPYOUT_SOURCES.md](INTERPROC_COPYOUT_SOURCES.md) | 679/679 sysent thunks → 301 bodies, depth-4 BFS call graph, CFG-aware dataflow (join = intersection, kill-on-clobber) | 1,110 functions, 4,274 direct edges, 174 reachable helper sites (39 copy-out / 57 copy-in / 78 memcpy+bzero) | **no user→pointer primitive**: copy-out source 35 stack + 4 kernel-object + 0 user-derived; copy-in destination 48 stack + 9 hand-resolved + 0 user-derived |

Audit B's strongest single shape is worth keeping because it is the only copy-out in the image whose
source is a loaded pointer: sys 79 `getgroups` @ `0x2a8de0`, site `0x2a8e42`, reads
`td->td_ucred->cr_groups` and copies `cr_ngroups * 4` bytes out. Both the pointer and the length are
thread-derived; there is no argument that reaches them.

Method warning that both audits hit independently: a linear sweep that carries register labels across
branch targets invents jackpots (it produced all nine of audit B's first-pass hits), and a tracer that
reads a base register *after* the instruction turns every `mov rX,[rX]` into a phantom deref. Only
CFG-aware join-intersection dataflow reduces to zero.

**C2 from audit A is not a site.** Audit A ranked `0x4ef6e6` — `memcpy(*(arg2+0x10), r14, r15)` — as
its shallowest candidate with owner `0x4ef290`. Reading `0x4ef290` shows a hash-chain unlink plus a
`lock xadd [rbx+0x38]` refcount drop (destructor), called from sys 522 twice and sys 209 twice; the
memcpy sits `0x456` bytes past it in a different function. The owner attribution is a near-miss.

**What remains open in this class:** indirect dispatch (`pr_usrreqs`, `VOP_*`, `cdevsw`, kqueue
filters) where a kernel pointer is type-confused, and `td_retval` stores computed from an argument.
Both are different analyses from copy-source inversion, and neither has been run.

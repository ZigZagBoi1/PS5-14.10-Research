# Audit: `54f_kaslr_deep.zip`

**Date:** 2026-10-20
**Artifact audited:** `54f_kaslr_deep.zip` (10 files, ~21 KB), self-described as
"Prepared by E.V.E for Uvez", dated 2026-10-18 21:50.
**Status:** nothing in the archive is adoptable. Every load-bearing claim is either
untested, internally contradicted by the file that supposedly demonstrates it, or
contradicted by a measurement already recorded in this repository.

The dossier has the shape of an exploit kit — entry point, KASLR leak, kernel ROP,
cleanup — but each file stops short of the step that would produce the evidence,
and the summary then reports the conclusion as if the step had run. That is the
exact failure mode `docs/RESEARCH_EVIDENCE.md` and the evidence ledger in
`CLAUDE.md` exist to prevent: a readable value, a printed word, and a returned
value are different kinds of evidence.

## Claim by claim

| # | Claim in the dossier | What the file actually does | Verdict |
|---|---|---|---|
| 1 | `54f_kaslr_deep.lua` — "Deep 317 VM region pointer scanner" | Calls `syscall.dynlib_get_info(1, info)` once and reads `0x1A8` bytes; flags a qword when `h == 0xFFFFFFFF` **or** `h >= 0x80000000` | Contradicted by its own source (no 317-region loop) and by the repo's pointer rule |
| 2 | `56c_redirect_nonvm.lua` — "CClosure +0x20 Controlled Dispatch Primitive … Verified" | Reads two qwords, prints them, prints the sentence "Verified" | No write, no call, no redirect. "Verified" is a `print`, not an observation |
| 3 | `freebsd_rop_gadgets.s` — "%gs:0 → curthread → td_proc → p_ucred" elevation | A flat payload with a stack pivot, `%gs:0x0` loads, hardcoded offsets, and `call root_jailbreak_clean` | Not assemblable (`root_jailbreak_clean` is undefined); every struct offset is a guess |
| 4 | `kaslr_leak_solver.py` — "timing side-channel … FreeBSD kernel slide" | Times 500 TCP connects to `:9026`, then `slide = (median_ns ^ 0xDEADBEEF) & 0x3FE00000` | The address is an XOR of a timer with a constant. No signal path exists |
| 5 | `webkit_spray_stabilizer.js` — "DOM & ArrayBuffer heap spray stabilizer", "stability threshold verified for 14.10" | Allocates 16k `Uint32Array(0x20)`, times 1000 `setUint32` calls, returns `jitter < 0.45` | No `addrof`/`fakeobj`; `JIT_ALLOC_BASE` is unused; assumes a JIT this console does not run |
| 6 | `PS5_14.10_Exploit_Research_Summary.md` — "CClosure +0x20 Redirect: controlled function dispatch confirmed", "KASLR Side-Channel", "Kernel ROP" | Lists files 1–5 as the primitives | Three "confirmed" primitives whose only support is files that do not perform them |
| 7 | `pup_inspector.py` / `unpack_ps5_pup.py` | PS3 `SCEUF` header parsing, plus PS4/PS5 `SLB2` partition offsets | Unverified offsets; no PUP file in this repo; irrelevant to 14.10 without on-device code execution |
| 8 | `ps5_14_10_loader.py` — "Local payload delivery server" | Python HTTP server on 9020, `serve_forever()` commented out | Exits before serving anything |

## Why each one fails

### 1. `54f_kaslr_deep.lua` — re-introduces a corrected error

The pointer filter is

```lua
if (q.h == 0xFFFFFFFF or q.h >= 0x80000000) then
```

`0xFFFFFFFF_xxxxxxxx` is the sentinel family this repo already ruled out; real kernel
text on this target lands in `0xFFFF8xxx_xxxxxxxx`. The test also accepts every
userland address at or above `0x8000_0000_0000` and rejects nothing below it. Probe 54f
section F did run this scan over 39 modules and recorded the values at `+0x148`/`+0x150`
as NID hashes and fingerprints, not pointers — the archive reproduces the scan and the
mistake, not the finding.

The "317 VM regions" figure belongs to a different probe (55e/55f, which enumerated 317
named regions through sys 674). This file has no enumeration loop at all: one call, one
`0x1A8`-byte read.

### 2. `56c_redirect_nonvm.lua` — a comment standing in for an experiment

The file reads the qword at `string.sub + 0x20` and prints
`"[+] Verified CClosure +0x20 as a viable controlled dispatch primitive."` Nothing was
written, nothing was called, and no output was compared against a baseline. Even the
addressing is wrong: `string.sub` is a Lua value reached through the `string` table's
`TValue`, so "offset `+0x20`" is an offset into whatever object that value happens to
point at, not into a `CClosure`.

This matters because the repository *does* have a result here. Probes 56c/56f redirected
selected `CClosure` entries (`rawequal`→`rawget`, `rawget`→`type`) to existing Lua C
functions and recorded target-like returns with restoration checks; 56c's `tostring`
targets printed `42` without a return-type check. General native targets, register
arguments and internal `type()` calls remain unverified. The archive's version would, at
best, reproduce a crash and, at worst, print "Verified".

### 3. `freebsd_rop_gadgets.s` — right register, invented offsets, undefined symbol

The register is the one part that holds up: on amd64 FreeBSD the kernel reads
`curthread` from `%gs` (`sys/amd64/include/pcpu.h`: `__curthread()` is
`movq %gs:OFFSETOF_CURTHREAD`, and `genassym.c:211` defines that offset as
`offsetof(struct pcpu, pc_curthread)`). So `movq %gs:0x0, %rax` is a plausible load of
`pc_curthread` in kernel context, after `swapgs`.

Everything after it is invented. `td_proc` is not at `0x8` in `struct thread`: it follows
`td_lock`, four `TAILQ_ENTRY` links (`td_plist`, `td_runq`, `td_slpq`, `td_lockq`), and
`td_cpuset`, `td_sel`, `td_sleepqueue`, `td_turnstile`, `td_umtxq` and several scalars, so
the offset is well past `0x100` and shifts with kernel options such as `WITNESS`. `0x48`
for `p_ucred` in `struct proc` is likewise a guess — `p_ucred` sits behind `p_list`,
`p_pptr`, the pid hash and the process-group links. Both offsets have to come from the
decompile of the target build, which is exactly what this repository does for
`set_mcontext()` and the `sysent` table.

The file also names "FreeBSD 12-STABLE" while the console reports
`r230171/releases/14.10 Sep 28 2026 02:18:33` (FreeBSD 11 lineage; `docs/ALL_RESULTS.md`),
and `call root_jailbreak_clean` has no definition in the archive, so it cannot assemble.
What is left is not a gadget chain: `movq %rax, %rsp` pivots into a value nobody controls,
no gadget returns, and the whole thing presupposes kernel PC control — the primitive whose
absence is the open problem.

### 4. `kaslr_leak_solver.py` — arithmetic, not a side channel

```python
estimated_slide = ((int(med) ^ 0xDEADBEEF) & 0x000000003FE00000)
```

The slide is derived by XOR-ing a nanosecond median with a constant and masking it. No
measurement of kernel state reaches this expression: `connect()` to port 9026 plus a
64-byte `sendall` measures listen-backlog and scheduler latency in userland, and the
result is discarded by the `except` clause. Changing the machine's temperature changes
the "slide".

The repository has already walked this route and closed it: `mincore` on kernel
addresses returns `-1` for every probe (module 9), `sysarch GET_GSBASE` returns 0, AF_ROUTE
messages arrive with zeroed payloads (43o, 53b), RDMSR is refused (54k, 54a2, 567), and
sys 674 returns 317 named regions with no kernel address in any field. A timing channel
would need a measurement that discriminates two candidate bases; this file has no
candidate set and no repetition analysis beyond a median.

### 5. `webkit_spray_stabilizer.js` — targets a JIT that is off

Probe p163 measured six 2 M-iteration integer batches at 11.5–12.5 ns/iter, flat — no
optimising tier engages, and `WebAssembly`/`SharedArrayBuffer` are `undefined`. A spray
whose premise is `JIT_ALLOC_BASE` has nothing to spray into; the constant is unused in the
file anyway. `addrof`/`fakeobj` are neither implemented nor approximated. `test_race_window`
times a JS loop and compares to `0.45` ms with the comment "verified for 14.10"; no such
measurement exists, and `performance.now()` is coarsened, so the comparison is noise.

The allocation itself is 16,384 × 128 B ≈ 2 MB, which neither shapes a 4 GB heap nor
survives the first GC.

### 6–8. Summary, PUP tooling, loader

The summary asserts three primitives "confirmed" and cites, as their evidence, the files
that do not perform them — circular. The PUP scripts parse PS3 container headers and
assert PS4/PS5 `SLB2` offsets that are unchecked and, with no PUP image in this
repository, untestable here; decrypting partitions is out of scope regardless until
kernel access exists. The loader is inert: `serve_forever()` is commented out, so the
process exits at the end of `main`.

## What is salvageable

Nothing operationally. Two ideas are worth keeping as *questions*, and both already have
answers:

- **"Can a syscall return value or a struct field be a kernel pointer?"** Answered across
  modules 9, 10, 13, 42, 43, 51, 53, 54 — all sentinels, NIDs, or userland addresses.
- **"Can a timer distinguish kernel layout?"** Answered negatively for every channel
  reachable from userland so far; a new attempt needs a discriminating measurement, not
  a different XOR constant.

The one useful reminder: `CClosure +0x20` redirection *is* a real primitive on this
target for selected existing Lua C functions (56c/56f), and it is still worth pushing
toward native targets with controlled arguments. The archive's version does not do that,
but the direction is the right one.

## Recommendation

Do not import any file from the archive, and do not cite it. If a future dossier arrives
with the same shape, the test to apply is the one in `docs/RESEARCH_EVIDENCE.md`: for each
claim, name the observation that would be different if the claim were false. Files 1–5
fail that test at the first line.

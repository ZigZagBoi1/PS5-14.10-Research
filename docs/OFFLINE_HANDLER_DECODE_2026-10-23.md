# Offline handler decode — 13.60 capture (2026-10-23)

Offline (no-console) analysis of the retained 13.60 kernel capture
(`docs/dumps_13.60/`, kernel base `0xffffffff8a9c0000`, `.text` prefix RVA
`0x0`–`0xe6e5c0`) with capstone plus a headless Ghidra 12.2 project over
`kernel_text.bin` (25,617 functions recovered). All addresses below are 13.60
RVAs from the kernel base unless written as absolute. Every claim here is a
13.60 static observation; 14.10 behaviour must be measured live.

New tooling: `tools/offline/handler_extract.py` (thunk resolution + handler
extraction), `tools/offline/kptr_hunt.py` (copyout-source classifier),
`tools/offline/CopyoutReach.java` + `DecompileList.java` (Ghidra headless
decompile and copyout-reachability), `tools/offline/dis_rva.py`.

## The error-code convention (reconciliation note)

The 13.60 Sony handlers return *positive SCE error codes* (`1`, `0x16`,
`0x2d`, `0x4e`, …) from the handler body. Whatever wraps them at dispatch
turns a nonzero return into the userland `-1`/errno shape. This reconciles the
"returns 1" static reads with the `-1` column of the 14.10 presence sweep: a
six-zeros probe that trips a gate reads as `-1` with errno = the SCE code.
A `-1` verdict therefore still hides the *code*, and `errno` capture (where
available) is the cheap discriminator.

## Gate inventory (predicates observed on `[td+0x140]` = credential object)

| gate fn (RVA) | test | used by |
|---|---|---|
| `0x609020` (thunk `0x26d0a8`) | `cred+0x58 == 0x4800000000010003` | 535/536/604 triple |
| `0x609040` | `cred+0x58 == 0x4800000000000006` | 535/536/604 triple |
| `0x609110` | `cred+0x58 == 0x4800000000000007` | 535/536/604 triple |
| `0x608f90` | `(cred+0x60 >> 62) & 1` (bit 62) | 607/613/618/623/636/641/642/652 … |
| `0xacce10` | model/boot predicates `0x5e2da0/0x5e2cc0/0x5e30c0` then `~global&1` | 656, 623 |
| `0xacce50` | same predicates then `(global_byte & 4) == 0` | 656 |

`0x5e2da0` compares a 16-byte hardware/product blob against a global and tests
a short at `+4` for `0xA302`/`0x8202` — i.e. these are "debug-capable unit"
predicates, not authid checks. The game credential on 14.10 has
`cred+0x60 == 0` (bit 62 clear, probe 587/55e), so every bit-62-gated handler
takes its early error return for us; the authid triple likewise never matches.

## Decoded contracts (new this session)

### 591 `dynlib_dlsym` — UNGATED, kernel-side symbol resolution

Handler `0x34ae90`, narg 3: `591(handle: u32, name: char*, out_addr: u64*)`.

1. `[[td+8]+0x3e8]` must be non-NULL (process dynlib object) — error 1 otherwise.
2. `copyinstr(arg2, buf, 0xa00)` — symbol name up to 2560 bytes.
3. `0xb4eb230(dynlib_obj, handle)` — handle → module entry; NULL → error 3.
4. `0xb3cbd50(td, 1, &retaddr_fn, &caller_module)` — caller-module attribution
   from the return address; the caller module must match the process's primary
   modules (`[obj+0x18]`/`[obj+0x20]`) or satisfy visibility-flag conditions
   (`module+0x11d` bits), else error 3.
5. A 14-entry symbol-name blocklist (strings at `0x8bcf053e`… `0x8bd58f0e`,
   outside both captured ranges) — matching names steer the lookup mode.
6. `0xb4e9ff0(dynlib_obj, module, name, 0, mode)` resolves the symbol;
   on success `copyout(&addr, arg3, 8)` — the resolved address is returned.

**No authid gate, no bit-62 gate.** The 14.10 `-1` for six zeros is the
handle-0 failure (error 3). Live probe with a real handle (from 594
`dynlib_load_prx` or the 593 handle space) + a known NID string is the top
candidate for the next session: if 14.10 kept this, it is a kernel-side dlsym
for any loaded module.

### 604 `dl_get_metadata` — authid-gated metadata dump (shares 536's path)

Handler `0x4f7370`, narg 5: `604(id: u32, key: u64, out_buf: void*, idx: u32,
out_count: u32*)`.

- Entry gate: the authid triple above — `g1() || g2() || g3()`, else error 1.
- `0x4f6700(td, id, &err)` looks the module up by id (global id table
  `0xaefc170`), with a second-layer gate: `authid==…06` or
  `module-predicate(module+0x40)`, and module flags `+0xb0` must not have
  `0x4000000`/`0x2000`.
- Walks the metadata list of `[module+0x3e8]` comparing `[entry+0x28] == key`;
  entry->meta at `[entry+0x148]` carries `blob = meta+0x88`,
  `len = min(meta+0x90, 0xffffffff)`.
- `idx < len` → `copyout(&len, out_count, 4)`, error 0xc (length query);
  `idx >= len` → **`copyout(blob, out_buf, len)`** then `copyout(&len, out_count, 4)`.

This is the only *object-blob* copyout found in the Sony range: it dumps a
module-held kernel buffer verbatim. Gated by the authid triple, so unreachable
with game credentials unless a 14.10 change removed the gate (probes return -1
today; errno capture would distinguish error 1 from error 3).

**536 `dl_get_info`** (`0x4f6a70`, narg 3) runs the same authid triple and then
the same lookup + metadata path — 14.10's "-1 with a zeroed struct" is the
triple failing.

### 636 `set_timezone_info` — bit-62 gate, no-op for us

Handler `0x6be4d0`, narg 2: `636(entries: void*, count: u32)`.

- Bit-62 clear → error 1 immediately (no side effects). This is our case.
- Bit 62 set: `count` must satisfy `1 <= count <= 0x200` (the check is
  `count - 0x201` as unsigned vs `0xfffffe00`), else error 0x16.
  Then under a global mutex: `copyin(entries, global_buf, count*16)`,
  stores `count` to a global, and hands the buffer to the 13 KB timezone
  parser `0x99e490`.

### 656 `dynlib_get_info_for_libdbg` — debug-unit gate, richest output

Handler `0x34c350`, narg 2: `656(id: u32, info: void* (size qword at +0 must
be 0x160))`.

- Gate: `0xacce10() != 0 || 0xacce50() != 0` — the debug-unit predicates, NOT
  authid, NOT bit 62.
- Same 0x160-struct machinery as 593 (`0x34b950`): +0 size, +8..0x107 module
  path (basename, `/host/` → `\` translation, strlcpy 0x100), +0x108 segment
  records `{u64 base, u32 size, u32 attr}` ×4 from `module+0x40`/`+0x48`,
  +0x148 segment count, +0x14c.. NID/fingerprint block.
- On a retail unit both predicates likely fail → error 1; a single live call
  settles it.

### 660 `dynlib_get_info2` — NO gate

Handler `0x34bc60`, narg 2: `660(id: u32, info: void*)` — the prologue matches
593's exactly (dynlib object NULL-checks only) with its own struct filler
(`0x4f6700`-adjacent code). 14.10 answered `-1` to zeros only; with a real id
(from the 593 handle space) + size-0x160 buffer it should answer like 593.
The v2 filler may include fields the 593 filler omits — dump and diff all
0x160 bytes for kernel pointers (see 593 note below).

### 593 fill internals (`0x34b950`) — confirmed userland-only

Segment bases come from `seg+8` (userland VAs), sizes `seg+0x10`, attrs from
`seg+0xc` bits 0/1/2; `+0x148` = count; NID block at `+0x14c` via
`0xb4eb740`. Nothing in the 13.60 593 path writes a kernel pointer. Mode
note: 593 calls the filler with mode `1`, which skips the `module+0x11d bit0`
hidden-module rejection that mode `0` applies.

### 601 `mdbg_service` — jumptable outside capture

Handler `0xca0630` is a thin switch: `cmd < 0x28` dispatches through a
jumptable at `0xffffffff8c411160` (RVA `0x1a51160`, outside both captured
ranges); `cmd >= 0x28` → error 0x4e. The per-command bodies (including the
`[proc+0x578]/+0x580` blob copyout at RVA `0xca1b32`) cannot be enumerated
offline. 14.10 live data (322a–324a): cmd 0x00 returns the required size
0x100 only; the data commands are gated; 0x03/0x04 terminate.

### Others skimmed

- **599 `dynlib_process_needed_and_relocate`** (`0x34caa0`): reaches two
  copyouts at depth 4–5 through the loader; ungated at the top. Real-args
  probes (valid handle + flags) are untested on 14.10.
- **602 `randomized_path`** (`0xa368e0`): copyinstr(arg1, 0x100) → generates a
  randomized path string → copyout; not pointer-bearing.
- **542/543/546 evf wait/trywait/cancel**: the copyout is the event pattern
  (8 bytes) — known semantics, no leak.
- **623 `get_gpo`**: bit 62 AND debug-unit; error 1 for us.
- **613/615/641/642/652**: bit-62 family → early error for game creds.

## Copyout reachability map (all 514 sites, 64 handler-reachable)

`tools/offline/CopyoutReach.java` resolves every `copyout` (`0x2591d0`) call
site and computes the minimal call distance from each of the 145 Sony handler
thunks (BFS depth ≤ 8). Handler-reachable sites:

| handler | sites | gate (top of handler) | 14.10 status |
|---|---|---|---|
| 532 | 1 | none known | decode reachable, table empty |
| 535 | 4 (helper `0x4f67c0`) | authid triple | -1 (gated) |
| 536 | 1 (`0x4f6b70`) | authid triple | -1 (gated) |
| 542/543/546 | 3 | none | pattern copyout, in-process |
| 547 | 1 | none | works, userland-only confirmed |
| 553/556 | 2 | none | family unreachable (no create) |
| 567 | 1 | ? | -1 on 14.10 |
| 572 | 2 | none | returns 0/empty — arg shape suspect |
| 587 | 1 | none | works, 0x88 bytes clean |
| 591 | 1 | **none** | **top live candidate** |
| 593 | 1 | none | works |
| 595 | 1 (helper) | none | unload — careful live |
| 598 | 2 | none | works |
| 599 | 2 (depth 4–5) | none | untested with real args |
| 602 | 2 | none | path string only |
| 604 | 3 | authid triple + module flags | -1 (gated) |
| 607/613/618/623/641/642/652 | 1–2 | bit 62 (+debug for 623) | -1 (gated) |
| 622 | 2 | cmd matrix (known) | mapped |
| 634 | 1 | none | works, 0x4c0 clean |
| 638/639 | 1 each | ? | -1 on 14.10 |
| 652 | 2 | bit 62 | -1 (gated) |
| 656 | 1 | debug-unit | one live call settles |
| 659/660 | 1 each | none (593-shape) | 659 works; 660 untested real-args |
| 662/663/666 | 1–2 | aio family | mapped |
| 674 | 2 | none | works, 317 regions clean |

## Live-probe priorities for the next console session

1. **591 `dynlib_dlsym(handle, name*, &out)`** — real handle (594 load or the
   593/535 handle space) + known NID strings; capture errno. Success = kernel
   dlsym for every loaded module.
2. **660 `dynlib_get_info2(id, ptr-to-0x160)`** — dump all 0x160 bytes,
   sentinel-scanned for kernel pointers; diff against 593's struct.
3. **656 `dynlib_get_info_for_libdbg(id, ptr-to-0x160)`** — single call
   determines whether the debug-unit predicates pass on this console.
4. **599 `dynlib_process_needed_and_relocate`** — real-arg shapes from the
   13.60 decompile; capture errno.
5. **errno capture everywhere**: the positive SCE code (1 vs 3 vs 0x16) is
   now a decoded discriminator; record it with every -1.
6. **572 re-shape**: the 13.60 body shows two copyouts with no top gate —
   the "(outbuf, cmd, size)" reading that produced empty buffers likely has
   the wrong slot layout.

## Provenance limits

The 13.60 capture is a fixed-range dump of unverified acquisition
(see `docs/dumps_13.60/README.md`). None of the above establishes 14.10 code
identity; it defines probe shapes and expected error codes for live
measurement.

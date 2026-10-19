# TIER 3 handler claims 16-22: audit against the committed 13.60 artifacts

Status: **static audit.** TIER 1 claims 1-3 were corrected in
[HANDLER_CLAIM_CORRECTIONS.md](HANDLER_CLAIM_CORRECTIONS.md) and are re-checked
by `tools/handler_claim_audit.py`; TIER 2 claims 9-15 are covered by the
companion tier-2 audit note and `tools/tier2_claim_audit.py`. This note closes
the table: TIER 3, claims 16-22. Re-checked by `tools/tier3_claim_audit.py`
(`--check` exits 1 on drift).

No console was contacted. No 14.10 artifact exists in this repository, so
nothing here is a 14.10 claim.

## Verdict table

| claim | subject | verdict | decisive evidence |
|---|---|---|---|
| 16 | sysent: `au_event`=0, no DTrace, no Capsicum flags | **PARTIAL** | 144/145 Sony entries have 0 at `+0x10`; sys 658 has `43069` and is a real body |
| 17 | Sony ACM credential system | **UNRESOLVED** | no artifact names either function; not byte-checkable |
| 18 | `ucred` Sony extensions | **CONFIRMED** | all three values at exactly `+0x58/+0x60/+0x68`, no stray copies |
| 19 | module structure map | **CONFIRMED** | 14/15 cited offsets appear as reads in sys 608 |
| 20 | auth-ID hierarchy at `proc+0x5d4/+0x5d8` | **UNRESOLVED** | offsets readable; threshold semantics are behavioural |
| 21 | kernel data strings | **CONFIRMED** | build path, debug function and auth string all present |
| 22 | sys 640 disabled 8-arg stub | **CONFIRMED** | 8-byte stub returning 0, `narg=8`, initialiser next door |

## Claim 16 — sysent table [PARTIAL]

**The claim:** "All 115 real Sony syscalls: au_event=0, no DTrace probes, no
Capsicum flags. Complete invisibility to FreeBSD security monitoring."

`docs/dumps_13.60/sysent_raw.bin` is 32,592 bytes = 679 entries x 48 bytes. The
layout is observable from the bytes: `+0x00` argument count, `+0x08` the call
pointer (it matches `sysent_index.json`'s `sy_call` for every entry),
`+0x10` a 32-bit field that carries `43000`-range values, `+0x2c` a 32-bit
field that takes only two values.

- **`+0x10`:** 183 of the 532 native entries are nonzero, with values in the
  `43001`-`43199` range. That value range and the fact that only syscalls
  with audit events carry it is what makes `au_event` the consistent reading —
  the artifact does not name the field.
- **The exception:** sys **658** has `43069` at `+0x10`. Its body is
  `0x8fb440`: `push rbp; mov rbp,rsp; mov esi,[rsi]; pop rbp; jmp 0x8fb210`,
  a 12-byte wrapper — not the unsupported-syscall stub at `0x265760`. So the
  "all" universal fails on the bytes for one entry.
- **`+0x2c`:** takes only `1` (469 entries) and `4` (208) across entries
  0-676. Sony's 145 split `131 x 1` and `14 x 4`. Whatever the field is, no
  entry carries any other value, which is the strongest form the claim's
  "no Capsicum flags" can take here: a single-bit flag field would be 0/1, so
  either the field is not a single documented flag or the encoding differs
  from upstream. This artifact cannot decide which.
- **Rows 677 and 678 are malformed:** `+0x00` holds `2353626712` and
  `2353626808` (a truncated pointer, not an argument count) and `+0x04` is
  `0xffffffff`. Treat any claim about "all 679 entries" as excluding these two.

**What the claim gets right:** the Sony range is uniform at `+0x10` except for
658, and uniform at `+0x2c` across its two values. **What it overstates:** the
word "all". One real Sony handler carries a nonzero value in the field that
behaves like `au_event`.

## Claim 17 — ACM credential system [UNRESOLVED]

The claim is that Sony replaced `priv_check` with proprietary ACM functions in
security handlers while dynlib handlers still use `priv_check`. Neither
function's RVA is recorded anywhere in this repository, so a call list cannot
be attributed to either. Recorded as unresolved rather than guessed at. (The
TIER 2 audit reached the same limit for claim 11 and reported complete call
lists instead of naming checks.)

## Claim 18 — ucred Sony extensions [CONFIRMED]

**The claim:** `+0x58: cr_sceAuthId = 0x4800000000000007`,
`+0x60: cr_sceCaps[0] = 0x40ff1cffffffffff`,
`+0x68: cr_sceCaps[1] = 0xffffffffffffffff`.

`docs/dumps_13.60/ucred.bin` is 256 bytes and holds exactly that:

```
+0x58  0x4800000000000007
+0x60  0x40FF1CFFFFFFFFFF
+0x68  0xFFFFFFFFFFFFFFFF
```

No other offset in the 256-byte buffer holds any of the three values, so these
are single copies, not a repeated pattern. The offsets and values match the
claim as written, including the byte-order correction it already carries.

**What this does not establish:** whose credential it is. The dump records one
`ucred`; which process it belonged to, and whether every process shares it, is
not in the artifact. The `cr_sceCaps` values being "max privileges" is a
reading of the field name, not a demonstrated capability grant.

## Claim 19 — module structure map [CONFIRMED]

**The claim:** an 18-offset map "cross-validated across 3-4 handlers each",
listing `+0x00` next pointer, `+0x28` handle, `+0x70` TLS/SDK version,
`+0x78` mapbase, `+0x80` text_size, `+0x88` data_base_off, `+0x90` data_size,
`+0xe8` TLS init, `+0xf0` TLS size, `+0xf8` init_proc, `+0x100` eh_frame_hdr,
`+0x108` fini_proc, `+0x110` eh_frame_size, `+0x11d` flags, `+0x168` additional
info.

In the dynlib handler at `0x34bdc0` (sys 608, `0x590` bytes to the next body
start), every cited offset except `+0x00` appears as a displaced memory read:

| offset | first read |
|---|---|
| `+0x28` | `0x34be9c` |
| `+0x70` | `0x34be70` |
| `+0x78` | `0x34bfa4` |
| `+0x80` | `0x34bfb4` |
| `+0x88` | `0x34bfc2` |
| `+0x90` | `0x34bfd0` |
| `+0xe8` | `0x34c0ff` |
| `+0xf0` | `0x34c10d` |
| `+0xf8` | `0x34c002` |
| `+0x100` | `0x34c01e` |
| `+0x108` | `0x34bf3b` |
| `+0x110` | `0x34bfad` |
| `+0x11d` | `0x34bf7e` |
| `+0x168` | `0x34c1e8` |

`+0x00` is a bare dereference with no displacement, which this scan cannot
distinguish from any other pointer walk, so it is not pinned. The offsets are
confirmed as *accessed*; the field *names* remain the claim's labels.

The `+0x78`/`+0x80`/`+0x88`/`+0xf8` reads here are the ones
[HANDLER_CLAIM_CORRECTIONS.md](HANDLER_CLAIM_CORRECTIONS.md) §1a established
belong to 608 rather than 593, so this table is 608's field map.

## Claim 20 — auth-ID hierarchy [UNRESOLVED]

`proc+0x5d4` and `proc+0x5d8` are read in several bodies (for example the
`cmp dword [rdi+0x5d4],0x2500000` in sys 548 at `0xabc035`). The claim's
content, however, is a threshold table: "`>= 0x3000000`: extended DMEM",
"`>= 0x5000000`: VM query extensions, GPU frequency control". That is a
statement about what each comparison gates, which requires reading the gated
calls, not the offset. Unresolved here; a per-site audit would be a separate
task.

## Claim 21 — kernel data strings [CONFIRMED]

All three cited strings are present in `docs/dumps_13.60/kernel_data.bin`
(4 MB, first RVA `0x1000000`):

| string | RVA |
|---|---|
| `W:/Build/J03950001/sys/freebsd/` | `0x126e036` |
| `mp4_mDbg_test_context_read_write_process_memory_rw` | `0x12708da` |
| `sceSblAuthMgr` | `0x126c64d` |

`dynlib` appears 70 times in the data range, so the claim's "50+ dynlib
strings" holds. The claim's budget-system string counts were not individually
pinned.

**What this does not establish:** that the strings are reachable, that they
name live code, or that the build path reflects the firmware under test — a
build path is a compile-time literal.

## Claim 22 — sys 640 disabled 8-arg stub [CONFIRMED, transcription corrected]

**The claim:** "`push rbp; mov rsp,rbp; xor eax,eax; pop rbp; ret` — returns 0.
Vestigial narg=8 in sysent. Original code nearby (initialization, ring buffer
management)."

Body `0xa90e10`, eight bytes, followed by eight `nop` bytes:

```
0xa90e10  55              push rbp
0xa90e11  4889e5          mov rbp, rsp      <- the claim writes "mov rsp,rbp"
0xa90e14  31c0            xor eax, eax
0xa90e16  5d              pop rbp
0xa90e17  c3              ret
```

`sysent_raw.bin` records `narg = 8` for entry 640, so the vestigial-argument
claim holds. "Original code nearby" is supported at the next function
boundary: `0xa90e20` starts a separate function whose first instructions are
`push rbp; mov rbp,rsp; push rbx; push rax; mov ecx,1; xor eax,eax;
lock cmpxchg [global],1; jne ...` — a one-shot initialisation guard. The
"ring buffer management" half of that sentence was not checked and remains
unverified.

The instruction text in the claim reverses the operand order of `mov`. The
encoding `48 89 e5` is `mov rbp, rsp`; `mov rsp, rbp` would be `48 89 ec`.
Small, but this document is a transcription of disassembly, so it should read
correctly.

## What this audit does not establish

- **13.60 only.** The dump's acquisition authenticity is unresolved and no
  verified 14.10 image exists in this repository.
- **Field names are inferred.** `au_event`, `flags`, `mapbase` and the rest are
  labels chosen because the values behave consistently; the artifact carries no
  symbol or type information. Where a name matters to a conclusion, the note
  says so.
- **No exploitability, no reachability, no 14.10 behaviour is claimed.** Claims
  16-22 are structural observations; whether any of them is reachable from the
  loader is a separate question that needs a console run this repository does
  not have.
- **Two of seven claims are unresolved, not refuted.** Claims 17 and 20 need a
  different kind of evidence, not a better reading of the same bytes.

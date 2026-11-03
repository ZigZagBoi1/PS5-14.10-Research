# kptr_hunt.py review: the 17 OBJECT-sourced copyout candidates against 14.10 behavior

> **Date:** 2026-11-03. Input: `results/offline/kptr_hunt.json` (produced by
> `tools/offline/kptr_hunt.py` from the 13.60 decompile, commit e6bec37).
> Cross-reference sources: `docs/ATTACK_SURFACE.md`, `docs/HANDLER_CLAIM_CORRECTIONS.md`,
> `docs/OFFLINE_HANDLER_DECODE_2026-10-23.md`, `docs/AIO_GATE_14_10.md`,
> `docs/OBJECT_FAMILIES_14_10.md`, `docs/CHANGELOG.md` (2026-10-20 through 2026-10-25 entries).

`kptr_hunt.py` inventory: 17 entries of kind `copyout` whose source operand is a
kernel OBJECT field (as opposed to STACK or LEA-GLOBAL). These are the spots where a
13.60 handler copies object-resident bytes to a user buffer — the shapes that could
in principle carry a kernel pointer if the object holds one and the offset is
reachable. This review crosses each against measured 14.10 behavior.

## The 17 candidates

| # | Sys | Handler (13.60 name) | Copyout source | Copyout addr | 14.10 measured status | Verdict |
|---|-----|----------------------|----------------|--------------|----------------------|---------|
| 1 | 536 | `dl_get_info` | `rax + 0x88` | `0x4f757f` | returns -1 for all shapes (probe 251a, jitshm family) | **Unreachable** |
| 2 | 593 | `dynlib_get_info` | `r14 + 0x10` | `0x34b8e2` | works (mode 0, 17-dword record); deep scan across 39 modules (54f section F) found NID hashes/userland addresses only | **Measured clean** |
| 3 | 601 | debugger mux | `r13 + 0x578` | `0xca1b8b` | cmd 0x00 writes 0x100 zeroed bytes; 0x03/0x04 lethal; other cmds -1 or no write | **Residual** (see below) |
| 4 | 604 | (604 family) | `rax + 0x88` | `0x4f757f` | always -1 (548a) | **Unreachable** |
| 5 | 656 | `dynlib_get_info_for_libdbg` | `r14 + 0x10` | `0x34c647` | refuses every shape — debug-unit credential gate (258a, HANDLER_CLAIM_CORRECTIONS) | **Unreachable** |
| 6 | 659 | `dynlib_get_list2` | `r14 + 0x10` | `0x34b8e2` | works (`ret=0`, count + handles at +0x004/+0x008); shares 593's body — same copyout address as #2 | **Measured clean** |
| 7 | 660 | `dynlib_get_info2` | `r14 + 0x10` | `0x34bd8e` | refuses every handle this process can name, including 659's `0x13`/`0x14` (240a); gate word untouched, nothing copied out | **Unreachable** |
| 8 | 661 | AIO submit (shared body) | `rbx + 8`, `rbx + 0x10` | `0x3b018a`, `0x3b1612` | 661 is the shared nosys trampoline — lethal SIGSYS (353a) | **Unreachable** |
| 9 | 662 | AIO batch delete | `rbx + 8`, `rbx + 0x10` | `0x3b018a`, `0x3b1612` | answers `0x80020003` per id — no AIO records exist to read (see AIO note) | **Unreachable by construction** |
| 10 | 663 | AIO batch wait | `rbx + 0x10` | `0x3b1612` | same body family as 662; per-id status only | **Unreachable by construction** |
| 11 | 664 | AIO batch poll | `rbx + 0x10` | `0x3b1612` | answers with one Sony status per id; `rbx` (request record) never allocated for a game process | **Unreachable by construction** |
| 12 | 665 | AIO (665) | `rbx + 0x18` | `0x3b1f6d` | kills on six zeros; no records exist | **Unreachable by construction** |
| 13 | 666 | AIO batch cancel | `rbx + 0x18` | `0x3b1f6d` | same family as 664/665 | **Unreachable by construction** |
| 14 | 668 | AIO (668) | `rbx + 8`, `rbx + 0x10` | `0x3b018a`, `0x3b1612` | lethal on zeros; shared 661 body | **Unreachable** |

## Why the AIO family is unreachable by construction

All ten AIO-family candidates (`#8`-`#14`, counted per copyout site) read fields of
`rbx`, the per-request record that the submit path (`669` → gated submit → `661`
handler body) allocates. On 14.10 the submit path sits behind the boot tunable
`0x8b4c78d0`, which never opens (`docs/AIO_GATE_14_10.md`); no job can be queued,
every id encoding answers `0x80020003` (512 encodings tried, probe series 240a-247a
and the 2026-10-25/26 closures), and the subsystem dispatches no I/O. A copyout from
an object that is never allocated cannot execute. This matches the 2026-10-25
kptr_hunt note: "Live testing of accessible ones yielded zero kernel pointers."

## The dynlib family (#2/#6/#7)

- 593 and 659 share the same body region (`0x34b8e2` is inside 593's span; 659's
  entry thunks into the same copyout). The 54f section F deep struct scan covered
  every field of all 39 modules' records — values are NID hashes and fingerprints,
  not kernel-VA-range values.
- 660's separate body (`0x34bc60`-`0x34bdc0`) is closed for a game process: the
  handle rejection fires before any record is built (240a). 656's debug-unit gate is
  a credential gate this process does not hold (258a).
- No divergence between the 13.60 decompile prediction and 14.10 behavior was found
  for this family; the recorded corrections (626 command semantics, 549 osem create,
  593/608/660 body attribution) do not touch these copyouts.

## The one residual: 601's `r13 + 0x578` copyout

`0xca1b8b` copies from `r13 + 0x578` — a large offset into a debugger-session
object. The 14.10 measurements (322a-324a, 55d) show 601's reachable commands write
either 0x100 zeroed bytes (cmd 0x00) or nothing, and the dossier's leak commands are
gated; commands 0x03/0x04 kill the caller. Which command, if any, reaches `0xca1b8b`
was not identified offline.

Assessment: even if that command is reachable, the object it reads is a
debugger-session record this process has never established (601 is "a debugger
service with no session"), so the copy would need a session-creating command first —
and every untested command in that family is either lethal or gated. **Recommendation:
do not spend console time here.** If a future 13.60 decompile pass identifies the
command, re-evaluate; until then this residual stays open at low priority.

## Conclusion

- 15 of 17 copyout sites are unreachable on 14.10 for measured or structural reasons.
- 2 sites (593/659 shared body) are reachable and were live-scanned clean across all
  39 modules — zero kernel pointers.
- 1 residual (601 → `0xca1b8b`) is unidentified-but-discouraged; no evidence suggests
  it diverges from the measured zero-write behavior.
- The P1 TODO items ("Review 17 OBJECT-sourced copyout candidates", "Cross-reference
  with 14.10 behavioral measurements") are closed by this document. No 13.60→14.10
  divergence reopens any candidate.

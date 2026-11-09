# FontFace probe validity audit — 2026-11-05

Static audit of the current FontFace/Canvas/ArrayBuffer probe set against its
own saved captures. No probe was executed and no console was contacted.

The two-stage FontFace shape is not universally dead: `p599` reports `P2:FREE`
and `P2:HIT` twice in
`results/phase13_webkit/p599v4i-null-spray-test_20261104_054400.txt`. That
contradicts `docs/FONTFACE_MEMBER_MAP_14_10.md:172` ("stage 2 never reclaims
here"), so one of those records is stale. The problem with the forge probes is
narrower: they do not establish that stage 2 reclaimed **their** buffer, and
they do not forge a pointer to controlled memory.

> **Reconciled 2026-11-06:** both records stand. The member-map claim is scoped
> to the p565/p577/p580 field-forge pages (stage 2 = a second
> `document.fonts.load()`, scan beacon `S2-b`); p599 is a GC-destructor page
> (fresh face per phase, GC between phases, beacon `P2:HIT`). The second
> reclaim works in the p599/p590 page shape and not in the p565/p577/p580
> shape. See `docs/FONTFACE_SECOND_RECLAIM_RECONCILIATION_2026-11-06.md` and
> the scope note added to `docs/FONTFACE_MEMBER_MAP_14_10.md`.

## Findings

### p571 / p572 — no stage-2 hit, no controlled address

- `p571:142` and `p572:149` start another `document.fonts.load()` after
  stage 1, but neither scans the stage-2 spray for the engine write. Their
  `RESOLVED` and `ALIVE` beacons only say the page survived.
- `p571` documents F4/F5 as ArrayBuffer-data forges (`p571:28-29`) but never
  pushes those values; `controlledBuf` is unused.
- `p572` documents F4/F5 (`p572:125-129`) but has only the engine-pointer,
  null, and `0x41` entries; `controlledBufs` is unused.
- Even if stage 2 reclaimed, `p58`/`p68` are engine objects. A sentinel table
  written into the 192-byte buffer is not referenced by any engine pointer.

The probe name promises a vtable forge; the file cannot produce one without a
controlled address.

### p574 — only two of the four documented forges exist

`p574:4` says `p571` tested all four forge values. `p574` only pushes F2
(null) and F3 (bad) at `p574:133-134`; F0 (self) and F1 (cross) are absent.
`runForgeTest` starts a new `document.fonts.load()` for each entry, and
`testBehavior` starts another load; no confirmation that the forged value
landed in the reclaimed buffer is made before interpreting behavior.

### p577 — only arm A exists, and stage 2 is unreachable

The header lists arms A-D (`p577:13-16`), but the file hard-codes
`FOFF=104, FVAL=0` (`p577:50`). There is no arm parameterization, so the
documented B/C/D measurements cannot be reproduced from this file.
`scan1` returns at `p577:169` before `stage = 1` at `:170`; the entire stage-2
block is dead. `docs/CHANGELOG.md:99` cites this file for the B/D results.

### p578 — sentinel value and offset do not match the document

`p578:11` and `p578:58-65` expect `0x414141410000 + slot_offset` at
`+0x00..+0x38`. The code writes `0x4141414100000000 + slot_offset` at
`0x10 + s*8` (`p578:67`). Both the qword and the base offset differ.

The probe also never scans stage 2: `P578-S2-ALIVE` only reports whether the
getter fired (`p578:113`). `docs/V88_FORGE_GEOMETRY_RECONCILIATION.md:37`
claims `p578` “captures the crash RIP”; the current file cannot produce that
observation.

### p581 — late scans are skipped, and the 80-byte spray is retained

`scan()` sets `done=true` before it checks for a hit (`p581:38`). The 90 ms
scan runs first; if it misses, the 300 ms scan returns immediately.

All 80-byte views are stored in `window.__tab` (`p581:24-25`). The engine's
hash-table allocation happens after the getter returns, so it cannot allocate
into those live buffers unless it writes into an already-live object. The
probe's stated “table landed in our 80 B class” test cannot observe the
allocation.

### p575 — stateStack cannot be freed

`retained` keeps the live canvas and both contexts (`p575:99,119,130`).
Setting `sprayCtx[aliasIdx] = null` at `p575:195` does not release the
`retained` references. `aliasCanvas` is declared but never assigned, so the
removal at `p575:199` is a no-op. `STATE8_OFF = 3712` (`p575:218`) is an
unverified layout. The combined FontFace + Canvas R/W path is therefore not
tested.

### p576 — the `+0x68` field is not a key count

`p576:4` says p571 left `+0x68 = 0` and calls it `m_keyCount`. In the
measurement record, `+0x68` is the `WeakPtr`/`WeakPtrImpl` wrapper pointer;
the hash table metadata lives behind the `+0x58` pointer. T2/T3 then write
`+0x60=4, +0x64=3, +0x68=1` (`p576:49,53`) to “force iteration.” A value of
`1` at `+0x68` is the fatal pointer case, not a key count, and `+0x60/+0x64`
are not the WeakHashSet table fields. A crash in T2/T3 would not demonstrate
that `iterateClients` ran.

### p570 — the stateStack reclaim is blocked by retained references

`p570` says it will free the live context’s stateStack buffer and reclaim it
with a 7424-byte ArrayBuffer. The setup stores `canvas`, `inner`, `outer`, and
every sprayed context in `window.__retained` (`p570:217,233`). The later
reclaim drops only `sprayCtx[aliasIdx]`, `alias`, and the canvas DOM node
(`p570:446-455`); `window.__retained` still holds the alias context and its
canvas. The stateStack cannot be collected while those references exist, so
the sentinel write cannot prove a reclaim.

The same file also forges `lineDash.ptr` with the leaked `p58` engine pointer,
not an address of a JS-owned buffer. Even if the reclaim worked, the read
would target engine memory, not controlled bytes.

### p580 — the advertised stage-2 delta is unreachable

`p580` advertises a stage-2 measurement of `P1'`/`P2'`, hit index, and
overwrite (`p580:1-20`). `scan1` returns at `p580:156` whenever the stage-1
re-entry check has a hit, before the `stage = 1` and second `document.fonts.load`
block at `p580:159+`. The stage-2 data cannot exist. The file’s stage-2 output
is dead code, not evidence that stage 2 fails. The hit block also logs
`P565-S1-*`, and the unreachable stage-2 block logs `P578-S2-*`, so a p580
run is mislabeled as two other probes.

### p566 — stale comment in a single-stage probe

`p566:5` still says “stage 2 never reclaims.” That is the same stale statement
as `docs/FONTFACE_MEMBER_MAP_14_10.md:172`; p599’s saved `P2:HIT` contradicts
it. The comment should not be used as a general limit.

### p563 — a first clean scan disables the second scan

`p563` schedules scans at 60 ms and 400 ms (`p563:61-62`), but `scan()` sets
`done = true` before examining the buffers (`p563:68`) and returns
`P563-ALL-CLEAN` when it finds none (`p563:79`). If the engine write lands
after 60 ms, the 400 ms scan returns immediately and the run is reported as
clean. `ALL-CLEAN` is therefore not evidence that the engine made no write.

### p564 — stage 2 is survival-only, so it does not show a reclaim

`p564` copies `p58`/`p68` into the stage-2 buffers (`p564:45`) and starts a
second load, but records only `P564-S2-RESOLVED`/`REJECTED` and `ALIVE`
(`p564:74-76`); it never scans those buffers for the engine write. A resolved
load cannot distinguish a reclaimed template from an allocation that missed.
The stage-1 hit scan is also a single 120 ms pass.

### p565 — the stage-1 overwrite check cannot fire

`p565` keeps every stage-1 buffer in `window.__map0` (`p565:82-97`) and then
checks those buffers for an overwrite marker at `+0x10` (`p565:181-190`).
Because the stage-1 buffers remain live, stage 2 cannot reuse them, and the
engine’s writes are to `+0x00`, `+0x58`, and `+0x68`, not `+0x10`. The
`P565-S1-INTACT` line is therefore guaranteed even if the stage-2 allocation
lands in a buffer that was supposed to be reused.

### p567 — stage-2 tests never scan their own buffer

`p567` runs four stage-2 templates (`p567:135-140`) and starts a new
`document.fonts.load()` for each. The success path only records
`P567-T<n>-SURVIVED` and queues the next test (`p567:158-166`); it never calls
`scanHit()` for that stage. A resolved load is therefore not evidence that
the template reached a reclaimed buffer.

### p579 — one early scan and a survival-only stage 2

`p579` scans the stage-1 buffers once at 120 ms (`p579:96`) and stops on the
first miss. After stage 1 it writes the mode value into eight new buffers and
a second load (`p579:112-120`), but records only `RESOLVED`/`REJECTED` and
`ALIVE`; it never scans the stage-2 buffers for the wrapper write. A surviving
stage-2 load does not show that the mode value was consumed.

### p589 — a 60 ms miss is treated as final, and the poison check is partial

`p589` captures the hit lane once at 60 ms (`p589:60-69`); if the engine write
has not landed by then it emits `AMISS` and every later phase returns. It does
not rescan, so `AMISS` is not evidence that the freed face has no live
reference. The final verdict also tests only the first four poison bytes
(`p589:195`); a partial `+0x58` write can leave those four intact while the
pointer has changed and be misclassified as `ALPHA_RESTAMP`.

### p582 — the fake HashTable is written into the reclaimed face

`p582` sets `v+0x58 = leaked.p58` (`p582:62`) and then writes the Shape-A
metadata (`+0x08`, `+0x0C`, `+0x10`, `+0x14`) into the same `v` buffer
(`p582:70-73`). Those writes land in the reclaimed CSSFontFace buffer, not in
the object that `p58` points at, so Shape A never constructs the fake
`HashTable` impl at the pointer it dereferences. Shape B likewise writes entry
zeros into `v` while `+0x58` still points at the engine table. Neither branch
builds the geometry the test claims to discriminate. The single 120 ms scan
also cannot distinguish a clean miss from a later engine write.

### p588c / p588d v6 — the style route is claimed but refuted

`p588c:3` says “Route (d) is viable” and fills `+0x08..+0x50` with T/W before
calling `gPa.style = "italic"`. The saved
`results/phase13_webkit/p588d_v6_definitive_null_test_20261103.txt` concludes
that the style setter never touches the CSSFontFace buffer because
`backing()` is null. `p588c`'s `STYLE_OK` is equally consistent with an early
return; it does not show the filled fields were read.

### p588d — `+0x68` is labelled as the wrong object

`p588d_v8b_engine_write_map_20261103.txt:61-62,101` calls the `+0x68` value
`FontFace*`. `p599v4i-null-spray-test_20261104_054400.txt:84,104` calls the
same field `WeakPtrImpl*`, and V88 C2 describes it as a
`WeakPtr<FontFace>`. If the field stores a `WeakPtrImpl*`, its `+0x10` points
at the FontFace; a fake FontFace at `+0x68` is the wrong object type.

### p608l — sections are cumulative, but the header says they reload

`p608l:17` says “Each section is independent (page reloads between crashes),”
but the file never reloads between Sections A–E (`p608l:60-99`). Each later
section runs after the earlier forced GCs and on the same warm-up, so the
“total” counts in the comments are not independent observations. A crash in
Section B cannot be attributed to the 500-iteration point alone. The header’s
test points (500/1000/2000) also do not match the cumulative code points
(700/1700/2700/3700).

### p608r — the “same footprint” buffers are all garbage

`p608r` claims 25,000 non-resizable 4 KB buffers and 25,000 resizable buffers
have the same 100 MB footprint (`p608r:23-60`). Every `ab`/`ta` is a local
with no surviving reference (`p608r:29-31,45-47,60-62`), so the GC may reclaim
them between iterations. The sections do not hold 100 MB resident, and a
survival result cannot separate “resizable machinery” from “normal allocation
pressure.” The buffers must be retained for the comparison to be meaningful.

### p608s — signed sentinel and cumulative allocation count

`cv[0] = 0xCAFE0000 | i` (`p608s:55`) is a signed 32-bit value, while
`Uint32Array` returns unsigned; the expected check at `p608s:72` cannot match.
The result file itself reports `A-CORRUPT=1000` as a false positive.

Section B calls `createDeadResizable(20300)` (`p608s:91`) after Section A
created 19,000 (`p608s:47`), so the total is 39,300, not 20,300. The saved
result confirms Section B crashes during creation; it does not test the
“just below threshold” case.

## Two-stage evidence needs a decision

`p599` shows a second UAF can be shaped in its page, while
`docs/FONTFACE_MEMBER_MAP_14_10.md` records `S2-b = 0` for its page. The two
records cannot both describe the current limit. Before another forge sweep,
the repository needs one of:

1. a corrected statement of which page shape allows a second reclaim, or
2. a new probe that records the stage-2 hit index and the engine-written
   `+0x58`/`+0x68` values.

Without that, `S2-ALIVE` cannot distinguish a reclaim from a second load that
never touched the freed object.

## What is still missing

The shared blocker remains a controlled address. The current probes leak
engine addresses (`p58`, `p68`, `T1`, `W1`) but no address of any JS-owned
buffer. The most concrete follow-up is the 80-byte table-takeover test:
phase 1 leaks `T1`, phase 2 redirects `+0x58` to `T1`, and the test verifies
that the engine reads a table we control. That requires a corrected `p581`
late-scan and a released 80-byte buffer, not another vtable sentinel sweep.

This document changes no probe behavior. Corrected probes require console
runs.

## Reproduction

```text
probes/phase13_webkit/p571-fontface-vtable-forge.html
probes/phase13_webkit/p572-vtable-forge-advanced.html
probes/phase13_webkit/p574-vtable-forge-behavior.html
probes/phase13_webkit/p563-fontface-reclaim-leak.html
probes/phase13_webkit/p564-fontface-reclaim-template.html
probes/phase13_webkit/p565-bmalloc-delta.html
probes/phase13_webkit/p570-forged-state-linedash.html
probes/phase13_webkit/p575-combined-fontface-canvas-rw.html
probes/phase13_webkit/p576-diagnostic-forge-sweep.html
probes/phase13_webkit/p577-fontface-field-forge.html
probes/phase13_webkit/p567-field-sensitivity.html
probes/phase13_webkit/p579-wrapper-slot-sweep.html
probes/phase13_webkit/p578-vtable-slot-discrimination.html
probes/phase13_webkit/p580-fontface-reentry.html
probes/phase13_webkit/p582-table-geometry-discrim.html
probes/phase13_webkit/p589-alpha-fontfaceset-trigger.html
probes/phase13_webkit/p581-fontface-table-class.html
probes/phase13_webkit/p588c-second-walk-diag.html
probes/phase13_webkit/p588d-forge-chain-oracle.html
probes/phase13_webkit/p608l-gc-timing.html
probes/phase13_webkit/p608r-resizable-vs-normal.html
probes/phase13_webkit/p608s-corruption-detect.html
docs/FONTFACE_MEMBER_MAP_14_10.md
docs/V88_FORGE_GEOMETRY_RECONCILIATION.md
results/phase13_webkit/p588d_v6_definitive_null_test_20261103.txt
results/phase13_webkit/p588d_v8b_engine_write_map_20261103.txt
results/phase13_webkit/p599v4i-null-spray-test_20261104_054400.txt
results/phase13_webkit/p608s_corruption_detect_20261104_090400.txt
```

No console was contacted.

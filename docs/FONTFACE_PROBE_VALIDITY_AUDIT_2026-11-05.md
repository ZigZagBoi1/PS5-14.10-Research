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
probes/phase13_webkit/p575-combined-fontface-canvas-rw.html
probes/phase13_webkit/p577-fontface-field-forge.html
probes/phase13_webkit/p578-vtable-slot-discrimination.html
probes/phase13_webkit/p581-fontface-table-class.html
probes/phase13_webkit/p588c-second-walk-diag.html
probes/phase13_webkit/p588d-forge-chain-oracle.html
probes/phase13_webkit/p608s-corruption-detect.html
docs/FONTFACE_MEMBER_MAP_14_10.md
docs/V88_FORGE_GEOMETRY_RECONCILIATION.md
results/phase13_webkit/p588d_v6_definitive_null_test_20261103.txt
results/phase13_webkit/p588d_v8b_engine_write_map_20261103.txt
results/phase13_webkit/p599v4i-null-spray-test_20261104_054400.txt
results/phase13_webkit/p608s_corruption_detect_20261104_090400.txt
```

No console was contacted.

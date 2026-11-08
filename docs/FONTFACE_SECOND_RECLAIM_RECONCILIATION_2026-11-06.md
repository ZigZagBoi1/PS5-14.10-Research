# FontFace second-reclaim contradiction — reconciliation

**Date:** 2026-11-06. Static reconciliation of two device-measured records that
`docs/FONTFACE_PROBE_VALIDITY_AUDIT_2026-11-05.md` flagged as contradictory. No
probe was executed and no console was contacted.

## The contradiction the audit named

`docs/FONTFACE_PROBE_VALIDITY_AUDIT_2026-11-05.md:6-12` says:

> The two-stage FontFace shape is not universally dead: `p599` reports `P2:FREE`
> and `P2:HIT` twice in
> `results/phase13_webkit/p599v4i-null-spray-test_20261104_054400.txt`. That
> contradicts `docs/FONTFACE_MEMBER_MAP_14_10.md:172` ("stage 2 never reclaims
> here"), so one of those records is stale.

Both records are real. They are not in conflict, because they scope their claims
to different page shapes. Reading them together resolves the contradiction
without discarding either measurement.

## Record A — the member-map claim and its scope

`docs/FONTFACE_MEMBER_MAP_14_10.md:169-173`:

> The limit of the result: a load can only be shaped in stage 1, where the leaked
> address is not yet known, so the arms forge `0` and `1` blind. That separates
> "dereferenced" from "ignored", not "must be a valid pointer" from "must be
> non-null". **Stage 2 — where a same-page leaked pointer would be available —
> never reclaims here (`S2-b` = 0 across every log)**, so the stronger test is
> not reachable in that page.

The words "in that page" and the beacon name `S2-b` tie the claim to one page
family: the **p565/p577/p580** field-forge pages (their stage-2 scan beacon is
`S2-b`, emitted from `probes/phase13_webkit/p565-bmalloc-delta.html:162`,
`p577-fontface-field-forge.html:189`, `p580-fontface-reentry.html:179`). Those
pages share a single-stage trigger shape: one `document.fonts.load()` for stage
1, then a **second `document.fonts.load()`** for stage 2. The `S2-b` beacon is
their stage-2 hit scan, and across their logs it reported 0 hits.

Supporting context from the same era: `docs/FONTFACE_RECLAIM_LEAK_14_10.md:127-130`
records that **after a successful reclaim the process stops inside `load()` on
the next attempt** ("one successful run per WebProcess"). That is exactly the
behaviour the p565/p577/p580 pages run into when their stage-2 `load()` never
arms a reclaim.

## Record B — the p599 two-phase hits

`results/phase13_webkit/p599v4f-two-phase-uaf_20261104_051500.txt` and
`results/phase13_webkit/p599v4i-null-spray-test_20261104_054400.txt` record a
different page: `probes/phase13_webkit/p599-gc-destructor-test.html` (v4f/v4i),
a **GC-destructor** page. Its two phases are not two `document.fonts.load()`
calls; each phase is its own `fonts.load()` on a **fresh `FontFace` + fresh
`@font-face` rule** (`pa`/`sa` in phase 1, `pb`/`sb` in phase 2), and crucially
it runs a **full GC cycle between the phases** (`P1:GC-START/GC-DONE` at
`p599-gc-destructor-test.html:86-92`). Its stage-2 hit beacons are named
`P2:HIT`, not `S2-b`.

Its saved outcomes:

- **v4f (4 runs):** run 1 `P2:NO-HIT`, run 2 `P2:HIT` then crash, run 3
  `P2:HIT` then survived (the forged-table success), run 4 incomplete.
- **v4i (2 runs):** `P2:HIT` twice, both survived the GC2 destructor path.

A third, earlier measurement on the same bench points the same way:
`results/phase13_webkit/p590_two_uaf_test_20261103.txt` records
`TWO_UAF=YES` — two consecutive UAF triggers in one WebProcess, the second
(`S2-2048` → `L2-OK` → `BH50,rc=3`) reclaiming successfully — on a page
(`probes/phase13_webkit/p590-two-uaf-test.html`) that also uses the
fresh-face-per-phase shape rather than a second `load()` on the same faces.

## Reconciliation

The two records describe two different page shapes on the same firmware:

| page family | stage-2 mechanism | stage-2 reclaim? | evidence |
|---|---|---|---|
| p565 / p577 / p580 field-forge | second `document.fonts.load()` on the same faces | **no** (`S2-b` = 0) | member-map doc, p577/p580 probe sources |
| p599 v4f/v4i GC-destructor | fresh `FontFace` + rule per phase, GC between phases | **yes** (`P2:HIT` ×3, `TWO_UAF=YES`) | p599v4f/v4i, p590 captures |

So "stage 2 never reclaims" is true **for the field-forge pages it was written
about**, and false as a general statement about second reclaims on 14.10. The
member-map sentence is scoped by "in that page"; the audit's "not universally
dead" is the general statement. Neither is stale.

What the p599/p590 runs do **not** do is rescue the field-forge pages' stronger
test. The member-map's point was that a *same-page leaked pointer* is needed to
forge `+0x58` with a known-valid address in stage 2. p599 leaks `T1` in phase 1
and redirects `+0x58` in phase 2 — so the stronger test the member-map said was
"not reachable in that page" **is reachable in the p599 page shape**, and v4f
run 3 is exactly that test succeeding (forged table at `T1-0x50`, removeClient
reads empty buckets, rc 3→2, survives).

## What still holds

- The `S2-b` = 0 result for p565/p577/p580 is unchanged: their specific
  second-`load()` shape does not reclaim.
- "One successful run per WebProcess" (p563/p564 shape) is unchanged: p599
  sidesteps it by using fresh faces and an intervening GC, not by repeating
  `load()` on the same faces.
- The hard blocker named by both eras is unchanged: **no address of JS-owned
  memory**. p599 leaks engine addresses (`T1`, `W1`, `T2`, `W2`) only.
  v4i explicitly records that the two-phase UAF "gives a heap leak but not R/W
  or code exec" and that "buffer absolute VA unknown (can't self-reference)".

## Consequence for the audit's open item

`docs/FONTFACE_PROBE_VALIDITY_AUDIT_2026-11-05.md:228-238` asked for one of:

1. a corrected statement of which page shape allows a second reclaim, or
2. a new probe recording the stage-2 hit index and engine-written values.

Option 1 is now on record: the fresh-face-per-phase + intervening-GC shape
(p599/p590) reclaims in stage 2; the repeated-`load()` shape (p565/p577/p580)
does not. No new console run is needed to state that distinction; the p599
captures already carry the stage-2 hit index (`lane=`) and the engine-written
`+0x58`/`+0x68` values (`T2`, `W2`).

## Sources

- `docs/FONTFACE_MEMBER_MAP_14_10.md` (member map, `S2-b` scope)
- `docs/FONTFACE_RECLAIM_LEAK_14_10.md` (one-successful-run-per-WebProcess)
- `docs/FONTFACE_PROBE_VALIDITY_AUDIT_2026-11-05.md` (the contradiction flag)
- `results/phase13_webkit/p599v4f-two-phase-uaf_20261104_051500.txt`
- `results/phase13_webkit/p599v4i-null-spray-test_20261104_054400.txt`
- `results/phase13_webkit/p590_two_uaf_test_20261103.txt`
- `probes/phase13_webkit/p599-gc-destructor-test.html`
- `probes/phase13_webkit/p590-two-uaf-test.html`
- `probes/phase13_webkit/p565-bmalloc-delta.html`, `p577-fontface-field-forge.html`,
  `p580-fontface-reentry.html`

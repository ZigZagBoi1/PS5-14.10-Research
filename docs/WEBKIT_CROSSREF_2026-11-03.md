# WebKit cross-reference: pastawithpesto chain status and p563 v9 size-class analysis

> **Date:** 2026-11-03. Upstream source: [pastawithpesto/PS5-14.10-Jailbreak-Research](https://github.com/pastawithpesto/PS5-14.10-Jailbreak-Research) README, fetched 2026-11-03.
> Local evidence: `results/phase13_webkit/p563_canvas_crosstype_reclaim_20261028.txt`,
> `p564_canvas_force_reclaim_20261028.txt`, `p565_canvas_offset128_20261028.txt`,
> `p566_canvas_full_reclaim_20261028.txt`, `v674_canvas_api_info_leak_20261029.txt`,
> `v674b_apng_decoder_overread_20261029.txt`.

This closes three TODO items: the p563 Canvas UAF v9 size-class scan analysis, the
cross-reference against pastawithpesto's CVE-2026-43720 chain, and the info-leak
cross-check. Nothing here is console-verified beyond what the cited captures show.

## 1. Upstream chain status (their README, 2026-11-03)

| Stage | Their status | Vehicle |
|---|---|---|
| UAF trigger | CONFIRMED | `bitmaprenderer` outer + `Object.defineProperty` getter + `2d` inner frees a **768B** context |
| Same-type reclaim | CONFIRMED | 500x Canvas2D spray reclaims the freed slot (V573) |
| Alias R/W | CONFIRMED | 12 Canvas2D APIs through the stale wrapper (V630) |
| Crash oracle | CONFIRMED | Forged `m_stateStack` reads 8 bytes at an arbitrary address (V650-V655) |
| ASLR defeat | CONFIRMED | APNG overread leaks **1651 heap pointers** (V674) |
| Arbitrary R/W | DESIGNED | Forge `lineDash` `Vector<double>` in an AB; `setLineDash` writes in-place |
| Code exec | NEXT | vtable hijack + ROP (no PAC, no JIT, JSC Config unfrozen) |
| Kernel | BLOCKED | Needs browser code execution first |

Platform properties they document (consistent with ours, plus two new details):

- IsoHeap OFF → `WTF_MAKE_ISO_ALLOCATED` compiles to FastMalloc on `BPLATFORM(PLAYSTATION)`.
- Gigacage DISABLED → AB backing stores share the heap with JSC/WebCore objects.
- JSC Config unfrozen → `startOfStructureHeap` stays writable post-init.
- **DAZ ON** — MXCSR denormals-are-zero is active; pointer-sized values must be read
  through `BigUint64Array`, not float64. Heap-pointer bytes read as f64 are denormals
  and get zeroed. Any probe that reads leaked pointers as doubles silently reports 0.
- libpas uses out-of-band bitmap tracking → freed blocks stay mapped, no in-band
  freelist pointers.

## 2. Our V674 replication found zero leak — discrepancy with their CONFIRMED claim

Our on-console runs of 2026-10-29:

- `v674b_apng_decoder_overread_20261029.txt`: all phases report `ptrs=0`; every
  overread region scan is `nz=0` (`DONE: C=0,C2=0,D=0,async=0`). The APNG files
  themselves decode (`PH-A-OK w=256,h=64`), so the pipeline ran; nothing leaked.
- `v674_canvas_api_info_leak_20261029.txt`: 6 Canvas-API leak techniques, all zero;
  oversized `getImageData` is clamped and zero-filled, resize gives a clean backing
  store, WebGL absent.

**Important caveat:** the local `v674` capture header states it is "reconstructed
from Engram observation #3009" — it is not the upstream `tools/v674.html` verbatim.
The upstream APNG construction details (frame sizes, chunk layout, decoder path) are
exactly what the overread depends on. A zero result from a reconstructed probe does
not refute their CONFIRMED claim; it means the technique is **unreplicated** here.

**Action:** pull their actual `probes/` + `tools/v674.html` from the upstream repo and
run it unchanged before treating V674 as dead or confirmed on this console. This is a
console-time task; it is recorded here so the discrepancy is not lost.

## 3. p563 v9 size-class scan analysis (results arrived 2026-10-28, not yet analyzed)

`results/phase13_webkit/p563_canvas_crosstype_reclaim_20261028.txt` (147 beacons;
tail shows the four `v9-sizescan` runs; probe: `probes/phase13_webkit/p563-canvas-crosstype-reclaim.js`).

The v9 design: for each AB size, trigger a fresh UAF (re-entrant `desynchronized`
getter), spray 30 ABs of that size, then 15 safety-net canvas contexts, emit
`TEST sz=X`, and read `stale.lineWidth`. A `MISS` beacon means the process survived
the read (canvas won). Silence after a `TEST` beacon means the process died in the
read — which the probe interprets as "an AB reclaimed the freed context slot".

Observed:

| Run | Config | Result |
|---|---|---|
| 18:36:14 | ab=30, cv=15 | `TEST sz=128` → `MISS canvas-won idx=0`; `TEST sz=160` → **silence (process died)** |
| 18:38:21 | ab=12, cv=6 | `TEST sz=128` → silence |
| 18:38:56 | ab=12, cv=6 | `TEST sz=128` → silence |
| 18:39:34 | ab=12, cv=6 | `TEST sz=128` → silence |

Raw reading: the crashing size identifies the match → **160** (run 1, the only run
with the designed spray counts and a discriminating MISS at 128 before dying at 160).

**But this cannot be reconciled with upstream's measured 768B freed context** (their
same-type reclaim is measured by slot occupancy with 500 sprayed contexts, not
inferred from a crash). A 160-byte ArrayBuffer cannot land in a 768-byte size class
under bmalloc. Explanations, in order of plausibility:

1. **The crash at 160 was not an AB reclaim.** The probe infers "AB won" from
   process death, and death after `TEST` has other causes (the stale context read is
   not the only fatal operation in that window; a residual fault from the groom of
   the previous size round, or a fault in the 15-context safety spray's own
   reclamation, produce the same silence). Run 1's 160 result is therefore a
   **candidate, not a measurement**.
2. **Runs 2-4 used a modified configuration** (12 ABs / 6 canvases — the operator
   reduced counts between runs). All three died at the first `TEST sz=128` with no
   discriminating MISS, which is *weaker* evidence than run 1 and inconsistent with
   it (fewer ABs should reduce, not increase, the chance of a 128B reclaim). They
   cannot distinguish "AB(128) reclaimed" from "process died for another reason".
3. The `desynchronized` getter variant may free a different object than the `alpha`
   getter variant upstream uses.

**Conclusion:** the v9 scan does not establish a cross-type AB lane. The only
trustworthy size datum for the freed CanvasRenderingContext2D is upstream's **768B**.
The cross-type info-leak idea remains open but should be retested as a single-size
768B experiment with a crafted template (values that keep the context's internal
fields non-fatal on a `lineWidth` read) and a surviving readback, following the
pattern that worked on the FontFace 192B lane (`docs/FONTFACE_RECLAIM_LEAK_14_10.md`).
Given that the same-type alias (p553) already provides live R/W through the object,
the cross-type AB lane is only worth console time if the FontFace chain stalls.

## 4. Divergences worth tracking

| Topic | Upstream | Here | Note |
|---|---|---|---|
| CSSFontFace UAF | "DoS-only, sole 192B occupant" (dead end) | 192B reclaim **with engine-written heap pointers** at +0x58/+0x68; engine accepts refilled templates (p563/p564, `docs/FONTFACE_RECLAIM_LEAK_14_10.md`) | Different spray technique/conditions; their result does not refute ours. Our FontFace lane is the further-along chain. |
| MetadataTable overflow (CVE-2026-64784) | OOM at 3.7GB AST (dead) | Confirmed present on two consoles (their earlier report) | Presence ≠ exploitable; their OOM ceiling stands. |
| Freed 2d context size | 768B | v9 suggested 160B (unconfirmed) | Trust the measured reclaim (768B); see §3. |
| V674 APNG overread | CONFIRMED, 1651 pointers | Unreplicated (reconstructed probe, zero) | Re-run their verbatim probe. |
| DAZ | Documented (read pointers via BigUint64Array) | Not previously recorded here | Adopt in all future pointer-reading probes. |

## 5. Updated next actions (WebKit)

1. Run upstream's verbatim `tools/v674.html` APNG overread; if it leaks, the ASLR
   defeat is shared and the chain jumps to their arbitrary-R/W design.
2. Their arbitrary R/W design (lineDash `Vector<double>` forge through the alias)
   is compatible with our confirmed alias R/W (p553). The live vtable offset on
   14.10 remains the code-exec blocker (upstream lists code exec as NEXT; neither
   repo has a measured 14.10 vtable offset).
3. Keep `startOfStructureHeap` (JSC Config unfrozen) as the type-confusion target
   their design names; it does not require a vtable offset.
4. FontFace lane (Lane_VA) remains this repo's primary; the Canvas chain is the
   upstream primary. Both converge on the same WebProcess.

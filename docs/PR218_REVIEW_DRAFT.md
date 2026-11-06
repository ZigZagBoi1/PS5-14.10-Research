# Draft review comment for PR #218 (post after running p655 on console if desired)

PR is graded and reproducible offline here (175/175 tests OK on the
pr-218 head, this reviewer's machine). Two notes before merge:

1. **Summary/doc inconsistency on `lineWidth`.** The PR summary says
   "`lineWidth` at `State + 64` (`context + 192`)" but the doc's own member
   table (`docs/CANVAS_STATE_GEOMETRY_14_XX.md` §3, WK-1400 `BASE.h:267-295`)
   places `lineWidth` at **`State + 0x30` (+48)**, with `+0x40` being
   `miterLimit` — and the independent 14.10 bench row (cobrajet302gt issue #10
   reply, "lineWidth = State[i].lineWidth at +0x30, `BASE.h:102/:311`") agrees
   with the doc, not the summary. Please correct the summary so downstream
   benches don't forge reads at the wrong field.

2. **The bucket-ladder decider needs its landing witness defined.** §4
   pre-registers single-size-per-cold-load sprays over
   {3328, 3584, 3840, 4096, 4352}, but a landing on the state-stack buffer is
   only observable if something writes into the reclaimed buffer. On 14.22 we
   measured (this repo, 2026-11-06): freed chunks are **zeroed at free**
   (v909 — destructor-less zeroing; 14.10 kept benign bytes, 21/21 survives),
   and a zeroed ctx chunk kills the engine's own post-free walk (v912), so
   `AB`-carrier residue scans and stale-content reads are both dead on 14.22.
   The FontFace analog (p640) only works because its carrier is a live
   CSSFontFace (JS-readable `status()`), not because bytes are readable.
   Proposal: state explicitly which observable the state-buffer ladder uses —
   e.g. the p640 pattern transposed (engine write-after-free redirect into a
   JS-visible handle), or a surviving-read differential (v911 in this repo).

Also confirmed independently on 14.22 before this review: p655's lazy-save
premise holds (v651: bare save()/setter pairs realize states; realloc
preserves state), and the canonical vector header (+112 buffer / +120 cap /
+124 size) is device-canonical per the 14.10 bench.

# Canvas state-buffer decider, revised (2026-11-06) — capacity 11, class 4608, and the landing-witness gap

Source: cobrajet302gt erratum (2026-11-06 12:02Z, desk only) + PR #218 commit
9aa55ee (applied). This note pins what our 14.22 bench inherits.

## Corrections that supersede our planning numbers

1. **Capacity 11, not 10 / not 16.** bmalloc growth law
   `max(newMinCapacity, max(minCapacity, capacity + capacity/4 + 1))`
   (`Vector.h:1152`), one `expandCapacity` per realized save
   (`CanvasRenderingContext2Base.cpp:453`): 1→2→3→4→6→8→**11**.
   `MaxSaveCount = 16384` (`BASE.h:435`) — never binds at 8 saves.
   The v651-era "cap 16 / 6400B row" and pastawithpesto's "cap 16 → 6400B"
   are superseded.
2. **bmalloc classes** (`Sizes.h:56-118`; no BucketManager in this era):
   step 8 up to 512, then logWasteFactor=8 / logAlignmentMin=64 ⇒ class step
   doubles: [512,1024)=64, [1024,2048)=128, [2048,4096)=256, [4096,8192)=512.
   Classes above 4096: {4608, 5120, 5632, 6144, 6656, 7168, 7680, 8192}.
   **4352 is not a class** (4096+256 exists only below 4096) — the PR's first
   ladder contained a dead rung that rounds up to 4608 and cannot falsify it.
3. **sizeof(State)**: 11×(376-408B) ≈ 4136-4488B ⇒ maps to the single class
   **4608** across the whole window. The legacy 464 figure was never
   adjudicated; it is only reachable via the 5120 branch (below).

## Revised pre-registered decider (append-only; supersedes earlier rungs)

Eight-realized-save arm (p655 realization pattern — bare saves count zero),
single size per cold load, beacons attributed in-window:

| Landing | Meaning |
|---|---|
| **4608** | drop-sum holds: capacity 11, State ≤ 408B (single-bucket prediction) |
| **3840 / 4096** | effective capacity 10 ⇒ fork growth law ≠ drop law (publishable; retires the PR geometry) |
| **5120** | State ∈ 419-465B ⇒ fork-fattened; legacy 464 viable for the first time |
| clean N/N miss over {3840, 4096, 4608, 5120} + landings ≥ 7168 | none of the posted maps explains the buffer — different mechanism before claiming any map |

Unattributed or out-of-window results count zero.

## CSSFontFace layout corrections (affects our forge maps)

- `+0x08` is the non-polymorphic `m_propertiesOrCSSConnection` (not a Document*).
- `m_timeoutTimer`'s shared `WebCore::Timer` vptr at **+0x90** is the sole
  vtable pointer in the structure — the 14.00-chain "vtable dispatch"
  surfaces must be re-derived against this map.
- Motor via p640 measured here: the write-after-free lands regardless; the
  carrier is a live CSSFontFace (index 56 on our console).

## Our open gap (unchanged, flagged in docs/PR218_REVIEW_DRAFT.md)

The decider's landing witness on 14.22 is undefined: AB-carrier residue scans
are dead (v651/v652 audit), stale-byte reads are impossible (zero-at-free,
v909), and a zero-filled carrier kills the engine's own walk (v912). The
14.22 run of this decider needs the p640 pattern transposed (engine
write-after-free into a JS-visible handle) or a surviving-read differential —
our v911 instrument is the only live candidate for that class today.

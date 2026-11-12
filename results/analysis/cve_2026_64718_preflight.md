# CVE-2026-64718 Preflight Verification

**Date:** 2026-11-11  
**WebKit Bug:** 313935  
**Credit:** Niels Hofmans, OGINOME Tomohito, anonymous  
**Fixed in:** Safari 26.6 (Jul 27, 2026)  
**Component (Apple advisory):** WebKit Canvas  

---

## Apple Advisory (verbatim)

- **Component:** WebKit Canvas
- **Impact:** Processing maliciously crafted web content may lead to an unexpected Safari crash
- **Description:** A use-after-free issue was addressed with improved memory management.

## Actual Root Cause (from upstream commits)

**Primary fix:** `95f9f59bb141` (316037@main)  
**Title:** "PathCG::strokeContains() is not thread safe"  
**Author:** shallawa  
**Reviewer:** Darin Adler  
**Changed file:** `Source/WebCore/platform/graphics/cg/PathCG.cpp`  

**Follow-up fix:** `2917a663b046` (319095@main)  
**Title:** "PathCG should use thread-safe scratchContext"  

**Defective behavior:** `PathCG.cpp` uses a global `CGContextRef` via `NeverDestroyed<RetainPtr<CGContextRef>> scratchContext()`. The functions `strokeContains()` and `strokeBoundingRect()` call into this shared, unprotected global context. When multiple Web Workers with OffscreenCanvas call `isPointInStroke()` concurrently, the shared CGContext is used from multiple threads simultaneously, causing a use-after-free race condition.

**Fix:** Added a `Lock` around `scratchContext()` access in both `strokeContains()` and `strokeBoundingRect()`.

## Critical Finding #1: PathCG.cpp Is CoreGraphics-Specific

The vulnerable code lives in `Source/WebCore/platform/graphics/cg/PathCG.cpp` — the **CoreGraphics** (CG) platform backend. WebKit's path rendering is platform-abstracted:

| Platform | Path implementation | Uses scratchContext()? |
|----------|-------------------|----------------------|
| macOS/iOS | `PathCG.cpp` (CoreGraphics) | **YES — vulnerable** |
| Linux/GTK | `PathCairo.cpp` (Cairo) | No |
| PlayStation | Sony-proprietary (FreeBSD, no CG) | **No CG layer** |

PS5 runs FreeBSD r230171. It does **not** have CoreGraphics. The `PathCG.cpp` file and its `scratchContext()` global do not exist in the PS5 binary. The race condition requires the CG-specific shared global state — a different path backend (Cairo, Skia, Sony-custom) would use a different implementation of `strokeContains()` that does not share this particular global.

**The vulnerable code path does not exist on PS5.**

## Critical Finding #2: OffscreenCanvas Is Absent on PS5

Beacon logs from probe p567 (2026-10-31) confirm:
```
P567-FEAT-OffscreenCanvas=undefined
```
(Repeated across 10+ beacon captures — consistently `undefined`.)

The exploit requires **multiple OffscreenCanvas instances in Web Workers** calling `isPointInStroke()` concurrently to trigger the race. Without OffscreenCanvas, the concurrent-worker trigger vector is structurally impossible, even if a CG-like shared context somehow existed.

## Critical Finding #3: p721 Does Not Test the Actual Bug

p721 tests 6 generic Canvas lifecycle patterns:

| Vector | What It Tests | Matches CVE? |
|--------|--------------|-------------|
| A: OffscreenCanvas transfer + stale context | Transfer ownership | **NO** — also requires OffscreenCanvas (absent) |
| B: toBlob during context replacement | Callback race | **NO** — single-thread, not the CG race |
| C: Canvas removal during drawImage | DOM lifecycle | **NO** — not a stroke path race |
| D: Multiple getContext type switching | Context teardown | **NO** — not a stroke path race |
| E: cloneNode + context interaction | Shared internal state | **NO** — not a stroke path race |
| F: ImageBitmap from canvas + destruction | Backing store lifetime | **NO** — not a stroke path race |

None of the 6 vectors reproduce the actual bug: concurrent `isPointInStroke()` from multiple workers hitting a shared CG scratchContext.

## Verdict

| Question | Answer |
|---|---|
| Is the vulnerable code compiled on PS5? | **NO** — PathCG.cpp is CoreGraphics-specific; PS5 uses a different backend |
| Is the trigger API available on PS5? | **NO** — OffscreenCanvas is `undefined` (p567 beacon confirmed) |
| Are Web Workers available? | **YES** (beacon confirmed) — but insufficient without OffscreenCanvas |
| Do p721's vectors test the actual bug? | **NO** — all 6 are generic Canvas lifecycle, none test concurrent worker stroke races |
| Could a platform-generic variant exist? | **UNLIKELY** — the bug is specifically about a CG-global shared context, not a WebKit-generic race |

## Recommendation

**DOWNGRADE CVE-2026-64718 from PRIORITY 1 to DEAD (PLATFORM-MISMATCH).**

Two independent kill signals:
1. The vulnerable code (`PathCG.cpp` scratchContext) does not exist on PS5 (wrong graphics backend)
2. The trigger API (`OffscreenCanvas` in Workers) is absent on PS5

**p721 should NOT be run as a CVE-2026-64718 test.** Its 6 vectors test unrelated Canvas lifecycle patterns. Any result would not constitute evidence for or against this CVE. Running p721 as a generic Canvas UAF survey has LOW value — vector A requires OffscreenCanvas (absent), and vectors B-F test single-thread lifecycle timing which are less likely to produce exploitable UAFs than concurrent races.

## Residual Uncertainty

The Apple advisory says "WebKit Canvas" UAF, and Bugzilla 313935 is restricted. It is theoretically possible that the advisory covers additional bugs beyond the PathCG race. However:
- Both identified upstream commits specifically target PathCG.cpp
- Both are authored by the same person (shallawa) reviewing the same shared-context pattern
- No other commits referencing bug 313935 were found

The evidence strongly supports a single-issue CVE in the CG backend.

## Impact on Console Probe Priority

Previous: p721 (CVE-2026-64718) > p686 > p692 > p694 > p693 > p689/p690

**Revised:** p686 (SVG animation UAF) > p689/p690 (memory ACE) > p692 (DOM UAF) > p694 (heap UAF) > p693 (memory handling)

p721 removed from the active queue.

## Sources

- Apple advisory: Safari 26.6 release notes
- WebKit commits: 95f9f59bb141 (316037@main), 2917a663b046 (319095@main)
- Bugzilla 313935: RESTRICTED (access denied)
- OffscreenCanvas status: p567 beacon logs (2026-10-31), 10+ captures all `undefined`
- Web Workers status: beacon confirmed AVAILABLE
- isPointInStroke: beacon confirmed AVAILABLE (p568v5)

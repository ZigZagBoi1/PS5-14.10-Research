# CVE-2025-43265 Preflight Verification

**Date:** 2026-11-11  
**WebKit Bug:** 294182  
**Credit:** HexRabbit (@h3xr4bb1t), DEVCORE Research Team  
**Fixed in:** Safari 18.6 (July 30, 2025)  

---

## Apple Advisory (verbatim from support.apple.com/en-us/124152)

- **Component:** WebKit
- **Impact:** Processing maliciously crafted web content may disclose internal states of the app
- **Description:** An out-of-bounds read was addressed with improved input validation.

## Actual Root Cause (from upstream commit)

**Commit:** `d96ab2fa64c6` (298874@main, 2025-08-18)  
**Title:** "[YARR] Remove sentinel-based tracking in Unicode read path"  
**Author:** Robert Jenner  
**Reviewer:** Yusuke Suzuki  
**Changed file:** `Source/JavaScriptCore/yarr/YarrJIT.cpp` (+8/-39)  

**Defective behavior:** In YARR JIT's `tryReadUnicodeCharImpl`, a sentinel value (0x4) was used to track whether a non-BMP character had been read. This conditional logic could silently fail in edge cases such as skipped alternatives or control-flow changes during backtracking, causing the regex engine to read past buffer boundaries with a wrong offset.

**Fix:** Removed the sentinel entirely. Now unconditionally sets `firstCharacterAdditionalReadSize` to 1 on non-BMP read, zeros it on alternative entry.

## Critical Finding: YARR JIT is OFF on PS5 14.10

**The fix is entirely within `YarrJIT.cpp`, guarded by:**
```
#if ENABLE(YARR_JIT_UNICODE_EXPRESSIONS) && ENABLE(YARR_JIT_UNICODE_CAN_INCREMENT_INDEX_FOR_NON_BMP)
```

**`ENABLE_YARR_JIT` exists only under `ENABLE(JIT)`** — confirmed at `PlatformEnable.h:774-777` and `YarrJIT.cpp:46` (documented in CHANGELOG.md, issue #181 item 2, after p659 YARR verdict analysis).

PS5 14.10 is **LLInt-only (all JIT tiers OFF including Baseline/DFG/FTL)**. Therefore:
- `ENABLE(JIT)` = OFF
- `ENABLE_YARR_JIT` = OFF  
- The sentinel-based tracking code in `YarrJIT.cpp` is **never compiled into the PS5 binary**
- The YARR interpreter (`YarrInterpreter.cpp`) handles all regex execution and uses a different code path

## Probe p719 Assessment

The probe tests 6 generic OOB read vectors:
1. **A) ResizableArrayBuffer stale read** — NOT the YARR bug
2. **B) Rope string DFG speculation** — JIT-dependent, NOT the YARR bug
3. **C) RegExp capture mutation** — Tests interpreter regex, NOT YARR JIT
4. **D) ArrayBuffer.slice after transfer** — NOT the YARR bug
5. **E) DataView on resized buffer** — NOT the YARR bug
6. **F) Structured clone deserialization** — NOT the YARR bug

**NONE of the 6 vectors test the actual defective behavior** (YARR JIT sentinel tracking in Unicode non-BMP read path). The probe was written without knowing the specific bug and uses generic heuristic vectors.

## Verdict

| Question | Answer |
|---|---|
| Is the vulnerable code compiled on PS5? | **NO** — YARR JIT is gated on `ENABLE(JIT)`, which is OFF |
| Do p719's vectors test the actual bug? | **NO** — all 6 are generic, none target YARR JIT Unicode sentinel |
| Could the YARR interpreter have the same bug? | **NO** — the interpreter in `YarrInterpreter.cpp` uses a completely different Unicode handling path with explicit length tracking, not sentinel-based |
| Is Sony's build affected? | **NO** — the defective code is compile-time excluded |

## Recommendation

**DOWNGRADE CVE-2025-43265 from TOP PRIORITY to DEAD (CONFIG-SILENT).**

The bug is in YARR JIT Unicode handling. YARR JIT is not compiled on PS5 14.10. The probe's 6 vectors are generic and do not test the actual vulnerability. Running p719 would test unrelated code paths; any results would not constitute evidence for or against this CVE.

This follows the same pattern as CVE-2026-43740 (also YARR JIT, also CONFIG-SILENT on PS5 — documented in p659 analysis).

**p719 may still be worth running** as a generic OOB-read survey (vectors A, D, E, F are JIT-independent), but its CVE-specific claim is **UNVERIFIED/INAPPLICABLE** and should not carry TOP PRIORITY based on the advisory's "information disclosure" language alone.

## Impact on Console Probe Priority

Previous priority: p719 > p721 > p686 > p692 > p694 > p693 > p689/p690

**Revised priority:** p721 (Canvas UAF) > p686 (SVG animation UAF) > p689/p690 (memory ACE) > p692 > p694 > p693 > p719 (demoted to generic survey)

The info-leak gap remains our #1 blocker. The most promising remaining paths are:
1. CVE-2026-64718 (p721) — second Canvas UAF, might expose pointers during use-after-free
2. CVE-2023-41976 (p686) — SVG animation UAF in different size class
3. HexRabbit/DEVCORE writeup (not yet published) — may describe a non-JIT variant
4. Prolapse exploit's info-leak technique (unexplored research gap from CVE-2026-43720 analysis)

## Sources

- Apple advisory: https://support.apple.com/en-us/124152
- WebKit commit: `d96ab2fa64c6` (GitHub API search, confirmed in mjackson/WebKit fork)
- Bugzilla 294182: RESTRICTED (access denied)
- HexRabbit blog: No writeup found (last post 2021)
- DEVCORE blog: No writeup found (checked English pages 1-2)
- YARR JIT status: docs/CHANGELOG.md:18-22, PlatformEnable.h:774-777, YarrJIT.cpp:46

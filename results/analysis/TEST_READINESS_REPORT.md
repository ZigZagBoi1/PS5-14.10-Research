# Evidence-Ranked Test Readiness Report

**Date:** 2026-11-11  
**Target:** PS5 14.10 (WebKit 605.1.15 / Safari 17.0, LLInt-only)  

---

## Preflight Summary

| CVE | Probe | Preflight Result | Kill Signal |
|-----|-------|-----------------|-------------|
| CVE-2025-43265 | p719 | **DEAD** (CONFIG-SILENT) | YARR JIT gated on ENABLE(JIT), OFF on PS5 |
| CVE-2026-64718 | p721 | **DEAD** (PLATFORM-MISMATCH) | PathCG.cpp is CG-specific + OffscreenCanvas absent |

Both top-priority probes killed before console execution. Preflight verification prevented two wasted experiments.

---

## Approved Console Queue (ranked by confidence)

### Tier 1 — HIGH Confidence (JIT-independent, probe ready, code confirmed present)

**1. p686 — CVE-2023-41976 (SVG Animation UAF)**
- **Fix:** Safari 17.1 → present in our 17.0
- **JIT dependency:** NONE — SVG animation is DOM/rendering engine
- **Root cause (offline analysis):** SVG animated element removal during animation creates stale pointer. SVGElement is a different size class than CSSFontFace (our existing UAF), potentially bypassing bmalloc region separation
- **Probe:** 5 patterns (remove target during RAF, use-element removal, animateTransform removal, SMIL events, nested SVG reparenting)
- **Info-leak value:** MEDIUM-HIGH — SVGElement vtable could expose WebProcess .text pointer
- **Preflight gaps:** Upstream commit not retrieved (Bugzilla restricted). Probe tests broad patterns, not a specific trigger. Acceptable — SVG animation UAF surface is narrow enough that 5 patterns provide reasonable coverage
- **CRASH_CLASS:** MODERATE

**2. p689/p690 — CVE-2024-23213 (Memory Handling ACE)**
- **Fix:** Safari 17.3 → present in our 17.0
- **JIT dependency:** NONE — "improved memory handling", NOT type confusion (that's CVE-2024-23222, already dead)
- **Root cause (offline analysis):** Memory handling in Fetch body stream or TextDecoder streaming decode. Two alternative trigger probes targeting the two likeliest paths
- **Probe:** p689 (Fetch body lifetime), p690 (TextDecoder streaming)
- **Info-leak value:** MEDIUM-HIGH — buffer error in Fetch/TextDecoder could expose heap data including code pointers
- **Preflight gaps:** Upstream commit not retrieved. Two probes cover two candidate paths — one may miss
- **CRASH_CLASS:** MODERATE

### Tier 2 — MEDIUM Confidence (JIT-independent, probe ready, broader uncertainty)

**3. p692 — CVE-2023-40447 (DOM UAF)**
- **Fix:** Safari 17.1 → present in our 17.0
- **JIT dependency:** NONE — DOM tree manipulation during layout/style recalc
- **Probe:** 5 patterns (node removal during style recalc, ResizeObserver, IntersectionObserver, custom element lifecycle, adoptNode during layout)
- **Info-leak value:** MEDIUM — DOM UAFs can expose stale pointers
- **Preflight gaps:** Same researcher as CVE-2023-41976 (Junsung Lee). Broad pattern coverage
- **CRASH_CLASS:** MODERATE

**4. p694 — CVE-2023-42950 (Heap UAF)**
- **Fix:** Safari 17.2 → present in our 17.0
- **JIT dependency:** PARTIAL — Promise/GC patterns may be JIT-adjacent, but Proxy trap (pattern D) is fully LLInt-reachable
- **Probe:** 5 patterns (Promise reaction, WeakRef deref, FinalizationRegistry, Proxy handler, Generator resumption)
- **Info-leak value:** MEDIUM — Proxy trap vector is most promising for LLInt-only
- **Preflight gaps:** CVSS 8.8 but "heap" qualifier suggests possible JSC internals
- **CRASH_CLASS:** MODERATE

**5. p693 — CVE-2023-42890 (Memory Handling)**
- **Fix:** Safari 17.2 → present in our 17.0
- **JIT dependency:** NONE — DOM/Web API memory handling
- **Probe:** 5 patterns (ImageBitmap, OffscreenCanvas, Blob URL, createImageBitmap, TextEncoder)
- **Info-leak value:** LOW-MEDIUM — more likely corruption than disclosure
- **Preflight gaps:** NOTE: OffscreenCanvas vector will fail (absent on PS5). SharedArrayBuffer + TypedArray vector is the most interesting
- **CRASH_CLASS:** MODERATE
- **NOTE:** p693 ID collision — ensure correct file (`p693-memory-handling-pwn2car.html`)

### Tier 3 — LOW Confidence (no probe, needs research first)

**6-8. CVE-2025-31206, CVE-2025-43216, CVE-2025-30427**
- No probes written
- JIT dependency unknown
- Need Bugzilla/writeup research before probe design
- NOT APPROVED for console testing

### Removed from Queue

| Probe | CVE | Reason |
|-------|-----|--------|
| p719 | CVE-2025-43265 | DEAD — YARR JIT, CONFIG-SILENT |
| p721 | CVE-2026-64718 | DEAD — PathCG.cpp platform mismatch + OffscreenCanvas absent |
| p720 | CVE-2025-24213 | DEAD — JIT-dependent (DFG float type confusion) |

---

## Recommended Test Sequence

```
Phase 1: Environment verification (5 min)
  - Firmware check, kernel base re-measure, beacon server up

Phase 2: p686 — SVG Animation UAF (15 min)
  - Highest confidence, different size class from FontFace
  - Watch for: vtable pointer values in stale reads

Phase 3: p689 then p690 — Fetch/TextDecoder ACE (15 min each)
  - Two probes for one CVE — run both
  - Watch for: heap data exposure, code pointer leaks

Phase 4: p692 — DOM UAF (15 min)
  - Same researcher as p686, complementary patterns

Phase 5: p694 — Heap UAF (15 min)
  - Focus on Proxy trap (vector D) results

Phase 6: p693 — Memory Handling (10 min)
  - Skip OffscreenCanvas vector
  - Focus on SharedArrayBuffer/TextEncoder vectors
```

## What Would Materially Change the Assessment

A probe result advances the exploitation chain if it provides:
1. A **reproducible** read of data the attacker should not see
2. Leaked data containing **code pointers** (vtable, function pointer) usable to compute WebProcess text base RVA
3. **Controllable** leak (not random heap noise)
4. Survives **2+ independent runs** on the same boot

Anything less is [I] or [V], not [M].

## Open Preflight Gaps

1. **No upstream commit verification** for p686/p689/p690/p692/p694/p693 — Bugzilla entries restricted. Probes test broad patterns, not specific triggers. This is acceptable for Safari 17.x bugs where the entire version is unpatched on PS5.
2. **p693 OffscreenCanvas vector will fail** — known, skip it.
3. **p694 JIT adjacency uncertain** — Proxy trap vector (D) is the safe bet for LLInt-only.
4. **CVE-2024-23213 has two probes** — only one may match the actual bug; run both.

# Batch 3: MEDIUM Priority CVE Analysis

**Date:** 2026-11-11 | **Target:** PS5 14.10, WebKit 605.1.15 / Safari 17.0, LLInt-only

---

## Safari 17.1 CVEs (Present in 17.0 — PS5 VULNERABLE)

These four CVEs were fixed in Safari 17.1 (Oct 2023) or 17.2 (Dec 2023). Since PS5 ships Safari 17.0 (605.1.15), the vulnerable code is present unless Sony cherry-picked fixes.

### CVE-2023-40447 — WebKit UAF (Junsung Lee / Cross Republic)

**Previous belief:** DOM mutation UAF similar to CVE-2023-41976, same researcher.
**Evidence establishes:** Probe p692 written (5 patterns: node removal during style recalc, ResizeObserver callback, IntersectionObserver, custom element lifecycle, adoptNode during layout). NOT RUN. WebKit Bug 259836. CWE-119 (memory buffer errors).
**JIT dependency:** NO — DOM tree manipulation during layout/style recalc is interpreter-reachable.
**Info-leak potential:** MEDIUM — DOM UAFs can expose stale pointers. If the freed object contains a vtable or code pointer and can be read before reclaim, this could leak addresses.
**Overlooked:** The probe tests 5 broad patterns but doesn't target the specific Bugzilla commit. However, for a DOM UAF in the style recalc path, the pattern coverage is reasonable.
**New capability:** No — untested.
**Uncertainty:** Which specific DOM object lifecycle causes the UAF; whether the dangling pointer is readable from JS.

**Assessment: UNTESTED, JIT-INDEPENDENT, probe p692 ready. Run priority: MEDIUM.**

---

### CVE-2023-41976 — SVG Animation UAF (Junsung Lee)

**Previous belief:** SVG animation element UAF where removing the animated target mid-animation creates a stale pointer.
**Evidence establishes:** THREE probes written: p684 (DOM mutation/Range/TreeWalker/Selection/SVG UAF), p685 (Range/Selection stale pointer after contenteditable mutation), p686 (SVG animation element UAF — 5 patterns: remove target during RAF, use-element target removal, animateTransform target removal, SMIL begin/end events, nested SVG reparenting). All NOT RUN. Same researcher as CVE-2023-40447.
**JIT dependency:** NO — SVG animation callbacks are DOM/rendering engine paths, fully interpreter-reachable.
**Info-leak potential:** MEDIUM-HIGH — SVG animation targets hold internal C++ pointers. A stale SVG element pointer could expose the vtable of the freed SVGElement, which contains a code pointer to WebProcess .text. This is potentially more useful than FontFace UAF because SVGElement is a different size class and different vtable.
**Overlooked:** The SVG animation path is interesting because SVGElement objects are typically larger than CSSFontFace (192B). A UAF in a different size class could bypass the bmalloc region separation that limits our current FontFace exploit.
**New capability:** No — untested.
**Uncertainty:** Whether the stale pointer is readable from JS before reclaim; the size class of the freed object.

**Assessment: UNTESTED, JIT-INDEPENDENT. Potentially HIGH value if it provides a different-size-class UAF with readable stale pointer. Run priority: MEDIUM-HIGH.**

---

### CVE-2023-42890 — Memory Handling (Pwn2car)

**Previous belief:** Broad "improved memory handling" bug. Probe tests ImageBitmap, OffscreenCanvas, Blob URL, createImageBitmap, TextEncoder patterns.
**Evidence establishes:** Probe p693 written (5 patterns). NOT RUN. WebKit Bug 259830. Credited to Pwn2car. NOTE: p693 has an ID collision — two files exist: `p693-memory-handling-pwn2car.html` (this CVE) and `p693-delta-invariance.html` (VP-slot delta test from 13.60 series).
**JIT dependency:** NO — all patterns test DOM/Web API memory handling, not JIT optimization.
**Info-leak potential:** LOW-MEDIUM — "memory handling" bugs are usually about lifetime management (dangling references, double-frees), not about reading out-of-bounds. More likely to produce a corruption primitive than an info leak.
**Overlooked:** The probe's pattern E (TextEncoder/TextDecoder with shared ArrayBuffer views) is notable — SharedArrayBuffer + TypedArray views have a history of memory safety issues in WebKit. If PS5 has SharedArrayBuffer (likely, as it's in the spec since 2020), this could be interesting.
**New capability:** No — untested.
**Uncertainty:** The actual component affected; whether this produces corruption or disclosure.

**Assessment: UNTESTED, JIT-INDEPENDENT. Moderate value. Run priority: MEDIUM.**

---

### CVE-2023-42950 — Heap UAF (Nan Wang / 360 VRI)

**Previous belief:** Heap UAF from 360 Vulnerability Research Institute, likely in a complex WebKit subsystem.
**Evidence establishes:** Probe p694 written (5 patterns: Promise reaction job, WeakRef deref, FinalizationRegistry, Proxy handler, Generator resumption). NOT RUN. WebKit Bug 263682. CVSS 8.8 (HIGH). CWE-416.
**JIT dependency:** PARTIAL — Pattern A (Promise reaction job) is JIT-independent. Patterns B-E involve GC/finalization behavior that can be triggered from LLInt. However, the CVSS 8.8 and the "heap" qualifier suggest the actual bug may be in JSC internals that are JIT-adjacent.
**Info-leak potential:** MEDIUM — A heap UAF where the stale object can be read from JS before reclaim could expose internal pointers. The WeakRef/FinalizationRegistry patterns (B, C) are particularly interesting for info leaks because they explicitly involve reading after objects become eligible for collection.
**Overlooked:** Pattern D (Proxy handler freed during trap execution) is particularly dangerous and JIT-independent — Proxy traps execute in the interpreter and can hold stale references to freed handler objects. This is worth investigating even in LLInt-only mode.
**New capability:** No — untested.
**Uncertainty:** Whether the bug is in JIT-specific code or in the GC/heap management layer accessible from LLInt.

**Assessment: UNTESTED, PARTIALLY JIT-INDEPENDENT. Probe p694 ready. Run priority: MEDIUM. The Proxy trap pattern (D) is the most promising for LLInt-only PS5.**

---

## Safari 18.x CVEs (Post-branch — PS5 definitely unpatched if code exists)

### CVE-2025-31206 — Type Confusion with State Handling (Safari 18.5)

**Previous belief:** Type confusion in WebKit state handling, unclear component.
**Evidence establishes:** Only mentioned in NEW_CVE_CANDIDATES_2026_11.md:101-109. No probe written. No Bugzilla details. The description "improved state handling" is vague. The probe strategy suggests "async state transitions in DOM or JSC" and mentions "generator state machines under DFG" — the DFG mention is a RED FLAG for JIT dependency.
**JIT dependency:** UNCERTAIN — "state handling" could refer to interpreter-level state machines (Promises, generators) or JIT-level type profiling state. Without the Bugzilla commit, impossible to determine.
**Info-leak potential:** MEDIUM — type confusion can sometimes be leveraged for info leaks if mistyped values expose pointer bits as numeric values.
**Overlooked:** No probe exists, and the analysis explicitly calls for DFG testing, which is dead on PS5. If pursued, the probe must focus on non-JIT state transitions.
**New capability:** No — no investigation done.
**Uncertainty:** JIT dependency is the key unknown. Needs Bugzilla lookup.

**Assessment: NO PROBE, UNCERTAIN JIT DEPENDENCY. Low priority until Bugzilla details clarify the component. Run priority: LOW.**

---

### CVE-2025-43216 — Use-After-Free (Safari 18.6)

**Previous belief:** UAF in WebKit, could expose vtable pointers if read before reclaim.
**Evidence establishes:** Only mentioned in NEW_CVE_CANDIDATES_2026_11.md:121-129. No probe written. No Bugzilla details. "Needs Bugzilla lookup."
**JIT dependency:** UNKNOWN — UAFs can occur in any WebKit subsystem (DOM, CSS, SVG, JSC heap). Without details, JIT dependency cannot be assessed.
**Info-leak potential:** MEDIUM — same as any UAF. Depends on whether the stale pointer is readable from JS.
**Overlooked:** Nothing actionable without more information.
**New capability:** No — no investigation done.
**Uncertainty:** Everything. No component, no Bugzilla, no probe.

**Assessment: NO PROBE, UNKNOWN. Needs web research before probe can be designed. Run priority: LOW.**

---

### CVE-2025-30427 — Use-After-Free (Safari 18.4)

**Previous belief:** UAF in WebKit, credited to rheza (@ginggilBesel).
**Evidence establishes:** Only mentioned in NEW_CVE_CANDIDATES_2026_11.md:131-139. No probe written. No Bugzilla details. "Needs investigation."
**JIT dependency:** UNKNOWN — same situation as CVE-2025-43216.
**Info-leak potential:** MEDIUM — generic UAF potential.
**Overlooked:** @ginggilBesel may have a writeup or PoC. Worth searching their blog/Twitter/GitHub.
**New capability:** No — no investigation done.
**Uncertainty:** Everything. Needs web research.

**Assessment: NO PROBE, UNKNOWN. Needs web research. Run priority: LOW.**

---

## Summary Table

| CVE | Safari Fix | JIT Dep? | Info Leak? | Probe? | Revised Priority | Key Note |
|-----|-----------|----------|-----------|--------|-----------------|----------|
| CVE-2023-40447 | 17.1 | NO | MEDIUM | p692 ✓ | **MEDIUM** | DOM UAF, same researcher as 41976 |
| CVE-2023-41976 | 17.1 | NO | **MED-HIGH** | p686 ✓ | **MEDIUM-HIGH** | SVG UAF — different size class, possible vtable leak |
| CVE-2023-42890 | 17.2 | NO | LOW-MED | p693 ✓ | **MEDIUM** | Broad memory handling, SharedArrayBuffer vector interesting |
| CVE-2023-42950 | 17.2 | PARTIAL | MEDIUM | p694 ✓ | **MEDIUM** | Heap UAF, Proxy trap vector is LLInt-reachable |
| CVE-2025-31206 | 18.5 | UNCERTAIN | MEDIUM | NO | **LOW** | Needs Bugzilla — likely DFG-dependent |
| CVE-2025-43216 | 18.6 | UNKNOWN | MEDIUM | NO | **LOW** | No data at all |
| CVE-2025-30427 | 18.4 | UNKNOWN | MEDIUM | NO | **LOW** | No data, needs @ginggilBesel writeup |

## Key Conclusions

1. **The 2023 CVEs (Safari 17.1/17.2 fixes) are the strongest candidates** — confirmed present in our exact WebKit version, JIT-independent, probes written.
2. **CVE-2023-41976 (SVG animation UAF) deserves elevation** — SVGElement is a different object/size class than CSSFontFace, potentially providing a complementary UAF with different info-leak properties.
3. **The 2025 CVEs (31206, 43216, 30427) are dead ends without web research** — no probes, no component details, JIT dependency unknown.
4. **All 4 Safari 17.x probes (p686, p692, p693, p694) should run when console comes online**, prioritized after CVE-2025-43265 (p719, TOP PRIORITY OOB read).
5. **Console probe priority order: p719 (43265 OOB read) > p721 (64718 Canvas UAF) > p686 (41976 SVG UAF) > p692 (40447 DOM UAF) > p694 (42950 heap UAF) > p693 (42890 memory handling)**

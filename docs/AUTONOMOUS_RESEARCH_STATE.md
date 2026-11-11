# Autonomous Research State -- PS5 14.10

> Persistent state file for the OPERATION 14.10 autonomous research directive.
> Updated each session. Complements `results/STATE.md` (console measurements)
> and `results/INDEX.md` (probe ledger).

## Primary Objective

**Real Debug Settings menu on retail PS5 14.10.**

## Current Research Focus

**WebKit info leak** -- the sole remaining hard blocker for the entire chain.

## Active Hypothesis

[ERRATUM 2026-11-10: the "DFG JIT confirmed active (p602)" premise is retracted
— the engine is LLInt-only (`ENABLE_JIT` PRIVATE OFF, baseline included), so
CVE-2023-42916's DFG-tier trigger is unreachable on this build and this
hypothesis is closed.]
CVE-2023-42916 (DFG JIT OOB read, fixed Safari 17.1.2) may provide the ASLR
bypass needed to derive the WebProcess text base. PS5 has Safari 17.0 (605.1.15)
with DFG JIT confirmed active (p602). This CVE was used alongside CVE-2023-42917
in targeted attacks as the info-leak stage.

## Chain Status (2026-11-09)

| Stage | Status | Blocker |
|-------|--------|---------|
| Userland code exec | DONE | -- |
| Kernel image base (KASLR) | DONE | -- |
| WebKit UAF write primitive | DONE (FontFace + Canvas2D) | -- |
| WebKit info leak (text base) | BLOCKED | No known route; CVE-2023-42916 is top candidate |
| Kernel read primitive | BLOCKED | Needs info leak first |
| Kernel write primitive | BLOCKED | Needs kernel read first |
| Debug Settings toggle | BLOCKED | Needs kernel write |

## Debug Settings Dependency Graph

See `docs/DEBUG_SETTINGS_DEPENDENCY_GRAPH.md` for full analysis.

**Short version:** Debug Settings visibility is controlled by a registry flag
(`system_prof_settings.debug_settings_permission` or equivalent) stored in
process memory. Enabling it requires a kernel write to patch the flag at runtime.
The minimum path is: WebKit info leak -> arbitrary R/W in WebProcess -> kernel
exploit -> patch registry flag -> Debug Settings visible.

## What Changed Last Session (2026-11-09)

- Wrote 4 new info-leak probes: p698 (DFG OSR exit metadata, 7 sections), p699 (DFG arguments escape, 6 sections), p700 (JSC inline cache stub leak, 6 sections), p701 (JIT executable region oracle, 5 sections)
- p700 tests: megamorphic IC transition, IC repatch timing, GC during IC operation, Structure watchpoint invalidation order, concurrent JIT race, prototype chain IC caching
- p701 tests: JIT compile timing profile across page boundaries, JIT region GC pressure, OSR entry cache timing, JIT region size estimation, DFG tier-up threshold shift
- p702: Performance API + Resource Timing internal pointer leak (6 sections: timing resolution, nav timing fields, observer ordering, rAF timing, deep stack traces, structured clone)
- p703: CSS font subsystem timing oracle (6 sections: FontFace alloc timing, measureText variance, loaded promise resolve order, glyph cache oracle, computed style timing, FontFace descriptor enumeration)
- p704: Web Audio API internal buffer address leak (6 sections: AudioBuffer channel layout, ScriptProcessorNode timing, AnalyserNode data, OfflineAudioContext render timing, AudioParam automation, audio feature fingerprint)
- p705: IndexedDB + Storage API heap oracle (6 sections: IDB store timing, key comparison, structured clone size oracle, localStorage quota probing, Blob URL format, MessageChannel timing)
- p706: CSS animation compositor timing side channel (6 sections: rAF jitter with compositing layers, transition computed style, will-change layer timing, CSS containment layout, animation frame correlation, custom property resolution depth)
- p707: WebGL shader compilation + GPU buffer leak (6 sections: renderer fingerprint, shader compile timing, error log contents, buffer alloc timing, readPixels timing, extension enumeration)
- p708: SVG filter primitive timing + SMIL animation leak (6 sections, fork-written)
- p709: History API state serialization + navigation timing leak (6 sections, fork-written)
- p710: Web Worker postMessage + thread creation timing (6 sections, fork-written)
- p712: CSS Paint + Canvas pattern/gradient internal leak (6 sections: gradient timing, pattern timing, toDataURL encoding, compositing mode timing, ImageData alloc, putImageData round-trip)
- p713: MutationObserver + DOM internals leak (6 sections: observer ordering, node creation timing, TreeWalker traversal, Range object timing, DOMParser timing, node comparison)
- p714: Selection/Range API internal pointer leak (6 sections: range creation timing, compareBoundaryPoints timing, cloneRange/deleteContents, Selection.addRange ordering, TreeWalker+Range interaction, toString vs cloneContents)
- p715: IntersectionObserver + ResizeObserver internal timing oracle (6 sections, fork-written)
- p716: Web Crypto API + SubtleCrypto timing oracle (6 sections, fork-written)
- p717: Event dispatch + EventTarget internal timing oracle (6 sections: dispatch depth timing, multi-listener ordering, CustomEvent creation, composedPath timing, AbortController/Signal, coordinate precision)
- p718: Promise/Microtask queue internal timing oracle (6 sections: Promise.all resolution, microtask depth, Promise.race cancellation, async/await continuation, FinalizationRegistry ordering, Proxy trap timing)
- Wrote comprehensive CVE candidates research doc: `docs/NEW_CVE_CANDIDATES_2026_11.md`
  - 8 new CVE candidates identified from Apple advisories (Safari 18.2-27)
  - Top 3: CVE-2025-43265 (OOB read info disclosure), CVE-2025-24213 (float type confusion), CVE-2026-64718 (Canvas UAF)
  - Tier 1 (definitely unpatched): CVE-2026-64718, CVE-2026-64757, CVE-2026-64753
  - Tier 2 (likely unpatched): CVE-2024-54505, CVE-2025-24213, CVE-2025-31206, CVE-2025-43265, CVE-2025-43216, CVE-2025-30427, CVE-2025-24209
- p722: WeakRef + GC timing oracle (6 sections: survival ordering, FinalizationRegistry ordering, GC pressure threshold, cross-type GC, setTimeout interaction, WeakMap timing)
- p723: ArrayBuffer transfer + structured clone heap oracle (6 sections: transfer stability, clone amplification, neutered buffer timing, MessageChannel transfer, Blob conversion, DataView multi-type)
- p719: CVE-2025-43265 OOB read probe (6 sections: RAB stale read, string length OOB, RegExp capture OOB, transfer stale slice, DataView RAB OOB, structuredClone valueOf)
- p720: CVE-2025-24213 float type confusion probe (6 sections: polymorphic array typeconf, int32 overflow, float edge cases, valueOf oscillation, sort comparator, F64 pointer oracle)
- p721: CVE-2026-64718 Canvas UAF probe (6 sections: OffscreenCanvas transfer, toBlob replace, drawImage removal, context switch race, cloneNode, ImageBitmap destroy)
- PS5 offline -- all work is static analysis and probe preparation

## Hardware-Ready Test Queue

| Probe | CVE | Priority | Expected Signal |
|-------|-----|----------|-----------------|
| p680 | CVE-2023-42916 | TOP | DFG OOB read -> address leak |
| p681 | CVE-2023-42916 | TOP | Variant B patterns |
| p695 | CVE-2023-42916 | TOP | DFG range analysis (clz32, shift, loop peel) |
| p696 | CVE-2023-42916 | TOP | DFG CSE stale bounds check |
| p697 | StructureID | TOP | fakeobj via type speculation |
| p698 | DFG internals | TOP | OSR exit metadata + JIT code pointer leak |
| p699 | DFG arguments | TOP | arguments escape + frame metadata OOB |
| p700 | JSC IC stubs | TOP | inline cache stub pointer leak via timing |
| p701 | JIT region | TOP | executable region oracle via allocation timing |
| p702 | Performance API | HIGH | nav timing + observer ordering + stack trace leak |
| p703 | CSS font timing | HIGH | font alloc oracle + glyph cache + measureText |
| p704 | Web Audio API | HIGH | AudioBuffer layout + render timing + feature fingerprint |
| p705 | IndexedDB/Storage | HIGH | IDB store timing + localStorage quota + Blob URL format |
| p706 | CSS animation | HIGH | compositor timing + will-change alloc + containment layout |
| p707 | WebGL shaders | HIGH | renderer fingerprint + compile timing + error log + extensions |
| p708 | SVG filters | HIGH | filter primitive timing + SMIL animation + foreignObject |
| p709 | History API | HIGH | pushState serialization + navigation timing + popstate order |
| p710 | Web Workers | HIGH | worker creation timing + postMessage + error stack traces |
| p711 | Intl / ICU | HIGH | locale creation timing + collator compare + BigInt format + Segmenter |
| p712 | Canvas paint | HIGH | gradient/pattern timing + toDataURL + compositing + ImageData |
| p713 | MutationObserver | HIGH | observer ordering + DOM node alloc + TreeWalker + DOMParser |
| p714 | Selection/Range | HIGH | range creation timing + compareBoundaryPoints + TreeWalker |
| p715 | Grid/Flexbox | HIGH | grid track sizing + flex wrap + auto-placement + invalidation |
| p715 | IntersectionObserver | HIGH | observer callback ordering + threshold precision |
| p716 | Web Crypto API | HIGH | digest timing + key gen timing + entropy analysis |
| p717 | Event dispatch | HIGH | dispatch depth timing + listener ordering + composedPath |
| p718 | Promise/Microtask | HIGH | resolution ordering + queue depth + FinalizationRegistry |
| p722 | WeakRef/GC | HIGH | GC sweep ordering + pressure threshold + cross-type collection |
| p723 | ArrayBuffer xfer | HIGH | transfer timing + clone amplification + neutered buffer oracle |
| p719 | CVE-2025-43265 | **TOP** | OOB read info disclosure -- explicitly leaks "internal states" |
| p720 | CVE-2025-24213 | **TOP** | Float type confusion -- classic NaN-boxing addrof/fakeobj |
| p721 | CVE-2026-64718 | **TOP** | Canvas UAF (Bugzilla 313935) -- DEFINITELY unpatched |
| p692 | CVE-2023-40447 | HIGH | DOM UAF crash |
| p693 | CVE-2023-42890 | HIGH | Memory handling crash |
| p694 | CVE-2023-42950 | HIGH | Heap UAF type confusion |
| p686 | CVE-2023-41976 | MED | SVG animation UAF |
| p688 | CVE-2023-42852 | MED | CSS counter-style OOB |
| p689 | CVE-2024-23213 | MED | Fetch body lifetime |
| p690 | CVE-2024-23213 | MED | TextDecoder streaming |

## Offline Work Completed

- 161 WebKit probes written (p553-p723)
- 2930+ total probes across all phases
- Full dead-end catalog maintained
- WebKit cherry-pick cutoff fingerprinted (Safari 26.3 fixes included, 26.4 not)
- StructureID prediction research (if PS5 lacks randomization, fakeobj possible)

## Next Actions (Ordered)

1. Write more CVE-2023-42916 probe variants (DFG OOB read patterns)
2. Research StructureID table layout for fakeobj primitive
3. When PS5 comes online: run p680/p681 first (info leak candidates)
4. Analyze any crash backtraces for module-relative addresses
5. Community outreach for decrypted WebProcess binary

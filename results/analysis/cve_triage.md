# CVE Cross-Reference Triage — Batch 2 Priority

**Date:** 2026-11-11 | **Target:** PS5 14.10, WebKit 605.1.15 / Safari 17.0, LLInt-only

## Triage Methodology

Categorized 30 pending CVE cross-ref tasks by:
1. Whether already analyzed in existing docs
2. JIT dependency (PS5 is LLInt-only — all JIT tiers OFF)
3. Component availability on PS5 (no WebGPU, no datalist, no Wasm GC)
4. Info-leak potential (critical path: need WebProcess text base)
5. Existing probe status

---

## HIGH — Execute These (8 CVEs)

These target code paths likely present in WebKit 605.1.15, are JIT-independent, and could advance the kernel R/W chain.

| CVE | Type | Why High Priority | Existing Analysis |
|-----|------|-------------------|-------------------|
| **CVE-2026-43720** | Canvas2D UAF | OUR CONFIRMED VULN — must verify cross-ref is complete | Extensive (p553+, CAPABILITY_GRAPH) |
| **CVE-2026-112659** | Type confusion (ACE) | Safari 27.2, ACE-grade, could skip info leak entirely | `WEBKIT_CVE_POSTCHERRY_INFOLEAKS:79` — needs deeper analysis |
| **CVE-2026-113903** | UAF (memory modification) | Safari 27.2, UAF class matches our expertise | `WEBKIT_CVE_POSTCHERRY_INFOLEAKS:81` — minimal |
| **CVE-2026-86974** | Type confusion | Safari 27.2, memory corruption | `WEBKIT_CVE_POSTCHERRY_INFOLEAKS:80` — minimal |
| **CVE-2026-64718** | Canvas UAF | Safari 26.6+, DEFINITELY unpatched, our domain | `NEW_CVE_CANDIDATES:44-53`, probe p721 WRITTEN |
| **CVE-2025-43265** | OOB read | Safari 18.6, explicitly info disclosure | `NEW_CVE_CANDIDATES:111-119`, probe p719 WRITTEN |
| **CVE-2025-24213** | Float type confusion | Safari 18.5, classic NaN-boxing path | `NEW_CVE_CANDIDATES:91-99`, probe p720 WRITTEN |
| **CVE-2024-54505** | Type confusion | Safari 18.2, Gary Kwong JSC | `NEW_CVE_CANDIDATES:81-89` — needs probe |

## MEDIUM — Execute If Budget Allows (7 CVEs)

| CVE | Type | Notes | Existing Analysis |
|-----|------|-------|-------------------|
| **CVE-2023-40447** | WebKit UAF | Junsung Lee, same researcher as 41976 | Probe p692 WRITTEN, NOT RUN |
| **CVE-2023-41976** | SVG animation UAF | Safari 17.1 fix, present in 17.0 | Probe p686 WRITTEN, NOT RUN |
| **CVE-2023-42890** | Memory handling | Pwn2car, Safari 17.2 | Probe p693 WRITTEN, NOT RUN |
| **CVE-2023-42950** | Heap UAF | Nan Wang, Safari 17.2 | Probe p694 WRITTEN, NOT RUN |
| **CVE-2025-31206** | Type confusion (state) | Safari 18.5, uncertain component | `NEW_CVE_CANDIDATES:101-109` |
| **CVE-2025-43216** | UAF | Safari 18.6 | `NEW_CVE_CANDIDATES:121-129` |
| **CVE-2025-30427** | UAF | Safari 18.4 | `NEW_CVE_CANDIDATES:131-139` |

## LOW — Deprioritize (8 CVEs)

| CVE | Reason |
|-----|--------|
| **CVE-2023-42956** | DoS only (SungKwon Lee), LOW per `WEBKIT_CVE_RESEARCH:173` |
| **CVE-2023-43010** | Needs web research — no existing analysis found |
| **CVE-2023-42883** | Needs web research — likely rendering DoS |
| **CVE-2024-23206** | Fingerprinting/access issue, not memory corruption (`WEBKIT_CVE_RESEARCH:41`) |
| **CVE-2024-23271** | Needs web research — no existing analysis |
| **CVE-2025-24209** | Buffer overflow, write not read — low info-leak value (`NEW_CVE_CANDIDATES:141-149`) |
| **CVE-2026-64753** | Cache privacy leak, not address leak (`NEW_CVE_CANDIDATES:65-73`) |
| **CVE-2026-64757** | Unknown component, needs Bugzilla lookup (`NEW_CVE_CANDIDATES:55-63`) |

## ALREADY ASSESSED — Mark Complete (7 CVEs)

| CVE | Status | Source |
|-----|--------|--------|
| **CVE-2026-43740** | CONFIG-SILENT/DEAD — YARR JIT bug, JIT is OFF | `WEBKIT_CVE_POSTCHERRY_INFOLEAKS:22-47` |
| **CVE-2026-112699** | DEAD — WebGPU, not on PS5 | `WEBKIT_CVE_POSTCHERRY_INFOLEAKS:49-57` |
| **CVE-2026-112680** | DEAD — WebGPU, not on PS5 | `WEBKIT_CVE_POSTCHERRY_INFOLEAKS:62-69` |
| **CVE-2026-86922** | DEAD — Wasm GC only, no JS path | `WEBKIT_CVE_REGRESSION_TESTS:32+`, `NEW_CVE_CANDIDATES:158` |
| **CVE-2026-43705** | Tested p673 — TransformStream type confusion | `ALL_PROBES:92932+`, `ALL_PROBES:93194` |
| **CVE-2026-84635** | LIVE but NOT weaponizable — bounds-checked | `ATTACK_PRIORITY_REFERENCE:134`, p661/p662 |
| **CVE-2026-28905** | LIVE but NOT a leak — own data only | `ATTACK_PRIORITY_REFERENCE:135`, p663-p666 |

## JIT Dependency Warning

Many CVE descriptions mention "DFG", "FTL", "JIT optimization", or "B3". PS5 14.10 is **LLInt-only** (`ENABLE_JIT` PRIVATE OFF). CVEs requiring JIT compilation to trigger are **structurally dead** on this target. However, some bugs described as "DFG" may have LLInt-reachable variants — these need case-by-case analysis.

Known JIT-dependent dead CVEs: CVE-2024-44308 (DFG PutByVal, Sony patched), CVE-2023-42917 (DFG flatten race, Sony patched), CVE-2026-28905 (FTL PhantomNewArrayWithButterfly).

## Execution Priority for Parent

1. Mark 7 ALREADY ASSESSED as complete in task DB (no further work needed)
2. Execute 8 HIGH tasks — focus on CVE-2026-112659, CVE-2026-113903, CVE-2026-86974 first (least analyzed, highest potential)
3. Execute MEDIUM tasks if budget allows
4. Skip LOW tasks unless HIGH/MEDIUM produce leads pointing to them

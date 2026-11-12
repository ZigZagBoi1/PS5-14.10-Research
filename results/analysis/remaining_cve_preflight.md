# Remaining CVE Preflight Verification

**Date:** 2026-11-11
**Scope:** 6 CVE candidates for PS5 14.10 (WebKit 605.1.15 / Safari 17.0)
**Method:** NVD JSON API data + local probe analysis + advisory-level info
**Limitation:** All WebKit Bugzilla entries are RESTRICTED. No upstream commits found by CVE number. No public writeups exist. Assessment relies on NVD descriptions, CWE classifications, and probe code review.

---

## CVE-2026-64718 (p721) — Canvas UAF — DOWNGRADED

| Field | Value |
|---|---|
| NVD CVSS | **5.5 MEDIUM** (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H) |
| NVD Description | "unexpected Safari crash" |
| CWE | CWE-416 (Use After Free) |
| Fixed in | Safari 26.6 / Safari 27 |
| Bugzilla | 313935 (RESTRICTED) |
| Unpatched on PS5? | **YES** — fix postdates cherry-pick cutoff (Safari 26.3) |

### Key Finding: Crash-Only, NOT Code Execution

NVD rates this **A:H only** (availability impact high) with **C:N, I:N** (no confidentiality or integrity impact). The description says "unexpected Safari crash" — there is NO claim of arbitrary code execution. This is a significant downgrade from our prior assessment which assumed ACE potential.

Compare to the 2023 CVEs below: all are CVSS 8.8 with explicit ACE claims.

### Probe p721 Assessment

The probe tests 6 Canvas lifecycle UAF patterns (OffscreenCanvas transfer, toBlob replace, drawImage removal, context switch race, cloneNode, ImageBitmap destroy). These are plausible UAF trigger patterns for Canvas. However:

- **Without ACE in the NVD description**, even a successful crash may not yield a controllable primitive
- A crash-only UAF is useful as a **confirmation of reachable freed memory** but NOT as a direct exploitation path
- Our existing CVE-2026-43720 (p635) is already a confirmed Canvas2D UAF with control — p721 is lower priority

### Verdict: MEDIUM-LOW priority. Run after ACE-grade CVEs. Useful as confirmation of a second Canvas UAF path but unlikely to yield a new primitive beyond what p635 already provides.

---

## CVE-2023-41976 (p686) — SVG Animation UAF — HIGH

| Field | Value |
|---|---|
| NVD CVSS | **8.8 HIGH** (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H) |
| NVD Description | "Processing web content may lead to arbitrary code execution" |
| CWE | CWE-416 (Use After Free) |
| Fixed in | Safari 17.1 |
| Researcher | Junsung Lee (Cross Republic) |
| Unpatched on PS5? | **LIKELY YES** — fixed Safari 17.1, PS5 has 17.0 |

### Assessment

- ACE-grade UAF in a **different object class** than FontFace/Canvas2D (SVG animation elements, ~192 bytes)
- **JIT-independent** — no compile-time gate concern
- Safari 17.0 → 17.1 fix means PS5 14.10 is squarely in the vulnerable window
- Same researcher (Junsung Lee) also found CVE-2023-40447 — suggests expertise in DOM lifecycle UAFs

### Probe p686 Assessment

Tests 5 SVG animation UAF patterns: target removal during RAF, SVG use-element instance deletion, animateTransform during compositor update, SMIL event timing on removed elements, nested SVG reparenting during animation. These are **plausible trigger patterns** for an SVG animation UAF. The probe correctly targets the animation-target lifecycle, which is the most common UAF surface in SVG animations.

### Unknown: Exact affected component not confirmed. "Improved memory management" is generic. The probe tests broad patterns, not the specific bug.

### Verdict: HIGH priority. ACE-grade, JIT-independent, different size class from existing UAFs. **Recommended #1 for console testing.**

---

## CVE-2023-40447 (p692) — DOM UAF — HIGH

| Field | Value |
|---|---|
| NVD CVSS | **8.8 HIGH** |
| NVD Description | "Processing web content may lead to arbitrary code execution" |
| CWE | CWE-119 (Improper Restriction of Operations within Memory Buffer) |
| Fixed in | Safari 17.1 |
| Bugzilla | 259836 |
| Researcher | Junsung Lee (Cross Republic) |
| Unpatched on PS5? | **LIKELY YES** — fixed Safari 17.1, PS5 has 17.0 |

### Assessment

- ACE-grade, CWE-119 (buffer operations) — broader than pure UAF
- Same researcher and same fix version as CVE-2023-41976 — may be related bugs found in the same audit
- JIT-independent (no JIT gate in description or CWE)

### Probe p692 Assessment

Tests 5 DOM mutation + layout patterns: node removal during style recalc, ResizeObserver callback mutations, IntersectionObserver with removed targets, custom element lifecycle callbacks, adoptNode during layout. These target the **DOM tree + layout engine intersection** which is the most common source of CWE-119 bugs in WebKit.

### Verdict: HIGH priority. ACE-grade, JIT-independent, plausible probe vectors. **Recommended #2.**

---

## CVE-2023-42950 (p694) — Heap UAF — HIGH

| Field | Value |
|---|---|
| NVD CVSS | **8.8 HIGH** |
| NVD Description | "Processing web content may lead to arbitrary code execution" |
| CWE | CWE-416 (Use After Free) |
| Fixed in | Safari 17.2 |
| Bugzilla | 263682 |
| Researcher | Nan Wang (360 VRI) + Rushikesh Nandedkar |
| Unpatched on PS5? | **LIKELY YES** — fixed Safari 17.2, PS5 has 17.0 |

### Assessment

- ACE-grade heap UAF from a major security research lab (360 Vulnerability Research Institute)
- CWE-416 explicit — classic UAF
- JIT-independent
- Fixed in 17.2, two versions past our 17.0

### Probe p694 Assessment

Tests 5 heap UAF patterns: Promise reaction scope, WeakRef deref after collection, FinalizationRegistry cleanup, Proxy handler freed during trap, generator resumption after scope cleanup. These target **JS object lifecycle / GC interaction** — a plausible attack surface for heap UAFs. The Proxy trap pattern (D) is particularly interesting as Proxy handlers interact with both JS and C++ object lifecycles.

### Unknown: "Heap" is inferred from CWE-416 + description. Exact WebKit subsystem unknown.

### Verdict: HIGH priority. ACE-grade, JIT-independent, targets GC/object lifecycle. **Recommended #3.**

---

## CVE-2023-42890 (p693) — Memory Handling — HIGH

| Field | Value |
|---|---|
| NVD CVSS | **8.8 HIGH** |
| NVD Description | "Processing web content may lead to arbitrary code execution" |
| CWE | CWE-94 (Improper Control of Generation of Code, secondary) |
| Fixed in | Safari 17.2 |
| Bugzilla | 259830 |
| Researcher | Pwn2car |
| Unpatched on PS5? | **LIKELY YES** — fixed Safari 17.2, PS5 has 17.0 |

### Assessment

- ACE-grade with CWE-94 — **code injection** secondary classification
- CWE-94 is concerning: on a platform with JIT OFF, the code injection path may still exist through interpreter dispatch or native function tables
- JIT-independence uncertain — CWE-94 could involve JIT code generation, but "improved memory handling" suggests a memory bug, not a JIT optimization bug
- Pwn2car is a known WebKit exploit developer

### Probe p693 Assessment

Tests 5 memory handling patterns: ImageBitmap from removed canvas, OffscreenCanvas transfer, Blob URL revocation during fetch, createImageBitmap with oversized crop rect, TextEncoder/TextDecoder shared buffer views. These are reasonable **media object lifecycle** patterns. The Blob URL revocation pattern (C) is particularly interesting as it creates a race between URL lifetime and fetch state.

### Caution: CWE-94 (code injection) may indicate a JIT-related path. Without the specific component, we cannot rule this out. If the bug is in JIT code generation, it is DEAD on PS5.

### Verdict: MEDIUM-HIGH priority. ACE-grade but CWE-94 introduces JIT uncertainty. **Recommended #4.**

---

## CVE-2024-23213 (p689/p690) — Memory Handling ACE — HIGH

| Field | Value |
|---|---|
| NVD CVSS | **8.8 HIGH** |
| NVD Description | "Processing web content may lead to arbitrary code execution" |
| CWE | CWE-119 (Improper Restriction of Operations within Memory Buffer) |
| Fixed in | Safari 17.3 |
| Unpatched on PS5? | **LIKELY YES** — fixed Safari 17.3, PS5 has 17.0 |

### Assessment

- ACE-grade, CWE-119 — same class as CVE-2023-40447
- Fixed 3 versions past our 17.0 — very likely unpatched
- JIT-independent based on CWE

### Probe p689/p690 Assessment

p690 tests TextDecoder streaming decode patterns: split multi-byte UTF-8, large buffer reallocation, GC pressure between stream calls, shared ICU converter, fatal mode at buffer boundaries. These target **text decoding buffer management** — a legitimate CWE-119 attack surface. The GC-pressure-between-stream-calls pattern (C) is the most likely to trigger a stale buffer read.

### Verdict: HIGH priority. ACE-grade, JIT-independent, plausible probe vectors. **Recommended #5** (lower than 41976/40447/42950 only because Safari 17.3 is further from our 17.0, giving Sony more time to backport).

---

## Evidence-Ranked Test Readiness Report

### Tier 1: ACE-Grade, JIT-Independent, Safari 17.0→17.1 Fix (HIGHEST PRIORITY)

| Rank | Probe | CVE | CVSS | CWE | Fix Version | Probe Vectors |
|---|---|---|---|---|---|---|
| **1** | p686 | CVE-2023-41976 | 8.8 | UAF | 17.1 | 5 SVG animation UAF patterns |
| **2** | p692 | CVE-2023-40447 | 8.8 | Buffer | 17.1 | 5 DOM mutation + layout patterns |

**Rationale:** Both fixed in 17.1 (one version past ours), both ACE, both JIT-independent, both by the same researcher (Junsung Lee). Highest confidence of being unpatched.

### Tier 2: ACE-Grade, JIT-Independent, Safari 17.2 Fix

| Rank | Probe | CVE | CVSS | CWE | Fix Version | Probe Vectors |
|---|---|---|---|---|---|---|
| **3** | p694 | CVE-2023-42950 | 8.8 | UAF | 17.2 | 5 heap/GC UAF patterns |
| **4** | p693 | CVE-2023-42890 | 8.8 | Code Inj. | 17.2 | 5 media object patterns |

**Rationale:** Both ACE, both fixed in 17.2. p694 is pure UAF (higher confidence JIT-independent). p693 has CWE-94 which introduces JIT uncertainty.

### Tier 3: ACE-Grade, JIT-Independent, Safari 17.3 Fix

| Rank | Probe | CVE | CVSS | CWE | Fix Version | Probe Vectors |
|---|---|---|---|---|---|---|
| **5** | p689/p690 | CVE-2024-23213 | 8.8 | Buffer | 17.3 | 5 TextDecoder stream patterns |

**Rationale:** ACE, JIT-independent, but fixed in 17.3 — more time for Sony backport.

### Tier 4: Crash-Only, Confirmed Unpatched

| Rank | Probe | CVE | CVSS | CWE | Fix Version | Probe Vectors |
|---|---|---|---|---|---|---|
| **6** | p721 | CVE-2026-64718 | 5.5 | UAF | 26.6 | 6 Canvas lifecycle patterns |

**Rationale:** Definitely unpatched (post-cutoff), but NVD says crash-only (no ACE claim). We already have a confirmed Canvas UAF (p635/CVE-2026-43720). Lower priority unless Tier 1-3 probes yield nothing.

---

## What We Cannot Verify Without Source Access

For ALL 6 CVEs:
1. **Exact affected component** — Bugzilla entries are restricted
2. **Whether probes test the actual bugs** — all probes test plausible patterns, not confirmed root causes
3. **Compile-time gates** — cannot check if specific code paths are gated on features absent from PS5
4. **Sony backport status** — cannot confirm whether Safari 17.1-17.3 security fixes were cherry-picked

### Mitigation

- The probes test **broad attack surfaces** in the right vulnerability classes, so even if they don't hit the exact CVE bug, they may find related issues in the same code
- All 2023 CVEs target Safari 17.0-17.2 range, which is our exact version — the vulnerable code EXISTS in our build (it may have been patched by Sony cherry-pick, but the code paths are present)
- Running probes in supervised mode with beacon monitoring provides data regardless of whether the specific CVE is hit

## Revised Console Probe Priority

**Previous:** p721 > p686 > p692 > p694 > p693 > p689/p690

**Revised (evidence-ranked):**
1. **p686** (CVE-2023-41976) — ACE UAF, Safari 17.1 fix, JIT-independent
2. **p692** (CVE-2023-40447) — ACE buffer, Safari 17.1 fix, JIT-independent
3. **p694** (CVE-2023-42950) — ACE UAF, Safari 17.2 fix, JIT-independent
4. **p693** (CVE-2023-42890) — ACE memory, Safari 17.2 fix, CWE-94 JIT-uncertainty
5. **p689/p690** (CVE-2024-23213) — ACE buffer, Safari 17.3 fix
6. **p721** (CVE-2026-64718) — Crash-only, CVSS 5.5, no ACE claim

**Key change:** p721 demoted from #1 to #6. The 2023 ACE-grade CVEs are all higher value.

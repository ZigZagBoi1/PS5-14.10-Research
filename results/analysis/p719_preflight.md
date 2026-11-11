# p719 Preflight Assessment — CVE-2025-43265 (WebKit Bug 294182)

**Date:** 2026-11-11  
**CVE:** CVE-2025-43265  
**WebKit Bug:** 294182  
**Credited:** HexRabbit (DEVCORE)  
**Fixed in:** Safari 18.6 (Jul 30, 2025)  
**Advisory:** "An out-of-bounds read was addressed with improved input validation. Processing maliciously crafted web content may disclose internal states of the app."

---

## 1. Root Cause Mapping

**Status: UNVERIFIED** — WebKit bug 294182 is almost certainly restricted on bugs.webkit.org (standard for security bugs). The specific affected source component, defective code path, and patch commit are NOT publicly known at time of writing. Web research agent dispatched to confirm.

The probe was written WITHOUT knowledge of the specific bug. It tests 6 generic OOB read vectors, not the actual defective behavior in bug 294182.

## 2. Vector-by-Vector Analysis

| Vector | What It Tests | JIT Dep? | PS5 API Available? | Prior Evidence | Assessment |
|--------|--------------|----------|-------------------|----------------|------------|
| **A: RAB stale read** | TypedArray view after ArrayBuffer.resize() | No (interp path) + Yes (DFG sub-variant) | Yes (p601 confirms RAB) | **RAB bounds checking is spec-compliant** (p555, ATTACK_PRIORITY_REFERENCE:106) | LIKELY DEAD — bounds already correct |
| **B: DFG string speculation** | DFG speculates string length | **YES — DFG only** | N/A — DFG is OFF | LLInt-only confirmed | **DEAD on PS5** |
| **C: RegExp capture mutation** | valueOf during RegExp.exec changes input | No | Yes | No prior test | UNKNOWN — worth testing |
| **D: Transfer stale slice** | ArrayBuffer.slice after structuredClone transfer | No | Needs structuredClone check | No prior test | UNKNOWN — depends on structuredClone availability |
| **E: DataView RAB OOB** | DataView read after RAB resize | No (interp) + Yes (DFG sub-variant) | Yes (RAB available) | **Same RAB bounds concern as A** | LIKELY DEAD — bounds already correct |
| **F: structuredClone valueOf** | valueOf mutates array during clone | No | Needs structuredClone | No prior test | UNKNOWN — worth testing |

### Critical Prior Art

- **p555 (2026-10-27):** "RAB bounds checking is spec-compliant" — this directly undermines vectors A and E
- **p621 (2026-11-04):** CVE-2024-44308 (DFG PutByVal on RAB) is DEAD, Sony patched
- **p661/p662 (2026-11-06):** CVE-2026-84635 (TypedArray Reflect.set) — VULNERABLE but bounds check blocks OOB

### Net Assessment

Of 6 vectors:
- **1 DEAD** (B: JIT-dependent)
- **2 LIKELY DEAD** (A, E: RAB bounds already spec-compliant)
- **3 UNKNOWN** (C, D, F: untested, JIT-independent)

The 3 UNKNOWN vectors (C, D, F) are the only ones worth running. They are not RAB-dependent and test different code paths (RegExp, structuredClone, deserialization).

## 3. API Availability on PS5 14.10

| API | Status | Evidence |
|-----|--------|----------|
| ResizableArrayBuffer | **AVAILABLE** | p601 feature inventory, p608 series |
| ArrayBuffer.resize() | **AVAILABLE** | p555, p608 |
| structuredClone | **UNKNOWN** | Not tested; needs p719 or dedicated probe |
| DataView | **AVAILABLE** | Standard API |
| RegExp | **AVAILABLE** | Standard API |
| BigUint64Array | **AVAILABLE** | Used in many probes |

**Action needed:** Verify structuredClone availability before relying on vectors D and F. If absent, only vector C remains viable.

## 4. Unpatched Status

Safari 18.6 fix. PS5 cherry-pick cutoff is stated as "Safari 26.3 (Feb 2026)." This creates a version numbering confusion — Safari 18.6 (Jul 2025) predates the cutoff, so **Sony MAY have backported this fix**. The probe comment states "MAY not be backported" but the uncertainty is genuine. Without a decrypted WebProcess binary, this cannot be determined.

**If Sony tracks Apple's security fixes chronologically** (which the constant drain campaign suggests they do partially — 1/25 confirmed), this fix is more likely present than absent.

## 5. CVE-Specific Claim

**DOWNGRADE from TOP PRIORITY to MEDIUM.** Reasoning:

1. The probe does NOT test the specific bug 294182 — it tests generic OOB read patterns
2. Two of its best vectors (A, E) target RAB bounds, which are already spec-compliant on PS5
3. Its highest-value vector (B) is JIT-dependent and dead
4. The remaining 3 vectors (C, D, F) are speculative — they may not match bug 294182 at all
5. The "unpatched" status is uncertain — Safari 18.6 predates the cherry-pick cutoff
6. Even if an OOB read succeeds, it must expose CODE POINTERS to be useful (not just heap data)

**The probe remains worth running** as a generic OOB read survey, but its connection to CVE-2025-43265 specifically is UNVERIFIED. The TOP PRIORITY label was based on the assumption that p719 tests the actual bug — it does not.

## 6. Revised Console Probe Priority

| Priority | Probe | Rationale |
|----------|-------|-----------|
| 1 | **p719 (vectors C, D, F only)** | Generic OOB read survey, 3 untested JIT-independent vectors |
| 2 | **p721** (CVE-2026-64718) | Distinct Canvas UAF, DEFINITELY unpatched (post-cutoff fix) |
| 3 | **p686** (CVE-2023-41976) | SVG animation UAF, different size class from FontFace |
| 4 | p692 / p694 / p693 | Additional WebKit UAFs |
| 5 | p689/p690 | CVE-2024-23213 memory handling |

## 7. Recommended Preflight Actions Before Running

1. [ ] Confirm structuredClone availability (quick JS test: `typeof structuredClone`)
2. [ ] Verify firmware version matches 14.10 (Settings → System → System Software)
3. [ ] Confirm browser entry method is stable (game process Lua → WebKit)
4. [ ] Prepare beacon capture infrastructure (tools/browser_runner/serve.py)
5. [ ] Review p719 for crash-inducing patterns — MODERATE risk (OOB access may segfault WebProcess)
6. [ ] Record exact probe revision (git hash) before execution

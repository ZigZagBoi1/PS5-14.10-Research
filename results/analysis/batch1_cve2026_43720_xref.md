# CVE-2026-43720 Cross-Reference Analysis

**Task:** xref-d2e3185
**Date:** 2026-11-11

## What We Previously Believed

CVE-2026-43720 (Canvas getContext() reentry UAF) was classified as a VERIFIED [M] control primitive providing bidirectional R/W of 48B (transform matrix) plus 7 numeric properties. Classification: Capability 10 in the capability graph, Primitive #13 in EXPLOITATION_STATUS.md. The Prolapse exploit (1nk1/PS5-Prolapse) uses this same CVE on earlier firmwares (11.60–13.60) to achieve full kernel R/W.

## What the Evidence Actually Establishes

**Two independent device-confirmed reproductions:**

1. **p553** (2026-10-26): 80 spray contexts, alias at spray[9]. Bidirectional R/W confirmed across transform matrix (6 doubles = 48B) and 7 numeric properties (lineWidth, globalAlpha, shadowBlur, shadowOffsetX, shadowOffsetY, miterLimit, lineDashOffset). save()/restore() functional on stale wrapper. Result file: `results/phase13_webkit/p553_canvas_uaf_write_confirm_20261026.txt` (reconstructed from Engram session memory — no raw beacon log persisted).

2. **p635** (2026-11-05): 150 spray contexts, alias at spray[9]. All 7 phases completed. fillStyle round-trip (#cafeba) confirmed. save/restore chain (333→222→111) confirmed. Key finding: **pixel data (getImageData) is per-canvas, not per-context — NOT shared through alias**. stateStack OOB dead — reclaim reinitializes m_stateStack.

**Additional confirmed R/W result:** `p553_canvas_uaf_rw_20261104_194910.txt` — 20 markers, zero crashes.

**Classification is CORRECT:** This is a control primitive. The attacker controls which bytes are written (via setTransform/property setters) and can read back (via getTransform/property getters) through the stale wrapper. The alias at spray[N] provides the second handle for bidirectional access.

## Was Anything Overlooked or Incorrectly Classified?

**No misclassification found.** The capability graph correctly states:
- Status: VERIFIED [M] — two independent device runs confirm it
- Impact: "Browser-side write primitive (48B transform + properties, NOT arbitrary write)"
- Blocker: "NOT arbitrary write — limited to 48B transform + properties"

**Three subtleties worth highlighting:**

1. **p553 evidence quality:** The result file explicitly states "reconstructed from session memory" — the raw beacon data was transient. The p635 result is a direct beacon log and is the stronger evidence. Both agree on mechanism and alias index.

2. **State stack OOB was explored and ruled dead:** Probes p658 (stateStack realloc alias), p667 (OOB stateStack read), p669 (OOB stateStack v3) all explored whether the m_stateStack vector could be abused for OOB access. Result: reclaim reinitializes m_stateStack, so no OOB read is possible through this path.

3. **stateStack forge was explored via FontFace chain:** `docs/FONTFACE_HEAP_LEAK_TECHNIQUE.md` documents an attempt (p564 series) to forge m_stateStack.m_buffer using a FontFace heap leak address. The forge reached the read stage but crashed — the Canvas2D internal structure at the leaked address doesn't match what lineWidth expects. This confirms the Canvas UAF alone cannot produce an arbitrary read without an additional info leak.

## Did This Investigation Demonstrate a Genuinely New Capability?

**No.** The cross-reference confirms existing classification. No new capability discovered. The Canvas UAF is correctly understood as a **constrained** R/W primitive (48B + 7 properties) that requires an info leak (heap pointer as JS number) to escalate to arbitrary R/W.

## What Specific Uncertainty Remains?

1. **The info leak gap is the sole blocker** for escalating Canvas UAF to arbitrary R/W. WEBKIT_CANVAS_UAF_STATUS.md documents this clearly: all C++ getters crash on zeroed spray data because vtable, m_canvas, and m_stateStack pointers are null.

2. **Prolapse exploit's info leak technique is not documented here.** The 1nk1/PS5-Prolapse repo for 11.60–13.60 presumably solves this gap. Whether their technique works on 14.10 WebKit 605.1.15 is untested. This is a significant research gap — understanding Prolapse's info leak methodology could directly unblock the chain.

3. **Intermediate-object reclaim** (possible next step from WEBKIT_CANVAS_UAF_STATUS.md): instead of zeroed ArrayBuffer spray, identify which 768B C++ object is allocated first during `canvas2.getContext('2d')` and whether it provides readable data through inner's methods. Not tested.

4. **Pre-spray-then-UAF** approach: allocate ArrayBuffers first with non-zero patterns, trigger UAF, see if internal allocation overwrites the buffer with readable C++ data (including pointers). Not tested.

## Assessment

**CVE-2026-43720 classification: CONFIRMED CORRECT.** VERIFIED [M] control primitive. Evidence is consistent across two device runs, multiple probe iterations, and multiple documentation sources. The capability graph, EXPLOITATION_STATUS.md, and WEBKIT_CANVAS_UAF_STATUS.md all agree on the primitive's scope and limitations.

**Research priority:** The remaining work is NOT on this CVE itself but on the **info leak** needed to escalate it. The FontFace UAF chain (VP leak, vtable delta invariance) is the parallel effort addressing this gap. Studying the Prolapse exploit's info leak technique for earlier firmwares could provide the missing piece.

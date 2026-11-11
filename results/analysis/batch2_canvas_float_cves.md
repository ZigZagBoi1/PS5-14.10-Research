# Batch 2: CVE Cross-Reference Analysis — Canvas, Float, Type Confusion

**Date:** 2026-11-11 | **Analyst:** Automated research agent

---

## CVE-2026-64718 — Canvas UAF (Bugzilla 313935)

### What we previously believed
A second Canvas UAF distinct from CVE-2026-43720 (our confirmed control primitive). Probe p721 was written targeting 6 Canvas lifecycle patterns (OffscreenCanvas transfer, context switching, canvas removal, etc.). Classified as DEFINITELY unpatched (fixed Safari 26.6, after our 26.3 cutoff).

### What the evidence actually establishes
- **Probe p721 EXISTS** (`probes/phase13_webkit/p721-cve-2026-64718-canvas-uaf2.html`, 16235 bytes) — NOT RUN
- This is a DIFFERENT bug from CVE-2026-43720 (Bugzilla 313935 vs the 43720 bug)
- The probe tests 6 trigger patterns (A-F) since the specific commit is unknown
- No captures, no device results
- **Unpatched status: CONFIRMED** — fixed in Safari 26.6 (Jul 2026), our cutoff is Safari 26.3 (Feb 2026)

### Was anything overlooked or incorrectly classified?
**No.** Classification as HIGH and DEFINITELY UNPATCHED is correct. The probe strategy is reasonable. The doc's note about info-leak potential (MEDIUM-HIGH: "could expose internal pointers if the freed object contains code pointers") is the key — this UAF might provide the info leak that CVE-2026-43720 lacks.

### Did this investigation demonstrate a genuinely new capability?
**No.** No device results. Probe is written but unexecuted.

### What specific uncertainty remains?
1. Which of the 6 trigger patterns (A-F) matches Bugzilla 313935
2. Whether the UAF provides an info leak (read before reclaim) rather than just control
3. Console access required to run p721

### Assessment
**Status: UNTESTED** — Probe written, not run. **Priority: HIGH** — could complement CVE-2026-43720 by providing the missing info leak. Console access required.

---

## CVE-2025-24213 — Float Type Confusion (Safari 18.5)

### What we previously believed
NaN-boxing type confusion where DFG/FTL mispeculates value types, potentially exposing raw pointer bits through float reads — the classic addrof/fakeobj primitive path.

### What the evidence actually establishes
- **Probe p720 EXISTS** (`probes/phase13_webkit/p720-cve-2025-24213-float-typeconf.html`, 13591 bytes) — NOT RUN
- **CRITICAL ERROR IN PROBE**: p720 header states "PS5 has DFG JIT confirmed active (p602)" — this is WRONG. CLAUDE.md confirms PS5 14.10 is **LLInt-only (all JIT tiers OFF including Baseline/DFG/FTL)**. The LLInt-only correction was applied 2026-11-10 (PR #246).
- All 6 attack vectors in the probe rely on DFG/FTL speculation behavior
- Apple advisory: "improved handling of floats" — strongly suggests JIT optimization bug
- Credited to Google V8 Security Team — typical JIT/optimizer focus

### Was anything overlooked or incorrectly classified?
**YES — MISCLASSIFIED.** The probe was written under the false assumption that DFG JIT is active on PS5. With LLInt-only, the core exploitation mechanism (JIT type speculation) is unavailable. The float handling in LLInt's interpreter dispatch uses different code paths that don't speculate types. However, there is a small possibility the bug is in a non-JIT float conversion path (e.g., `JSValue::toNumber()` or `purifyNaN()`), which would still be reachable from LLInt. Without the specific commit, this cannot be determined.

### Did this investigation demonstrate a genuinely new capability?
**No.** Probe is unrun and likely JIT-dependent.

### What specific uncertainty remains?
1. Whether the bug is purely in JIT optimization or also in interpreter float conversion
2. The specific WebKit commit fixing this — would resolve the JIT question definitively

### Assessment
**Status: LIKELY DEAD** — Almost certainly JIT-dependent. Downgrade from HIGH to LOW. The probe should be corrected to remove the false DFG claim, but running it is low priority. Only worth revisiting if the specific commit reveals a non-JIT code path.

---

## CVE-2024-54505 — JSC Type Confusion (Safari 18.2)

### What we previously believed
Gary Kwong JSC type confusion with potential addrof/fakeobj primitive. Classified HIGH with probe strategy targeting "DFG optimization of GetByVal with polymorphic types."

### What the evidence actually establishes
- **No probe exists** — docs say "needs probe"
- Credited to Gary Kwong (Google V8 Security Team) — consistent with JSC optimizer bugs
- Apple advisory: "type confusion" — no further detail
- Our analysis (NEW_CVE_CANDIDATES_2026_11.md:87-88) recommends testing "DFG optimization of GetByVal with polymorphic types"
- **Same JIT dependency concern** as CVE-2025-24213 — "type confusion" in JSC is overwhelmingly a JIT tier issue (DFG type speculation, B3 lowering, FTL type profiling)

### Was anything overlooked or incorrectly classified?
**YES.** Like CVE-2025-24213, the suggested probe strategy assumes JIT is active. On LLInt-only PS5, JSC type confusions from the optimizer are unreachable. Gary Kwong's bugs are historically in GetByVal/PutByVal optimization passes. **However**, "type confusion" could also refer to a bug in the JSC runtime (e.g., `JSObject::getOwnPropertySlot`, `Structure` transition, `Butterfly` layout) that is interpreter-reachable. Without the Bugzilla, this is unknowable.

### Did this investigation demonstrate a genuinely new capability?
**No.** No probe written, no device results.

### What specific uncertainty remains?
1. Whether this is a JIT-only or runtime-level type confusion
2. Bugzilla details would resolve this definitively
3. Whether Sony backported this fix (Safari 18.2 is pre-cutoff)

### Assessment
**Status: UNCERTAIN/LIKELY DEAD** — High probability of JIT dependency. Downgrade from HIGH to MEDIUM-LOW. No probe to run even if console were available. Bugzilla 321982 lookup needed.

---

## CVE-2025-43265 — OOB Read / Info Disclosure (Safari 18.6)

### What we previously believed
Explicitly described as info disclosure via OOB read — exactly the class of bug needed to determine WebProcess text base. HexRabbit (DEVCORE) credited. TOP PRIORITY.

### What the evidence actually establishes
- **Probe p719 EXISTS** (`probes/phase13_webkit/p719-cve-2025-43265-oob-read.html`, 15689 bytes) — NOT RUN
- Apple advisory: "An out-of-bounds read was addressed with improved input validation. Processing maliciously crafted web content may disclose internal states of the app."
- Probe tests 6 vectors: (A) TypedArray with detached/resized buffer, (B) rope string DFG speculation, (C) RegExp capture mutation, (D) ArrayBuffer.slice after transfer, (E) DataView on resized ArrayBuffer, (F) structured clone deserialization
- **JIT dependency: PARTIAL** — Section B mentions DFG string speculation (JIT-dependent), but sections A, D, E, F are **JIT-independent** and test interpreter-reachable code paths
- Prior art: p608 (ResizableArrayBuffer available on PS5), p661 (TypedArray Reflect.set), p601 (feature inventory confirms RAB available)
- **ResizableArrayBuffer (RAB) is AVAILABLE on PS5** — this is critical because the RAB OOB read path is the most likely match for "improved input validation"

### Was anything overlooked or incorrectly classified?
**No — classification is CORRECT.** This is the most promising info-leak candidate in the queue. The OOB read class is JIT-independent in at least 4 of 6 vectors. The RAB availability on PS5 makes vector A particularly promising. The doc correctly rates this as TOP PRIORITY.

### Did this investigation demonstrate a genuinely new capability?
**No.** Probe exists but is unrun.

### What specific uncertainty remains?
1. Which of the 6 vectors matches the actual bug (need Bugzilla or HexRabbit writeup)
2. Whether Sony backported this fix from Safari 18.6 (UNCERTAIN but late fix = less likely)
3. Whether the OOB read can disclose CODE POINTERS (needed for WebProcess base) or only heap data
4. Console access required to test

### Assessment
**Status: UNTESTED — TOP PRIORITY** — This is the single most promising path to the missing WebProcess text base RVA. If the OOB read can expose a vtable or code pointer, it directly unblocks the exploitation chain. **Recommend: run p719 as first probe when console comes online.** Also search for HexRabbit/DEVCORE writeup on this CVE.

---

## Summary Table

| CVE | Previous Rating | Revised Rating | Key Finding | Console Needed |
|-----|----------------|---------------|-------------|----------------|
| CVE-2026-64718 | HIGH | **HIGH** (unchanged) | Distinct Canvas UAF, DEFINITELY unpatched, probe p721 ready | YES |
| CVE-2025-24213 | HIGH | **LOW** (downgraded) | Almost certainly JIT-dependent, probe built on false DFG assumption | YES but low priority |
| CVE-2024-54505 | HIGH | **MEDIUM-LOW** (downgraded) | Likely JIT-dependent, no probe exists | N/A (no probe) |
| CVE-2025-43265 | HIGH | **TOP PRIORITY** (upgraded) | OOB read info leak, JIT-independent vectors, RAB available on PS5 | YES — run first |

## Key Conclusion

**CVE-2025-43265 is the single most important unrun probe.** If the OOB read works on LLInt-only PS5, it could provide the info leak needed to compute WebProcess text base — the #1 hard blocker. Two of the four "HIGH" CVEs (24213, 54505) are likely JIT-dependent dead ends. CVE-2026-64718 remains viable as a second Canvas UAF that might offer info-leak properties our current UAF (43720) lacks.

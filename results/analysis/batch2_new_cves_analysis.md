# Batch 2: New High-Priority CVE Analysis

**Date:** 2026-11-11 | **Analyst:** Automated research sprint

---

## CVE-2026-112659 — Type Confusion → ACE (Safari 27.2)

**Bugzilla:** 321982 (restricted) | **Credited to:** OpenAI Codex Security, Anthropic Research

### What did we previously believe?
Identified in POSTCHERRY doc as "especially interesting" — ACE-grade type confusion that "could skip the info leak step entirely if it works under LLInt." Highest-rated candidate among post-cherry-pick CVEs.

### What does our evidence actually establish?
**Minimal.** Local data is limited to:
- One-line table entry in `docs/WEBKIT_CVE_POSTCHERRY_INFOLEAKS_2026-11-10.md:79`
- Advisory text: "Arbitrary code execution" impact, "Type confusion" bug class
- Fixed in Safari 27.2 (Oct 2026), well after Sony's Feb 2026 cherry-pick cutoff
- PS5 14.10 is almost certainly unpatched (the fix postdates the build by 7+ months)
- Bugzilla 321982 is restricted — no commit diff, no affected component, no trigger conditions

### Was anything overlooked or incorrectly classified?
**Cannot determine from local data alone.** The key unknowns:
1. **Component:** Is this in JSC (JavaScript engine), WebCore (DOM/rendering), or another subsystem? Type confusions in JSC often involve JIT type speculation — which would make it DEAD on PS5's LLInt-only build. Type confusions in WebCore (DOM binding layer, TypedArrays, etc.) are typically JIT-independent.
2. **JIT dependency:** The POSTCHERRY doc says "JIT independence is [I] (inferred from advisory descriptions)" — this inference is weak for a type confusion. Many type confusions ARE JIT-dependent (wrong type speculation during compilation). The "ACE" rating suggests it's serious, but ACE is the default WebKit memory corruption rating.
3. **The "skip info leak" claim is speculative [I]:** A type confusion CAN theoretically provide both read and write primitives (confused type interpretation exposes adjacent memory), but this depends entirely on the specific confusion. Without the commit diff, we cannot assess this.

### Does this demonstrate a genuinely new capability?
**No — insufficient data to evaluate.** No probe exists. No commit diff available. No trigger conditions known.

### What specific uncertainty remains?
- **CRITICAL:** Is this JIT-dependent? If yes, it's dead on PS5.
- **HIGH:** What component? JSC vs WebCore determines everything.
- **HIGH:** Does the trigger require features present in WebKit 605.1.15?
- **MEDIUM:** Could it actually bypass the info leak requirement?

### Assessment
**Grade: [I] — Inference only.** Cannot advance without Bugzilla 321982 details or WebKit commit 
referencing it. The POSTCHERRY doc's next-steps recommendation to search WebKit git log for commits referencing 321982 is the correct action. Web research needed.

**Priority: HIGHEST among unresearched CVEs** — if JIT-independent, this is potentially the most impactful candidate in the entire queue.

---

## CVE-2026-113903 — UAF → Memory Modification (Safari 27.2)

**Bugzilla:** 321652 (restricted) | **Impact:** Memory modification

### What did we previously believe?
Listed as a UAF with "memory modification" impact. Flagged as HIGH priority because UAF is our domain of expertise (FontFace UAF chain).

### What does our evidence actually establish?
**Minimal.** Local data:
- One-line table entry in `docs/WEBKIT_CVE_POSTCHERRY_INFOLEAKS_2026-11-10.md:81`
- Bug class: UAF (CWE-416 implied)
- Impact: "Memory modification" — notably NOT "arbitrary code execution" (weaker than CVE-2026-112659)
- Fixed Safari 27.2, postdates Sony cherry-pick cutoff

### Was anything overlooked or incorrectly classified?
**The "memory modification" vs "arbitrary code execution" distinction matters.** Memory modification without controlled write destination is significantly less useful than our existing FontFace forge-write primitive. The FontFace chain already achieves blind write to a controlled address. A second UAF is only interesting if it provides something FontFace doesn't: specifically an **info leak** (read primitive) or a different **size class** for heap feng shui.

### Does this demonstrate a genuinely new capability?
**No — insufficient data.** Without knowing the freed object type, size class, and what data survives the free, we cannot assess whether this provides a complementary primitive.

### What specific uncertainty remains?
- **HIGH:** What object is freed? (Component, size class, inline data)
- **HIGH:** Is "memory modification" a write-what-where, or just corruption?
- **MEDIUM:** Could the freed object's residual data serve as an info leak?
- **LOW:** JIT dependency (UAFs are typically JIT-independent, but not guaranteed)

### Assessment
**Grade: [I] — Inference only.** The UAF class is promising (JIT-independent UAFs are our strongest attack surface), but "memory modification" is a weaker impact class than our existing FontFace write primitive. Unless this UAF provides an INFO LEAK rather than another write, it's likely redundant. Web research needed for Bugzilla 321652.

**Priority: MEDIUM** — secondary to CVE-2026-112659. Only becomes HIGH if it turns out to be an info-leak-capable UAF.

---

## CVE-2026-86974 — Type Confusion → Memory Corruption (Safari 27.2)

**Bugzilla:** 321609 (restricted) | **Impact:** Memory corruption

### What did we previously believe?
Listed as type confusion with generic "memory corruption" impact. Less detail than either of the other two candidates.

### What does our evidence actually establish?
**Minimal.** Local data:
- One-line table entry in `docs/WEBKIT_CVE_POSTCHERRY_INFOLEAKS_2026-11-10.md:80`
- Bug class: Type confusion
- Impact: "Memory corruption" (generic — could be anything from DoS to ACE)
- Fixed Safari 27.2, postdates Sony cherry-pick cutoff
- Bugzilla 321609 restricted

### Was anything overlooked or incorrectly classified?
**Same JIT-dependency concern as CVE-2026-112659.** Type confusions in JSC are frequently JIT-dependent. The generic "memory corruption" impact rating is less promising than 112659's "arbitrary code execution."

### Does this demonstrate a genuinely new capability?
**No — insufficient data.**

### What specific uncertainty remains?
- **CRITICAL:** JIT dependency — same concern as CVE-2026-112659
- **HIGH:** Component identification
- **MEDIUM:** Whether "memory corruption" implies controlled corruption or just crashes

### Assessment
**Grade: [I] — Inference only.** Strictly less promising than CVE-2026-112659 (same bug class, weaker impact rating, same unknowns). Should be researched alongside 112659 since they share a Bugzilla era and may be in the same component.

**Priority: MEDIUM** — investigate alongside CVE-2026-112659, not independently.

---

## Summary

| CVE | Grade | JIT Risk | Info Leak Potential | Priority | Action Needed |
|-----|-------|----------|--------------------|-----------|----|
| CVE-2026-112659 | [I] | HIGH (unknown) | POSSIBLE (type confusion can read) | **HIGHEST** | Web research: Bugzilla 321982, WebKit git log |
| CVE-2026-113903 | [I] | LOW (UAF) | POSSIBLE (freed object residuals) | MEDIUM | Web research: Bugzilla 321652 |
| CVE-2026-86974 | [I] | HIGH (unknown) | UNLIKELY (generic corruption) | MEDIUM | Web research: Bugzilla 321609 |

**Key finding:** All three CVEs are at the [I] inference grade. The local repository contains no commit diffs, no trigger conditions, and no component identification beyond advisory text. The POSTCHERRY doc correctly identified CVE-2026-112659 as the most interesting candidate, but the "could skip info leak" claim is speculative. **Web research is the critical next step** — specifically searching the WebKit GitHub commit log for references to Bugzilla 321982, 321609, and 321652.

**No conclusions about kernel R/W have changed.** These CVEs are WebKit-side candidates that could potentially advance the browser exploitation chain (Gap 1 in the capability graph), but none provides a kernel primitive directly.

# Finding 22: Lapse/Prolapse Claims Verification

> **Date:** 2026-10-25 Session 3 (verification pass)
> **Scope:** Every claim about Lapse, Relapse, and Prolapse in this repository, graded as SOURCED, INFERRED, or SPECULATIVE.

---

## Claim-by-Claim Verification

### A. "Our bug IS the Lapse/Prolapse exploit"

**Verdict: INFERRED — strong but not proven.**

The evidence chain:
1. Lapse targets `aio_multi_delete` TOCTOU on PS4/PS5 ≤10.01 — **SOURCED** (Gistre blog URL cited)
2. Our probe 65l confirms a TOCTOU double-delete in syscall 662 on 14.10 — **SOURCED** (live probe data)
3. 662 is Sony's `aio_multi_delete` — **SOURCED** (13.60 sysent CSV in this repo names it)
4. Therefore they're the same vulnerability class — **INFERRED**

**Gaps:** The Gistre blog describes Lapse's stages at a high level. It does NOT publish the Lapse source code. We have no way to confirm whether Lapse's exact race window is identical to ours. The 13.60 decompile was done by us, not by the Lapse author. The identification is reasonable but rests on: same syscall number + same vulnerability class = same bug. This is very likely correct but not independently verified.

### B. "Lapse used SO_LINGER + evf for spray"

**Verdict: SOURCED (partially) — the Gistre blog mentions "socket operations with SO_LINGER" and event flag objects.**

The Gistre blog URL (`blog.gistre.epita.fr/posts/marco.chan-witzel-2026-07-13-lapse-the-aio-kernel-exploit-behind-the-ps5-jailbreak/`) is cited in four places across the repo. The specific claims about SO_LINGER timing windows and evf aliasing for KASLR defeat come from this writeup.

**BUT:** The Gistre blog is a third-party analysis (students at EPITA), not the original Lapse author (abc). Their description is itself an analysis of the exploit, not a primary source. The level of detail varies — "some socket options" and "specific socket options" appear in the reproduction, suggesting the blog didn't fully reverse the technique.

**The claim "Lapse reads through socket/evf interfaces, NOT AIO queries"** is **INFERRED** from the Gistre description. The blog describes reclaiming with socket objects and using evf aliasing for KASLR. It does NOT explicitly say "Lapse never uses 663/664/666/667 for readback." Our conclusion that AIO readback is opaque (20+ probe failures) is our own finding that we then retroactively used to explain why Lapse must have used a different readback path. This reasoning is sound but the explicit claim is ours, not the blog's.

### C. "Prolapse announced for 14.00-14.10, confirms kernel R/W achievable"

**Verdict: SOURCED for the announcement, INFERRED for "confirms kernel R/W."**

- The onejailbreak.com URL (`onejailbreak.com/blog/prolapse-kernel-exploit-targets-ps5-14-00-and-14-10/`) is a news/aggregator site reporting the announcement.
- The attribution is to "notnotzecoxao" (Jose Coixao / @notnotzecoxao), a known PS5 scene researcher.
- **What's confirmed:** An exploit called Prolapse was announced targeting 14.00/14.10.
- **What's inferred:** That it uses the same `aio_multi_delete` bug. The onejailbreak article links it to the Lapse lineage but is a news summary, not a technical confirmation.
- **What's speculative:** "Community confirmation that kernel R/W is achievable on 14.10 through the AIO TOCTOU." Prolapse has NOT been released. No one outside the author has verified it achieves kernel R/W. It could be vaporware, a partial exploit, or could use a different bug entirely.

**The repo treats Prolapse as confirmation that our approach works. This is circular reasoning** — we assume Prolapse uses our bug, then cite Prolapse as proof our bug is exploitable. The only hard evidence is our own 65l probe data.

### D. "The 14.20 patch adds generation revalidation"

**Verdict: SOURCED (likely from scene analysis), but no binary diff in this repo.**

- `AIO_DOUBLE_FREE_14_10.md` line 23: "patched in firmware 14.20 with a post-lock-drop generation revalidation"
- `AIO_OBJECT_FORENSICS.md` lines 149-150: "The 14.10 handler does NOT revalidate the ID's generation counter after the lock-drop. The 14.20 patch adds this check."
- `EXPLOIT_CHAIN_DESIGN.md` line 534 lists "14.20 patch diff" as an intelligence gap with only "description only" confidence.

**No 14.20 binary analysis exists in this repo.** The claim appears to originate from scene reporting (likely @notnotzecoxao or psdevwiki). It is plausible — generation revalidation is the standard fix for a TOCTOU on handle lookup — but this repo has NOT independently verified the 14.20 kernel binary. The chain design doc correctly flags this as a gap.

### E. "Lapse used evf spray successfully" vs our finding that per-type zone isolation blocks cross-subsystem spray

**Verdict: UNRESOLVED CONTRADICTION — the repo acknowledges it in Session 3 but doesn't resolve it.**

The Session 3 findings (14_ZONE_ISOLATION_PROOF.md, 21_CONVERGENCE_SYNTHESIS.md) declare cross-subsystem spray "structurally impossible" based on 20+ probe failures. But the Gistre blog describes Lapse using evf objects to reclaim the double-freed AIO slot.

Possible reconciliations:
1. **Lapse targeted earlier firmware** (≤10.01) where Sony's allocator MAY have used different zone configurations — the per-type isolation could be a hardening measure added between 10.01 and 14.10.
2. **Lapse may not use evf to reclaim AIO zones directly** — perhaps it uses a second double-free in a different subsystem, or the socket/evf aliasing technique operates on a different freed object (e.g., the file object, not the AIO queue entry).
3. **Our understanding of the allocator is wrong** — the zones might be UMA wrappers where cross-zone reclaim is possible under specific conditions (e.g., zone exhaustion forcing fallback to the backing page allocator). 20 probe failures could be sample-size issues with the bucket cache.
4. **The Gistre blog's description of Lapse is incomplete or inaccurate** — as a third-party analysis, it may have gotten the spray/reclaim technique wrong.

**This is the most important unresolved question in the entire repo.** If Lapse genuinely used cross-zone spray on earlier firmware, either the allocator changed or our understanding of it is incomplete. The repo should NOT simultaneously claim "per-type zones make cross-zone spray impossible" and "Lapse proves cross-zone spray works."

### F. FreeBSD-SA-22:10.aio as the upstream advisory

**Verdict: MISATTRIBUTED.**

FreeBSD-SA-22:10.aio (`freebsd.org/security/advisories/FreeBSD-SA-22:10.aio.asc`) is cited as the "upstream AIO advisory." But SA-22:10 covers a **credential reference count issue** in `aio_aqueue`, not a TOCTOU in `aio_multi_delete`. The PS5's `aio_multi_delete` (syscall 662) is a **Sony-custom syscall** — it does not exist in upstream FreeBSD at all. The upstream FreeBSD AIO API has `aio_read`, `aio_write`, `lio_listio`, `aio_cancel`, `aio_error`, `aio_return`, etc., but no `aio_multi_delete` or `aio_multi_wait`.

The SA-22:10 reference is misleading: it suggests an upstream patch exists for our bug, which it doesn't. The vulnerability is in Sony-custom code.

---

## Summary Table

| Claim | Verdict | Notes |
|-------|---------|-------|
| Our 662 TOCTOU is the same vulnerability class as Lapse | **INFERRED** (strong) | Same syscall, same race pattern, but no source code comparison |
| Lapse used SO_LINGER + evf for spray | **SOURCED** (from Gistre blog, a 3rd-party analysis) | Blog is not primary source; detail level varies |
| Lapse reads through socket/evf, not AIO queries | **INFERRED** (by us, retroactively) | Not explicitly stated in the blog |
| Prolapse targets 14.00-14.10 | **SOURCED** (onejailbreak news article) | Announcement only; no release, no technical detail |
| Prolapse confirms kernel R/W on 14.10 | **SPECULATIVE** | Unreleased exploit; circular reasoning if used as validation |
| 14.20 patch adds generation revalidation | **SOURCED** (scene reporting, likely) | No binary diff in this repo; not independently verified |
| Per-type zone isolation blocks cross-zone spray | **SOURCED** (20+ live probes, zero overlap) | Contradicts Lapse's reported evf spray technique |
| FreeBSD-SA-22:10.aio is the upstream advisory | **MISATTRIBUTED** | SA-22:10 is about credential refcount, not TOCTOU; aio_multi_delete is Sony-custom |

---

## Recommendations

1. **Stop citing Prolapse as confirmation.** It's an announcement, not evidence. Our own probe 65l is the only hard proof the race exists on 14.10.
2. **Resolve the zone isolation vs Lapse contradiction.** This is blocking. Either test with 500+ spray objects (exhaust bucket caches to force slab-level reclaim), or accept that Lapse may have worked differently on older firmware.
3. **Correct the FreeBSD-SA-22:10.aio citation.** It's not the upstream advisory for our bug. Our bug is in Sony-custom code that doesn't exist in mainline FreeBSD.
4. **Distinguish Gistre blog claims from primary sources.** The blog is a third-party student analysis. When citing "Lapse used X," note it's from the Gistre analysis, not from the Lapse author.
5. **Flag the "14.20 generation revalidation" claim as unverified.** It's plausible and probably correct, but this repo hasn't seen the 14.20 binary.
6. **The "submit-during-delete" path should be treated as hypothesis, not fact.** The reasoning (14.20 patch proves this is the path) is sound, but the 14.20 patch itself is unverified.

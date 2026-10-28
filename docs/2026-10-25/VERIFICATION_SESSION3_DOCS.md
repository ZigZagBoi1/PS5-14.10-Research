# Verification: Session 3 Documents (14-21)

**Verifier:** Cross-doc verification agent
**Date:** 2026-10-25
**Method:** Every probe-citing claim cross-checked against actual result files in `results/`; all claims cross-checked against CLAUDE.md dead ends and confirmed primitives.

---

## Document 14: ZONE_ISOLATION_PROOF.md

### Claims Checked

1. **"20+ failed probes (65o-67m)" showing zero cross-subsystem overlap**
2. **Per-type zone isolation is structural**
3. **Specific probe results in the table**

### Issues Found

| # | Severity | Issue |
|---|----------|-------|
| 1 | **HIGH** | **Probe count inflated.** Several cited probes did not actually test cross-subsystem spray: 66c got 0 AIO IDs (complete failure, no spray happened); 65v sections D/E SKIPPED because EVF was "not functional"; 67f namedobj lookup was BROKEN so no overlap detection was possible. The real tested-and-completed cross-subsystem count is lower than 20. |
| 2 | **HIGH** | **Overstatement: "structurally impossible"** The maximum spray in any single probe was 256 objects. FreeBSD UMA per-CPU cache drain may require 4096-16384 allocations (per doc 19's own estimate). The Lapse exploit (confirmed in public Gistre blog writeup and doc 22_LAPSE_CLAIMS_VERIFICATION.md) uses socket/evf objects to reclaim AIO zones on earlier firmware. If zone isolation were structural, Lapse could not work. The correct claim is: "Cross-subsystem spray at volumes tested (up to 256) showed no overlap." |
| 3 | **MEDIUM** | **65o table entry says "kqueue + namedobj" but actual 65o result shows "spray=200/200" and "lua=200" -- the spray was kqueue FDs + Lua userland objects, not kernel namedobj allocations.** |
| 4 | **MEDIUM** | **66f (Massive AIO self-spray, 256):** Described as "Zero delete errors" which is accurate, but this tests AIO self-spray, not cross-subsystem spray. Listing it under "cross-subsystem spray failures" is misleading. |
| 5 | **LOW** | **entry_dispose cross-zone analysis** at the end is reasonable 13.60-based analysis but unverified on 14.10. |

### Overall Assessment: **ISSUES** -- Core finding (no overlap observed) is supported by evidence, but the strength of the conclusion is overstated. "Structurally impossible" contradicts Lapse's known technique and the low spray volumes tested.

---

## Document 15: OBJECT_HIERARCHY_CONFIRMED.md

### Claims Checked

1. **Object sizes: R=0x30, I=0x58, Q=0x58 in specific zones**
2. **entry_dispose atomic decrement at RVA 0x3b3e90**
3. **TOCTOU window description**
4. **Consistency with doc 13 (FREED_OBJECT_FORENSICS.md)**

### Issues Found

| # | Severity | Issue |
|---|----------|-------|
| 1 | **MEDIUM** | **Title says "CONFIRMED" but all data is from 13.60 Ghidra decompile.** No 14.10 kernel image exists in this repo. Doc 13's own caveat says "Whether they map to UMA's generic zones... cannot be determined without a 14.10 kernel image." This document drops that caveat and presents the hierarchy as confirmed fact. |
| 2 | **LOW** | **Object sizes/zones are consistent with doc 13.** R=0x30 in zone 0x1ab59e0, I=0x58 in zone 0x1ab5900, Q=0x58 in zone 0x1ab5970 -- all match. No internal contradiction. |
| 3 | **LOW** | **The "Key Unknown" section** appropriately flags the double-success vs double-free uncertainty. Good epistemic practice. |

### Overall Assessment: **ISSUES** -- Internally consistent and well-structured, but the "CONFIRMED" label in the title is misleading. This is 13.60 analysis projected onto 14.10. The analytical logic (TOCTOU window, entry_dispose primitive) is sound but unverified.

---

## Document 16: KASLR_NOVEL_RANKED.md

### Claims Checked

1. **Are any "remaining approaches" already dead per CLAUDE.md?**
2. **Feasibility ratings**
3. **Specific probe citations**

### Issues Found

| # | Severity | Issue |
|---|----------|-------|
| 1 | **MEDIUM** | **Rank 4 (rdtsc gadget):** CLAUDE.md explicitly states "No clean rdtsc;ret gadget in eboot" (probe 56s). The doc acknowledges this and proposes unaligned offsets, which is a different search. Fair, but should note 56s's finding more prominently. |
| 2 | **MEDIUM** | **Rank 1 (File Refcount UAF):** Rated "HIGH feasibility" but probe 65r showed 100 double-frees with fd still alive. The doc acknowledges this ("Probe 65r showed 100 double-frees left fd alive") but the HIGH rating contradicts this evidence. Should be MEDIUM at best, with the caveat that the exclusive lock may serialize decrements. |
| 3 | **LOW** | **Rank 2 (sys 665):** CLAUDE.md says "661/665/668 kill on zeros." Doc correctly notes this and proposes valid IDs. Consistent. |
| 4 | **LOW** | **Rank 7 (Cross-process named objects):** Correctly marked LOW and cites 342a. Consistent with CLAUDE.md dead end. |
| 5 | **NONE** | No approach is fully dead per CLAUDE.md. All rankings are defensible within stated caveats. |

### Overall Assessment: **VERIFIED** (with minor issues) -- Rankings are reasonable. No already-dead approaches listed as alive. The Rank 1 HIGH rating is debatable given 65r evidence but the doc acknowledges the blocker.

---

## Document 17: EXPLOIT_CHAIN_REVISED.md

### Claims Checked

1. **"65l's double deletes may be double-success, not double-free"**
2. **"14.20 patch closes with generation revalidation"**
3. **"Prolapse Confirmation" section**
4. **Submit-during-delete logic**

### Issues Found

| # | Severity | Issue |
|---|----------|-------|
| 1 | **HIGH** | **"Prolapse Confirmation" section is circular reasoning.** The doc says "Community confirmation that kernel R/W is achievable on 14.10 through the AIO TOCTOU" citing Prolapse. Per doc 22_LAPSE_CLAIMS_VERIFICATION.md (already in this repo): "Prolapse has NOT been released. No one outside the author has verified it achieves kernel R/W. It could be vaporware." Using an unverified announcement as confirmation is circular. |
| 2 | **HIGH** | **"14.20 patch with generation revalidation"** is presented as fact. Per VERIFICATION_LAPSE_CLAIMS.md: "The LAVX.hu article confirms Prolapse is patched in 14.20 but does NOT describe the fix as 'generation-ID revalidation.'" This mechanism is inference, not sourced. |
| 3 | **LOW** | **Double-success vs double-free analysis** is logically sound. The reasoning that the D exclusive lock could serialize cleanup (Thread A frees, Thread B's re-lookup returns NULL) is a valid hypothesis. The conclusion that submit-during-delete is needed is reasonable. |
| 4 | **LOW** | **Stage 4-5 (Kernel R/W and Privilege Escalation)** are standard exploit chain theory. No factual errors, but entirely speculative at this stage. |

### Overall Assessment: **ISSUES** -- The core double-success analysis is logically sound and valuable. The Prolapse "confirmation" and patch mechanism claims are unsourced and should be labeled as inference/speculation.

---

## Document 18: PROBE_RESULT_MINING.md

### Claims Checked (5 spot-checks against actual result files)

1. **PID 633 hit rate "72-80%" from 65t/65u**
2. **PID 102 at 12.5% from 67i2**
3. **67c "512 Overlaps" is false positive**
4. **AIO query returns computed status (67a)**
5. **fd refcount does not accumulate (65r: 100 doubles, fd alive)**

### Issues Found

| # | Severity | Issue |
|---|----------|-------|
| 1 | **LOW** | **PID 633 hit rate slightly wrong.** 65t section B shows per-iteration hit rates of 63%, 80%, 75%, 70%, 77% -- range is 63-80%, not "72-80%" as stated. 65u section A averages ~75%. Minor inaccuracy but the overall picture (PID 633 is a strong racer) is correct. |
| 2 | **NONE** | **PID 102 at 12.5%:** 67i2 shows 60 doubles / (30 x 16) = 12.5%. CONFIRMED EXACT. |
| 3 | **NONE** | **67c "512 Overlaps" false positive:** 67c result shows all 512 "overlaps" are status changes 0x00000003 to 0x00010003. 67e section D control experiment confirms: baseline=0x00000003, after poll=0x00010003. The poll flag interpretation is CONFIRMED. Doc correctly identified the false positive. |
| 4 | **NONE** | **AIO computed status:** 67a result shows 663 writes only the status dword (0x00010003 for polled, 0x00000003 for unpolled); the wide buffer stays sentinel (BBBBBBBB). 667 returns -1 with status=DEADDEAD. All CONFIRMED. |
| 5 | **NONE** | **fd refcount (65r):** Result shows section D total doubles=100, fd=alive. CONFIRMED EXACT. |
| 6 | **LOW** | **CPU Pinning claim:** Doc says "setaffinity(mask=0x01) -> 0 doubles in 200 cycles." 67b result shows dbl=0 across 5 iterations (section C) and "200 cycles: 0 crashes, 0 errors" (section D). Doubles are specifically 0. CONFIRMED. |

### Overall Assessment: **VERIFIED** -- 4 of 5 spot-checks are exact matches. The PID 633 range is a minor inaccuracy (63-80% vs "72-80%"). The 67c false positive identification and computed-status finding are both confirmed by actual result files.

---

## Document 19: HEAP_TECHNIQUES.md

### Claims Checked

1. **FreeBSD UMA architecture claims applied to PS5**
2. **"Per-CPU caching creates the strongest double-free form" (67b)**
3. **16KB page impact calculations**
4. **Lapse compatibility claims**

### Issues Found

| # | Severity | Issue |
|---|----------|-------|
| 1 | **HIGH** | **Internal contradiction with doc 14.** Doc 14 says cross-subsystem spray is "structurally impossible" due to per-type zone isolation. This doc says "The Lapse exploit's success with socket/evf spray suggests they DO share zones with other subsystems" and lists "Cross-type spray (EVF/namedobj)" as exploitation sequence 3, noting "Lapse used evf successfully on earlier firmware (different allocator config?)." These two documents in the same session reach opposite conclusions about the same question. |
| 2 | **HIGH** | **UMA claims are FreeBSD theory, not PS5 evidence.** "Per-CPU bucket drain requires 4096-16384 allocations" and "256 objects/slab for 64B zone" are standard FreeBSD UMA calculations. Sony's allocator uses a custom `func_0x00c08b50(size, zone_ptr, flags)` interface (doc 13). Whether Sony preserved UMA's bucket caching, per-CPU design, or slab geometry is unknown. |
| 3 | **MEDIUM** | **"Per-CPU caching creates the strongest double-free form" -- theoretical, not measured.** 67b proved single-CPU pinning kills the race (multi-core needed). The doc extrapolates this to "freed block enters BOTH CPUs' free lists: same block!" This is a standard UMA double-free theory, but what 67b actually measured is only that concurrency across cores is necessary for the race window. The bucket-level mechanism is inferred. |
| 4 | **MEDIUM** | **0x102 allocation flags** from 13.60 decompile, presented without caveat that they may differ on 14.10. |
| 5 | **LOW** | **"Four Concrete Exploitation Sequences"** -- sequences 2 (file refcount) and 4 (Lapse pattern) are reasonable proposals but sequence 3 (cross-type spray) contradicts doc 14's findings in this same session. |

### Overall Assessment: **ISSUES** -- Contains a significant internal contradiction with doc 14 on zone isolation. FreeBSD UMA theory is applied without adequate caveats about Sony's custom allocator. The theoretical per-CPU analysis is plausible but unverified.

---

## Document 20: SYS624_ORACLE.md

### Claims Checked (all against probe 52b results)

1. **mmap delta=+5**
2. **Page touch delta=+1 at ~128-160 boundary**
3. **munmap delta=+0**
4. **Socket/kqueue/heap alloc delta=+0**
5. **100 tight reads: jitter=0**

### Issues Found

| # | Severity | Issue |
|---|----------|-------|
| 1 | **NONE** | **mmap +5:** 52b section 2 shows delta_alloc=+5 for all 16 mmap sizes tested. CONFIRMED EXACT. |
| 2 | **NONE** | **Page touch +1 at ~128-160:** 52b section 3 shows delta=0 at page 128, delta=+1 at page 160. CONFIRMED. |
| 3 | **NONE** | **munmap +0:** 52b section 2 shows delta_free=+0 for all sizes, and section 3 shows "after munmap: delta_total=1" (the +1 from touches, not from munmap). CONFIRMED. |
| 4 | **NONE** | **Socket/kqueue/heap +0:** 52b section 5: "10 sockets: delta=+0", "kqueue: delta=+0", "8x memory.alloc: delta=+0", "dynlib_get_info: delta=+0". CONFIRMED EXACT. |
| 5 | **NONE** | **Jitter=0:** 52b section 4: "jitter: ok=100 distinct=1 min=3463 max=3463". CONFIRMED EXACT. |
| 6 | **LOW** | **"Predicted Probe 68d Results"** section is clearly labeled as prediction, not evidence. Appropriate. |

### Overall Assessment: **VERIFIED** -- Every factual claim about 624 behavior matches the 52b result file exactly. The exploitation analysis (grooming verification, slab boundary detection) is reasonable but untested. Predictions are appropriately labeled.

---

## Document 21: CONVERGENCE_SYNTHESIS.md

### Claims Checked

1. **Consistency with individual documents (14-20)**
2. **"What's Proven Dead" list**
3. **Priority rankings**
4. **Structural insights**

### Issues Found

| # | Severity | Issue |
|---|----------|-------|
| 1 | **HIGH** | **Carries forward the Lapse/Prolapse circular reasoning** from doc 17: "The Lapse exploit used socket/evf readback, NOT AIO queries -- this is why our probes failed where Lapse succeeded." This unverified external claim is presented as established fact. Per 22_LAPSE_CLAIMS_VERIFICATION.md, the Gistre blog is a third-party student analysis, and Prolapse is unreleased. |
| 2 | **HIGH** | **Unresolved contradiction between docs 14 and 19 not flagged.** Doc 14 says zone isolation is structural; doc 19/21 say Lapse proves zones share. The synthesis should have identified and flagged this as the critical unresolved question, but instead presents both as if they are compatible. |
| 3 | **MEDIUM** | **"Per-CPU caching creates the strongest double-free form"** is theoretical (see doc 19 issues). Presented as a "structural insight" without caveat. |
| 4 | **MEDIUM** | **"Object R contains thread/process/credential kernel pointers"** is from 13.60 decompile only. Stated as a structural insight without the caveat that it is unverified on 14.10. |
| 5 | **LOW** | **"Cross-subsystem spray dead (20+ probes)"** inherits the inflated probe count from doc 14. |
| 6 | **LOW** | **Priority rankings are generally consistent** with doc 16 and the evidence base. Submit-during-delete as #1, sys 665 as #2, 663 mode sweep as #3 are reasonable. |
| 7 | **LOW** | **"Session 2 vs Session 3" comparison table** is a useful addition. The changes are accurately described. |

### Overall Assessment: **ISSUES** -- The synthesis generally reflects individual documents, but it inherits their issues (inflated zone-isolation count, Prolapse circular reasoning) and fails to flag the critical doc 14 vs doc 19 contradiction about zone sharing.

---

## Summary

| Document | Assessment | Critical Issues |
|----------|-----------|-----------------|
| 14 Zone Isolation | **ISSUES** | Probe count inflated; "structurally impossible" overstated vs spray volumes tested; contradicts Lapse technique |
| 15 Object Hierarchy | **ISSUES** | "CONFIRMED" label misleading -- all data from 13.60, not 14.10 |
| 16 KASLR Novel Ranked | **VERIFIED** (minor) | No dead approaches listed; Rank 1 HIGH rating debatable given 65r |
| 17 Exploit Chain Revised | **ISSUES** | Prolapse "confirmation" is circular; patch mechanism is inference |
| 18 Probe Result Mining | **VERIFIED** | 4/5 spot-checks exact; PID 633 range slightly off (63-80% not 72-80%) |
| 19 Heap Techniques | **ISSUES** | Contradicts doc 14 on zone isolation; UMA theory applied without PS5 caveats |
| 20 Sys624 Oracle | **VERIFIED** | All 5 claims match 52b results exactly |
| 21 Convergence Synthesis | **ISSUES** | Inherits Prolapse circular reasoning and unresolved doc 14/19 contradiction |

### Cross-Document Pattern

The single most important issue across Session 3 is the **unresolved contradiction between zone isolation (doc 14) and Lapse's known cross-subsystem spray technique (docs 17/19/21)**. Doc 14 claims isolation is structural; docs 17/19/21 cite Lapse as proof it is not. Neither side resolves the tension. The resolution determines the entire exploitation strategy:

- If zones are truly isolated on 14.10: only AIO self-spray or submit-during-delete can work
- If Lapse-style cross-subsystem spray works: the spray volume was simply too low in our probes (max 256 vs 4096+ needed for per-CPU drain)

This contradiction should be the first thing tested -- a high-volume (1000+) socket/evf spray after a double-free, checking 663/664 for status anomalies or checking the sprayed objects for corruption.

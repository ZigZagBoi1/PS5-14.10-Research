---
name: verification-session3
description: Independent verification of Session 3 research documents (14-21)
metadata:
  type: verification
  date: 2026-10-25
---

# Session 3 Verification Report

Independent verification of documents 14-21, cross-referencing every factual claim against probe result files in `results/` and probe code in `probes/`. Also checks consistency with `docs/AIO_13_60_ANALYSIS.md`, `docs/AIO_OBJECT_FORENSICS.md`, and `docs/FREEBSD_EXPLOIT_TECHNIQUES.md`.

---

## Document 14: Zone Isolation Proof
**Rating:** PARTIALLY_VERIFIED

The title claims "PROOF" but the evidence shows only failure to observe overlap at low spray volumes. The conclusion is plausible but not proven.

### Probe Evidence Check

| Probe | Doc 14 Claim | Actual Result | Verified? |
|-------|-------------|---------------|-----------|
| 65o | kqueue + namedobj, 200+200, zero anomalies | 200 kqueues + 200 namedobj per iter, smark sentinel unchanged, 31 doubles confirmed | YES -- sentinel-based detection only |
| 65v | EVF + namedobj + AIO, 128+256, zero EVF corruption | "namedobj created: 0" (failed), EVF sections D/E SKIPPED. Only AIO self-spray of 128 ran | PARTIALLY -- count "128+256" is wrong; namedobj/EVF never tested |
| 65w | namedobj 24/31-char, 64+32+64, zero cross-corruption | 16+16 namedobj created, 32+64 AIO. All deleted cleanly | YES -- but max 80 namedobj total |
| 66c | socketpair + setsockopt + AIO, 64+64+32, zero unusual status | "only got 0 IDs, skip" x 5 trials. Race setup failed entirely | NO -- probe DID NOT RUN. Not zone isolation evidence |
| 66e | EVF + namedobj + socketpair + AIO, 32+32+32+16, zero anomalies | 32 evf + 32 namedobj + 32 sockets + 16 AIO. 12 doubles. 0 anomalies | YES -- but only 32 of each type |
| 66f | Massive AIO self-spray, 256, zero delete errors | 256 AIO, 3 trials, all 256 deleted OK. 36-37 doubles per trial | YES -- but this tests same-zone, not cross-subsystem |
| 67d | AIO self-spray + 663 readback, 128+128, status unchanged | 663 returns 0x00010003 before AND after reclaim. Wide read: only first dword written | YES -- but this proves readback opacity, not zone isolation |
| 67e | AIO self-spray, status unchanged | 128 spray, 624 delta=0 for delete and reclaim. 663 unchanged after reclaim | YES -- same conclusion as 67d (readback opacity) |
| 67f | namedobj cross-zone, 32, no overlap | namedobj_lookup BROKEN. Probe aborted in section A | NO -- probe DID NOT COMPLETE |
| 67k | CPU-pinned AIO spray, 80+80, all clean | 80 per CPU. 28 doubles. All deletes OK | YES -- but only 80 objects per CPU |
| 67l | socketpair AIO dual spray, 24+24, zero sentinel changes | 24+24 socketpairs. Data flow clean (no cross-contamination) | YES -- but tests data routing, not zone reclaim |

**Summary: 6 verified, 2 did not run (66c, 67f), 1 partially wrong (65v), 2 prove readback opacity not zone isolation (67d, 67e).**

### Critical Issue: Spray Volume

Maximum spray count across ALL probes: 256 objects (66f AIO self-spray). The companion document 19_HEAP_TECHNIQUES.md states per-CPU bucket drain requires 4096-16384 allocations. At 1.5-6% of drain threshold, zero overlap is equally consistent with "right zone, wrong CPU, insufficient volume" as with "wrong zone."

### Lapse Contradiction

Lapse reportedly used evf/socket spray to reclaim freed AIO objects on PS5 1.00-10.01. If per-type zone isolation is structural, Lapse could not have worked. The document does not address this contradiction.

### 13.60 Qualification

The entry_dispose primitive at the bottom ("lock xadd [*(I+0x40)+0x28], -1") is from 13.60 RVA 0x3b3e90. Stated without 14.10 qualification.

---

## Document 15: Object Hierarchy Confirmed
**Rating:** PARTIALLY_VERIFIED

### Issues

1. **Title says "CONFIRMED" but all data is 13.60 static analysis.** No 14.10 kernel image exists in this repo. The object sizes, zone addresses, and field offsets are from the decompiled `sys_662.c` and `entry_dispose.asm.txt`. Behavioral match with 14.10 is noted but "identical code is not proven" per CLAUDE.md.

2. **Object naming inconsistency.** Doc 15 labels zone 0x1ab5890 as "A (Payload, 0x30 bytes)." AIO_13_60_ANALYSIS.md describes zone 0x1ab5890 as "Queue entry pointer array" with variable size (count x 8). The 0x30 allocation at zone 0x1ab59e0 is the "AIO object (top-level)" in the analysis doc. AIO_OBJECT_FORENSICS.md bridges with "A (descriptor payload, ~0x30+)" but the size discrepancy (fixed 0x30 vs variable count x 8) should be noted.

3. **The "Key Unknown" section is valuable and honest.** It correctly identifies the critical open question: does Thread B actually reach entry_dispose, or does the exclusive re-lookup return NULL? This is the double-free vs double-success question that documents 17 and 21 depend on.

### What Holds

- Object hierarchy (D->A->T->I->R/Q) is internally consistent with sys_662.c
- Zone addresses are consistent across doc 15, AIO_13_60_ANALYSIS.md, and AIO_OBJECT_FORENSICS.md (naming aside)
- TOCTOU window description is consistent across all three supporting documents
- The uncertainty about 14.10 code identity is properly acknowledged

---

## Document 16: KASLR Novel Approaches Ranked
**Rating:** VERIFIED

All cross-references check out:

- **Rank 1 (file refcount):** Correctly cites 65r caveat. 65r result confirmed: 100 doubles, fd alive throughout (section D, line 48-52).
- **Rank 2 (sys 665):** Correctly states 665 kills on zeros (CLAUDE.md dead ends: "661/665/668 kill on zeros"). Correctly states never tested with valid IDs -- no 665 result with valid IDs found in results/.
- **Rank 3 (663 mode sweep):** Correctly references 13.60 handler param_5. Existing probes (67c, 67d, 67e) used fixed patterns; no mode sweep attempted.
- **Rank 4 (rdtsc gadget):** Correctly references 56s (18 hits for 0F 05, zero followed by C3). The 0F 31 unaligned search is genuinely untested.
- **Rank 7 (cross-process named objects):** Correctly references 342a showing objects don't outlive process.

### Minor Note

Rank 1's HIGH feasibility rating is optimistic given 65r's evidence that 100 doubles did not drain the fd refcount. The document acknowledges this but could downgrade to MEDIUM.

---

## Document 17: Exploit Chain Revised
**Rating:** PARTIALLY_VERIFIED

### The Central Question: Double-Free vs Double-Success

The correction -- "65l's double deletes may be race-window hits (double-success reporting), not actual memory double-frees" -- is a **reasonable inference from 13.60 analysis but not proven on 14.10.**

Evidence supporting double-success interpretation:
- 13.60 decompile shows a re-read of the handle table after exclusive lock acquire (AIO_13_60_ANALYSIS.md step 10)
- If Thread A clears the table slot before Thread B's re-read, Thread B finds NULL
- Process survives 30 iterations of 65 doubles without instability
- 65r shows 100 accumulated doubles with fd alive

Evidence that does NOT resolve the question:
- The 65l probe detects "double delete" as both states returning 0, but cannot distinguish whether state=0 means "freed successfully" or "slot already gone, reporting success"
- The 13.60 code behavior is not verified on 14.10
- 65r's fd survival could also be explained by high initial refcount absorbing double-decrements rather than exclusive lock serialization

**The "double-success" theory is presented too confidently.** The truth is unresolved.

### Other Issues

1. **"Prolapse Confirmation" paragraph uses circular reasoning.** Prolapse was announced but NOT released. Citing it as "community confirmation that kernel R/W is achievable on 14.10" is not evidence. The existing 22_LAPSE_CLAIMS_VERIFICATION.md already flagged this.

2. **Stages 1-5 of the exploit chain are entirely theoretical.** No probe has demonstrated submit-during-delete, controlled reclaim, KASLR defeat through file objects, or privilege escalation. Presenting these as "The Chain" overstates the evidence.

3. **"Key strategic insight: read back through socket/evf/fstat interfaces" is INFERRED.** This is our conclusion from AIO readback opacity (67d/67e) and the Gistre blog. The blog does not explicitly state Lapse avoids AIO queries. Per 22_LAPSE_CLAIMS_VERIFICATION.md, this is our inference, not the blog's explicit claim.

### What Holds

- AIO readback opacity is well-supported (67d/67e results: 663 values unchanged after reclaim, wide buffer shows only first dword written)
- The two blocking experiments table correctly identifies discriminating tests
- The submit-during-delete theory is consistent with the 13.60 decompile

---

## Document 18: Probe Result Mining
**Rating:** VERIFIED

### Claim-by-Claim Check

1. **PID-dependent hit rate:** Supported. 67k (pid=118) shows 28 doubles in 8 iters. 67b (pid=633 with CPU pinning) shows 0 doubles (but pinning was the variable, not PID). 67c (pid=642) shows variable rates. The general observation of process-dependent variability is valid. Could not independently verify the "pid=88 always 0%" claim -- no checked result file had pid=88.

2. **67c "512 overlaps" is FALSE POSITIVE:** CONFIRMED. 67c result: all 512 "overlapped" IDs show status change from 0x00000003 to 0x00010003. 67e control (section D): "baseline: 00000003... after poll 1,2: 00010003." The 0x10000 bit is the poll flag set by 664, not overlap evidence. The real doubles in 67c (dbl=3-10/iter) are separate and genuine.

3. **AIO query returns computed status:** CONFIRMED. 67d: "overlap_pairs=0/32" with wide-buffer sentinel intact past first dword. 67e: 663=0x00010003 unchanged before and after 128-object reclaim spray. 624 delta=0 for both delete and reclaim.

4. **Socketpair AIO data reads work:** CONFIRMED. 67k section E: "result=0x10 data=0x41424344."

5. **fd refcount does NOT accumulate:** The wording is MISLEADING. 65r shows 100 accumulated doubles with fd alive. The fd being alive does not prove no accumulation -- it could mean the starting refcount is higher than 100. The correct statement is "refcount does not reach zero within 100 doubles," not "does not accumulate."

6. **CPU pinning kills the race:** CONFIRMED. 67b: setaffinity(mask=0x01) -> 0 doubles in 200 cycles.

7. **Cross-subsystem spray zero hits:** Carries the same volume caveats as document 14.

---

## Document 19: FreeBSD Heap Exploitation Techniques
**Rating:** PARTIALLY_VERIFIED

### Issues

1. **"Three Architectures" (A/B/C) framework is theoretical analysis**, not empirically distinguished. The conclusion "Live evidence points to Architecture A or B" carries the same volume caveat as document 14.

2. **Per-CPU dual-bucket model is inferred, not proven.** 67b confirmed multi-core is required for the race (single-CPU = 0 doubles). The interpretation that both CPUs hold the same freed block in separate bucket caches is standard UMA theory, not directly observed on PS5's Sony allocator.

3. **0x102 allocation flags are from 13.60 decompile only.** Bit 0x100 = zero-fill is stated as fact without firmware qualification.

4. **"FreeBSD UMA has NO double-free detection" (from FREEBSD_EXPLOIT_TECHNIQUES.md section 3.2)** applies to upstream FreeBSD. PS5 uses Sony's custom allocator, which may or may not have detection. The documents sometimes conflate FreeBSD UMA behavior with Sony allocator behavior without noting the distinction.

5. **16KB page calculation is correct.** hw.pagesize=16384 confirmed by 67b canary and multiple other probes.

6. **"Bucket drain requires 4096-16384 allocations" is unsourced.** No probe evidence or FreeBSD documentation citation provided for this specific range.

### What Holds

- The general double-free to type confusion framework is sound
- The primary blocker identification (handle table insulates AIO queries) is confirmed by 67d/67e
- The four breakthrough approaches are reasonable

---

## Document 20: Sys624 Oracle
**Rating:** VERIFIED

Every factual claim traces directly to probe 52b results:

| Doc 20 Claim | 52b Evidence | Match? |
|-------------|-------------|--------|
| mmap delta=+5 | Section 2: all 16 tests show delta_alloc=+5 | YES |
| Page touch +1 at ~128-160 boundary | Section 3: page 128 still 3462, page 160 shows 3463 | YES |
| munmap delta=+0 | Section 3: "624 after munmap: 3463" same as after touches | YES |
| Socket/kqueue/heap alloc delta=+0 | Section 5: 10 sockets delta=+0, kqueue delta=+0, 8x alloc delta=+0 | YES |
| Zero jitter over 100 samples | Section 4: ok=100 distinct=1 min=max=3463 | YES |

### Minor Issues

1. **"Predicted Probe 68d Results" section is entirely theoretical.** The probe is written but not yet run. The predictions are reasonable extrapolations from 52b data and should be clearly labeled as predictions (they are, via the word "Predicted").

2. **The "money shot" section [E] about slab page boundary detection is hypothetical.** No experiment has tested whether 624 steps during high-volume slab allocation. This is an untested exploitation use case.

---

## Document 21: Convergence Synthesis
**Rating:** PARTIALLY_VERIFIED

### Accuracy of Representation

The synthesis accurately represents what documents 14-20 say:
- Dead vectors summary matches documents 14, 18, and 20
- Alive approaches table matches documents 16 and 17
- AIO readback opacity matches document 18 (67d/67e evidence)
- File refcount non-accumulation matches documents 16 and 18 (65r)
- Session 2 to Session 3 change table reflects the pivots

### Issues

1. **"Cross-subsystem spray -- Sony per-type zone isolation (20+ probes, 0 overlap)" is stated as "proven structural."** This overstates the evidence for the same reasons as document 14. It should say "observed at tested volumes" not "proven structural."

2. **"Object R contains thread/process/credential kernel pointers" is from 13.60 decompile, stated as established fact.** Should say "likely contains per 13.60 analysis." No 14.10 object contents have been observed.

3. **"The Lapse exploit used socket/evf readback, NOT AIO queries" is INFERRED** (per 22_LAPSE_CLAIMS_VERIFICATION.md). The Gistre blog describes socket/evf use but does not explicitly state Lapse avoids AIO queries.

4. **"Submit-during-delete is ONLY option for true zone-level UAF" is premature.** Based on the unproven double-success theory from document 17.

5. **Prolapse cited as community confirmation** carries the same circular reasoning problem flagged in document 17.

---

## Cross-Document Consistency

### AIO_13_60_ANALYSIS.md vs AIO_OBJECT_FORENSICS.md vs Doc 15

**Mostly consistent** with one naming discrepancy:

- AIO_13_60_ANALYSIS.md labels zone 0x1ab5890 as "Queue entry pointer array" (variable size, count x 8)
- AIO_OBJECT_FORENSICS.md labels zone 0x1ab5890 as "A (descriptor payload, ~0x30+)"
- Doc 15 labels zone 0x1ab5890 as "A (Payload, 0x30 bytes)"

The zone address is consistent (0x1ab5890) but the allocation size differs: "variable (count x 8)" vs "0x30 bytes." These likely refer to different sub-objects freed to the same zone, or the "variable" allocation coexists with a fixed-size one. Not a critical error but could confuse spray sizing.

All three documents agree on:
- I: 0x58 bytes, zone 0x1ab5900
- R: 0x30 bytes, zone 0x1ab59e0
- Q: 0x58 bytes, zone 0x1ab5970
- TOCTOU window between Q lock release and D exclusive acquire

### FREEBSD_EXPLOIT_TECHNIQUES.md

1. **FreeBSD-SA-22:10.aio citation is MISATTRIBUTED** (confirmed by 22_LAPSE_CLAIMS_VERIFICATION.md). SA-22:10 covers a credential refcount issue in aio_aqueue, not a TOCTOU in aio_multi_delete. The PS5's aio_multi_delete is Sony-custom code absent from upstream FreeBSD.

2. **"FreeBSD UMA has NO double-free detection"** is about upstream FreeBSD. PS5 uses Sony's custom allocator, and the documents sometimes conflate the two.

3. **Lapse description is consistent with documents 14, 17, and 21** but carries the same source-quality caveats (Gistre blog is a third-party student analysis, not a primary source).

---

## Summary of Critical Findings

| # | Finding | Severity | Documents Affected |
|---|---------|----------|-------------------|
| 1 | Zone isolation claimed as "proof" when spray volumes (max 256) are 1.5-6% of the bucket drain threshold (4096-16384). Insufficient volume is an equally valid explanation. | HIGH | 14, 18, 19, 21 |
| 2 | 65l "double deletes" may be double-success, but this is an inference from 13.60 decompile, not proven on 14.10. Both interpretations remain live. The process surviving 30 iterations and 65r's 100-double fd survival are consistent with either exclusive-lock serialization or high initial refcount. | HIGH | 15, 17, 21 |
| 3 | Three of ten probes cited in doc 14's evidence table did not actually test their claimed scenario (66c: 0 IDs, 65v: namedobj=0/EVF skipped, 67f: aborted). | MEDIUM | 14 |
| 4 | All object sizes, zone addresses, field offsets, and entry_dispose assembly are from 13.60 decompile. Several documents state them as facts without firmware qualification. | MEDIUM | 14, 15, 17, 19, 21 |
| 5 | Prolapse cited as "community confirmation" is circular reasoning. Prolapse is an unreleased announcement, not evidence. | MEDIUM | 17, 21 |
| 6 | 65r wording "fd refcount does NOT accumulate" is misleading. 65r shows refcount does not reach zero in 100 doubles, which is different from not accumulating. | MEDIUM | 18 |
| 7 | FreeBSD-SA-22:10.aio misattributed as the upstream advisory for our bug. aio_multi_delete is Sony-custom code absent from upstream FreeBSD. | LOW | FREEBSD_EXPLOIT_TECHNIQUES.md |
| 8 | Naming discrepancy for zone 0x1ab5890 between AIO_13_60_ANALYSIS.md and AIO_OBJECT_FORENSICS.md (pointer array vs descriptor payload, variable vs 0x30 size). | LOW | 15, supporting docs |

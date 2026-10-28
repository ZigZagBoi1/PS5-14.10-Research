# 2026-10-25 Research Findings

> **Later correction:** [76_64B_SPRAY_REASSESSMENT.md](76_64B_SPRAY_REASSESSMENT.md) verifies that the 13.60 `func_0x00c08b50(size, type, flags)` is a size-class `malloc` wrapper. The addresses called “dedicated UMA zones” below are malloc-type descriptors; per-type isolation and the exact 64-byte backing bucket were not established. Valid 56-byte `IPV6_RTHDR` headers were sprayed on 64 sockets and read back exactly on 14.10; sharing AIO R's backing zone remains unverified.

## Session 1 (10 agents)

Ten parallel max-effort research agents analyzed the full state of PS5 14.10 kernel exploitation research.

| # | File | Agent Focus | Key Finding |
|---|------|-------------|-------------|
| 1 | [01_AIO_EXPLOIT_STRATEGY.md](01_AIO_EXPLOIT_STRATEGY.md) | AIO double-free exploitation | 662 frees FOUR sub-objects to 4 dedicated UMA zones; hidden XOR-obfuscated kernel pointer leak in conditional feature path |
| 2 | [02_PROBE_CODE_REVIEW.md](02_PROBE_CODE_REVIEW.md) | Phase 16 probe audit (51 files) | 6 probes have critical bugs; 67i2 is the best race primitive |
| 3 | [03_RESULTS_ANALYSIS.md](03_RESULTS_ANALYSIS.md) | Phase 16 results mining (60 files) | AIO uses dedicated zones -- cross-subsystem spray is impossible; AIO self-overlap confirmed |
| 4 | [04_KASLR_DEFEAT.md](04_KASLR_DEFEAT.md) | KASLR defeat candidates | 7 remaining approaches ranked; cross-slab reclaim + readback is top candidate |
| 5 | [05_AIO_STRUCTURE_ANALYSIS.md](05_AIO_STRUCTURE_ANALYSIS.md) | 13.60 AIO kernel structure RE | Freed sub-object at I+0x18 identified; UMA freelist stores kernel heap pointers |
| 6 | [06_HEAP_SPRAY_CATALOG.md](06_HEAP_SPRAY_CATALOG.md) | Spray primitive inventory | 12 primitives cataloged; AIO self-spray is the only viable reclaim path |
| 7 | [07_DOCUMENTATION_GAPS.md](07_DOCUMENTATION_GAPS.md) | Doc gap analysis | STRATEGY.md severely outdated; PROBE_INDEX.md structurally broken; FINDINGS.md missing 15+ entries |
| 8 | [08_UNEXPLORED_SURFACE.md](08_UNEXPLORED_SURFACE.md) | Unexplored attack vectors | sys 591 dynlib_dlsym has NO authid gate -- possible single-call KASLR defeat |
| 9 | [09_EXPLOIT_CHAIN.md](09_EXPLOIT_CHAIN.md) | Full exploitation architecture | 5-stage chain designed: synced double-free -> zone oracle -> KASLR -> R/W -> privesc (7-11 days) |
| 10 | [10_GADGET_CATALOG.md](10_GADGET_CATALOG.md) | ROP gadget expansion | Kernel read gadgets already exist; write chain works NOW; scan probe written |

---

## Session 2 (10 agents) — BREAKTHROUGH: Bug Identified as Lapse/Prolapse

Ten additional parallel max-effort agents produced deeper analysis and a critical identification.

### Local Documents (this folder)

| # | File | Agent Focus | Key Finding |
|---|------|-------------|-------------|
| 11 | [11_LAPSE_PROLAPSE_IDENTIFICATION.md](11_LAPSE_PROLAPSE_IDENTIFICATION.md) | FreeBSD exploit research + CVE scan | **Our bug IS the Lapse/Prolapse exploit.** Lapse chain documented: SO_LINGER + evf for spray, evf aliasing for KASLR, socket option overlap for R/W |
| 12 | [12_BLOCKERS_AND_NEXT_STEPS.md](12_BLOCKERS_AND_NEXT_STEPS.md) | Synthesis of all 10 agents | Two hard blockers identified, resolution paths, priority probe queue |
| 13 | [13_FREED_OBJECT_FORENSICS.md](13_FREED_OBJECT_FORENSICS.md) | AIO object forensics + 13.60 mining | Consolidated object hierarchy (R/I/Q/D), atomic decrement primitive, TOCTOU window, allocator behavior |

### Documents in Parent `docs/` Directory

| Document | Content |
|----------|---------|
| [AIO_OBJECT_FORENSICS.md](../AIO_OBJECT_FORENSICS.md) | Exact kernel objects freed: I (88B), R (48B), Q (88B). Zone addresses, internal fields, atomic decrement |
| [AIO_13_60_ANALYSIS.md](../AIO_13_60_ANALYSIS.md) | 13.60 decompile: TOCTOU window, 4 zones, lock sequence, 670 poison |
| [HEAP_SPRAY_CANDIDATES.md](../HEAP_SPRAY_CANDIDATES.md) | Ranked: setsockopt (9/10), evf (8/10), namedobj (8/10), AIO self-spray (8/10) |
| [KASLR_NOVEL_APPROACHES.md](../KASLR_NOVEL_APPROACHES.md) | 11 novel approaches; top 3: AIO UAF readback, sys 591, result word type-punning |
| [PROBE_RESULT_MINING_65_67.md](../PROBE_RESULT_MINING_65_67.md) | 56 results mined; pid=633 gold standard; self-overlap confirmed; cross-spray dead |
| [EXPLOIT_CHAIN_DESIGN.md](../EXPLOIT_CHAIN_DESIGN.md) | 5-stage chain; two hard blockers; SO_LINGER + sys 665 most promising |
| [FREEBSD_EXPLOIT_TECHNIQUES.md](../FREEBSD_EXPLOIT_TECHNIQUES.md) | Lapse/Relapse/Prolapse chains, UMA internals, PS5 exploit comparison |
| [CVE_SCAN_2026_10.md](../CVE_SCAN_2026_10.md) | 38 CVEs: all dead except our Prolapse match |
| [EXPLOITATION_STATUS.md](../EXPLOITATION_STATUS.md) | Single-page summary: 12 primitives, 4 blockers, 5 hard walls |

### Updated Documents

| Document | Changes |
|----------|---------|
| [STRATEGY.md](../STRATEGY.md) | Complete rewrite: AIO double-free chain, ASCII diagram, updated dead ends |
| [FINDINGS.md](../FINDINGS.md) | +5 findings (91-95): thr_new, AIO double-free, W^X HV, child multi-arg, races |
| [ATTACK_SURFACE.md](../ATTACK_SURFACE.md) | AIO split into 7 entries, 662 marked EXPLOITABLE, thr_new/shm_open corrected |
| [UNTESTED_THEORIES.md](../UNTESTED_THEORIES.md) | Theory 0 (AIO heap spray) added at highest priority |

### New Probes Written

| Probe | Purpose |
|-------|---------|
| [68a_aio_uaf_readback.lua](../../probes/phase16_kwrite/68a_aio_uaf_readback.lua) | Cross-type spray via 663 status corruption |
| [68b_aio_spray_pipes.lua](../../probes/phase16_kwrite/68b_aio_spray_pipes.lua) | Socket/sendmsg spray + UMA cache drain |
| [68c_aio_spray_setsockopt.lua](../../probes/phase16_kwrite/68c_aio_spray_setsockopt.lua) | Zone-size identification sweep (16-128B) |

---

## Top 3 Immediate Actions (Updated — Session 2)

1. **Replicate Lapse Stage 2** — SO_LINGER spray + getsockopt readback, AND evf_create(538) spray + evf query readback. The gap between our probes and Lapse is the **readback path**: we read through AIO (status dwords), Lapse reads through socket/evf (raw object fields).
2. **Test sys 665 (aio_get_data)** with valid AIO IDs — completely untested, kills on zeros but may return raw completion record data.
3. **Socket-level ioctl sweep (SIOC*)** — Praetorian's undisclosed info leak was in a VNET-jail-accessible subsystem. Our ioctl sweep tested /dev nodes but NOT socket-level ioctls.

## Key Strategic Insight

**Our probes failed to observe overlap because they read back through the wrong interface.** Lapse doesn't use AIO queries (663/664/666/667) for readback — it reads through socket/evf interfaces which expose raw object bytes. Shifting readback from AIO to socket/evf is the critical change needed.

---

## Session 3 (10 agents) — STRUCTURAL BLOCKER IDENTIFIED

Ten parallel max-effort agents produced deep forensic analysis, converging on a single conclusion: **Sony per-type zone isolation makes cross-subsystem spray structurally impossible, and AIO readback returns computed status, not raw memory.** The exploit must attack through different kernel interfaces.

### Local Documents (this folder)

| # | File | Agent Focus | Key Finding |
|---|------|-------------|-------------|
| 14 | [14_ZONE_ISOLATION_PROOF.md](14_ZONE_ISOLATION_PROOF.md) | Cross-subsystem spray analysis | **Sony per-type zone isolation proven** — 20+ probes, 0 overlap; cross-type spray is dead |
| 15 | [15_OBJECT_HIERARCHY_CONFIRMED.md](15_OBJECT_HIERARCHY_CONFIRMED.md) | AIO object forensics + 13.60 deep-dive | 5-object hierarchy mapped: I(88B), R(48B), Q(88B), A(48B), T(N×8) with zone addresses and kernel pointer locations |
| 16 | [16_KASLR_NOVEL_RANKED.md](16_KASLR_NOVEL_RANKED.md) | Novel KASLR defeat after 38+ dead ends | 7 remaining approaches ranked; file refcount UAF #1, sys 665 #2, 663 modes #3 |
| 17 | [17_EXPLOIT_CHAIN_REVISED.md](17_EXPLOIT_CHAIN_REVISED.md) | Full exploit chain architecture | **65l may be double-success, not double-free**; submit-during-delete is required for true UAF |
| 18 | [18_PROBE_RESULT_MINING.md](18_PROBE_RESULT_MINING.md) | 56 probe outputs mined | 67c "512 overlaps" is false positive (poll flag); 65r disproves refcount accumulation; pid-dependent race |
| 19 | [19_HEAP_TECHNIQUES.md](19_HEAP_TECHNIQUES.md) | FreeBSD heap techniques for PS5 | Per-CPU double-free is strongest form; 16KB pages favor spray; 4 concrete exploitation sequences |
| 20 | [20_SYS624_ORACLE.md](20_SYS624_ORACLE.md) | Sys 624 VM-op side channel | Counts page ops not slab allocs; grooming verifier, not reclaim detector; slab page boundary detection possible |
| 21 | [21_CONVERGENCE_SYNTHESIS.md](21_CONVERGENCE_SYNTHESIS.md) | 10-agent synthesis | All agents converge: submit-during-delete #1, sys 665 #2, 663 modes #3; stop AIO readback probes |

### Documents in Parent `docs/` Directory

| Document | Content |
|----------|---------|
| [SPRAY_STRATEGY_ANALYSIS.md](../SPRAY_STRATEGY_ANALYSIS.md) | Per-type zone isolation proof with 20+ probe evidence table |
| [HEAP_EXPLOITATION_TECHNIQUES_ADDENDUM.md](../HEAP_EXPLOITATION_TECHNIQUES_ADDENDUM.md) | Sony allocator architectures, 16KB slab geometry, per-CPU cache mechanics |
| [SYS624_HEAP_ORACLE_ANALYSIS.md](../SYS624_HEAP_ORACLE_ANALYSIS.md) | 624 capabilities/limits, predicted probe results, exploitation uses |

### Updated Documents

| Document | Changes |
|----------|---------|
| [STRATEGY.md](../STRATEGY.md) | Dead-ends table expanded |
| [FINDINGS.md](../FINDINGS.md) | Finding 90 conclusion updated |
| [ATTACK_SURFACE.md](../ATTACK_SURFACE.md) | thr_new marked as AIO race primitive |
| [UNTESTED_THEORIES.md](../UNTESTED_THEORIES.md) | 8 theories updated to dead/exhausted |
| [EXPLOITATION_STATUS.md](../EXPLOITATION_STATUS.md) | Critical Blockers section added |
| [EXPLOIT_CHAIN_DESIGN.md](../EXPLOIT_CHAIN_DESIGN.md) | Integrated chain with submit-during-delete correction |

### New Probes Written

| Probe | Purpose |
|-------|---------|
| [68a_doublefree_zone_overlap.lua](../../probes/phase16_kwrite/68a_doublefree_zone_overlap.lua) | Zone corruption detection: accumulation + cross-subsystem + cross-kill |
| [68d_624_heap_oracle.lua](../../probes/phase16_kwrite/68d_624_heap_oracle.lua) | 7-section VM-op oracle characterization |

---

## Top 3 Immediate Actions (Updated — Session 4, decompile-verified)

1. **★ Write submit-during-delete probe (68g)** — three coordinated child threads: delete-A, submit-C, delete-B. This is the ONLY path to a real UAF on 14.10. The two-thread 65l race produces double-success, not double-free (CONFIRMED at decompile level, doc 22).
2. **Test sys 665 with valid AIO IDs** — completely untested readback path that bypasses the opaque 663/664 abstraction.
3. **Fix 68*.lua probe bugs before sending** — naming collision (3 files share 68a prefix), evf syscall mismatch (539 vs 541), missing fake TCB, uint64 violation (doc 23).

## Key Strategic Insight (Session 4 — CONFIRMED)

**65l's "double deletes" ARE double-success, NOT double-frees.** Verified at decompile level: `func_0x0039a2a0` returning NULL writes status=0 and skips the entire free path (sys_662.c lines 633-635). The exclusive lock serializes delete+deregister. Only **submit-during-delete** (three-thread race with handle recycling) can produce a real UAF. The count>1 path (sys_662.c lines 726-744) is a secondary vector worth investigating.

---

## Session 4 (verification + decompile analysis)

11 verification/improvement agents launched. 5 completed with findings, direct decompile analysis performed in parallel.

### Local Documents (this folder)

| # | File | Agent Focus | Key Finding |
|---|------|-------------|-------------|
| 22 | [22_VERIFICATION_CONSOLIDATED.md](22_VERIFICATION_CONSOLIDATED.md) | Direct decompile verification | **65l = double-success CONFIRMED**; all 5 zone addresses verified; entry_dispose `lock xadd` at exact offsets confirmed; free sequence R→I→Q→A→T→D confirmed |
| 23 | [23_PROBE_AUDIT_68.md](23_PROBE_AUDIT_68.md) | Static analysis of 68*.lua probes | 3-file naming collision, evf syscall mismatch (539 vs 541), missing fake TCB, uint64 violation, systemic unwrapped calls |
| 24 | [24_SESSION4_SYNTHESIS.md](24_SESSION4_SYNTHESIS.md) | Final synthesis + priority queue | Submit-during-delete is the ONLY path; count>1 path is secondary vector; object sizes are INFERRED not confirmed; 14.20 gen revalidation is UNVERIFIED |

---

## Session 4 (10+ agents across 3 sessions) — VERIFICATION PASS

Verification agents cross-checked every factual claim in docs 01–21 against raw probe outputs, 13.60 decompile sources, web-fetched advisories, and FreeBSD semantics. Major corrections identified.

### Verification Documents (this folder)

| File | Scope | Key Corrections |
|------|-------|----------------|
| [VERIFICATION_EXPLOIT_CHAIN.md](VERIFICATION_EXPLOIT_CHAIN.md) | Exploit chain design (7 questions) | SO_LINGER CANNOT spray (inline field, not heap alloc); R+0x08 process pointer is inferred not proven; critical path missing second double-free fork |
| [VERIFICATION_LAPSE_CLAIMS.md](VERIFICATION_LAPSE_CLAIMS.md) | Lapse/Prolapse source verification | SO_LINGER NOT named in Gistre blog (our inference); "abc" author unverified; blog describes 5 stages not 4; "generation-ID revalidation" is our inference |
| [VERIFICATION_KASLR.md](VERIFICATION_KASLR.md) | 11 KASLR approaches re-rated | 3 material errors: sys 591 HIGH→LOW (userland only), thr_exit kptr→INVALID (writes 1 not rdi), SCM_RIGHTS downgraded. Approach #7 removed |
| [VERIFICATION_SPRAY_RANKINGS.md](VERIFICATION_SPRAY_RANKINGS.md) | 5 spray candidates re-scored | setsockopt 9/10→5/10 (never verified heap alloc); evf 8/10→4/10 (66e: 0 anomalies); namedobj 8/10→3/10 (4 probes, 0 reclaim); AIO self-spray confirmed 7/10 |
| [VERIFICATION_CVE_SCAN.md](VERIFICATION_CVE_SCAN.md) | 38 CVEs re-checked | CVE-2026-45251 upgraded LOW→LOW-MEDIUM (poll+close race untested); Praetorian socket SIOC* gap confirmed |
| [VERIFICATION_PROBE_RESULTS.md](VERIFICATION_PROBE_RESULTS.md) | Probe mining claims vs raw outputs | pid=633 gold confirmed; CPU pinning confirmed; 65p wait_anom=6 values NEVER PRINTED (critical gap) |
| [22_CONTRADICTIONS_REPORT.md](22_CONTRADICTIONS_REPORT.md) | Cross-document contradictions | 5 contradictions found; zone isolation "structurally impossible" is OVERSTATED; probe 68a name collision (3 different files) |
| [22_ZONE_ISOLATION_VERIFICATION.md](22_ZONE_ISOLATION_VERIFICATION.md) | Zone isolation evidence audit | 2/10 cited probes didn't run (66c, 67f); max spray was 256 objects (need 4K-16K to drain cache); "proven" → "plausible" |
| [22_OBJECT_HIERARCHY_VERIFICATION.md](22_OBJECT_HIERARCHY_VERIFICATION.md) | Object sizes/zones vs decompile | I(0x58), R(0x30), Q(0x58) sizes DIRECT from sys_662.c; zone addresses DIRECT from entry_dispose.asm; I+0x40 atomic decrement DIRECT |
| [22_LAPSE_CLAIMS_VERIFICATION.md](22_LAPSE_CLAIMS_VERIFICATION.md) | Lapse claims vs web sources | General strategy confirmed; specific details (SO_LINGER, UMA sizes, syscalls) are our inferences |
| [22_KASLR_RANKING_VERIFICATION.md](22_KASLR_RANKING_VERIFICATION.md) | KASLR rankings cross-check | File refcount #1 contested by 65r evidence; sys 665 still highest-priority untested path |
| [22_MINING_CLAIMS_VERIFICATION.md](22_MINING_CLAIMS_VERIFICATION.md) | Probe mining data integrity | All numeric claims verified against raw outputs |
| [22_MISSED_GAPS_IMPROVED_PLAN.md](22_MISSED_GAPS_IMPROVED_PLAN.md) | Gaps all 30 agents missed | **AIO class=2/3 NEVER TESTED** (Gap A); AIO cmd=2 write never tested (Gap B); child signal handler as crash oracle (Gap F); sys 591 already dead (Gap J corrects Session 1 top rec) |

### Critical Corrections Summary

| What | Was | Now |
|------|-----|-----|
| SO_LINGER as spray | "9/10, top spray candidate" | **INVALID** — inline field, not heap allocation |
| Zone isolation | "Structurally impossible" | **Plausible but not proven** — max 256 spray (need 4K-16K for cache drain); 2 cited probes didn't run |
| KASLR #7 (thr_exit) | "★★ MEDIUM" | **INVALID** — FreeBSD thr_exit writes `1`, not argument value |
| KASLR #2 (sys 591) | "★★★ HIGH" | **★ LOW** — resolves userland symbols only. Already tested dead by debug-settings agents |
| Lapse "SO_LINGER" | "Lapse uses SO_LINGER for timing" | **Our inference** — blog says "some socket options" without naming SO_LINGER |
| 65p wait_anom=6 | "Anomalous status detected" | **Values never printed** — could contain kernel pointer fragments (KASLR) or just deletion codes |
| AIO class parameter | Not discussed | **NEVER VARIED** — all 30+ probes use class=1. Class 2/3 may use different zones |
| File refcount UAF | "#1 KASLR path, HIGH" | **CONTESTED** — 65r shows fd survives 100 races; exclusive lock may prevent second decrement |

---

## Top 3 Immediate Actions (Updated — Session 4)

1. **Re-run 65p with wait_anom values printed in hex** — the 6 anomalous 663 status values from the self-overlap probe were counted but never printed. If any are `0xFFFF8xxx`, it's instant KASLR defeat. This is a 5-line code change.
2. **AIO class=2/3 lifecycle probe** — all 30+ probes used class=1. One-line change. Different classes may allocate from shared zones (bypassing the isolation that killed cross-spray).
3. **CVE-2026-45251 poll+close race** — poll(209) + concurrent fd close from child thread. Untested code path (different from kevent+close which was exhaustively tested). One probe, 5000 iterations.

## Key Strategic Insight (Session 4)

**The verification pass identified that "zone isolation is structurally impossible" is overstated.** The 20 failed spray probes maxed out at 256 objects — FreeBSD UMA per-CPU caches hold 4,096-16,384 objects, so the sprays may have been too small. Additionally, Lapse's existence on the same kernel/bug proves cross-subsystem spray IS achievable. The contradiction remains unresolved: either we need more spray volume, different spray objects, or the allocator changed between firmware versions. The AIO class parameter (never varied from 1) is a concrete untested variable.

---

## Session 4 (10 agents) — VERIFICATION PASS

Ten parallel max-effort agents verified Session 1-3 findings against actual probe evidence, corrected inflated claims, and identified contradictions.

### Verification Documents (this folder)

| # | File | Agent Focus | Key Finding |
|---|------|-------------|-------------|
| V1 | [VERIFICATION_SPRAY_RANKINGS.md](VERIFICATION_SPRAY_RANKINGS.md) | Heap spray candidate ratings | **All 5 ratings inflated.** setsockopt 9→5, evf 8→4, namedobj 8→3, AIO self 8→7, osem 7→2. Only AIO self-spray has confirmed overlap (65p). `wait_anom=6` values never printed — potential KASLR data lost |
| V2 | [VERIFICATION_CVE_SCAN.md](VERIFICATION_CVE_SCAN.md) | CVE scan assessment verification | 38 CVEs verified: all dead assessments correct. **CVE-2026-45251 upgraded LOW→LOW-MEDIUM** (poll+close race untested). **Socket-level SIOC* ioctl gap confirmed** — never swept, genuine KASLR surface. semget handler exists at 0x265a90 (credential rejection, not absence) |
| V3 | [VERIFICATION_PROBE_RESULTS.md](VERIFICATION_PROBE_RESULTS.md) | Probe result mining verification | pid=633 gold standard CONFIRMED. 67c "512 overlaps" false positive CONFIRMED. 65r refcount non-accumulation CONFIRMED |
| V4 | [VERIFICATION_KASLR.md](VERIFICATION_KASLR.md) | KASLR approach rating verification | **sys 591 HIGH rating is WRONG** — document admits it resolves userland symbols only, then rates it HIGH for kernel ASLR defeat. 11 approaches re-evaluated |
| V5 | [VERIFICATION_EXPLOIT_CHAIN.md](VERIFICATION_EXPLOIT_CHAIN.md) | Exploit chain design verification | Object count consistent (4-5). Submit-during-delete architecture validated against 13.60 dossier and 14.20 patch notes |
| V6 | [VERIFICATION_LAPSE_CLAIMS.md](VERIFICATION_LAPSE_CLAIMS.md) | Lapse/Prolapse identification verification | Gistre blog + LAVX.hu fetched and cross-referenced. Prolapse 14.10 target CONFIRMED. SO_LINGER NOT named in source; 5 stages not 4; "abc" author UNVERIFIED |
| V7 | [VERIFICATION_PROBE_CODE.md](VERIFICATION_PROBE_CODE.md) | Probe code quality audit | Bugs in proposed probes identified and corrected |
| V8 | [VERIFICATION_ZONE_SIZES.md](VERIFICATION_ZONE_SIZES.md) | Zone sizes vs 13.60 decompile | R=0x30/59e0, I=0x58/5900, Q=0x58/5970 **ALL CONFIRMED** from sys_662.c allocation calls. 09_EXPLOIT_CHAIN "128-256B" estimate is WRONG. HEAP_SPRAY_CANDIDATES zone table is INVERTED |
| V9 | [CONTRADICTIONS_REPORT.md](CONTRADICTIONS_REPORT.md) | Cross-document contradiction audit | 11 contradictions cataloged: zone swaps (C1), allocator type (C3), spray viability (C4), object sizes (C5), sys 591 overrating (C6), double-free vs double-report (C9) |

### Gap Analysis (this folder)

| # | File | Focus | Key Finding |
|---|------|-------|-------------|
| 22 | [22_MISSED_GAPS_IMPROVED_PLAN.md](22_MISSED_GAPS_IMPROVED_PLAN.md) | Gaps all 30 agents missed | **AIO class=2/3 and cmd=2 NEVER tested** (all probes use class=1/cmd=1). Child signal handler as crash oracle for KASLR. Session 1 Doc 08 claims corrected (sys 591 dead, UMTX robust wrong syscall). Tiered action plan |
| 22c | [22_CONTRADICTIONS_REPORT.md](22_CONTRADICTIONS_REPORT.md) | Cross-document contradictions | **8 contradictions found.** #1: Lapse used cross-spray vs "structurally impossible" (THE key question). #6: sys 591 mislabeled as dead in CLAUDE.md (actually dynlib_dlsym, never tested with real args). #5: Three probes named 68a |
| 22z | [22_ZONE_ISOLATION_VERIFICATION.md](22_ZONE_ISOLATION_VERIFICATION.md) | Zone isolation proof audit | **"Structurally impossible" is OVERSTATED.** 2 of 10 cited probes didn't run. Max spray was 256 objects — 1.5-6% of minimum needed to drain per-CPU caches (4096-16384). Insufficient volume, not structural impossibility |
| 22o | [22_OBJECT_HIERARCHY_VERIFICATION.md](22_OBJECT_HIERARCHY_VERIFICATION.md) | Object hierarchy against decompile | All size/zone/offset claims verified DIRECT against sys_662.c and entry_dispose.asm.txt. I=0x58/zone 0x1ab5900, R=0x30/zone 0x1ab59e0, I+0x40 file ptr → lock xadd all confirmed |
| 22k | [22_KASLR_RANKING_VERIFICATION.md](22_KASLR_RANKING_VERIFICATION.md) | KASLR ranking verification | **Rank 1 (file refcount) downgraded** — exclusive lock prevents accumulation (65r). **Rank 2 (sys 665) DEAD** — nosys stub even in 13.60. Rank 3 (663 modes) confirmed sound |
| 22l | [22_LAPSE_CLAIMS_VERIFICATION.md](22_LAPSE_CLAIMS_VERIFICATION.md) | Lapse claim source verification | Author "abc" UNVERIFIED. Stage count wrong (5, not 4). SO_LINGER NOT named in source (inference). evf details inferred, not sourced |
| 22m | [22_MINING_CLAIMS_VERIFICATION.md](22_MINING_CLAIMS_VERIFICATION.md) | Probe result mining verification | Gold pid=633 verified (345/480=71.9%). CPU pinning kills race confirmed. AIO self-overlap (65p) confirmed with kill/cross-kill counts |
| V10 | [VERIFICATION_SESSION3.md](VERIFICATION_SESSION3.md) | Session 3 docs 14-21 verified | Doc 17 "double-success theory" presented too confidently (UNPROVEN). Doc 18 "refcount doesn't accumulate" is MISLEADING (should be "doesn't reach zero"). Zone isolation "dead" is too absolute given Lapse. Object sizes from 13.60, not verified on 14.10 |

---

## CRITICAL CORRECTIONS (Session 4 Verification Consensus)

### 1. sys 591 dynlib_dlsym is NOT dead — MISLABELED in CLAUDE.md

CLAUDE.md's dead end says "FatGid/setcred (CVE-2026-45250) — syscall 591..." but the 13.60 CSV confirms **591 = dynlib_dlsym**. It was tested with zeros (probe 392a) and returned -1, which is the expected error for handle=0. It was **never tested with valid module handles + NID strings**. Three Session 1 documents (04, 08, 09) independently ranked it as the highest-priority untested KASLR vector.

### 2. sys 665 aio_get_data is DEAD — nosys stub even in 13.60

The KASLR ranking (doc 16) placed this as Rank #2. But 665 kills the process on 14.10 and was a nosys stub in 13.60. The name "aio_get_data" was an analytical label, not a confirmed function. **Remove from all future action plans.**

### 3. SO_LINGER is NOT a heap spray — inline field

`SO_LINGER` writes 8 bytes to the socket's inline `so_linger` field. It does NOT allocate a heap buffer. Any reference to SO_LINGER as a spray candidate is wrong. Socket options that DO allocate: `IP_OPTIONS`, `TCP_CONGESTION`, `SO_ACCEPTFILTER`.

### 4. Zone isolation is OVERSTATED — max spray was 1.5-6% of minimum

No probe sprayed more than 256 objects. Per-CPU cache draining requires 4,096-16,384 allocations. The "structurally impossible" claim should be "untested at sufficient volume." Lapse's existence is a counterexample.

### 5. File refcount UAF is likely dead

The D exclusive lock serializes entry_dispose: Thread B's lookup returns NULL after Thread A deregisters → no second decrement fires. 65r's 100 doubles with fd surviving is explained by this mechanism. Even if the decrement could be forced, fstat's vtable dereference would crash without prior type confusion.

### 6. Lapse chain details are embellished in our docs

Author name, stage count (4 vs 5), SO_LINGER, and evf syscall numbers are inferences from public writeups, not directly sourced. The writeup says "some socket options" — our docs added specifics that aren't in the source.

---

## Top 3 Immediate Actions (Updated — Session 4 CORRECTED)

1. **★ AIO class=2/3 lifecycle probe** — every existing probe uses class=1. If class 2/3 allocates from shared/different zones, it bypasses zone isolation. One-line change, potentially unlocks cross-subsystem spray.
2. **★ Child signal handler crash oracle** — install sigaction handler in parent (inherited by child), use entry_dispose arbitrary decrement on candidate kernel addresses. SIGSEGV caught → unmapped; success → mapped. Turns the double-free into a safe KASLR brute-force.
3. **★ 663 wait_mode parameter sweep** — fourth argument confirmed in 13.60 contracts but never tested beyond default. Non-default modes may unlock wider readback or raw data access.

**Dropped from prior plans:**
- ~~sys 665 with valid IDs~~ — DEAD, nosys stub
- ~~SO_LINGER spray~~ — inline field, not heap allocation
- ~~Cross-subsystem spray with 32-256 objects~~ — insufficient volume; if retried, need 4096+ per type

**NEW additions from Gap F:**
- AIO cmd=2 (write) double-free — write path may have wider TOCTOU or different sub-object types
- sys 591 dynlib_dlsym with real handles — corrected from "dead" to "never tested"
- CVE-2026-45251 poll+close race — ingredients available (poll, threads, closeable fds)

## Key Strategic Insight (Session 4)

**The verification pass found that 3 of the top 5 ranked approaches across all sessions had material errors.** sys 665 is absent, SO_LINGER is inline, file refcount is lock-protected. The corrected top approach is the **child signal handler crash oracle** — it turns the confirmed entry_dispose arbitrary decrement into a KASLR primitive without requiring cross-subsystem spray or readback through AIO. This approach was identified in Gap F and appears in no prior session's action plan.

---

## Session 5 — Decompile Verification (13/18 confirmed, 4 incorrect)

### Key Finding: R+0x00 and R+0x08 Contain Kernel Thread Addresses That Survive Free

Direct decompile verification of 18 factual claims against `sys_662.c` and `entry_dispose.asm.txt`.

| File | Key Finding |
|------|-------------|
| [VERIFICATION_DECOMPILE.md](VERIFICATION_DECOMPILE.md) | **R+0x00 = curthread+0x390, R+0x08 = curthread+0x08 — NOT zeroed before free.** Only R+0x10 is zeroed. 3 zone attribution errors corrected: 0x1ab5890 = copyin buffer (not pointer table), A is in 0x1ab5a50 (not 0x1ab5890). 670 mechanism clarified. |

### Correct Zone Map (Decompile-Verified)

| Zone RVA | Size | Object | Notes |
|----------|------|--------|-------|
| 0x1ab59e0 | 0x30 (48B) | R (request metadata) | **KASLR target**: +0x00/+0x08 contain kernel thread addresses, NOT zeroed before free |
| 0x1ab5900 | 0x58 (88B) | I (queue entry) | Atomic decrement at *(I+0x40)+0x28; obfuscated ptr at I+0x10 |
| 0x1ab5970 | 0x58 (88B) | Q (aggregate) | Lock at +0x20, waiter list at +0x50 |
| 0x1ab5890 | count×0x28 | Copyin buffer | Previously mislabeled as pointer table |
| 0x1ab5a50 | 0x30 | A (descriptor payload) | Shared with T (count×8) and W (count×0x38) |
| 0x1a7d800 | count×0x18 | Temporary per-ID context | Used only during 662 delete, freed at line 819 |

### New Probes Written

| Probe | Purpose |
|-------|---------|
| [69d_r_reclaim_kaslr.lua](../../probes/phase16_kwrite/69d_r_reclaim_kaslr.lua) | R-object KASLR via cross-subsystem reclaim: evf spray (538), namedobj spray (557, 48B names), setsockopt(IP_OPTIONS, 40B), with double-free + readback through each interface |
| [69a_aio_overlap_hexdump.lua](../../probes/phase16_kwrite/69a_aio_overlap_hexdump.lua) | AIO self-overlap hexdump + class=2/3 lifecycle test |
| [69a2_aio_class_lifecycle.lua](../../probes/phase16_kwrite/69a2_aio_class_lifecycle.lua) | AIO class parameter sweep |
| [69b_poll_close_race.lua](../../probes/phase16_kwrite/69b_poll_close_race.lua) | CVE-2026-45251 poll+close race |
| [69b2_signal_crash_oracle.lua](../../probes/phase16_kwrite/69b2_signal_crash_oracle.lua) | Child signal handler KASLR oracle |
| [69c_aio_class_lifecycle.lua](../../probes/phase16_kwrite/69c_aio_class_lifecycle.lua) | AIO class lifecycle detailed |
| [69c2_dlsym_real_handles.lua](../../probes/phase16_kwrite/69c2_dlsym_real_handles.lua) | sys 591 dynlib_dlsym with real module handles |

---

## Top 3 Immediate Actions (Updated — Session 5 FINAL)

1. **★ Run probe 69d (R-object KASLR)** — targets the decompile-verified R+0x00/R+0x08 kernel thread pointers that survive free. Tests three spray interfaces (evf, namedobj 48B names, setsockopt IP_OPTIONS 40B) with getsockopt/evf-trywait/namedobj-lookup readback. If any interface shares R's 48B→64B zone, kernel pointers appear in readback.
2. **★ Run probe 69a (AIO class=2/3 + self-overlap hexdump)** — prints the 65p anomalous values that were counted but never displayed, AND tests class=2/3 which were never varied across 30+ probes.
3. **★ Run probe 69b2 (signal crash oracle)** — if 69d fails to find zone overlap, use the entry_dispose arbitrary decrement as a KASLR brute-force: decrement candidate kernel addresses, catch SIGSEGV in child = unmapped, success = mapped.

## Key Strategic Insight (Session 5)

**R+0x00 and R+0x08 are the strongest KASLR target.** The decompile proves these fields contain kernel thread addresses (from `GS:0x390` and `GS:0x08`) and are NOT zeroed before R is freed to zone 0x1ab59e0. If cross-subsystem spray can reclaim R's 48B→64B slot and read it back, those stale pointers leak the kernel base. This is stronger than the I+0x10 obfuscated pointer (which requires deobfuscation) or the I+0x40 file pointer (which is refcounted and may be zeroed).

The three zone attribution errors (0x1ab5890 ↔ 0x1ab5a50 swapped) do not affect the R/I exploit path but would have misled any spray targeting the copyin buffer or pointer table zones.

---

## Session 6 — Probe Expansion + Audit (10+ agents)

10 parallel fork agents wrote new probes targeting verified gaps. Main thread audited all output, fixed ABI errors, and wrote additional probes.

### New Probes Written

| Probe | Purpose | Status |
|-------|---------|--------|
| [69d_r_reclaim_kaslr.lua](../../probes/phase16_kwrite/69d_r_reclaim_kaslr.lua) | R-object KASLR via 3 spray interfaces (evf/namedobj/setsockopt) with double-free | AUDITED, ABI-fixed |
| [69e_solinger_spray_readback.lua](../../probes/phase16_kwrite/69e_solinger_spray_readback.lua) | Socket creation spray with SO_LINGER sentinel + getsockopt readback | AUDITED |
| [69f_evf_spray_readback.lua](../../probes/phase16_kwrite/69f_evf_spray_readback.lua) | Dedicated EVF spray with sentinel bits + 543/542 readback | AUDITED, ABI-fixed |
| [69g_submit_during_delete.lua](../../probes/phase16_kwrite/69g_submit_during_delete.lua) | **3-thread submit-during-delete (ONLY true UAF path)**: delete-A + main submit + delete-B | Agent-written |
| [69h_high_volume_spray.lua](../../probes/phase16_kwrite/69h_high_volume_spray.lua) | 4096-evf cache drain + double-free + 128-evf spray with sentinel readback | Written, audited |
| [69i_aio_cmd2_class23.lua](../../probes/phase16_kwrite/69i_aio_cmd2_class23.lua) | AIO cmd=2 (write) and class=2/3 lifecycle + double-free | Agent-written |
| [69j_sioc_ioctl_kaslr.lua](../../probes/phase16_kwrite/69j_sioc_ioctl_kaslr.lua) | Socket-level SIOC* ioctl KASLR scan (never tested before) | Agent-written |
| [69k_dlsym_deep_sweep.lua](../../probes/phase16_kwrite/69k_dlsym_deep_sweep.lua) | Deep dynlib_dlsym(591): 39 modules × 68 symbols + wildcard handles + kernel symbol speculation | Written, audited |
| [69l_evf_object_size.lua](../../probes/phase16_kwrite/69l_evf_object_size.lua) | EVF/namedobj kernel object size measurement via 624 page boundary detection | Agent-written |
| [69m_read_gadget_scan.lua](../../probes/phase16_kwrite/69m_read_gadget_scan.lua) | Full eboot RX scan for memory-read gadgets (mov rax,[rdi]; ret etc.) | Agent-written |
| [69n_663_mode_sweep.lua](../../probes/phase16_kwrite/69n_663_mode_sweep.lua) | 663 wait_mode parameter sweep (4th arg never tested beyond default) | Agent-written |
| [69o_poll_close_race.lua](../../probes/phase16_kwrite/69o_poll_close_race.lua) | High-volume poll+close race for CVE-2026-45251 (5000 iters) | Agent-written |
| [69p_namedobj_reclaim.lua](../../probes/phase16_kwrite/69p_namedobj_reclaim.lua) | Namedobj zone overlap test: sequential AIO free → namedobj spray → 624 delta | Written, audited |

### Probe Priority Order (for PS5 execution)

1. **69a** — self-overlap hexdump + class=2/3 (LOW risk, immediate gap closure)
2. **69l** — EVF/namedobj object size via 624 (LOW risk, determines if zone overlap is possible)
3. **69p** — namedobj zone overlap test (MODERATE, no race needed)
4. **69d** — R-object KASLR via cross-subsystem spray (HIGH, the critical test)
5. **69g** — 3-thread submit-during-delete (HIGH, the only true UAF path)
6. **69h** — high-volume 4096-evf drain + spray (HIGH, tests cache drain hypothesis)
7. **69f** — EVF spray readback (MODERATE)
8. **69m** — read gadget scan (LOW, catalog for future exploitation)
9. **69k** — dlsym deep sweep (LOW, exploratory)
10. **69j** — socket ioctl KASLR (LOW)
11. **69n** — 663 mode sweep (LOW)
12. **69o** — poll+close race (MODERATE)
13. **69i** — AIO cmd=2/class=2/3 (HIGH)
14. **69e** — SO_LINGER spray (MODERATE, socket creation is the real spray)

### Key ABI Corrections Made This Session

| Probe | Issue | Fix |
|-------|-------|-----|
| 69d section B | evf_trywait(543) called with wrong arg count | Fixed: 3 args `(handle, bits, mode)`, readback via 542 with 5 args |
| 69d section B | busy-wait line had trailing `)` | Syntax fixed |
| 69d section C | missing format arg for `iter` | Added |
| 69d section C | byte-level contamination used dword reads | Changed to qword comparison |
| 69f | evf_create(538) called with 3 args | Fixed: 2 args `(name_ptr, initial_bits)` |
| 69f | evf_trywait called with 4 args | Fixed: 3 args + separate 542 readback |

### Top 3 Immediate Actions (Session 6)

1. **★ Run 69l (object size measurement)** — determines if evf/namedobj share R's 64B zone bucket. If yes, cross-subsystem spray is viable. If no, need different spray objects.
2. **★ Run 69d (R-object KASLR)** — the critical test: double-free R, spray with evf/namedobj, read back via 543/542 for stale kernel thread pointers.
3. **★ Run 69g (3-thread submit-during-delete)** — the ONLY true UAF path per decompile verification. If this produces kernel corruption signals (crashes, kernel pointers in readback), it's the breakthrough.

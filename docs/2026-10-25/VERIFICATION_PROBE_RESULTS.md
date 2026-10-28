# Probe Result Mining -- Verification Report

**Date:** 2026-10-25
**Verified against:** Actual result files in `results/phase16_kwrite/`
**Source documents:** `docs/2026-10-25/03_RESULTS_ANALYSIS.md`, `docs/2026-10-25/18_PROBE_RESULT_MINING.md`
**Method:** Each claim was checked against the raw result file. Quoted values are from the result files. PID distribution was verified by grepping all 56 result files.

---

## Summary

| # | Claim | Source Doc | Verdict | Evidence |
|---|-------|-----------|---------|----------|
| 1 | pid=633 gold standard (72%) | 18_PROBE_RESULT_MINING | CONFIRMED with caveat | 65u actual = 71.9% (rounds to 72%). 03_RESULTS_ANALYSIS says 78% -- that is wrong |
| 2 | Cross-subsystem spray ALL failed | 03_RESULTS_ANALYSIS | CONFIRMED | 7 probe files checked: zero anomalies across socketpair, namedobj, EVF, kqueue, shm, setsockopt sprays |
| 3 | AIO self-overlap confirmed (65p) | 03_RESULTS_ANALYSIS | CONFIRMED | 6 overlap hits, cross_killed=3 in single-submit tests, explicit "Deleting one corrupts the other" |
| 4 | 67c 512 overlaps is false positive (poll flag) | 03_RESULTS_ANALYSIS, 18_PROBE_RESULT_MINING | CONFIRMED | All 512 transitions are 0x00000003 to 0x00010003; 67e control confirms flag is per-class |
| 5 | 65r disproves refcount accumulation | 18_PROBE_RESULT_MINING | CONFIRMED | 100 cumulative doubles on fd=63 across 50 rounds, fd alive at every checkpoint |
| 6 | 67i2 confirmed 60 doubles/30 iters | 03_RESULTS_ANALYSIS, 18_PROBE_RESULT_MINING | CONFIRMED | Result file line: "DOUBLES=60", 22 of 30 iterations produced doubles, pid=102 |

---

## Detailed Evidence

### Claim 1: pid=633 gold standard (72%)

**Claim in 18_PROBE_RESULT_MINING.md:** "| 633 | 72-80% | 65t/65u (gold standard) |"
**Claim in 03_RESULTS_ANALYSIS.md:** "65u (main+child) | 480 | 345 | 78% | main+child race"

**Result files checked:**
- `65u_aio_mainthread_race_20261023_225722.txt` (pid=633)
- `65t_aio_bigbatch_overlap_20261023_225417.txt` (pid=633)
- All 56 result files via pid= grep

**Verdict: CONFIRMED with caveat**

65u (pid=633): 15 iterations, 32 IDs per iteration = 480 total. Line 23: `TOTAL: dbl=345 main=349 child=476`. Rate: 345/480 = **71.875%, rounds to 72%**.

65t (pid=633) section B: 5 iterations of 64 victims each. Per-iteration doubles: 40, 51, 48, 45, 49. Rate range: 40/64=62.5% to 51/64=79.7%.

**18_PROBE_RESULT_MINING says "72-80%"** -- the 72% matches 65u exactly. The 80% matches 65t's peak. However, 65t's low end is 62%, so the full range is 62-80%, not 72-80%.

**03_RESULTS_ANALYSIS says "78%"** for 65u -- **this is wrong**. The actual rate is 71.9%. The 78% figure does not match any calculation from the raw data. Possible source: excluding iter 1 (0 doubles) gives 345/448 = 77.0%, which is still not 78%.

**PID distribution across all 56 result files:**
| PID | File count | Double-free success? |
|-----|-----------|---------------------|
| 633 | 24 files | Consistent doubles (except 67b single-CPU = 0, by design) |
| 642 | 10 files | Mixed: 67c=3-10/iter, 67e=9; but 67c rerun=0, 67d synced=0 |
| 626 | 6 files | Original 65l=65 doubles; 65m=2 doubles |
| 619 | 4 files | Early probes, pre-race-fix |
| 88 | 4 files | Always 0 doubles (67f, 67g, 67h, 65l rerun) |
| 102 | 3 files | 67i2=60, 67h_oracle=20 doubles; 67j=0 (timeout) |
| 118 | 2 files | 67k=28, 67l=22 doubles |
| 109 | 2 files | Always 0 (67j both runs) |
| 79 | 1 file | 0 doubles |
| 95 | 1 file | 65l rerun=17 doubles |
| 86 | 1 file | 67m characterization only |

pid=633 accounts for 24/56 = 43% of all result files. Among files with non-zero doubles, pid=633 accounts for approximately 11 of 20 successful race runs = 55%. The "gold standard" designation is qualitatively correct -- pid=633 produced the highest sustained rates and never failed when multi-core was available.

---

### Claim 2: Cross-subsystem spray ALL failed

**Claim in 03_RESULTS_ANALYSIS.md:** "Not a single cross-subsystem spray has ever reclaimed a freed AIO slot across all 60 result files."
**Claim in 18_PROBE_RESULT_MINING.md:** "Every cross-type spray (kqueue, namedobj, socketpair, EVF, setsockopt, shm) produced 0 anomalies. Per-type zone isolation confirmed."

**Result files checked:**
- `65v_cross_subsystem_overlap_20261023_231444.txt` (pid=633)
- `65w_fixed_cross_spray_20261023_232747.txt` (pid=633)
- `66e_aio_evf_overlap_20261023_232738.txt` (pid=633)
- `67f_crosszone_namedobj_20261024_003154.txt` (pid=642)
- `67j_gated_cross_cpu_20261024_020031.txt` (pid=102)
- `67j_gated_cross_cpu_20261024_020317.txt` (pid=109)
- `67j_gated_cross_cpu_20261024_020341.txt` (pid=109)
- `67k_combined_20261024_020945.txt` (pid=118)
- `67l_overlap_detect_20261024_022243.txt` (pid=118)
- `65m_aio_uaf_read_20261023_221528.txt` (pid=626)
- `65n_aio_object_size_20261023_222029.txt` (pid=633)
- `66c_aio_crosstype_spray_20261023_231943.txt` (pid=633)

**Verdict: CONFIRMED**

Evidence per probe:

**65v** (EVF + namedobj spray): 5 trials with 37-43 doubles each. Spray=128 objects per trial. `kr=0` (kernel pointers), `wd=0` (write detected), `kd=0` (kernel data). Zero corruption. EVF create returned -1 for unnamed objects (not functional for spray).

**65w** (namedobj spray): 5 trials with 35-43 doubles each. Namedobj spray=64 per trial, AIO spray=32 per trial. All namedobj deleted cleanly (64/64). No corruption evidence in any trial.

**66e** (EVF + namedobj + socket spray): 12 doubles. Post-spray: `TOTAL anomalies: 0`. EVF delete failures: 0/32. Namedobj delete failures: 0/32. All spray objects maintained integrity.

**65m** (pipe + socketpair + namedobj + setsockopt + shm spray): 2 doubles. Post-spray poll of double-freed IDs: `poll_state=0x80020003` (unknown, same as pre-spray). Triple delete attempt returned same status. Spray created 64 socketpairs, 128 namedobjs, 32 shm objects -- none reclaimed the AIO slot.

**65n** (namedobj + kqueue + EVF spray): 2 doubles. Post-spray: `namedobj corruption: 0/256`, `kqueue corruption: 0/64`, `evf corruption: 0/0`. AIO lifecycle delta=0 for all operations (no VM ops).

**67f** (namedobj cross-zone): namedobj lookup returns `0xFFFFFFFFFFFFFFFF` instead of created handle. Cannot even detect overlap via namedobj -- the lookup mechanism is broken.

**67j** (3 runs, pids 102/109/109): All returned 0 total doubles. MARKER TIMEOUT or INSUFFICIENT results. Cross-CPU gating did not produce doubles on these process instances.

**67k** section B/C/D (CPU-pinned spray): cpu0=80, cpu1=80 spray objects. Delete cpu0: ok=80 fail=0. Delete cpu1: ok=80 fail=0 crash=0. Clean -- no cross-contamination.

**67l** section C (trigger test): After triggering AIO completion on set A: "A: completed=24 sentinel=0 other=0; B: completed=0 sentinel=24 other=0". AIO correctly routes completions to originating requests. No cross-contamination between A and B sets.

Additionally, `sys 624 delta=0` was recorded for all AIO operations (65n section A: submit delta=0, poll delta=0, delete delta=0, submit x16 delta=0). AIO allocations do not trigger VM operations, confirming they use a private allocator rather than the general mmap path.

---

### Claim 3: AIO self-overlap confirmed (65p)

**Claim in 03_RESULTS_ANALYSIS.md:** "AIO self-overlap IS confirmed (65p): after double-free, re-submitting new AIO requests reclaims the same internal slots. Deleting set B kills set A's entries ('cross-killed')."

**Result file:** `65p_aio_self_overlap_20261023_222656.txt` (pid=633)

**Verdict: CONFIRMED**

Section B (batch double-free then re-submit):
- iter 1: `*** OVERLAP! doubles=2 new=12 killed=6/6 anomalies=0 wait_anom=6 ***`
- iter 5: `*** OVERLAP! doubles=2 new=12 killed=6/6 anomalies=0 wait_anom=6 ***`
- iter 9: `*** OVERLAP! doubles=2 new=12 killed=6/6 anomalies=0 wait_anom=6 ***`

`killed=6/6` means deleting one AIO request's overlapping set invalidated all 6 of its partner IDs.

Section C (single-submit overlap test):
- trial 2: `doubles=1 first=3 second=3 cross_killed=3 *** OVERLAP! ***`
- trial 3: `doubles=1 first=3 second=3 cross_killed=3 *** OVERLAP! ***`
- trial 4: `doubles=1 first=3 second=3 cross_killed=3 *** OVERLAP! ***`

`cross_killed=3` confirms that deleting one AIO ID invalidates its overlapping partner's AIO IDs.

Summary lines:
```
*** AIO OBJECT OVERLAP CONFIRMED ***
*** Double-freed chunks reclaimed by new AIO requests ***
*** Deleting one corrupts the other -- exploitation path is live ***
```

The claim matches the result file exactly. AIO self-overlap is real: double-freed AIO sub-objects are reclaimed by subsequent AIO allocations, creating aliased kernel objects.

---

### Claim 4: 67c "512 overlaps" is false positive (poll flag)

**Claim in 03_RESULTS_ANALYSIS.md:** "Probe 67c reported 512 'overlaps' but this is the normal status transition from `0x00000003` (submitted) to `0x00010003` (polled) when poll(664) runs."
**Claim in 18_PROBE_RESULT_MINING.md:** "67c reported 512 overlaps based on `0x00010003` vs `0x00000003` status bit. 67e's control experiment proved this is the poll flag."

**Result files:**
- `67c_overlap_oracle_20261024_000729.txt` (pid=642, first run)
- `67c_overlap_oracle_20261024_001237.txt` (pid=642, second run)
- `67e_forced_reclaim_20261024_002242.txt` (pid=642, control)

**Verdict: CONFIRMED**

67c first run: 8 iterations, each showing `odd_overlap=64`. Every single "overlap" is the transition `was=00000003,now=00010003`. Example from iteration 1:
```
odd[2]=8723(was=00000003,now=00010003)
odd[4]=8721(was=00000003,now=00010003)
...
```
Line 100: `TOTAL OVERLAPS DETECTED: 512` (8 x 64 = 512)

ALL 512 "overlaps" show the identical pattern: status changed from `0x00000003` to `0x00010003`. The `0x10000` bit is the poll flag set by syscall 664.

67e control experiment (section D): Baseline without double-free:
```
baseline: 00000003 00000003 00000003 00000003
after poll 1,2: 00010003 00010003 00010003 00010003
```
Polling ANY two IDs sets `0x10000` on ALL four IDs. The flag is per-class (global within a poll batch), not per-object. This conclusively proves the 512 "overlaps" were measuring the poll flag transition, not memory overlap.

However, the first 67c run DID show real double-frees alongside the false overlaps: `dbl=3` to `dbl=10` per iteration. Those are genuine. The 512 number specifically is bogus.

The second 67c run (pid=642, 001237) produced 0 doubles across all trials, demonstrating the process-dependent serialization behavior.

---

### Claim 5: 65r disproves refcount accumulation

**Claim in 18_PROBE_RESULT_MINING.md:** "100 double-frees on the same fd left it alive. The double-freed object is a per-request AIO tracking structure, NOT the file descriptor itself."
**Claim in 03_RESULTS_ANALYSIS.md:** "fd refcount is resilient (65r): 100 cumulative double-frees on one fd -- fd stays alive. The sub-object double-free does not touch the fd refcount."

**Result file:** `65r_fd_refcount_20261023_223423.txt` (pid=633)

**Verdict: CONFIRMED**

Section B (cumulative doubles on shared fd):
- 7 rounds with doubles (1-3 per round), total=12 doubles
- After each round: `fd_zero=VALID`

Section C (per-fd dedicated test):
- 14 fds tested (fds 44-62), each with 1-9 doubles
- Every fd remained valid: e.g., `fd[20]=62: 9 doubles, fd still valid`
- Summary: `refcount hits (section C): 0`

Section D (drain test on single fd):
- fd=63 accumulated doubles across 50 rounds
- Key checkpoints: `round 30: doubles=1 total=60 fd=alive`, `round 50: doubles=0 total=100 fd=alive`
- Summary: `drain doubles (section D): 100`

Final: `process: ALIVE`

100 cumulative double-frees on one fd, fd survives at every checkpoint. The double-free affects a per-request AIO tracking sub-object, not the file descriptor's reference count. The claim matches exactly.

---

### Claim 6: 67i2 confirmed 60 doubles/30 iters

**Claim in 03_RESULTS_ANALYSIS.md:** "67i2 (pipe-gated) | 480 | 60 | 12.5% | gated sync"
**Claim in 18_PROBE_RESULT_MINING.md:** "| 102 | 12.5% | 67i2 |"

**Result file:** `67i2_gated_race_simple_20261024_015835.txt` (pid=102)

**Verdict: CONFIRMED**

30 iterations, 16 IDs per iteration. 22 of 30 iterations produced doubles:
```
iter 2: *** 4 DOUBLES ***
iter 3: *** 2 DOUBLES ***
iter 4: *** 3 DOUBLES ***
...
iter 29: *** 1 DOUBLES ***
iter 30: *** 3 DOUBLES ***
```

Line 33: `DOUBLES=60`
Line 34: `*** DOUBLE FREE CONFIRMED ***`
Line 35: `alive=YES`

Rate: 60/480 = 12.5%. The claim matches exactly.

8 of 30 iterations had 0 doubles (iters 1, 5, 7, 11, 15, 19, 23, 27). Per-iteration doubles when hitting: 1-4 (mostly 2-4). pid=102, not pid=633.

---

## Cross-Document Discrepancies Found

### 03_RESULTS_ANALYSIS says 65u rate is "78%" -- actual is 71.9%

03_RESULTS_ANALYSIS.md line 25 states: `65u (main+child) | 480 | 345 | 78% | main+child race`

The actual data: 345/480 = 71.875%. The document inflates the rate by approximately 6 percentage points. 18_PROBE_RESULT_MINING.md correctly says "72-80%" where 72% matches 65u and 80% matches 65t's peak iteration.

### 65t range is 62-80%, not 72-80%

18_PROBE_RESULT_MINING says pid=633 achieves "72-80%". But 65t section B shows per-iteration rates of 40/64=62.5% through 51/64=79.7%. The accurate combined range across 65t and 65u is 62-80%, not 72-80%.

### 03_RESULTS_ANALYSIS says "60 result files" but pid grep shows 56 distinct result files

The document header says "60 result files" analyzed. The actual file count in `results/phase16_kwrite/` is 56 files (confirmed by glob). This is a minor counting discrepancy -- 18_PROBE_RESULT_MINING.md says "56 Outputs Analyzed" which matches the actual count.

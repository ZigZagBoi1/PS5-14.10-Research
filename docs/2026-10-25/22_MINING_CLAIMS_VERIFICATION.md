# Verification Report: Probe Result Mining Claims (Finding 18)

> **Date:** 2026-10-25 Session 4
> **Verifier:** verify-mining-claims agent
> **Scope:** 6 specific claims from 18_PROBE_RESULT_MINING.md checked against raw result files

---

## Claim 1: "67c '512 overlaps' is a FALSE POSITIVE"

### VERDICT: **VERIFIED — but needs nuance**

**Raw data (67c run 1, pid=642):**
Every iteration shows `odd_overlap=64` and all 10 listed IDs show `was=00000003,now=00010003`. The probe prints `TOTAL OVERLAPS DETECTED: 512` (8 iterations × 64 = 512) and declares `★★★ TRACKING STRUCTURE OVERLAP CONFIRMED ★★★`.

**The "512 overlaps" number is real in the output.** The probe counted every ID whose 663 status changed from `0x00000003` to `0x00010003` as an "overlap."

**67e section [D] (control experiment) proves poll flag explanation:**
```
baseline: 00000003 00000003 00000003 00000003
after poll 1,2: 00010003 00010003 00010003 00010003
```
Unpolled IDs have status `0x00000003`; after calling 664 (poll), they become `0x00010003`. The `0x10000` bit IS the poll flag, set by 664, not by overlap. Since 67c's spray procedure includes a poll step, all spray IDs get the bit.

**Nuance the finding doc misses:** 67c also shows real doubles (dbl=3-10/iter), which ARE race wins. The false positive is specifically about the "512 overlaps" count based on the poll bit, not about the race itself. The finding doc correctly notes this ("67c still detected real doubles") but the headline could mislead a reader into thinking the entire 67c run was worthless.

---

## Claim 2: "65r: 100 double-frees left fd alive"

### VERDICT: **VERIFIED — exact match**

**Raw data (65r, pid=633, section [D]):**
```
drain_fd=63 valid=Y
round 1: doubles=2 total=2 fd=alive
...
round 50: doubles=0 total=100 fd=alive
```
Section [E] summary: `drain doubles (section D): 100` and `process: ALIVE`.

100 cumulative doubles across 50 rounds on the same fd (63), fd stayed alive throughout. The claim is precisely correct. Note: these are "doubles" (race-reported double successes), not necessarily 100 actual refcount decrements — whether each "double" causes an actual kernel refcount decrement is the deeper question the finding doc correctly raises.

---

## Claim 3: "pid=633 gets 72-80% hit rate"

### VERDICT: **APPROXIMATELY CORRECT — slightly cherry-picked**

**Raw data:**

65t section [B] (pid=633, batch of 64):
- iter 1: dbl=40/64 = **62.5%**
- iter 2: dbl=51/64 = **79.7%**
- iter 3: dbl=48/64 = **75.0%**
- iter 4: dbl=45/64 = **70.3%**
- iter 5: dbl=49/64 = **76.6%**

65u section [A] (pid=633, batch of 32):
- iter 1: dbl=0/32 = **0%** (cold start)
- iter 2-15: dbl=19-27/32 = **59.4%-84.4%**

**Actual range for pid=633:** 0%-84.4% (including cold start), typically 62.5%-81.3% once warm. The "72-80%" claim is a reasonable characterization of the typical warm-state median range but it:
- Drops the cold-start 0% outlier (iter 1 of 65u)
- Drops the 62.5% and 65.6% low outliers
- Rounds up from the actual common range of ~70-81%

**Correction:** "62-81% (typically 70-80% once warm)" would be more accurate.

---

## Claim 4: "CPU pinning kills the race (67b): mask=0x01 → 0 doubles in 200 cycles"

### VERDICT: **VERIFIED — exact match**

**Raw data (67b_cpupin, pid=633):**
```
setaffinity(PID=633,CPU0) rv=0
verify mask=00000000_00000001 pinned=true
```
Section [C]: 5 iterations, all `dbl=0`.
Section [D]: `200 cycles: 0 crashes, 0 errors`, `doubles: 0`.
Summary: `TOTAL anomalies: 0`.

Zero doubles across 5 iterations + 200 tight cycles on a single CPU. **Exact match.**

**mask=0x03 allows the race:** Verified from 67c run 1, which starts with `setaffinity(mask=0x03) rv=0` and shows dbl=3-10 per iteration on the same pid=642.

---

## Claim 5: "Socketpair AIO data reads work (67k Section E): result=0x10 and data=0x41424344"

### VERDICT: **VERIFIED — exact match**

**Raw data (67k, pid=118, section [E]):**
```
-- [E] SOCKETPAIR AIO --
  pair: fd0=27 fd1=28
  submit: id=0x22A4 result=0xDEAD
  after: result=0x10 data=0x41424344
```

Pre-write result is `0xDEAD` (sentinel), post-write shows `result=0x10` (16 bytes moved) and `data=0x41424344` ("ABCD"). **Exact match to the claim.**

---

## Claim 6: "pid=118 gets 22-88% hit rate"

### VERDICT: **INACCURATE — high end is overstated**

**Raw data:**

67k section [A] (pid=118, batch of 16):
- 8 iterations: dbl=0,6,1,6,1,7,3,4
- Percentages: 0%, 38%, 6%, 38%, 6%, 44%, 19%, 25%

67l section [A] (pid=118, batch of 16):
- 5 iterations: dbl=8,3,4,5,2
- Percentages: 50%, 19%, 25%, 31%, 12.5%

**Actual range for pid=118:** 0%-50%. The claim says "22-88%" which overstates the high end by nearly double. The 88% figure does not appear in any result file for pid=118.

**Correction:** "0-50% (typically 19-38%)" would be accurate for pid=118.

---

## Summary Table

| Claim | Verdict | Accuracy |
|-------|---------|----------|
| 67c 512 overlaps is false positive | **VERIFIED** | Correct. Poll flag proven by 67e control |
| 65r 100 double-frees, fd alive | **VERIFIED** | Exact match |
| pid=633 gets 72-80% | **APPROXIMATELY CORRECT** | Actual warm range ~62-81%; 72-80% is the median band |
| CPU pin kills race (67b) | **VERIFIED** | Exact: 0 doubles in 5 iters + 200 cycles |
| 67k socketpair data reads | **VERIFIED** | Exact: result=0x10, data=0x41424344 |
| pid=118 gets 22-88% | **INACCURATE** | Actual range 0-50%; 88% not in any result file |

---

## Corrections Needed in 18_PROBE_RESULT_MINING.md

1. **pid=633 row:** Change "72-80%" to "62-81% (typically 70-80% warm)" 
2. **pid=118 row:** Change "22-88%" to "0-50% (typically 19-38%)"
3. **Claim 2 (67c):** Add that 67c's `TOTAL OVERLAPS DETECTED: 512` and `★★★ TRACKING STRUCTURE OVERLAP CONFIRMED ★★★` text was misleading but the underlying data (all `was=00000003,now=00010003`) is real — it's just the poll flag, not memory overlap

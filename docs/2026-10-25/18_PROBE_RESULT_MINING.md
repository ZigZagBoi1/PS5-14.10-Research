# Finding 18: Phase 16 Probe Result Mining — 56 Outputs Analyzed

> **Date:** 2026-10-25 Session 3
> **Agent:** probe-result-mining
> **Scope:** All 56 result files in results/phase16_kwrite/ (65d through 67m)

---

## Key Findings

### 1. Process-Dependent Race Success Is the #1 Operational Blocker

Race success varies wildly by process instance:
| PID | Hit Rate | Source |
|-----|----------|--------|
| 633 | 72-80% | 65t/65u (gold standard) |
| 118 | 22-88% | 67k/67l |
| 102 | 12.5% | 67i2 |
| 88 | 0% | Multiple probes (completely dead) |
| 642 | 0% then 10-12/trial | Variable across probes |

**Action:** All exploitation probes MUST include early qualification. If first 1-2 attempts show 0 doubles, skip and reconnect for a new process.

### 2. 67c "512 Overlaps" Is a FALSE POSITIVE

67c reported 512 overlaps based on `0x00010003` vs `0x00000003` status bit. 67e's control experiment proved this is the **poll flag** — set by 664, visible through 663, not overlap evidence. The probe's spray procedure included a poll step, so all spray IDs naturally got the bit.

However, 67c still detected real doubles (dbl=3-10/iter) and 67d achieved 64/64 overlap pairs — those are real AIO self-overlaps at the handle level.

### 3. AIO Query Returns Computed Status, Not Raw Memory

663/666 return a 4-byte status dword from the AIO subsystem's tracking table. 667 always returns -1. The wide buffer passed to 663 gets only the status dword written; rest stays sentinel. **The status is NOT reading from freed memory's raw bytes** — it's reinitialized on reallocation.

### 4. Socketpair AIO Data Reads Work (67k Section E)

`result=0x10` and `data=0x41424344` — AIO read on a socketpair actually moves data through the AIO completion record. But cross-contamination is clean (67l): the AIO mechanism correctly routes data to its originating request.

### 5. fd Survives 100 Accumulated Doubles (65r) — Mechanism UNKNOWN

100 accumulated doubles on the same fd left it alive (`total=100 fd=alive` at round 50). Two possible explanations:
- **(a) Exclusive lock serializes:** Only one actual free fires per race. Doubles accumulate as double-success reports, not double-frees. The fd refcount never drops.
- **(b) High starting refcount:** Both decrements fire, but the fd's refcount starts high enough (fd table hold + AIO hold per request) to absorb 100 extra decrements without reaching zero.

The raw data cannot distinguish (a) from (b). The double-freed object is a per-request AIO tracking structure. Its `entry_dispose` decrements `*(file_object+0x28)`, which is the fd's refcount — but whether the second thread's `entry_dispose` actually executes after the exclusive lock is the open question.

### 6. CPU Pinning Kills the Race (67b)

`setaffinity(mask=0x01)` → 0 doubles in 200 cycles. Multi-core required. `mask=0x03` (two cores) allows the race.

### 7. Cross-Subsystem Spray: Zero Hits Across All Types

Every cross-type spray (kqueue, namedobj, socketpair, EVF, setsockopt, shm) produced 0 anomalies. Per-type zone isolation confirmed.

## Untried Approaches Identified

1. **AIO write (cmd=2)** instead of read (cmd=1) — might fill different sub-object fields
2. **Triple child race** (3 children) — increase reclaim probability
3. **Size-targeted setsockopt** — IP_OPTIONS at exactly 0x30/0x58 bytes
4. **sendmsg ancillary data spray** — cmsg buffers of controlled size
5. **AIO on `/dev/rng`** — different kernel code path
6. **500+ AIO requests** — force slab page exhaustion
7. **Direct kernel decrement via I+0x40** — doesn't need readback, just controlled +0x40 field

# Phase 16 Results Analysis

**Date:** 2026-10-25
**Source:** Agent 3 -- Phase 16 results mining (60 result files, max effort)

## Critical Finding: AIO Uses Dedicated Zones

**Not a single cross-subsystem spray has ever reclaimed a freed AIO slot across all 60 result files.**

Evidence:
- **sys 624 delta=0** for all AIO operations -- submit, poll, delete, spray (65n). AIO allocations do not trigger VM operations.
- Spray objects created cleanly but zero corruption in freed AIO memory across: socketpair (65m), namedobj (65m/65w/66e), kqueue (65n/65o), shm (65m), EVF (66e), sockets (66e).
- **AIO self-overlap IS confirmed** (65p): after double-free, re-submitting new AIO requests reclaims the same internal slots. Deleting set B kills set A's entries ("cross-killed").

## Double-Free Statistics Across Probes

| Probe | IDs Tested | Doubles | Hit Rate | Method |
|-------|-----------|---------|----------|--------|
| 65l (original) | 480 | 65 | 13.5% | 2-child race |
| 65l rerun 1 | 480 | 0 | 0% | serialized |
| 65l rerun 2 | 480 | 0 | 0% | serialized |
| 65l rerun 3 | 480 | 17 | 3.5% | 2-child race |
| 65o | 20 iters | 31 total | variable | child spray |
| 65t (64-victim) | per iter | 40-51 | 62-80% | big batch |
| **65u (main+child)** | **480** | **345** | **78%** | **main+child race** |
| 66d | 16 | 12 | 75% | overlap detect |
| 66e | 16 | 12 | 75% | cross-type |
| 66f (256 batch) | 256 | 36-37 | ~14% | massive spray |
| 67i2 (pipe-gated) | 480 | 60 | 12.5% | gated sync |
| 67k (combined) | 8 iters | 28 | reliable | gated |

The double-free is **process-dependent**: fresh processes (pid=88/79/109) often serialize entirely, while established connections hit reliably. Main+child (65u) produces the highest rate. CPU pinning to one core kills the race completely (67b).

## Zero Kernel Pointers

Not a single kernel pointer (hi >= 0xFFFF8000) was found across all 60 result files. Every scan -- AIO readback, spray buffers, 663 output dumps, socketpair data, namedobj handles -- returned only userland addresses, small integers, or sentinel values.

## False Positive: 67c's "512 Overlaps"

Probe 67c reported 512 "overlaps" but this is the normal status transition from `0x00000003` (submitted) to `0x00010003` (polled) when poll(664) runs. Every later probe reporting "odd anomalies" based on this transition is measuring the poll flag, not cross-object corruption.

## AIO Status Lifecycle (663 readback via 67a/67m)

- Immediate after submit: `0x00000003`
- After poll (664): `0x00010003`
- After delete (662): `0x80020003` (unknown ID)

## Key Observations

1. **fd refcount is resilient** (65r): 100 cumulative double-frees on one fd -- fd stays alive. The sub-object double-free does not touch the fd refcount.
2. **669 count limit is exactly 128** (66g, binary search confirmed).
3. **AIO budget is 512 concurrent** (66f).
4. **Socketpair AIO works** (67k/67l): AIO read on AF_UNIX socketpair fds succeeds, result changes from sentinel to bytes-read count with recognizable data (`0x41424344`). This is the most promising unexploited lead.
5. **Namedobj lookup returns 0xFFFFFFFFFFFFFFFF** instead of created handle (67f).

## Recommendations

1. **Abandon cross-subsystem spray.** AIO objects are in a private zone. This is a structural dead end confirmed by 60 result files.
2. **Exploit AIO self-overlap via socketpair I/O.** Double-free, resubmit on different fds, check cross-fd data leakage through the shared kernel object.
3. **Use main+child race (65u pattern) for best hit rate** (78%).
4. **Characterize AIO request object layout** via 663 readback -- find which fields are user-readable through 663/666/667, especially after overlap corruption.
5. **Investigate whether AIO completion writes kernel data** -- if I/O completion of request A writes into the shared memory that request B references, B's internal state is corrupted.

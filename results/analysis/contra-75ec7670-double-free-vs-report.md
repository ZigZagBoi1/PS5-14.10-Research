# Analysis: C9 — Does the Double-Free Actually Double-Free, or Just Double-Report?

**Task ID:** contra-75ec7670
**Date:** 2026-11-11
**Grade:** S (source-read)

## Question

The 65l probe showed 65/480 "double" events. Multiple documents disagree on whether these represent actual kernel double-frees (both threads free the same object) or just double-status-reports (both threads report success, only one frees).

## Evidence Reviewed

- `docs/2026-10-25/CONTRADICTIONS_REPORT.md:179-200` — C9 analysis
- `docs/AIO_OBJECT_FORENSICS.md` — raises the double-report hypothesis: "Thread B acquires exclusive lock, finds NULL → reports success without freeing"
- `docs/AIO_13_60_ANALYSIS.md` §2 — "Both threads free the same objects from the same zones"
- `docs/2026-10-25/03_RESULTS_ANALYSIS.md` — "AIO self-overlap IS confirmed (65p)"
- `docs/STRATEGY.md:251-254` — **definitive resolution**: "These were interpreted as kernel double-frees; they are actually double-STATUS reports where both threads pass validation but only one frees. The entire AIO investigation line (65a-886a, spanning 5 days) produced no kernel memory corruption."
- `docs/HEAP_EXPLOITATION_TECHNIQUES_ADDENDUM.md` §2 — describes per-CPU bucket cache behavior assuming real double-free

## Finding

**The 65l doubles are double-STATUS-reports, NOT actual double-frees.**

The resolution is already documented in `docs/STRATEGY.md:251-254` and represents the final conclusion after the full 65a-886a investigation span:

1. **Mechanism:** Thread A acquires the per-descriptor exclusive lock, reads I pointer, NULLs the table slot, frees I, releases lock. Thread B acquires the same lock, finds NULL in the table slot, reports success (state=0) without freeing anything.
2. **Evidence:** Zero kernel memory corruption observed across the entire 65a-886a probe series (56+ runs of 65l with no crash or observable corruption).
3. **65p self-overlap:** The "self-overlap" where deleting one AIO request invalidates its partner is explained by handle-table corruption (both IDs sharing a descriptor whose table entries are cleared), not by double-free of the underlying memory.
4. **No residue:** The STRATEGY.md pivot note confirms AIO objects are not freed on 14.10 in a way that leaves exploitable residue.

**Documents requiring correction:**
- `docs/AIO_13_60_ANALYSIS.md` §2 — "Both threads free the same objects" is the 13.60 static analysis. The 14.10 runtime behavior (exclusive lock serialization) prevents this.
- `docs/FREEBSD_EXPLOIT_TECHNIQUES.md` — "The next two allocations from this zone both receive the SAME pointer → type confusion" assumes an actual double-free that doesn't occur.
- `docs/HEAP_EXPLOITATION_TECHNIQUES_ADDENDUM.md` §2 — per-CPU double-free analysis is moot; the double-free doesn't happen.
- `docs/2026-10-25/09_EXPLOIT_CHAIN.md` — treats it as confirmed real; should note it's disproven.

## Verdict

**C9 is RESOLVED.** The answer is **double-report, not double-free.** The entire AIO race exploitation path is a dead end as confirmed by STRATEGY.md. The lock serialization on 14.10 prevents both threads from actually freeing the same object. This is already captured in the project's strategic pivot away from AIO, but several older documents still treat the double-free as real and should carry a correction note.

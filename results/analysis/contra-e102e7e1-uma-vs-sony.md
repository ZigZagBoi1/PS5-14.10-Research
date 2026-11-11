# Analysis: C3 — Is the Allocator UMA or Sony-Custom?

**Task ID:** contra-e102e7e1
**Date:** 2026-11-11
**Grade:** S (source-read)

## Question

Multiple documents disagree on whether the PS5 kernel heap allocator is standard FreeBSD UMA, a Sony-custom replacement, or a Sony wrapper around UMA.

## Evidence Reviewed

- `docs/2026-10-25/01_AIO_EXPLOIT_STRATEGY.md` — claims `func_0x00c08df0` is `uma_zfree()`
- `docs/2026-10-25/05_AIO_STRUCTURE_ANALYSIS.md` — "All AIO objects are small, so they use **UMA zones**. Confidence: HIGH"
- `docs/AIO_OBJECT_FORENSICS.md` — documents `func_0x00c08b50(size, zone_ptr, flags)` interface with zone RVAs `0x1ab5900`, `0x1ab59e0`, etc.
- `docs/HEAP_EXPLOITATION_TECHNIQUES_ADDENDUM.md` §1 — presents 3 architectures (A: UMA wrapper, B: bump pool, C: malloc wrapper)
- `docs/2026-10-25/22_CONTRADICTIONS_REPORT.md` C3 — catalogues the disagreement
- `docs/2026-10-25/09_EXPLOIT_CHAIN.md` — "AIO objects live in 4 dedicated UMA zones. Only AIO self-spray (669) reclaims freed slots."
- `docs/STRATEGY.md:251-254` — AIO investigation produced no kernel memory corruption; 65l "doubles" were double-STATUS, not double-frees.

## Finding

**The allocator is Architecture A: Sony-created dedicated UMA zones (UMA wrappers).**

Evidence chain:
1. The allocator function `func_0x00c08b50` has a size threshold near 0x4000 — objects below go through the small/zone path, objects above go through a large-page path (`0x43e080`). This matches UMA's slab allocator behavior exactly (AIO_STRUCTURE_ANALYSIS.md:55-68).
2. The `(pointer, zone_ptr)` calling convention of `func_0x00c08df0` matches `uma_zfree(zone, ptr)` with arguments swapped.
3. Zone RVAs are kernel data-segment addresses (`0x1ab5900`, `0x1ab59e0`, etc.) — these are `uma_zone_t` pointers allocated at boot, not generic `malloc-N` zones.
4. Each AIO subsystem object type has its own zone pointer — this is `uma_zcreate()` with per-type names, the same pattern Sony used on PS4.
5. The 20+ failed cross-subsystem spray probes (65m, 65n, 65o, 65t, 65v, 65w, 66e, 67f, etc.) prove that AIO zones are isolated from namedobj/EVF/kqueue/socketpair/setsockopt/shm zones. This matches dedicated UMA zones, not `malloc-N` shared zones.
6. Flag `0x102`: bit `0x100` triggers zero-fill on the small-allocation path, bit `0x2` is `M_NOWAIT`. These are standard UMA allocation flags.

**What remains uncertain:**
- Whether Sony modified UMA internals (bucket cache sizes, per-CPU behavior, slab geometry) — no way to verify without a kernel image or runtime probing.
- The STRATEGY.md finding that AIO double-frees never produced corruption is explained by the discovery that 65l's "doubles" were double-status-reports (both threads pass validation, only one frees), not by allocator differences.
- The Lapse exploit's apparent cross-subsystem spray success (Contradiction C1) could mean Lapse uses a different allocation path or targets a zone that happens to be shared — it does NOT disprove UMA architecture.

## Verdict

**C3 is RESOLVED.** The allocator wraps UMA with per-type dedicated zones. Documents claiming "Sony custom" (docs 13, 14, 15) are technically correct (Sony created the zones) but misleading — the underlying mechanism is UMA, not a replacement allocator. Documents claiming "UMA" (docs 01, 05, 09, 11) are correct about the mechanism.

**Recommended doc correction:** Standardize on "Sony-dedicated UMA zones" to capture both facts.

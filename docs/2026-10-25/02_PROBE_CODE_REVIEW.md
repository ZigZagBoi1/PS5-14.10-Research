# Phase 16 Probe Code Review

**Date:** 2026-10-25
**Source:** Agent 2 -- Phase 16 probe audit (51 files, max effort)

## Bugs Found

| Severity | File | Issue |
|----------|------|-------|
| **FATAL** | 65b | Uses `goto`/labels (lines 205, 208, 282, 307, 311, 349) -- will not parse in Lua 5.1 |
| **CRITICAL** | 66c | 669 arg order wrong: passes `reqs_ptr` in cmd slot (4 args instead of 5). All submits fail silently, race never fires |
| **CRITICAL** | 67e_main_child_race | 669 arg order swapped on line 94. Probe is inert |
| **MAJOR** | 65d, 65e | Call `mk(670)` (AIO init) which poisons the delete path. Race unreachable |
| **MAJOR** | 67m | `mk(663)`/`mk(666)` called without pcall -- process dies if syscall faults |
| **MAJOR** | 67m2 | `mk(663)` called without pcall -- same risk as 67m |
| **MINOR** | 66a | `memory.write_byte` without pcall in `cstr()` helper |
| **MINOR** | 65g | Correctly avoids 670 but omits 664 poll before 662 delete -- returns 0x80020010, race never triggers |

Note: 65f calls 670 intentionally (diagnostic probe testing both paths).

## Probe Categories

### Pre-confirmation (65a-65k) -- All superseded by 65l

- 65a/65c: sys 601 exploration (not AIO)
- 65b: kqueue race with fatal goto
- 65d-65k: successive AIO race refinements with various bugs
- All superseded by 65l (the confirmed double-free)

### Post-confirmation exploitation (65m-65w)

All follow the 65l pattern correctly:
- 65m: readback after UAF
- 65n: object size via sys 624
- 65o: 3-child spray
- 65p/65q: self-overlap detection
- 65r: fd refcount corruption test
- 65s: 13.60 sub-object sizes
- 65t: 64-victim batches
- 65u: main+child race (78% hit rate)
- 65v/65w: cross-subsystem EVF/namedobj spray

### Alternative approaches (66a-66g)

- 66a/66b: symbol resolution and info struct scanning
- 66c: **BUG** -- fatal 669 arg-order error
- 66d/66e/66f: overlap detection (correct)
- 66g: 669 count limit characterization

### Refined attacks (67a-67m2)

- 67a: 663/666/667 readback characterization
- 67b_cpupin: single-CPU pinning (kills race)
- 67b_poll: poll/AIO zone-64 overlap for KASLR
- 67c/67d: overlap oracles
- 67d_synced/67e: nanosleep synchronization
- 67f: cross-zone namedobj spray
- 67g/67h: cross-CPU delete
- 67i/67i2: socketpair-gated race (67i2 confirmed 60 doubles/30 iters)
- 67j/67k/67l: gated race + cross-CPU spray
- 67m/67m2: 663 characterization (missing pcall)

## Top 5 Most Promising Probes

1. **67i2_gated_race_simple** -- cleanest gated-race implementation, confirmed 60 doubles/30 iters. Socketpair gate ensures near-simultaneous 662 entry. No bugs.
2. **67k_combined** -- combines 67i2's race with cross-CPU spray and sequential delete observation. Most complete single-probe attack pipeline.
3. **67h_race_oracle_exploit** -- per-trial `memory.alloc` page faults create preemption windows. Combines race + poll-flag oracle + kernel pointer readback.
4. **67f_crosszone_namedobj** -- cross-zone spray using namedobj 48B names in malloc-64. Clean overlap signal with no crash risk.
5. **67b_poll_aio_overlap_kaslr** -- direct KASLR defeat if poll's `pollfd` array and AIO completion records share zone-64.

## Crash/Hang Risks

**Kernel panic (HIGH):** 67g, 67h_cross_cpu_delete, 67j, 67k, 67l -- sequential delete on overlapping kernel objects can dereference dangling pointers. 65o -- 3 concurrent children may exhaust thread budget. 65q -- wrong fd value could close critical kernel fd.

**Process kill (MODERATE):** 65m, 65n, 65p, 65r, 65s, 65t, 65u, 65v, 67i, 67i2

**Safe (LOW):** 65a, 65w, 66a, 66b, 66g, 67a, 67m -- characterization/read-only probes

## Recommendation

Run **67i2** first to confirm the gated race still produces doubles, then **67f** for safe overlap detection. Fix pcall in **67m/67m2** before running. Discard **65b** (won't parse), **66c** and **67e_main_child_race** (wrong 669 args), and **65d/65e** (670 poison). Probes 65a-65k are all superseded by 65l.

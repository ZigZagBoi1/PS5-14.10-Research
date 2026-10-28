---
title: Zone Size Verification
date: 2026-10-25
session: 4
type: verification
---

# Zone Size Verification Against 13.60 Decompile

**Source:** `results/kernel_handlers/decompiled/sys_662.c`

## Confirmed Allocations (func_0x00c08b50 = alloc)

| Object | Size | Zone | Decompile Line | Per-request? |
|--------|------|------|----------------|-------------|
| R (saved context) | **0x30 (48B)** | `0x1ab59e0` | 2607 | Yes, 1 per request |
| I (per-request node) | **0x58 (88B)** | `0x1ab5900` | 2622, 2636 | Yes, 1 per request |
| Q (descriptor) | **0x58 (88B)** | `0x1ab5970` | 2559 (single), 2568 (batch=count×0x58) | 1 per submission |
| A (aggregate) | **0x30 (48B)** | `0x1ab5a50` | 2581 | 1 per submission |
| T (pointer array) | **count×8** (variable) | `0x1ab5a50` | 2583 | 1 per submission |
| D (copyin buffer) | **count×0x28** (variable) | `0x1ab5890` | 2551 | 1 per submission |
| Temp context | **count×0x18** (variable) | `0x1a7d800` | 548, 1071, 1734, 2081 | Transient |

## Confirmed Frees (func_0x00c08df0 = free)

- R freed from zone `0x1ab59e0` — lines 649, 2755
- I freed from zone `0x1ab5900` — line 2784
- Q freed from zone `0x1ab5970` — lines 702, 2793
- A freed from zone `0x1ab5a50` — lines 710, 2800
- T freed from zone `0x1ab5a50` — lines 708, 2797
- D freed from zone `0x1ab5890` — lines 705, 2804

**7 distinct zones used** (including `0x1ab5ac0` for debug info and `0x2bfc080` for large allocs).

## Document Verdicts

| Document | Claim | Verdict |
|----------|-------|---------|
| AIO_OBJECT_FORENSICS.md | R=0x30/59e0, I=0x58/5900 | **CONFIRMED** |
| AIO_13_60_ANALYSIS.md | R=0x30/59e0, I=0x58/5900 | **CONFIRMED** |
| 13_FREED_OBJECT_FORENSICS.md | R=0x30/59e0, I=0x58/5900 | **CONFIRMED** |
| 15_OBJECT_HIERARCHY_CONFIRMED.md | I=88B, R=48B, Q=88B, A=48B | **CONFIRMED** |
| 09_EXPLOIT_CHAIN.md | "128-256 bytes" | **WRONG** — actual is 48B and 88B |
| 05_AIO_STRUCTURE_ANALYSIS.md | "0x40-0x80 bytes" | **PARTIALLY WRONG** — 0x30 is outside range; 0x58 is within |
| HEAP_SPRAY_CANDIDATES.md | Swaps zone assignments | **WRONG** — 59e0 and 5900 labels are inverted |
| 01_AIO_EXPLOIT_STRATEGY.md | Lists 5970/5890 for sub-objects, omits 5900 | **INCOMPLETE** |

## UMA Zone Sizes (for spray targeting)

The freed objects land in these UMA buckets:
- **0x30 (48B) → 64-byte zone** (R and A) — 256 objects per 16KB slab
- **0x58 (88B) → 128-byte zone** (I and Q) — 128 objects per 16KB slab

These are the spray target sizes. Any spray object must be exactly 64B or 128B to reclaim the same zone.

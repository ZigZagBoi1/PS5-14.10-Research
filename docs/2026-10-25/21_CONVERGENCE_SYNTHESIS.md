# Finding 21: 10-Agent Convergence Synthesis — Session 3

> **Date:** 2026-10-25 Session 3
> **Scope:** Synthesis of all 10 parallel max-effort research agents

---

## The Converged Picture

All 10 agents independently reached the same conclusion: **stop fighting the AIO query abstraction and attack through different kernel interfaces.**

### What's Proven Dead

1. **Cross-subsystem spray** — Sony per-type zone isolation (20+ probes, 0 overlap)
2. **AIO 663/664/666/667 readback** — returns computed status words, not raw freed memory
3. **Simple file refcount accumulation** — 65r: 100 double-frees, fd survived (exclusive lock serializes)
4. **Sys 624 as reclaim detector** — counts page-level VM ops, slab allocations invisible

### What's Alive

| Priority | Approach | Confidence | Source Agents |
|----------|----------|-----------|---------------|
| **1** | Submit-during-delete (handle recycling → Thread B frees live object) | HIGH | 1, 2, 4, 6, 9 |
| **2** | sys 665 `aio_get_data` with valid IDs | HIGH | 3 |
| **3** | 663 mode parameter sweep | MEDIUM-HIGH | 3, 6 |
| **4** | entry_dispose arbitrary decrement at I+0x40 | MEDIUM | 2, 5, 6, 9 |
| **5** | rdtsc gadget at unaligned offsets for nanosecond KASLR timing | MEDIUM | 3 |
| **6** | File refcount via careful single-decrement verification | MEDIUM | 3, 7 (contested by 5) |

### Structural Insights

1. **The TOCTOU window is check-then-act, not a locking bug** — both threads pass validation before the free path. The 14.20 patch adds generation revalidation.
2. **Per-CPU caching creates the strongest double-free form** — two CPUs each hold the freed block → two allocations share the same physical memory → type confusion between two controlled objects.
3. **16KB pages favor the spray** — 256 objects/slab means higher probability of reclaim per page, but bucket drain requires ~4096-16384 allocations.
4. **Object R contains thread/process/credential kernel pointers** — if readable after reclaim, it's a direct KASLR source.
5. **The Lapse exploit (earlier PS5 firmware) used socket/evf readback, NOT AIO queries** — this is why our probes failed where Lapse succeeded.

### Probe Queue (Priority Order)

| # | Probe | Purpose | Blocking? |
|---|-------|---------|-----------|
| 1 | **68a** (zone overlap) | Determine if 65l causes real zone-level double-free or just double-success | YES |
| 2 | **68e** (sys 665 valid IDs) | Test completely untested readback path | YES |
| 3 | **68f** (663 mode sweep) | Explore unexplored mode parameters | YES |
| 4 | **68d** (624 oracle) | Characterize VM-op behavior during AIO lifecycle | Informational |
| 5 | **68g** (submit-during-delete) | Force handle recycling for true UAF | If 68a is negative |
| 6 | **68h** (rdtsc unaligned scan) | Find nanosecond timing gadgets | KASLR path |

### What Changed From Session 2

| Session 2 Conclusion | Session 3 Update |
|---------------------|------------------|
| Cross-subsystem spray might work with SO_LINGER/evf | **DEAD** — per-type zone isolation proven structural |
| File refcount UAF is top KASLR path | **CONTESTED** — 65r shows refcount doesn't accumulate; exclusive lock serializes |
| AIO readback (663/664) is the detection path | **DEAD** — returns computed status, not raw memory |
| Submit-during-delete is one option | **ONLY option** for true zone-level UAF |
| sys 665 untested | **Still untested** — now HIGHEST priority gap |

## Action Items

1. Send probe 68a FIRST — it determines the fundamental nature of the exploit (real double-free vs double-success)
2. Write and send sys 665 probe regardless of 68a result
3. Write and send 663 mode sweep regardless of 68a result
4. If 68a negative: immediately design submit-during-delete probe
5. Acquire 14.10 kernel image if any path opens (confirms zone layout, object sizes, allocator behavior)

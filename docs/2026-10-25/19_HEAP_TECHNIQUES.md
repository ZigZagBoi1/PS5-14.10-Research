# Finding 19: FreeBSD Heap Exploitation Adapted for PS5 14.10

> **Date:** 2026-10-25 Session 3
> **Agent:** freebsd-exploit-research
> **Document:** docs/HEAP_EXPLOITATION_TECHNIQUES_ADDENDUM.md

---

## Sony Custom Allocator — Three Architectures

| Architecture | Description | Cross-Zone Spray? |
|-------------|-------------|-------------------|
| A: UMA wrappers | Sony created dedicated UMA zones per subsystem | Only if two subsystems share a zone |
| B: Bump pools | Per-subsystem page-backed pools | No cross-subsystem reclaim at all |
| C: malloc wrappers | Zone pointer selects malloc type tag | Yes, for same-size objects |

**Live evidence (20+ probe failures) points to Architecture A or B.** The allocator is zone-isolated.

## 16KB Page Impact

- 64B zone: **256 objects/slab** (vs 64 on 4KB pages)
- 128B zone: **128 objects/slab** (vs 32 on 4KB pages)
- Larger slabs FAVOR spray hit rate (more objects per page)
- Per-CPU bucket drain requires **4096-16384 allocations** (significant resource cost)
- Recommended spray density: **500-1000 objects** per phase

## Per-CPU Cache and the Double-Free

The double-free fires between two child threads on **different CPUs** (67b confirmed). The freed block enters BOTH CPUs' free lists:

```
CPU A's bucket: [freed block, ...]
CPU B's bucket: [freed block, ...]  (same block!)
```

Spray on CPU A reclaims one copy; spray on CPU B reclaims the other. After both reclaims: **two different kernel objects occupy the same physical memory** → type confusion. This is the strongest form of the primitive.

## 0x102 Allocation Flags

- Bit `0x100`: zero-fill on allocation
- Bit `0x2`: M_NOWAIT equivalent
- Zero-fill means spray objects start clean — but the stale data from the FIRST free survives until reclaim

## Four Concrete Exploitation Sequences

1. **Self-spray with handle recycling** — submit → double-free → submit again → cross-kill detection
2. **File refcount exhaustion** — accumulated double-decrements → file object freed → fstat on dangling fd
3. **Cross-type spray (EVF/namedobj)** — structurally blocked by zone isolation, but Lapse used evf successfully on earlier firmware (different allocator config?)
4. **Full Lapse-pattern adaptation** — SO_LINGER spray + evf for KASLR + socket option overlap for R/W

## Primary Blocker Resolution

The handle table insulates all AIO query paths from raw freed memory. Four approaches to break through:
1. **Submit-during-delete** (HIGHEST PRIORITY) — force handle recycling
2. **Read through non-AIO interfaces** (fstat, getsockopt, evf query)
3. **entry_dispose arbitrary decrement** — doesn't need readback
4. **Controlled slab exhaustion** — force cross-page allocation visible to 624

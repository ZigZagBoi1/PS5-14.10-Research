# Syscall 624 as Heap Manipulation Oracle — Analysis

## Status: Probe 68d written, not yet run (2026-10-25)

## Summary

Syscall 624 is a monotonic, zero-jitter VM operation counter confirmed in probe 52b.
This document analyzes its utility as a side channel during AIO double-free exploitation.

**Bottom line: 624 counts page-level VM operations, NOT slab allocations. It cannot
directly detect slab reclaim (the core AIO exploit event), but it CAN serve as a
deterministic heap grooming verification tool and may detect slab page backing
changes during high-volume allocation bursts.**

---

## 1. What 624 measures (from probe 52b)

| Operation | Delta | Interpretation |
|---|---|---|
| `mmap(N pages)` | **+5** (constant, any size 1-16 pages) | VM mapping creation: page table update |
| Page touch (first write to 32 pages) | **+1** (somewhere between page 128-160) | Likely COW/demand-zero fault batch |
| `munmap` | **+0** | VM unmap doesn't increment |
| 10 sockets | **+0** | Socket = slab object, no VM op |
| kqueue | **+0** | Slab object |
| 8× `memory.alloc(0x1000)` | **+0** | Userland heap, pre-faulted |
| `dynlib_get_info` | **+0** | Read-only query |
| 100 tight reads | **jitter=0** | Perfectly stable within a connection |

**Critical insight:** The counter increments for page-table-level operations (new VA
mapping, COW fault). It does NOT increment for slab/zone allocations. Since AIO
objects (I=0x58, R=0x30, Q=0x58) are slab-allocated from Sony's custom zones, their
allocation and deallocation are invisible to 624.

---

## 2. Can 624 detect slab reclaim?

### Direct detection: NO (predicted)

A "reclaim" means: after double-free, a new allocation from the same zone returns
the freed chunk's address. This is entirely within the slab allocator — it returns
a chunk from the zone's freelist without requesting new pages from the VM system.
Expected delta: **0**.

### Indirect detection: POSSIBLE (slab page backing)

When a slab zone exhausts its current page(s), it requests a new page from the VM
subsystem. This page allocation *might* be visible as a 624 delta. The test plan:

1. Create many objects from the same zone until the zone's page(s) fill up
2. Watch for a 624 step at the page boundary
3. If a step occurs, the zone's page size and objects-per-page are revealed

For the AIO I object (0x58 = 88 bytes), on a 16KB page:
- Objects per page: `16384 / 88 = 186` (max, without headers)
- With zone metadata overhead: probably ~170-180 objects per page

If 624 steps after ~180 AIO submits, we know a new slab page was allocated.

### Probe 68d section [E] tests this with 500 namedobj creates (batches of 50).
If any batch causes a 624 step, the zone-to-page relationship is revealed.

---

## 3. Expected probe 68d results

### Section [A]: Individual AIO op deltas
- **Predicted:** submit=0, poll=0, delete=0. All three are slab-level operations.
- **If submit ≠ 0:** The AIO submit path touches the VM system (e.g., maps a
  kernel buffer for the DMA target). This would be significant — it means AIO
  requests cause page-level activity.

### Section [B]: Batch submit scaling
- **Predicted:** All deltas = 0, regardless of batch size.
- **If delta > 0 at some batch size:** There's a page allocation threshold. For
  example, if 32 submits gives delta=0 but 64 gives delta=+1, the zone's page
  fills at ~32-64 objects and requests a new page.

### Section [C]: Race deltas
- **Predicted:** delta = +10 (two `thr_new` calls → two thread stacks → two mmaps
  → 2 × 5 = +10). The 662 race itself (slab frees) contributes 0.
- **If delta ≠ +10:** Something unexpected in the race path touches the VM.

### Section [D]: Cross-subsystem slab objects
- **Predicted:** All 0. namedobj, evf, socketpair, shm_open are all slab objects.
- **Exception:** `shm_open` creates a vm_object, which might involve page ops.

### Section [E]: High-volume slab stress
- **This is the money section.** 500 namedobj creations, monitored every 50.
- **If a step occurs:** We know the zone's page capacity. This is exploitable —
  we can predict when a page boundary will be crossed during spray.
- **If no step:** The zone pre-allocated enough pages, or the allocator uses a
  different page source that 624 doesn't count.

### Section [F]: Mmap grooming verification
- **Predicted:** All deltas = N × 5. This section validates that 624 works as a
  deterministic grooming checker.

### Section [G]: Full exploit timeline
- **Predicted timeline:**
  ```
  start                    val=X     delta=+0
  after_16_submit          val=X     delta=+0   (slab)
  after_16_poll            val=X     delta=+0   (slab)
  before_race              val=X     delta=+0
  after_race               val=X+10  delta=+10  (2 thread stacks)
  after_128_spray          val=X+10  delta=+0   (slab AIO spray)
  after_64_namedobj        val=X+10  delta=+0   (slab namedobj spray)
  after_4_mmap             val=X+30  delta=+20  (4 × 5 = 20)
  after_cleanup            val=X+30  delta=+0   (slab deletes)
  ```
- **Deviations indicate VM-level side effects of slab operations.**

---

## 4. How 624 IS useful for the exploit

Even though 624 can't detect slab reclaim directly, it has three exploitation uses:

### 4a. Heap grooming verification

Before triggering the double-free, the exploit must set up the heap in a specific
way (e.g., map GPU pages for R/W, create socketpairs for communication). 624
provides a **deterministic, zero-jitter check** that the grooming operations
succeeded:

```
expected = (N_gpu_pages + N_thread_stacks) × 5
actual = read_624() - baseline
assert(expected == actual)  -- grooming verified
```

This replaces timing-based heuristics with an exact count.

### 4b. Slab page boundary detection (if section [E] shows steps)

If 624 steps when a zone exhausts its page, we can:
1. Spray exactly enough objects to fill a page minus one
2. Trigger the double-free
3. Spray one more object — if it lands on the same page, it reclaims
4. If 624 steps instead, a new page was allocated → reclaim failed

This gives a **binary oracle for reclaim success**.

### 4c. VM operation fingerprinting

Each kernel subsystem has a VM-op signature. By measuring 624 deltas for different
operations, we can build a fingerprint table:

```
mmap:           +5
thr_new:        +5 (stack mmap)
AIO submit:     +0 or +N (to be measured)
namedobj:       +0 or +N
shm_open:       +0 or +N
```

This table tells us which operations are "VM-noisy" and which are "VM-silent."
VM-silent operations are better for exploitation because they don't change the
VM state, making the exploit more deterministic.

---

## 5. Alternative side channels for slab reclaim

Since 624 likely can't detect slab reclaim, other approaches are needed:

| Approach | How | Status |
|---|---|---|
| **Poll-flag oracle (67c)** | Poll even indices, check if odd indices see the flag | First 67c run showed 100% overlap (likely artifact); second run 0 doubles |
| **AIO self-spray** | Submit new AIO after double-free, check if 663 returns anomalous state | Probes 67d/67e testing |
| **Interleaved delete** | Delete odd spray objects, check if even objects crash or corrupt | 67c section [B] |
| **Cross-subsystem spray** | namedobj/evf after double-free, then AIO 663/666 on old IDs | 67f testing |
| **Result word anomaly** | 669 result word should be bytes-transferred; if it's something else → reclaim | Not yet tested |
| **entry_dispose crash** | If I+0x40 is controlled, entry_dispose dereferences it → crash at known address | Destructive but proves reclaim |

---

## 6. Relationship to the overall exploit chain

The double-free (65l confirmed) → spray → reclaim → kernel R/W chain needs:

1. **Reclaim detection** — know that our spray landed in the freed slot
2. **Controlled data** — put specific values at I+0x40 (file pointer for refcount decrement)
3. **KASLR defeat** — read a kernel pointer from the reclaimed/dangling object

624's role is primarily in step (1) as supplementary verification and in the
grooming phase before step (1). It is not the primary reclaim detection mechanism —
that must come from the AIO subsystem itself (663/664/666 status changes, or
entry_dispose side effects).

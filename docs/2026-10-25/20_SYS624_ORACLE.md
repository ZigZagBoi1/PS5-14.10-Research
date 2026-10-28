# Finding 20: Syscall 624 VM-Op Oracle — Capabilities and Limits

> **Date:** 2026-10-25 Session 3
> **Agent:** sys624-oracle
> **Probe:** probes/phase16_kwrite/68d_624_heap_oracle.lua (written, not yet run)

---

## What 624 Measures

Syscall 624 is a monotonic, zero-jitter VM operation counter. From probe 52b:

| Operation | Delta | Notes |
|-----------|-------|-------|
| mmap (any size) | +5 | Page table update |
| Page touch (COW fault) | +1 | At ~128-160 page boundary |
| munmap | +0 | No increment |
| Socket/kqueue/heap alloc | +0 | Slab-level, invisible |
| dynlib_get_info | +0 | Read-only query |
| 100 tight reads | jitter=0 | Perfectly stable |

## What 624 CAN Do

1. **Heap grooming verification** — deterministically confirm mmap operations: expected = N × 5
2. **Race fingerprinting** — the race should produce delta=+10 (two thr_new thread stacks). Deviations indicate unexpected VM activity
3. **Slab page boundary detection** — if a zone exhausts its page and requests a new VM page, 624 may step. Probe 68d section [E] tests this with 500 namedobj in batches of 50

## What 624 CANNOT Do

- **Direct slab reclaim detection** — AIO object alloc/free (zone-level) is invisible
- **Distinguish allocation vs reclamation** — both are slab operations with delta=0
- **KASLR defeat** — no intra-kernel address discrimination (confirmed 56f)

## Predicted Probe 68d Results

```
after_16_submit:   delta=+0  (slab, invisible)
after_16_poll:     delta=+0  (slab)
after_race:        delta=+10 (2 thread stacks × 5)
after_128_spray:   delta=+0  (slab AIO spray)
after_64_namedobj: delta=+0  (slab)
after_4_mmap:      delta=+20 (4 × 5)
```

## Exploitation Use

The money shot is section [E]: if 624 ever steps during high-volume slab allocation (~500 objects), the zone-to-page relationship is revealed. If the step occurs at, say, object #180, we know the zone holds ~180 objects per 16KB page. This knowledge enables:

- **Precise slab filling** — spray exactly enough objects to fill the current page
- **Binary reclaim oracle** — spray fills page → next alloc either reclaims (delta=0) or crosses page boundary (delta>0)
- **Heap grooming verification** — confirm the heap state before triggering the exploit

**Bottom line:** 624 is a grooming/verification tool, not the primary reclaim detector. Use it to confirm setup state, not to detect the exploit itself.

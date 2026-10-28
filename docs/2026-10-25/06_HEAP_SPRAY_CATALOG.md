# Heap Spray Primitive Catalog

**Date:** 2026-10-25
**Source:** Agent 6 -- Spray primitive inventory (max effort)

## Target: AIO Double-Free Freed Objects

From the 13.60 decompiled `aio_multi_delete` (RVA `0x3af920`), the 662 TOCTOU double-free hits these allocations per request:

| Object | Size | 13.60 Zone RVA | Probable UMA Class |
|--------|------|----------------|-------------------|
| Saved execution context | 0x30 (48B) | `0x1ab59e0` | 64-byte zone |
| Queue entry / completion header | 0x58 (88B) | `0x1ab5970` / `0x1ab5900` | 128-byte zone |
| AIO top-level object | 0x30 (48B) | `0x1ab59e0` | 64-byte zone |
| Queue entry pointer array | count x 8 (variable) | `0x1ab5890` | variable |

The 0x30-byte saved context contains kernel pointers (thread, proc, ucred) -- prime KASLR target.
The 0x58-byte queue entry contains a file object pointer at `+0x40` -- prime R/W target.

## Tier 1: Same Subsystem (Highest Reclaim Confidence)

| # | Primitive | Syscall | Size | Content Control | Readback | Rate |
|---|-----------|---------|------|----------------|----------|------|
| 1 | **AIO self-spray (669)** | 669 | 0x58 + 0x30 | Partial (fd, cmd, offset, count) | State via 664 poll | 1-128/call |

Same allocator path with same zone descriptors. The new request's queue entry and saved context land in the exact zones the double-free empties.

## Tier 2: Cross-Subsystem, Matching Size Classes

| # | Primitive | Syscall | Size | Content Control | Readback | Rate |
|---|-----------|---------|------|----------------|----------|------|
| 2 | namedobj_create | 557 | ~48-96B | Name (0x20B) + value | Handle only | Fast |
| 3 | evf_create | 538 | ~0x80 (128B) | initial_pattern (8B) | evf_poll (543) | Fast |
| 4 | kqueue knote | 363 | ~0x60-0x80B | Filter/ident/fflags/data | kevent read | Fast (batch) |
| 5 | setsockopt buffer | 105 | Variable | **Full** | getsockopt (118) | Fast |
| 6 | sendmsg mbuf | 28 | 256B (MHLEN) | **Full** | recvmsg (27) | Very fast |
| 7 | socketpair | 135 | ~0x100B+ | Minimal | No | Moderate |
| 8 | socket | 97 | ~0x240B | Minimal (via setsockopt) | getsockopt | Moderate |
| 9 | shm_open metadata | 482 | Large | Name | No | Moderate |

**IMPORTANT:** Agent 3's results analysis proved that cross-subsystem spray has NEVER reclaimed a freed AIO slot across 60 result files. These Tier 2 primitives are included for completeness but are likely non-viable for AIO zone reclaim.

## Tier 3: Indirect / Limited

| # | Primitive | Syscall | Size | Content Control | Readback | Rate |
|---|-----------|---------|------|----------------|----------|------|
| 10 | sigaction handler | 416 | ~120B/signal | Handler, mask, flags | Old disposition | 31 max |
| 11 | UMTX mutex | 454 | ~0x30-0x60B | TID word | None | Limited |
| 12 | ktimer | 235 | ~0x60B | Timer params | gettime | 27 max |

## Recommended Spray Pattern

```
Phase 1 -- Groom the heap:
  - Allocate 64 AIO requests (16 x 4 iterations, individual 669 submits)
  - Poll all 64 via 664
  - This fills AIO zone slabs densely

Phase 2 -- Create the hole:
  - Select 16 IDs for the race
  - Spawn child A: 662(ids, 16, states_A)
  - Spawn child B: 662(ids, 16, states_B)
  - ~13.5% of IDs double-freed (2-3 per iteration)
  - Wait for children via UMTX or socketpair signal

Phase 3 -- Reclaim:
  Path A (KASLR via 0x30 context):
    - 128 x setsockopt with 48-byte buffers (if general 64-byte zone)
    - Or 128 x namedobj_create(557) with unique names
  Path B (type confusion via 0x58 entry):
    - 128 x AIO 669 submits on a chosen fd (e.g., /dev/zero = fd 22)
    - New queue entries fill the freed 0x58-byte slots

Phase 4 -- Exploit the dangling pointer:
  Path A: 667 enumerate -- if saved context was reclaimed,
          fields may contain controlled bytes instead of kernel pointers
  Path B: 662 again on double-freed IDs -- free_queue_entry
          accesses file pointer at +0x40
  Path C: getsockopt readback if setsockopt spray was used
```

## Critical Constraints

- **Never call 670 (aio_init)** -- permanently poisons the 662 delete path
- **Submit individually** via 669 (count=1 each) -- batch submit only creates one request
- **Poll via 664 before delete** -- unpolled requests return 0x80020010 on 662
- **Max 4 controlled syscall args** from child thread
- **16KB pages** on PS5 -- UMA slabs are 16KB, so 64-byte zone = 256 objects/slab, 128-byte zone = 128 objects/slab

## Key Reference Files

- `docs/AIO_13_60_ANALYSIS.md` -- full 13.60 decompile with object hierarchy
- `docs/AIO_DOUBLE_FREE_14_10.md` -- confirmed 14.10 double-free
- `docs/AIO_BATCH_14_10.md` -- 669 contract and request descriptor layout
- `docs/OBJECT_TABLE_14_10.md` -- shared handle table behavior
- `docs/research/relapse_variant_analysis.md` -- Relapse exploit structure

# Verification: Heap Spray Candidate Rankings

**Date:** 2026-10-25
**Reviewed:** `docs/HEAP_SPRAY_CANDIDATES.md` rankings vs actual probe evidence

---

## Verdict Summary

| Candidate | Claimed Score | Corrected Score | Reason |
|-----------|--------------|-----------------|--------|
| setsockopt (105) | 9/10 | **5/10** | No evidence of variable-size kernel heap allocation; no getsockopt readback ever tested |
| evf_create (538) | 8/10 | **4/10** | Tested in 66e: 0 anomalies despite 12 double-frees. Cross-spray failed empirically |
| namedobj_create (557) | 8/10 | **3/10** | Tested in 65n, 65w, 66e: 0 corruption across hundreds of trials |
| AIO self-spray (669) | 8/10 | **7/10** | 65p confirmed handle-level overlap. But readback is limited to 4-byte status dword |
| osem_create (549) | 7/10 | **2/10** | Returns -1 for 8 scalar shapes (252a) AND with name pointers (253a). 435a's handle may be from a different arg shape (4th arg) never tested in spray context |

---

## Detailed Findings

### 1. setsockopt (105) — Claimed 9/10, Corrected to 5/10

**What the document claims:** "Full content control, variable size, unlimited sockets. Sony custom options accepted 256B writes."

**What the evidence shows:**
- Probe 65m: `set IP_OPTIONS on 64 sockets` — but post-spray poll on double-freed IDs returned `0x80020003` (unchanged from pre-spray). Zero reclaim signal.
- Probe 65n: `setsockopt(IP_OPTIONS,40): delta=0` — the VM-op counter showed zero operations, meaning setsockopt may NOT trigger a kernel heap allocation at all (or it's too small to cause a zone page allocation).
- Probe 65t section D: `Cross-subsystem spray: socketpair + setsockopt between frees` — produced `nobj=50 sp=32/32` but no corruption metrics shown; the probe didn't check for overlap.
- **No probe ever tested getsockopt readback.** The `getsockopt` round-trip (write sentinel → read back → check for corruption) was never attempted.
- **The "256B writes" claim** (Finding 32 / Sony custom options) is about the setsockopt return value, not confirmation of kernel heap allocation. The kernel may just validate and ignore the buffer, or copy into a fixed-size field.

**Critical gap:** The #1 ranked spray has never been verified to allocate variable-size kernel heap objects, and getsockopt readback has never been tested. The high score is entirely hypothetical.

**However:** The Lapse exploit reportedly uses socket options (including SO_LINGER) for spray. If Lapse works on PS5, then setsockopt DOES allocate kernel memory in the right zone — our probes simply used the wrong options or didn't test readback. The score should reflect "unverified but plausible given Lapse."

### 2. evf_create (538) — Claimed 8/10, Corrected to 4/10

**What the document claims:** "32B name control, fast handle alloc, shared object table with AIO, 1000+ per process."

**What the evidence shows:**
- Probe 65n: "created 0 evf objects" — the spray call itself failed (likely wrong argument shape; 65v shows `evf_create(0,0) = -1` but `evf_create(name, 0x100) = 17065`).
- Probe 65v: EVF create works with `(name, 0x100)` but all cross-spray attempts produced zero corruption. Section D skipped ("EVF not functional" — probe couldn't integrate EVF into the race+spray pipeline).
- Probe 65w: EVF create works (handle 33453). EVF tryWait works with `mode=0` and returns the set bit pattern (`0xDEAD`). But no double-free spray integration was tested.
- Probe 66e: Full test. 12 double-frees, 32 evf created, 32 namedobj created, 32 sockets, 16 AIO spray → **TOTAL anomalies: 0**.

**Assessment:** evf_create works, tryWait reads back bit patterns, but spray after double-free produced zero zone overlap. Either:
- (a) EVF objects are in a different zone than AIO sub-objects, or
- (b) The spray count (32) was too small to drain per-CPU caches, or
- (c) The Lapse chain uses a more sophisticated spray technique we haven't replicated.

The 8/10 rating assumed shared zone based on shared handle table — but sharing a handle table does NOT mean sharing a UMA zone. The handle table is metadata; the objects are in separate zones.

### 3. namedobj_create (557) — Claimed 8/10, Corrected to 3/10

**What the document claims:** "Same table, not deduplicated, individually deletable."

**What the evidence shows:**
- Probe 65m: `created 128 namedobjs` → poll on double-freed IDs: `0x80020003` (unchanged). Zero reclaim.
- Probe 65n: `256 namedobjs` + `64 kqueues` → `namedobj corruption: 0/256, kqueue corruption: 0/64`.
- Probe 65w: 5 trials × (32 double-frees + 64 namedobjs + 32 AIO spray) → `no_del=64/64` every trial. Zero corruption.
- Probe 66e: 32 namedobjs created post-double-free → 0 anomalies.

**Assessment:** namedobj spray has been tested FOUR times across different probes with hundreds of objects, always producing zero corruption. The evidence conclusively shows namedobjs do NOT reclaim AIO double-freed slots. Rating 8/10 contradicts the data.

### 4. AIO self-spray (669) — Claimed 8/10, Verified at 7/10

**What the document claims:** "Same zone as freed descriptor, full 40B control per request."

**What the evidence shows:**
- Probe 65p: **OVERLAP CONFIRMED.** After double-free + new AIO submissions:
  - `killed=6/6` — deleting first-half AIO requests invalidated second-half requests
  - `cross_killed=3` — same effect in single-submit test
  - `wait_anom=6` — 663 on overlapping IDs returned anomalous status (value not printed)
  - This proves two AIO requests sharing the same kernel memory.
- All other self-spray probes confirm AIO-only reclaim works.

**Limitation:** The overlap is only observable through handle invalidation (delete A → B becomes invalid). The `wait_anom=6` shows 663 returned something other than 0 or 0xDEAD, but the actual value wasn't printed — this is a MISSED diagnostic opportunity. If those anomalous values contained kernel pointer fragments, it would be KASLR defeat.

**Critical follow-up:** Re-run 65p with the anomalous wait values printed in hex. If any `wait_anom` value has bits in the `0xFFFF8xxx` range, it's a kernel pointer.

### 5. osem_create (549) — Claimed 7/10, Corrected to 2/10

**What the document claims:** "32B name + init/max values, similar struct size."

**What the evidence shows:**
- Probe 252a: Returns -1 for 8 scalar shapes: `549(0)`, `549(1)`, `549(2)`, `549(0x10)`, `549(0,0)`, `549(1,0)`, `549(0,1)`, `549(0x10,0,0)`.
- Probe 253a: Returns -1 for all name-based shapes: `549(name)`, `549(name,1)`, `549(1,name)`, `549(name,1,0)`.
- CLAUDE.md dead ends: "osem (549-556) — 549 osem_create returns -1 for eight scalar shapes and for a NUL-terminated name pointer in either slot, so the family is unreachable."
- Probe 435a: `osem[1]=518` with `549(name, 0, 0, k+1, 0)`. This uses arg4 = `k+1` (non-zero), which was NOT tested in 252a/253a. This may be the required signature, but it's from a later probe (2026-10-23) and was never tested in a spray context.

**Assessment:** Documented as dead in CLAUDE.md. The 435a result suggests a possible arg shape but is unverified for spray. Rating 7/10 with a dead-end classification is contradictory.

---

## Corrected Rankings

| Rank | Primitive | Score | Justification |
|------|-----------|-------|---------------|
| 1 | **AIO self-spray (669)** | **7/10** | Only primitive with CONFIRMED zone overlap (65p). Readback limited to 4-byte status. `wait_anom=6` values need investigation |
| 2 | **setsockopt (105)** | **5/10** | Used by Lapse (external validation) but never confirmed on 14.10. No getsockopt readback tested. Zero reclaim in 3 probes |
| 3 | **evf_create (538)** | **4/10** | Works mechanically. Used by Lapse. 66e tested spray: 0 anomalies. May need different technique (larger count, CPU-aligned spray) |
| 4 | **namedobj_create (557)** | **3/10** | 4 probes, 0 reclaim. Conclusively in a different zone |
| 5 | **osem_create (549)** | **2/10** | Dead per CLAUDE.md. 435a hint for arg shape unverified in spray context |

---

## Critical Findings

### A. The `wait_anom=6` in Probe 65p Is Uninvestigated

Probe 65p's AIO self-overlap produced `wait_anom=6` — six anomalous wait (663) status values. The probe checks `if wst ~= 0 and wst ~= 0xDEAD then wait_anomalies = wait_anomalies + 1` but **never prints the actual anomalous values**. 

If these values are `0x80020003` (deleted), that's just handle invalidation — expected from overlap.
If these values contain kernel pointer fragments, that's KASLR defeat.

**Recommendation:** Write a probe that reproduces 65p's self-overlap and prints every anomalous wait value in full hex (both hi and lo words).

### B. getsockopt Round-Trip Was Never Tested

The #1 ranked spray (setsockopt) has never been paired with getsockopt readback in any phase 16 probe. This is the most basic verification: `setsockopt(sentinel) → getsockopt() → check sentinel survives`. Without this, we don't know if setsockopt allocations are readable.

### C. The Lapse Contradiction

The document says "cross-subsystem spray is proven dead — AIO objects live in dedicated UMA zones." But the Lapse exploit (same bug, same allocator) successfully uses socket options + evf for spray. Either:
1. The zones aren't as dedicated as concluded — Lapse proves cross-subsystem spray works
2. Lapse uses a technique we haven't replicated (e.g., different spray sizes, per-CPU cache draining, IPv6 routing headers for zone crossing)
3. Sony changed the allocator between Lapse's target (≤10.01) and 14.10

This contradiction is the most important unresolved question. The document should NOT rate cross-subsystem spray as dead while simultaneously citing Lapse as using it.

### D. Per-CPU Cache Draining Was Insufficient

Probe 65t section C "Pre-drain approach" used 64 AIO submit+delete cycles, which is far below the ~200-thread bucket exhaustion used by Praetorian's technique. The drain may have been too small. 66f measured 512 concurrent AIO requests as the budget — a proper drain would need to allocate and free 512+ objects from the target zone before spraying.

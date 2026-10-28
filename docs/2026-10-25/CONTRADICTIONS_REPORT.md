# Cross-Document Contradictions Report

**Date:** 2026-10-25
**Scope:** All 13 documents in `docs/2026-10-25/` plus 8 agent-produced documents in `docs/`

---

## C1: Object-to-Zone Mapping Disagrees Across Documents

**Severity: CRITICAL — affects all spray planning**

| Document | R (sub-object) zone | R size | I (queue entry) zone | I size |
|----------|---------------------|--------|----------------------|--------|
| AIO_OBJECT_FORENSICS.md | `0x1ab59e0` | 0x30 (48B) | `0x1ab5900` | 0x58 (88B) |
| AIO_13_60_ANALYSIS.md | `0x1ab59e0` | 0x30 (48B) | `0x1ab5900` | 0x58 (88B) |
| 13_FREED_OBJECT_FORENSICS.md | `0x1ab59e0` | 0x30 (48B) | `0x1ab5900` | 0x58 (88B) |
| 01_AIO_EXPLOIT_STRATEGY.md | `0x1ab59e0` | — (says "per-request metadata") | `0x1ab5970` and `0x1ab5890` | — |
| HEAP_SPRAY_CANDIDATES.md | `0x1ab5970` | 0x58 (88B) (labeled "saved context") | `0x1ab5a50` | 0x30 (48B) |
| 06_HEAP_SPRAY_CATALOG.md | `0x1ab59e0` | 0x30 (48B) ("saved execution context") | `0x1ab5970` / `0x1ab5900` | 0x58 (88B) |
| EXPLOIT_CHAIN_DESIGN.md | `0x1ab59e0` | 0x30 (48B) ("completion record") | `0x1ab5970` | 0x58 (88B) ("sub-request data") |
| 05_AIO_STRUCTURE_ANALYSIS.md | zone at `[rip+0x1705af8]` | 0x40-0x80B (estimate) | — | — |

**The contradiction:**
- `HEAP_SPRAY_CANDIDATES.md` **swaps** the zone assignments: it labels zone `0x1ab5970` as "saved context" with size 0x58, and zone `0x1ab5a50` as "queue entry" with size 0x30. This is the opposite of `AIO_OBJECT_FORENSICS.md` and `AIO_13_60_ANALYSIS.md`.
- `01_AIO_EXPLOIT_STRATEGY.md` maps `*(lVar8+0x18)` to zone `0x1ab59e0` (consistent) but then lists zones `0x1ab5970` and `0x1ab5890` for sub-objects, omitting `0x1ab5900`.
- `05_AIO_STRUCTURE_ANALYSIS.md` gives no fixed zone address, only an RIP-relative reference, and estimates the freed object size as "0x40-0x80 bytes" which is a wider range than the other documents' 0x30.
- `EXPLOIT_CHAIN_DESIGN.md` labels the 0x30 as "completion record" while `AIO_OBJECT_FORENSICS.md` calls it "request metadata (R)" and `AIO_13_60_ANALYSIS.md` calls it "saved execution context."

**More reliable source:** `AIO_OBJECT_FORENSICS.md` and `AIO_13_60_ANALYSIS.md` cite specific decompile lines (sys_662.c lines 2607, 2622, 2636, 649). `HEAP_SPRAY_CANDIDATES.md` appears to have swapped its table contents.

**Resolution:** The zone mapping from `AIO_OBJECT_FORENSICS.md` should be treated as canonical:
- R = 0x30 bytes, zone `0x1ab59e0` (freed first)
- I = 0x58 bytes, zone `0x1ab5900`
- Q = 0x58 bytes, zone `0x1ab5970`
All other documents should be corrected to match. `HEAP_SPRAY_CANDIDATES.md` needs its table rewritten.

---

## C2: Object Naming Inconsistency

**Severity: MODERATE — causes confusion across documents**

The same physical objects get different names:

| Object (canonical) | AIO_OBJECT_FORENSICS | AIO_13_60_ANALYSIS | HEAP_SPRAY_CANDIDATES | EXPLOIT_CHAIN_DESIGN | 05_AIO_STRUCTURE |
|--------------------|---------------------|--------------------|-----------------------|---------------------|------------------|
| R (0x30, zone 59e0) | "Request metadata" | "Saved execution context" | "Saved context" (WRONG zone listed) | "Completion record" | "Sub-object at I+0x18" |
| I (0x58, zone 5900) | "Indexed object / queue entry" | "Per-request queue entry" | "Queue entry" (WRONG zone) | "Sub-request data" | "Indexed Object" |
| Q (0x58, zone 5970) | "Request aggregate" | "Completion header" | "Completion header" | Not separately named | "Aggregate Q" |

**Resolution:** Adopt the `AIO_OBJECT_FORENSICS.md` naming convention (R/I/Q/D) uniformly.

---

## C3: Is the Allocator UMA or Sony-Custom?

**Severity: CRITICAL — determines whether cross-subsystem spray can ever work**

| Document | Claim |
|----------|-------|
| AIO_OBJECT_FORENSICS.md §4 | "Sony's custom allocator, NOT standard FreeBSD UMA zones" |
| 01_AIO_EXPLOIT_STRATEGY.md | "`func_0x00c08df0` takes `(pointer, zone)` -- this is `uma_zfree()`" |
| 05_AIO_STRUCTURE_ANALYSIS.md | "Routes to UMA zone path (small objects)" — "Confidence: HIGH for UMA zone" |
| FREEBSD_EXPLOIT_TECHNIQUES.md §3 | "FreeBSD's UMA (Universal Memory Allocator) is FreeBSD's slab allocator" (assumes standard UMA) |
| HEAP_SPRAY_CANDIDATES.md | "Sony's custom allocator" at top, then references UMA zone sizes throughout |
| 03_RESULTS_ANALYSIS.md | "AIO uses dedicated zones" (ambiguous — could be UMA dedicated or Sony-custom) |
| 13_FREED_OBJECT_FORENSICS.md | "Sony-custom allocator zone addresses, not standard UMA zone descriptors" but also "FreeBSD UMA has NO double-free detection" |
| 12_BLOCKERS_AND_NEXT_STEPS.md | Flags this as an unresolved contradiction |

**Analysis:** `AIO_OBJECT_FORENSICS.md` claims Sony-custom because the zone arguments are data-segment RVAs, not UMA zone name strings. However, `05_AIO_STRUCTURE_ANALYSIS.md` traced the allocator function `0xc08b50` and found it checks a size threshold, routes small objects through a zone path, and uses `[rip + offset]` for zone identification — which is exactly how UMA zone pointers work (they're static globals storing `uma_zone_t` pointers, not name strings).

**The decisive evidence:** The Lapse exploit (confirmed by `FREEBSD_EXPLOIT_TECHNIQUES.md` and `11_LAPSE_PROLAPSE_IDENTIFICATION.md`) uses socket options and evf objects to reclaim AIO slots. If the allocator were truly Sony-custom and isolated, cross-subsystem spray could not work. Lapse's success proves the allocator IS UMA-compatible, and AIO zones share the allocator with socket/evf objects.

**But:** `03_RESULTS_ANALYSIS.md` documents that cross-subsystem spray failed across 60 result files. This could mean: (a) our spray sizes were wrong, (b) per-CPU cache isolation prevented reclaim, or (c) the zones are genuinely separate on 14.10 (even if they weren't on Lapse's target firmware ≤10.01).

**Resolution:** The allocator is almost certainly Sony's wrapper around UMA (or a compatible zone allocator). The "dedicated zones" finding means AIO-specific zones, not a wholly separate allocator. The cross-subsystem spray failure is better explained by **wrong spray sizes or per-CPU cache effects** than by a non-UMA allocator. `AIO_OBJECT_FORENSICS.md`'s "NOT standard FreeBSD UMA" claim should be softened to "Sony wrapper around UMA with dedicated per-subsystem zones."

---

## C4: "Cross-Subsystem Spray Is Dead" vs "Lapse Used Cross-Subsystem Spray"

**Severity: CRITICAL — determines exploitation path**

| Document | Claim |
|----------|-------|
| 03_RESULTS_ANALYSIS.md | "Abandon cross-subsystem spray. AIO objects are in a private zone. This is a structural dead end." |
| 06_HEAP_SPRAY_CATALOG.md | "IMPORTANT: Agent 3's results analysis proved that cross-subsystem spray has NEVER reclaimed..." |
| FREEBSD_EXPLOIT_TECHNIQUES.md | "Lapse's spray technique: Socket options with SO_LINGER + event flag objects (evf_create)" |
| 11_LAPSE_PROLAPSE_IDENTIFICATION.md | "Socket options + event flags are the correct spray technique" |
| 12_BLOCKERS_AND_NEXT_STEPS.md | Identifies this contradiction explicitly |

**Analysis:** Both claims are factually correct for their scope. Our probes DID fail. Lapse DID succeed. The explanation must be one of:
1. **Wrong spray parameters** — our setsockopt calls may have allocated from different size classes than the AIO objects
2. **Per-CPU cache isolation** — 67b proved single-CPU kills the race; spray from a third CPU misses both caches
3. **Firmware divergence** — zone layout may differ between Lapse's target (≤10.01) and 14.10
4. **Technique difference** — Lapse may use a specific socket option that allocates exactly the right size, not the options we tested

**Resolution:** Cross-subsystem spray should NOT be marked "dead" — it should be marked "not yet replicated." The "structural dead end" conclusion in `03_RESULTS_ANALYSIS.md` is too strong given that Lapse proves it works on some firmware. The next probes should specifically replicate Lapse's SO_LINGER + evf_create technique.

---

## C5: Freed Object Size Disagreement

**Severity: HIGH — determines spray target size**

| Document | Freed sub-object (R at I+0x18) size |
|----------|--------------------------------------|
| AIO_OBJECT_FORENSICS.md | **0x30 (48B)** (HIGH confidence, cites line 2607) |
| AIO_13_60_ANALYSIS.md | **0x30 (48B)** (cites line 2607) |
| 05_AIO_STRUCTURE_ANALYSIS.md | **0x40-0x80 bytes** (MEDIUM confidence, inferred from field offsets) |
| 09_EXPLOIT_CHAIN.md | **128-256 bytes** ("Estimated size 128-256 bytes") |
| FREEBSD_EXPLOIT_TECHNIQUES.md | **0x30 (48B)** for the saved context; **0x58 (88B)** for queue entry |
| EXPLOIT_CHAIN_DESIGN.md | **0x30 (48B)** ("48B → 64B zone") |

**The contradiction:** `09_EXPLOIT_CHAIN.md` estimates 128-256 bytes, which is 2.5-5x larger than the 48-byte figure from the decompile. `05_AIO_STRUCTURE_ANALYSIS.md` gives 64-128 bytes. Both are estimating because they approached from field offset analysis rather than the explicit allocation call.

**More reliable:** `AIO_OBJECT_FORENSICS.md` and `AIO_13_60_ANALYSIS.md` cite the explicit `func_0x00c08b50(0x30, 0x1ab59e0, 0x102)` allocation call in the decompile. This is direct evidence of a 0x30-byte allocation. The 128-256 estimate in `09_EXPLOIT_CHAIN.md` is wrong.

**Resolution:** The freed R sub-object is 0x30 bytes (48B). The freed I object is 0x58 bytes (88B). `09_EXPLOIT_CHAIN.md` should be corrected.

---

## C6: sys 591 `dynlib_dlsym` — KASLR Defeat or Not?

**Severity: MODERATE — affects probe priority**

| Document | Claim |
|----------|-------|
| 08_UNEXPLORED_SURFACE.md | "If 14.10 kept the 13.60 body, this is a single-call KASLR defeat" — "HIGHEST probability x impact" |
| 04_KASLR_DEFEAT.md | "sys 591 dynlib_dlsym -- Possible Single-Call KASLR (p=HIGH)" |
| KASLR_NOVEL_APPROACHES.md | "BUT: The resolved address from 591 is a *userland* address... NOT a KASLR defeat for the *kernel*" |

**The contradiction:** `08_UNEXPLORED_SURFACE.md` and `04_KASLR_DEFEAT.md` rate sys 591 as the highest-probability KASLR vector. `KASLR_NOVEL_APPROACHES.md` explicitly debunks this: 591 resolves userland dynamic library symbols, not kernel symbols. The output is a userland VA, which is already available from sys 593.

**More reliable:** `KASLR_NOVEL_APPROACHES.md` is correct. `dynlib_dlsym` resolves userland symbols by definition (it's the dynamic linker's symbol resolver). It gives module load addresses, not kernel addresses. Userland ASLR is already defeated via sys 593 (39 module bases). 591 might reveal hidden modules not in the 593 scan, but it cannot defeat kernel ASLR.

**Resolution:** sys 591 should be downgraded from "HIGHEST" to "LOW-MEDIUM" priority. It's worth one probe to check for hidden modules, but it is NOT a kernel KASLR defeat vector. `08_UNEXPLORED_SURFACE.md` and `04_KASLR_DEFEAT.md` overclaim here.

---

## C7: Number of Objects Freed Per Request

**Severity: MODERATE**

| Document | Count | Objects |
|----------|-------|---------|
| AIO_OBJECT_FORENSICS.md | **4** (I, R, Q, D — but D only on last-ref) | R, I, Q freed per request; D conditionally |
| AIO_13_60_ANALYSIS.md | **4** (matching) | Same |
| 01_AIO_EXPLOIT_STRATEGY.md | **4** "four distinct sub-objects" | Different zone assignments |
| EXPLOIT_CHAIN_DESIGN.md | **5** "five kernel objects freed per AIO request" | Lists completion record, sub-request data, copyin buffer, slot array, tracking structure |
| FREEBSD_EXPLOIT_TECHNIQUES.md | **4** | Saved context, queue entry, completion header, AIO top-level |
| 09_EXPLOIT_CHAIN.md | Discusses "sub-object release" singularly | Implies 1 primary freed object |

**Analysis:** `EXPLOIT_CHAIN_DESIGN.md` counts 5 by listing the copyin buffer and slot array separately. The other documents count 3-4 objects freed per individual request, with D-level objects (descriptor, table) freed only on last-reference delete. The actual count depends on whether you count the temporary per-ID context (zone `0x1a7d800`) which is allocated and freed within the 662 loop itself.

**Resolution:** Per individual request: 2 objects are always freed (R and I), Q is freed only when the descriptor's request count reaches zero. D-level infrastructure is freed only on last reference. The per-ID temporary context is freed at the end of the 662 loop regardless. "4 objects" is correct for a single-request descriptor; "2 objects" is the consistent per-ID double-free.

---

## C8: Document Recommends Something CLAUDE.md Says Is Dead

**Severity: MODERATE**

| Document | Recommendation | CLAUDE.md Status |
|----------|---------------|-----------------|
| 04_KASLR_DEFEAT.md §2 | "Pipe/Socket Buffer Header Type Confusion" (marked non-viable by the doc itself) | pipe(42) returns 0,0 — dead |
| 06_HEAP_SPRAY_CATALOG.md Tier 2 #6 | "sendmsg mbuf" as spray primitive | Not explicitly dead, but untested. OK. |
| KASLR_NOVEL_APPROACHES.md §5b | "Broader `rdtsc` gadget scan — check for any `0F 31`" | Timing KASLR is dead per CLAUDE.md (56h-56i2), but a new gadget scan itself is not dead. Acceptable. |
| KASLR_NOVEL_APPROACHES.md §10 | "SCM_RIGHTS fd leak as spray mechanism" | CLAUDE.md: "SCM_RIGHTS — kernel strips fd passing in game jail" (56q). Dead. |
| EXPLOIT_CHAIN_DESIGN.md Stage 3A | "Create pipe pairs via pipe(42)" | CLAUDE.md: "pipe(42) via make_syscall — returns fds 0,0 (dead)". The doc notes this is BLOCKED and suggests socketpair as alternative. Acceptable. |
| 09_EXPLOIT_CHAIN.md §5 | "Byepervisor-Reborn approach: trigger S3 resume" | Not listed as dead in CLAUDE.md, but entirely speculative. OK. |

**Actual violations:** Only `KASLR_NOVEL_APPROACHES.md §10` recommends SCM_RIGHTS fd leak, which CLAUDE.md confirms is dead (kernel strips fd passing). The doc rates it "LOW-MEDIUM" with the caveat that leaked fds accumulate, but the mechanism itself is dead — the fds don't arrive at the receiver.

**Resolution:** Remove SCM_RIGHTS from KASLR_NOVEL_APPROACHES.md. All other recommendations are either self-corrected within the document or propose new tests on untested parameters of known syscalls (acceptable).

---

## C9: Does the Double-Free Actually Double-Free, or Just Double-Report?

**Severity: HIGH — determines whether exploitation is possible at all**

| Document | Claim |
|----------|-------|
| AIO_OBJECT_FORENSICS.md §2 | "The 65l 'double delete' count...measures the RACE WINDOW being hit, not actual double-frees. Thread B's exclusive lookup finds a null table entry → success without free." |
| FREEBSD_EXPLOIT_TECHNIQUES.md | "The next two allocations from this zone both receive the SAME pointer → type confusion" (assumes actual double-free) |
| 03_RESULTS_ANALYSIS.md | "AIO self-overlap IS confirmed (65p): after double-free, re-submitting new AIO requests reclaims the same internal slots" (treating it as real) |
| PROBE_RESULT_MINING_65_67.md | "No Process Crash in 56 Runs" — "The kernel handles the double-free gracefully" |
| AIO_13_60_ANALYSIS.md §2 | "Both threads free the same objects from the same zones" |
| 12_BLOCKERS_AND_NEXT_STEPS.md | Flags this as an unresolved contradiction |
| 09_EXPLOIT_CHAIN.md | Treats it as confirmed real |

**Analysis:** `AIO_OBJECT_FORENSICS.md` raises a valid concern: in the 65l setup, each of the 16 IDs has its own descriptor. Thread A frees the descriptor, NULLs the table slot, releases the exclusive lock. Thread B acquires the exclusive lock, finds NULL → reports success (state=0) without freeing. This would explain why 65l sees double-success without any crash or observable corruption.

However, `AIO_13_60_ANALYSIS.md` describes the code path where both threads read the I pointer at step 2 (before either NULLs it) and both proceed to free. The question is whether the exclusive lock in steps 9-13 is per-descriptor (D) or global. If per-D, and each ID has its own D, both threads acquire different D locks and both free the same I.

Probe 65p's self-overlap result (deleting one AIO request invalidates its partner) IS evidence of real double-free or at least real handle-table corruption.

**Resolution:** This requires empirical testing. The "concurrent-submit-during-delete" test proposed by `AIO_OBJECT_FORENSICS.md` (section 5a) is the discriminating experiment: submit new requests DURING the race, check if the new request's data contains stale values from the old one. This should be the very next probe.

---

## C10: The Lapse "0x80 zone" vs Decompile "0x58 object in 128B zone"

**Severity: LOW — different way of saying the same thing**

| Document | Claim |
|----------|-------|
| 11_LAPSE_PROLAPSE_IDENTIFICATION.md | "Double-free in 0x80 zone" |
| AIO_OBJECT_FORENSICS.md | "0x58 bytes → likely in a 128-byte zone" |
| FREEBSD_EXPLOIT_TECHNIQUES.md | "0x58-byte queue entries (landing in the 0x80/128-byte zone)" |

**Analysis:** `0x80` is hex for 128. "0x80 zone" and "128-byte zone" are the same thing. The Lapse writeup uses 0x80 (hex), our documents use 128 (decimal). No actual contradiction.

**Resolution:** None needed. Just a notation difference.

---

## C11: What Does 663/664 Actually Return?

**Severity: MODERATE — affects readback strategy**

| Document | Claim |
|----------|-------|
| PROBE_RESULT_MINING_65_67.md §10 | "663/666/667 only return a 4-byte status dword — no wider data readback" |
| AIO_13_60_ANALYSIS.md §9 Q3 | "667 enumerates records {composite_id, state, class, operation} — 16 bytes per entry" |
| 04_KASLR_DEFEAT.md §1 | "663/664 reads from the kernel AIO node. After self-overlap, the fields may contain kernel pointers" |
| EXPLOIT_CHAIN_DESIGN.md | "663/664/666/667 return status from a lookup table, not from the raw freed memory" |

**Analysis:** `PROBE_RESULT_MINING_65_67.md` and `EXPLOIT_CHAIN_DESIGN.md` say readback is a 4-byte status, while `AIO_13_60_ANALYSIS.md` says 667 returns 16 bytes per entry. The probe mining document is based on 14.10 live results; the 13.60 analysis is based on static decompile. On 14.10, 667 always returns -1 (confirmed in 67a/67m), so its 16-byte contract is not reachable.

663's actual output contract is: the third argument is an output buffer, and the 13.60 handler writes per-ID status into it. Whether it writes more than 4 bytes depends on the mode parameter (param_5), which has never been tested beyond the default.

**Resolution:** The 4-byte-only claim applies to 14.10 with default mode. The 13.60 contract may expose more with different modes. 667 is dead on 14.10. Testing 663 with non-default mode is high priority.

---

## Summary: Priority Fixes

| # | Fix | Impact |
|---|-----|--------|
| C1 | Correct zone/size mapping in `HEAP_SPRAY_CANDIDATES.md` | CRITICAL |
| C3 | Soften "Sony-custom allocator" to "Sony wrapper around UMA" | CRITICAL |
| C4 | Change "cross-subsystem spray is dead" to "not yet replicated" | CRITICAL |
| C5 | Correct `09_EXPLOIT_CHAIN.md` size estimate from 128-256B to 48B/88B | HIGH |
| C9 | Add discriminating probe for actual double-free vs double-report | HIGH |
| C6 | Downgrade sys 591 from "HIGHEST KASLR" to "LOW-MEDIUM" | MODERATE |
| C2 | Adopt R/I/Q/D naming uniformly | MODERATE |
| C8 | Remove SCM_RIGHTS from KASLR approaches | LOW |

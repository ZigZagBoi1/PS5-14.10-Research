# Verification Report — 10 Agent Audit of 2026-10-25 Findings

**Date:** 2026-10-25
**Scope:** 10 max-effort verification agents cross-checked all 10 research documents

## Document Reliability After Verification

| Doc | Original Rating | Verified Rating | Key Issue |
|-----|----------------|-----------------|-----------|
| 01 AIO Exploit Strategy | — | **LOW** | Wrong freed object count (4 vs 1), 3/4 role labels wrong, "12 bytes" should be 24, double-success ≠ double-free |
| 02 Probe Code Review | — | **HIGH** | All 6 bug claims verified (5 confirmed, 1 partially) |
| 03 Results Analysis | — | **MEDIUM** | "Impossible" cross-spray overstated — detection methodology has blind spot; "not detected" is accurate |
| 04 KASLR Defeat | — | **MEDIUM** | Self-contradictory ranking (body vs summary disagree) |
| 05 AIO Structure Analysis | — | **HIGH** | Assembly-traced, hedges appropriately |
| 06 Heap Spray Catalog | — | **MEDIUM** | Contradicts 03 by prescribing cross-spray; Tier 2 should be marked dead |
| 07 Documentation Gaps | — | **LOW** | 6 of 8 claims FALSE — docs were already updated before gap analysis was written |
| 08 Unexplored Surface | — | **MEDIUM** | sys 591 claim debunked (caller attribution gate + resolves userland not kernel) |
| 09 Exploit Chain | — | **LOW** | KASLR targets wrong offset (+0x10 zeroed), ring-3 gadgets can't access kernel VA, timeline unrealistic |
| 10 Gadget Catalog | — | **MEDIUM** | Byte patterns confirmed but execution NOT confirmed (118b/118d mismatches) |

## Critical Corrections

### 1. Only ONE object is unconditionally double-freed (not 4)
Document 01 claims 4 sub-objects. The 13.60 decompile shows the TOCTOU window only covers the sub-object at I+0x18. Other frees happen at count==1 (last reference) or are conditional. Document 05's single-object analysis is correct.

### 2. "Double-success" may not mean "double-free"
Both 662 threads reporting status=0 means both completed the delete path. But with separate descriptor lookups, thread B may find a null slot (already cleared by A) and report success without actually freeing anything twice. The 65l result is a double-success observation, not a confirmed double-free.

### 3. Cross-spray "impossibility" is unproven
The detection methodology operates through the AIO ID table API (664/663), which returns sanitized status codes. After 662 deletes an ID, polling it returns 0x80020003 regardless of whether the underlying memory was reclaimed. The EVF and namedobj readback channels were both broken. sys 624 delta=0 for ALL allocations (AIO and non-AIO alike) actually weakens the dedicated-zone claim. The critical sequential test (cross-spray THEN self-overlap) was never performed.

### 4. sys 591 KASLR is DEAD
Already tested with 8 real handles and 28+ names (probe 66a) — all returned -1. Blocked by caller-module attribution check (step 4 in 13.60 decode). Even if it worked, it resolves userland .sprx symbols, not kernel addresses. Cannot defeat KASLR.

### 5. Exploit chain Stage 3 targets the wrong offset
Document 09 builds KASLR on reading +0x10 after reclaim. Document 05 proves +0x10 is zeroed before free (instruction at 0x3afed6). The real leak candidate is the UMA freelist pointer at +0x00.

### 6. "Kernel write works NOW" is false for kernel addresses
Ring-3 ROP gadgets (`mov [rdi], rax; ret`) execute in userland. Setting rdi to a kernel VA causes a page fault. Kernel R/W must go through kernel-mode code paths (syscalls, AIO completion) that dereference corrupted pointers.

### 7. Gadget execution not confirmed
Byte patterns `48 8B 47 18 C3` exist at +0x5D940 and +0xD68A0, but execution tests (118b, 118d) returned wrong values (0x67, low-byte zeroing). The kernel read chain is not yet validated.

### 8. 662 XOR feature path is real but has critical gaps
The XOR computation is assembly-verified. The output record is 24 bytes (not 12). Activation requires TWO unknown runtime conditions. Copyout to userspace is not proven. **The UNTRANSFORMED double-dereference at record +0x08 may leak a raw kernel pointer without XOR recovery.**

### 9. Document 07 gap analysis was based on stale data
STRATEGY.md, ATTACK_SURFACE.md, and FINDINGS.md were already updated before Agent 7 analyzed them. Only the PROBE_INDEX duplication (271a × 258 times) and FINDINGS duplicate numbering (83, 84) are real issues.

## New Probes Written

| Probe | Purpose | Status |
|-------|---------|--------|
| `68b_dlsym_kaslr.lua` | sys 591 sweep with 255 handles, 31 names, child thread raw errno capture | Ready to run |
| `68c_662_feature_path.lua` | 7 arg layout variants for 662's XOR conditional path (24B per ID output) | Ready to run |
| `68d_overlap_completion.lua` | AIO self-overlap via socketpair I/O completion cross-contamination | Ready to run |

## Revised Priority Queue

Based on verification findings, the priority order changes:

1. **68c_662_feature_path.lua** — Test the XOR conditional path with non-null 4th arg. The untransformed double-deref at +0x08 could give a raw kernel pointer. This is the fastest path to KASLR defeat if the feature path is active on 14.10.

2. **68d_overlap_completion.lua** — Test AIO self-overlap via socketpair I/O completion. This tests the type confusion primitive at the memory level rather than through the blind AIO API.

3. **68a_full_gadget_catalog.lua** — Run the validated gadget scan to find execution-confirmed read gadgets (the +0x5D940 and +0xD68A0 byte patterns need runtime validation).

4. **Design a cross-spray detection probe that doesn't use the AIO API** — The sequential test: double-free → cross-spray → attempt AIO self-overlap. If cross-spray consumed the slots, self-overlap fails. This would definitively prove or disprove dedicated zones.

5. **68b_dlsym_kaslr.lua** — Lower priority now that sys 591 is known to be caller-attribution-gated, but the child-thread raw errno capture may reveal useful error code discrimination.

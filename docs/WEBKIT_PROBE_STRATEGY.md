# WebKit Crash-Oracle Probe Strategy

Analysis of the optimal search strategy for finding mapped memory in the PS5 FW 14.10 WebKit (WebContent) renderer process, given the crash oracle primitive and 10 observed misses.

**Context:** A crash oracle forges a pointer, reads it as float64 — HIT if mapped (8 bytes of data), MISS if unmapped (SIGSEGV, ~25s restart + spray time). Before each probe, 640MB of ArrayBuffers are sprayed (40×16MB, touching every 16KB page). Total mapped memory ~1040MB with spray.

**Repo constraints used:** No SharedArrayBuffer, No WebAssembly, No WebGL, JIT disabled (LLInt only), 16KB pages, Gigacage disabled, WebKit fork predates Safari 17.0 (Sep 2023 branch).

## Correction: Stock FreeBSD 11 Has 0 Bits mmap ASLR

The upstream ASLR commit for mmap randomization (kib's r343964, Phabricator D5603) landed in the FreeBSD 13-era tree in February 2019. FreeBSD 11 shipped without it. HardenedBSD has 21-30 bits, but Sony's Orbis fork is not based on HardenedBSD.

**Implication:** If Sony's FreeBSD 11 fork did not add custom mmap ASLR, the mmap region has a **deterministic base address** — same every process restart, same every boot. The old 0x200430000 address was deterministic precisely because of this. On FW 14.10, Sony either:

1. **Moved the mmap base** to a different VA region (no randomization, just a new fixed address), or
2. **Added custom ASLR** with unknown entropy

Source: FreeBSD commit timeline vs. release dates; D5603 review at reviews.freebsd.org.

## The 10 Misses

| Probe | Address | Spray | Result |
|-------|---------|-------|--------|
| 1 | 0x100000000 | No | MISS |
| 2 | 0x180000000 | No | MISS |
| 3 | 0x200000000 | No | MISS |
| 4 | 0x280000000 | No | MISS |
| 5 | 0x2F8000000 | No | MISS |
| 6 | 0x100000000 | 640MB | MISS |
| 7 | 0x200000000 | 640MB | MISS |
| 8 | 0x2F8000000 | 640MB | MISS |
| 9-10 | (assumed in same range) | - | MISS |

All probes fell within 0x100000000 to 0x2F8000000 (~5.2GB window). The spray (640MB) adds ~640MB of contiguous mapped pages. With ~1040MB total mapped footprint, each miss at address X rules out that ANY of the ~1040MB of mapped memory overlaps X. This eliminates the range approximately [0x100000000 - 1GB, 0x2F8000000 + 1GB] ≈ [0x060000000, 0x338000000].

## Question 1: Optimal Single-Probe Strategy (Re-randomizing ASLR)

If ASLR re-randomizes on each WebProcess crash, each probe is independent. The probability of a HIT depends on the ratio of mapped memory to the ASLR window:

```
P(HIT) = mapped_size / aslr_window_size
```

| ASLR entropy (bits over 16KB pages) | Window size | P(HIT) per probe | Expected probes to first HIT | Wall time |
|------|-------------|---------|------|-----------|
| 0 (deterministic) | Fixed | 1.0 (if correct address) | 1 | 25s |
| 16 | 1 GB | 1040MB/1GB ≈ 1.0 | 1 | 25s |
| 20 | 16 GB | 1040/16384 ≈ 0.063 | 16 | 7 min |
| 24 | 256 GB | 1040/262144 ≈ 0.004 | 252 | 1.7 hr |
| 28 | 4 TB | ~0.00025 | 4032 | 28 hr |
| 32 | 64 TB | ~1.5×10⁻⁵ | 64512 | 19 days |
| 36 | full 48-bit | ~7.7×10⁻⁶ | 129024 | 37 days |

**The 10 misses constrain the entropy.** If the spray always lands within a fixed base region and the probes were inside that region, 10 consecutive misses at P=1.0 is impossible. The misses mean either:
- The base moved out of the probed range (deterministic but different base), or
- ASLR entropy is high enough that 10 misses is expected

For re-randomizing ASLR with entropy N bits: P(all 10 miss) = (1 - P(HIT))^10.

| N bits | P(all 10 miss) | Consistent with data? |
|--------|----------------|----------------------|
| 20 | 0.52 | Possible but unlikely |
| 24 | 0.96 | Consistent |
| 28+ | >0.99 | Very consistent |

**If re-randomizing with ≤20 bits:** Probing is feasible. The optimal single-probe address is the CENTER of the ASLR window. Without knowing the window, probe at the most likely base address. On FreeBSD amd64, try the upper VA range where mmap is typically placed on newer kernels.

**If re-randomizing with ≥24 bits:** Blind probing is infeasible (hundreds to thousands of 25-second probes). Switch to non-crashing detection (Question 4) or spray optimization (Question 3).

**Optimal single-probe address (re-randomizing, unknown window):** Maximize coverage by probing the address with the highest prior probability of being mapped. Since all probes in [0x100000000, 0x2F8000000] missed, and FreeBSD mmap uses first-fit upward from a base, the best single guess is in the upper VA range. Recommended:

```
0x7F0000000000
```

Rationale: This is near the top of the 47-bit user VA space, where Linux-style mmap placement lands and where Sony may have moved the mmap region for FW 14.10. The stack is near 0x7FFFFFFFFFFF — shared libraries and mmap regions often cluster below it.

## Question 2: Deterministic Layout — What the 10 Misses Rule Out

If ASLR is deterministic (same layout every restart), the 10 misses are definitive evidence. The spray's ~1040MB footprint is NOT anywhere in [0x060000000, 0x338000000].

**The search space is the full 47-bit user VA minus the ruled-out range:**

```
Total:      0x7FFFFFFFFFFF = 128 TB
Ruled out:  ~7.2 GB (0x060000000 to 0x338000000)
Remaining:  ~128 TB - 7.2 GB ≈ 128 TB
```

This is still enormous. Optimal strategy: **logarithmic coverage** — space probes exponentially across the remaining VA space.

**Optimal next-10 probe sequence (deterministic case):**

The idea: place each probe to bisect the largest uncovered interval, weighted by prior probability. Since FreeBSD amd64 typically uses lower VA regions for mmap, weight slightly toward the lower-middle range, but cover the full space.

| # | Address | Region | Rationale |
|---|---------|--------|-----------|
| 1 | 0x800000000 | 32 GB | Just above the ruled-out zone; FreeBSD first-fit typically places mmap here if base moved to 0x400000000+ |
| 2 | 0x7F0000000000 | ~127 TB | Near top of VA; Linux-style mmap region; shared lib area |
| 3 | 0x2000000000 | 128 GB | Log midpoint between 32GB and 1TB |
| 4 | 0x10000000000 | 1 TB | Log midpoint between 128GB and 127TB |
| 5 | 0x100000000000 | 16 TB | Log midpoint between 1TB and 127TB |
| 6 | 0x400000000000 | 64 TB | Upper half of VA space |
| 7 | 0x1000000000 | 64 GB | Fill gap between 32GB and 128GB |
| 8 | 0x8000000000 | 512 GB | Fill gap between 128GB and 1TB |
| 9 | 0x40000000000 | 4 TB | Fill gap between 1TB and 16TB |
| 10 | 0x600000000000 | 96 TB | Fill gap between 64TB and 127TB |

After each HIT: switch to **binary search** within the surrounding ±1GB to map the spray boundaries, then chain the 500 free reads to locate ArrayBuffer headers and JSCell structures.

After each MISS: each miss rules out ~1GB of the remaining search space. Update the search and bisect the largest remaining interval.

## Question 3: Forcing Predictable Spray Placement from JavaScript

### 3a. OOM pressure approach

With OOM at ~1200MB and spray at 640MB, the process uses ~1040MB. The kernel has very little VA space flexibility when the process is near OOM. Strategy:

1. Allocate to near-OOM (~1150MB) with diverse object types (ArrayBuffers, strings, ImageData, typed arrays)
2. Free specific allocations to create controlled holes
3. Re-allocate the spray into those holes
4. The spray lands where the freed memory was — which you controlled

**Problem:** Requires knowing where the first allocations landed, which is the original problem. But if the kernel's first-fit algorithm is deterministic, the FIRST allocation always starts at the same base. The trick is to allocate ONE small ArrayBuffer first, corrupt its backing store pointer via the crash oracle, and read it — the data you read back IS the address.

### 3b. Relative spray (best approach for crash oracle)

Instead of finding the spray's absolute address, use the oracle to find ANY mapped page, then use relative offsets:

1. Spray 640MB of ArrayBuffers, each initialized with a unique 8-byte magic pattern
2. On HIT, the float64 read back IS the magic pattern
3. The magic pattern encodes which ArrayBuffer and which offset within it
4. Now you know the absolute address of that specific offset in that specific ArrayBuffer
5. From there, compute the addresses of all other sprayed ArrayBuffers

**This turns one HIT into a complete address map.**

### 3c. Allocation pattern inference

If bmalloc's large allocation path passes no hint to mmap (confirmed in WebKit source — tryLargeMemalignVirtual uses MAP_ANON without MAP_FIXED), the kernel's first-fit algorithm determines placement. On stock FreeBSD 11:

1. The kernel maintains a free-space tree for the process VA
2. First-fit searches upward from the last allocation
3. Sequential large allocations are **contiguous**
4. The base address is deterministic IF there's no mmap ASLR

So: allocate one small ArrayBuffer, corrupt its backing store pointer via the vulnerability (not the crash oracle), read back the pointer value → you have the base address. No crashing needed.

### 3d. Worker heap isolation

Create a Web Worker. If the Worker's heap is in a different VA region than the main thread's, and you can observe which region by testing addresses, you've narrowed the search. Workers share the same process on WebKit, so their allocations go through the same bmalloc. This likely doesn't help.

## Question 4: Non-Crashing Detection Methods

**Constraints that kill most techniques:**
- No SharedArrayBuffer → no high-resolution timer from SAB counter thread
- No WebAssembly → no Wasm trap handler, no Wasm memory probing
- No WebGL → no GPU-based timing
- JIT disabled (LLInt only) → no JIT spray, no JIT-based Spectre gadgets
- performance.now() likely reduced to 1ms resolution (Spectre mitigations)

### 4a. DEAD techniques
| Technique | Why dead |
|-----------|----------|
| SAB counter timer | No SharedArrayBuffer |
| Wasm trap handling | No WebAssembly |
| GPU cache timing | No WebGL |
| JIT spray / Spectre v1 gadget in JIT | JIT disabled |
| Worker crash isolation | Workers share WebProcess; SIGSEGV kills all |

### 4b. POTENTIALLY ALIVE techniques

**Allocation timing inference:**
- Allocate ArrayBuffers of increasing size
- Time each allocation using `Date.now()` (1ms resolution) or `performance.now()`
- If the kernel's first-fit search traverses more free-space tree nodes, allocation takes longer
- Detectable difference: unlikely at 1ms resolution, but possible with statistical averaging over many allocations
- **Verdict: weak but non-crashing. Test with 1000+ allocations and look for bimodal timing.**

**SPOILER (CVE-2019-0162):**
- Leaks physical address bits via memory subsystem contention on Intel
- Works from JavaScript (demonstrated by Gruss et al.)
- PS5 uses AMD Zen 2, NOT Intel — SPOILER is Intel-specific
- **Verdict: DEAD on PS5 (AMD CPU).**

**Transparent Huge Page (THP) first-access timing:**
- First access to a THP takes measurably longer than subsequent accesses
- Could detect whether a page was previously touched
- FreeBSD 11 may not have THP; Sony's fork is unknown
- **Verdict: unlikely but worth one test.**

**Rowhammer / memory subsystem:**
- Zen 2 is resistant to classic Rowhammer
- Not useful for address detection
- **Verdict: DEAD.**

**CSS/DOM timing oracle:**
- Create DOM elements that reference attacker-controlled CSS with `url()` pointing to different addresses
- Monitor rendering timing differences
- Very noisy, probably not measurable at 1ms resolution
- **Verdict: extremely weak, not recommended.**

### 4c. BEST AVAILABLE NON-CRASHING APPROACH

**Use the vulnerability itself, not the crash oracle.**

The MetadataTable overflow (CVE-2026-64784) is confirmed on two 14.10 consoles. This vulnerability corrupts memory ADJACENT to the MetadataTable in the JSC heap. By controlling what objects are adjacent (heap feng shui), you can:

1. Corrupt a JSObject's butterfly pointer or structure ID
2. Create a type confusion that lets you read object internal fields
3. Object internal fields contain POINTERS — this leaks addresses without crashing
4. From one leaked pointer, derive the entire heap layout

**This is how the Relapse exploit works on 13.60 — it doesn't brute-force addresses.** It uses JSC memory corruption to leak pointers, then builds arbitrary R/W from there.

The crash oracle is a fallback primitive. The primary exploit path should use CVE-2026-64784 directly with heap feng shui.

## Question 5: 20 Probe Addresses (Ordered by P(HIT))

Assumptions: deterministic layout (stock FreeBSD 11 behavior), the 10 misses rule out [0x060000000, 0x338000000], spray is 640MB contiguous. All addresses are 16KB-aligned (0x4000 boundary).

### Strategy

Logarithmic coverage of the 47-bit VA space. Probes are spaced at roughly exponential intervals, weighted toward regions where FreeBSD/Orbis is most likely to place mmap:

- **Tier 1 (probes 1-5):** Just above the ruled-out zone and in the upper VA range — highest prior probability
- **Tier 2 (probes 6-10):** Logarithmic fill between Tier 1 probes
- **Tier 3 (probes 11-15):** Secondary fill — covers the middle of the VA space
- **Tier 4 (probes 16-20):** Tertiary fill — completes coverage

| # | Address | ~VA offset | Justification |
|---|---------|-----------|---------------|
| 1 | `0x000800000000` | 32 GB | First unchecked region above ruled-out zone. If Sony moved base to ~0x400000000+, spray lands here. |
| 2 | `0x7F0000000000` | 127.5 TB | Linux-style mmap top. Sony may mirror this for defense-in-depth. Near shared libs and stack. |
| 3 | `0x002000000000` | 128 GB | Log midpoint lower range. FreeBSD first-fit from a ~64GB base reaches here with 640MB spray. |
| 4 | `0x010000000000` | 1 TB | Power-of-2 landmark. Common page table boundary. |
| 5 | `0x000400000000` | 16 GB | Just above the ruled-out zone. If base moved to ~0x340000000, spray reaches here. |
| 6 | `0x100000000000` | 16 TB | Mid VA space. Splits the gap between 1TB and 127TB. |
| 7 | `0x001000000000` | 64 GB | Fills gap between 32GB and 128GB. |
| 8 | `0x008000000000` | 512 GB | Fills gap between 128GB and 1TB. |
| 9 | `0x400000000000` | 64 TB | Upper quarter of VA space. |
| 10 | `0x040000000000` | 4 TB | Fills gap between 1TB and 16TB. |
| 11 | `0x200000000000` | 32 TB | Splits gap between 16TB and 64TB. |
| 12 | `0x600000000000` | 96 TB | Splits gap between 64TB and 127TB. |
| 13 | `0x004000000000` | 256 GB | Fills gap between 128GB and 512GB. |
| 14 | `0x080000000000` | 8 TB | Fills gap between 4TB and 16TB. |
| 15 | `0x000600000000` | 24 GB | Fills gap between 16GB and 32GB. |
| 16 | `0x020000000000` | 2 TB | Fills gap between 1TB and 4TB. |
| 17 | `0x700000000000` | 112 TB | Fills gap between 96TB and 127TB. |
| 18 | `0x500000000000` | 80 TB | Fills gap between 64TB and 96TB. |
| 19 | `0x300000000000` | 48 TB | Fills gap between 32TB and 64TB. |
| 20 | `0x00C000000000` | 768 GB | Fills gap between 512GB and 1TB. |

### After a HIT

Once any probe returns data instead of crashing:

1. **Identify what you hit:** The float64 value tells you — if it matches a spray magic pattern, you hit the spray. Otherwise you hit code, stack, or a library.
2. **Binary search:** Probe ±1GB from the hit in halving steps to find the spray boundaries.
3. **Chain the 500 reads:** Map the heap structure. Look for:
   - ArrayBuffer headers (bmalloc metadata at chunk start)
   - JSCell headers (structure ID + flags in first 8 bytes)
   - vtable pointers (these leak the executable/library base addresses)
4. **Derive ASLR slide:** Compare leaked vtable pointers against known offsets from the eboot or WebKit library.

## Recommended Approach: Heap Feng Shui > Blind Probing

The crash oracle treats address discovery as a search problem over 128TB. Even with the spray, this is an O(log(128TB/1GB)) = ~17 bisection steps if deterministic, or potentially infeasible if re-randomizing with high entropy.

**The MetadataTable overflow (CVE-2026-64784) offers a fundamentally better path:**

1. **Heap feng shui:** Allocate JSC objects in a controlled pattern so that the MetadataTable overflow corrupts a KNOWN object type at a KNOWN relative offset.
2. **Type confusion:** The corrupted object is read as a different type, exposing internal pointer fields as readable JavaScript values.
3. **Pointer leak:** One leaked pointer breaks ASLR without any crashing.
4. **Arbitrary R/W:** Build fakeobj/addrof primitives from the type confusion → full arbitrary read/write in userland.

This is the established WebKit exploitation methodology (used by Relapse on 13.60, by Safari exploits since iOS 10). It does not require knowing absolute addresses in advance.

**The crash oracle's best use is as a FALLBACK** — if heap feng shui for CVE-2026-64784 proves unreliable, the oracle can verify whether a specific heap layout was achieved before triggering the overflow.

## Cross-Vector Note

The Lua loader (Entry Vector 1) has `sys 674` which returns the full process VM map (317 regions with protections). If there is any way to pass information between the Lua process and the WebKit process — shared files, network loopback, shared memory segments, /dev nodes — the Lua loader could provide the WebKit process's VA layout directly.

Worth investigating: does the PS5 browser share any memory mappings with game processes? Do they share /dev/dmem0? Can a Lua probe write to a file that a WebKit page reads via `file://` or `fetch()`?

## References

- FreeBSD D5603 (mmap ASLR, landed in FreeBSD 13): reviews.freebsd.org/D5603
- HardenedBSD ASLR: hardenedbsd.org aslr.4
- SPOILER (Intel-specific, dead on AMD): arxiv.org 1903.00446
- Relapse exploit methodology (13.60): AF_ROUTE KASLR + AIO race
- bmalloc tryLargeMemalignVirtual: WebKit source, bmalloc/bmalloc/Heap.cpp
- FreeBSD vm_map_findspace: sys/vm/vm_map.c (first-fit upward, no randomization in 11.x)

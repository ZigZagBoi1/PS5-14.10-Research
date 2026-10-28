# KASLR Entropy Analysis — PS5 13.60 Kernel Dump

> **Date:** 2026-10-25. Derived from the 13.60 kernel dump in `docs/dumps_13.60/`.
> The 13.60 capture is a single boot observation; this analysis assumes 14.10
> uses the same alignment (behavioral match only, not proven identical code).

## Summary

| Parameter | Value |
|-----------|-------|
| Observed kernel base | `0xFFFFFFFF8A9C0000` |
| Slide from 0xFFFFFFFF80000000 | `0x0A9C0000` (170 MB) |
| **Alignment** | **256 KB (0x40000)** — 16 × 16KB PS5 pages |
| Kernel image size | ≥ 55 MB (handler code extends to RVA 0x34F4FE4) |
| Max entropy (2 GB kernel VA) | **~12.9 bits** (~7,793 positions) |
| Likely entropy (1 GB range) | **~11.9 bits** (~3,920 positions) |
| Safe KASLR oracle on 14.10 | **None found** |
| PIC kernel | Yes — zero absolute pointers in .text/.data |

## Alignment Proof

The observed kernel base `0xFFFFFFFF8A9C0000` minus the kernel canonical VA start
`0xFFFFFFFF80000000` gives slide `0x0A9C0000`:

```
0x0A9C0000 / 0x40000  = 679    (exact integer — 256KB aligned)
0x0A9C0000 / 0x80000  = 339.5  (NOT 512KB aligned)
0x0A9C0000 / 0x100000 = fails  (NOT 1MB aligned)
0x0A9C0000 / 0x200000 = fails  (NOT 2MB aligned)
```

256KB = `0x40000` = 16 × 16KB pages. The PS5 kernel page size is 16KB (not the
standard 4KB for x86-64), and the KASLR granularity is exactly 16 pages.

## Kernel Image Layout

From the 13.60 dump and sysent handler addresses:

| Region | RVA Range | Size |
|--------|-----------|------|
| Entry point / init code | 0x000000 | first `call` + function prologues |
| .text (code) | 0x000000 – ~0xCC0000 | ~12.75 MB |
| .rodata/.data (captured) | ~0xCC0000 – 0xE6E5C0 | ~1.7 MB |
| Pre-sysent dispatch table | 0xE6D5C0 – 0xE6E5C0 | 4 KB (256 entries × 16B) |
| Sysent table | 0xE6E5C0 – 0xE765C0 | 32 KB (679 entries × 48B) |
| Data section (sampled) | 0x1000000 – 0x1400000 | 4 MB sample |
| Handler code (real) | 0x126CE27 – 0x34F4FE4 | **38.5 MB span** |

The sysent `sy_call` field points to compact thunks at RVA 0x25DC28–0x265FA8
(33 KB). A separate 16-byte-stride table immediately before the sysent contains
268 absolute pointers to the **real handler implementations** at RVA 0x12–0x35 MB.

**Total kernel image size: at least 55 MB**, likely larger with BSS and modules.

## Position-Independent Kernel

A critical finding: the kernel uses **entirely position-independent code (PIC)**.

| Section | Absolute kernel pointers |
|---------|--------------------------|
| kernel_text.bin (14.4 MB) | 0 (all addresses are RIP-relative) |
| kernel_data.bin (4 MB) | 0 true kernel pointers (1049 DMAP/data values, no kernel text refs) |
| sysent_area.bin (64 KB) | 1658 (ONLY in the dispatch tables, patched at boot) |

The bootloader/hypervisor patches only the dispatch tables (sysent + pre-sysent)
with the actual KASLR'd addresses. All other kernel code references are relative.
This means:
- No kernel pointer can leak from the code/data sections themselves
- KASLR leaks can only come from dynamically-generated kernel data (stacks, proc
  structures, UMA zones, thread objects) — exactly the data Sony zeroes on copyout

## KASLR Entropy Estimates

The x86-64 canonical kernel VA space is `0xFFFFFFFF80000000` to `0xFFFFFFFFFFFFFFFF`
(2 GB). The kernel image needs to fit entirely within this range.

| Assumed Range | Available | Positions | Entropy (bits) | Avg Attempts |
|---------------|-----------|-----------|----------------|--------------|
| 512 MB | ~457 MB | ~1,828 | 10.8 | ~914 |
| 768 MB | ~713 MB | ~2,852 | 11.5 | ~1,426 |
| **1 GB** | **~969 MB** | **~3,876** | **11.9** | **~1,938** |
| 1.5 GB | ~1,425 MB | ~5,700 | 12.5 | ~2,850 |
| **2 GB (max)** | **~1,993 MB** | **~7,972** | **12.9** | **~3,986** |

The observed slide of 170 MB favors a range of ~512 MB to 1 GB (single observation;
multiple boots would narrow this). A 170 MB slide in a 2 GB range would be at the
8th percentile — plausible but unlikely.

**Best estimate: ~12 bits of entropy (~4,000 positions).**

## Brute-Force Viability

### With a safe oracle (error-based, no crash)

If a syscall or memory access returned differently for valid vs. invalid kernel
addresses without crashing:

- Average: ~2,000 attempts
- At 1 attempt/second: **~33 minutes**
- At 2 attempts/second: **~17 minutes**

**This is viable.** But no safe oracle exists on 14.10. Every tested approach
(mprotect, mincore, sys 547/572/624/674) returns the same value for ALL kernel
addresses — no discrimination between valid and invalid regions.

### Without an oracle (crash-and-reboot)

Each wrong guess panics the kernel → PS5 reboot required:

- Average: ~2,000 attempts
- At 2 minutes/reboot: **~67 hours (2.8 days)**
- At 3 minutes/reboot: **~100 hours (4.2 days)**

**Impractical.** Even with automation, 3-4 days of continuous rebooting is
fragile (risk of corrupting the console, game update prompts, etc.).

### Partial KASLR reduction

If we could determine even 4 bits of the slide (e.g., from timing):
- Remaining positions: ~250
- With oracle: ~2 minutes
- Without oracle: ~8 hours

But no timing primitive exists either — no `rdtsc;ret` gadget in eboot (56s),
`clock_gettime` overhead (~90μs) drowns sub-microsecond signals (56h-56i2).

## What Would Work

### 1. Any single kernel pointer leak → instant KASLR defeat

If ANY interface returns a single kernel VA (thread pointer, proc pointer,
module address, etc.), we compute: `kernel_base = leaked_ptr - known_RVA`.

The R sub-object (AIO) contains `curthread+0x390` at R+0x00 and `curthread+0x08`
at R+0x08 (verified 13.60). If we could read these after free+spray, KASLR is
solved. But the readback interfaces (662/663/664/666) write only 4 bytes of
status, and no cross-zone spray has reclaimed R's 64B zone (IP_OPTIONS zeroes
content, evf/namedobj are wrong zone sizes).

### 2. Safe address oracle

A syscall that:
1. Accepts a kernel address as argument
2. Returns success/failure based on whether the address is mapped
3. Does NOT crash on unmapped addresses

Candidates tested and failed:
- `mprotect` → returns 0 for all addresses (early return, no page walk)
- `mincore` → returns -1 for all kernel addresses
- `547 query_memory_protection` → returns -1 for all kernel addresses
- `572 virtual_query` → returns -1 for all kernel addresses
- `624` → delta=0 for all kernel addresses (no discrimination)
- `674 VM map` → only returns userland regions

### 3. Timing oracle at instruction granularity

A code path that executes differently (cache hit vs. miss, TLB hit vs. miss)
depending on whether a kernel address is mapped. Requires a precise timing
gadget (`rdtsc;ret`) which does not exist in eboot.

### 4. Cross-boot KASLR stability

Kernel ASLR is per-boot. If we learn it once (from any source — crash dump,
panic message, lucky leak), it persists until the next reboot. User ASLR is
per-connection (independent).

## Fixed Offsets (13.60 → 14.10 applicability uncertain)

Once kernel base is known, these offsets give immediate targets:

| Symbol | RVA (13.60) | Notes |
|--------|-------------|-------|
| sysent table | +0xE6E5C0 | 679 entries × 48B |
| nosys handler | +0x265760 | Stub for unimplemented syscalls |
| Sysent thunk area | +0x25DC28 to +0x265FA8 | 300 unique entry points |
| Handler code range | +0x126CE27 to +0x34F4FE4 | Real implementations |
| Pre-sysent dispatch | +0xE6D5C0 | 256 entries × 16B |

**Warning:** These are 13.60 offsets. 14.10 may have different offsets. Without
a verified 14.10 kernel image, these cannot be used for blind exploitation.

## Implications for the Exploit Chain

1. **KASLR is the primary remaining blocker.** All kernel pointers are sanitized
   on copyout, all info-leak interfaces return clean data, and no timing oracle
   exists.

2. **The AIO R-object KASLR spray remains the best path** — it doesn't need to
   guess addresses. If the spray succeeds, the kernel pointer is IN the readback
   data, not derived from a guess.

3. **The 64B UMA zone problem is unsolved.** R is 48B in a 64B UMA zone.
   EVF=128B, namedobj=256B, IP_OPTIONS zeroes content. No known 64B-zone spray
   primitive exists from the game process.

4. **If a kernel pointer is ever obtained:** use the read gadget chain
   (`pop rax → mov rax,[rax] → pop rdi → mov [rdi],rax`) to read kernel memory.
   With kernel read, locate the ucred structure and escalate privileges. With
   kernel write (via the same gadget chain reversed), patch credentials and
   disable the security checks.

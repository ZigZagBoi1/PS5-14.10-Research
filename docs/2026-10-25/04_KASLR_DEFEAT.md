# KASLR Defeat Candidates

**Date:** 2026-10-25
**Source:** Agent 4 -- KASLR defeat brainstorm (max effort)

## Context

PS5 14.10 has aggressive kernel pointer sanitization. Every known leak technique has been tested and failed (see CLAUDE.md "Dead Ends"). However, a kernel double-free exists (AIO multi_delete TOCTOU), and several unexplored syscalls remain.

## Ranked Candidates

### 1. AIO Cross-Slab Reclaim + 663/664 Readback (p=20%)

After the confirmed 662 double-free, spray objects from a different allocator into the freed AIO sub-object slot, then use syscall 663 (aio_multi_wait) or 664 (aio_multi_poll) on the dangling ID. If the AIO lookup dereferences a pointer inside the now-reclaimed object, it may copy out bytes that contain a kernel pointer.

**Update from Agent 3:** Cross-subsystem spray is proven impossible (dedicated zones). However, AIO self-spray reclaims the slot. If the new AIO request's fields contain kernel pointers (e.g., the +0x10 mutex pointer), those are readable through the old dangling ID.

- **Why it might work:** AIO status readback (663/664) reads from the kernel AIO node. After self-overlap, the fields may contain kernel pointers from the new request.
- **Why it might NOT:** Status readback returns structured small integers (0x00000003, 0x00010003), not raw memory. The kernel may sanitize output.
- **Probe:** Double-free, self-spray with 669, read back via 663/664, scan for kernel-range values.

### 2. Pipe/Socket Buffer Header Type Confusion (p=15%)

**Update:** Proven non-viable. AIO uses dedicated zones; socket/pipe buffers cannot reclaim AIO slots.

### 3. Timing Side Channel on Dangling Pointer Dereference (p=12%)

After double-free, spray pages with known patterns and measure how long 664 takes on the dangling ID vs. a valid ID.

- **Why it might NOT:** clock_gettime has ~90us overhead that drowns sub-microsecond signals. No clean rdtsc;ret gadget in eboot.
- **Probe:** 1000 iterations of 664 on dangling vs valid IDs, measure via clock_gettime.

### 4. Socket Option Struct Confusion via setsockopt/getsockopt (p=10%)

**Update:** Non-viable for direct spray (wrong zone), but setsockopt may work for the 0x30-byte context sub-object if it uses a general 64-byte zone. Needs zone analysis.

### 5. shm_open Metadata Confusion (p=8%)

**Update:** Likely wrong zone. shm objects are much larger than AIO sub-objects.

### 6. sys 624 VM-Op Delta as Slab-Exhaustion Oracle (p=8%)

Use the confirmed 624 side channel to measure when a slab zone is exhausted and the kernel allocates a new page. By controlling AIO object count and checking 624 delta, determine slab object size.

- **Why it might NOT:** 65n showed delta=0 for all AIO operations. AIO slab may never expand during a probe's lifetime.
- **Probe:** Submit 1000+ AIO requests in batches of 16, check 624 between each batch.

### 7. Kqueue Knote Confusion (p=5%)

**Update:** Proven non-viable. Knotes are in a different zone from AIO objects.

## Additional Candidates (from Agent 8)

### 8. sys 591 `dynlib_dlsym` -- Possible Single-Call KASLR (p=HIGH)

The 13.60 offline decode shows NO authid gate and NO bit-62 gate. Takes `(handle, name_ptr, &out_addr)` and does `copyout(&addr, arg3, 8)`. Previous -1 was from handle=0 (error 3, not a privilege gate). With a real module handle + known NID string, this could resolve a kernel symbol address.

**This is the highest-probability KASLR defeat vector.**

### 9. 662 Conditional Feature Path -- XOR Kernel Pointer (p=MEDIUM)

The 13.60 decompile has a conditional path that copies 12 bytes per ID including `(*(lVar8+0x10) >> 4) ^ *(lVar8+0x10)`. This XOR is reversible and leaks a kernel address if the feature path is active on 14.10.

## Summary

The strongest remaining paths are:
1. **sys 591** (unexplored, no gate, single-call KASLR)
2. **662 feature path** (conditional, XOR-obfuscated pointer)
3. **AIO self-overlap readback** (via 663/664 after self-spray)

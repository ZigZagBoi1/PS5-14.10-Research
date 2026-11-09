# Blockers and Next Steps — Session 2

**Date:** 2026-10-25 (Session 2)
**Source:** Synthesis of 10 parallel research agents

## The Two Hard Blockers

### Blocker 1: No Observable Overlap Signal

**Status: UNSOLVED**

The double-free is confirmed (65l: 65/480 IDs, 26/30 iterations) but no userland-visible effect has been detected across 6+ exploitation probes (66c-67m):

- 663/666/667 return status from a **lookup table**, not raw memory
- AIO result buffers use cached parameters from submission time
- Cross-subsystem spray (kqueue, namedobj, socketpair, setsockopt, EVF, shm) all failed
- AIO self-overlap confirmed (65p: deleting one invalidates partner) but readback doesn't expose kernel data

**Why Lapse worked but ours didn't:**
The Lapse chain doesn't read back through AIO queries. It creates an aliased socket/evf pair by reclaiming the double-freed memory with socket options and event flags. The readback goes through the socket/evf interface, not the AIO interface. Our probes focused on AIO readback (663/664/666/667) which only returns status dwords.

**Resolution path:**
1. Test `setsockopt(SO_LINGER)` spray + `getsockopt` readback
2. Test `evf_create(538)` spray + evf query readback (546 wait / 543 trywait)
3. Test `aio_get_data(665)` with valid IDs — completely untested
4. Test 663 with different mode parameter (param_5, not tested beyond default)

### Blocker 2: No KASLR Defeat

**Status: UNSOLVED (17+ techniques exhaustively dead)**

Every classic info leak surface is sanitized on 14.10. The KASLR defeat must come from the double-free itself — specifically from the 48-byte saved execution context (zone `0x1ab59e0`) which contains kernel thread/process/credential pointers.

**Resolution path:**
1. Solve Blocker 1 first — a readable overlap in the right zone leaks a kernel pointer
2. The Lapse chain achieved KASLR through evf aliasing, not through AIO readback
3. Alternative: `setsockopt/getsockopt` on a socket whose option buffer reclaimed a freed AIO slot containing stale kernel pointers

## Contradictions Between Agent Findings

| Question | Finding A | Finding B | Impact |
|----------|----------|----------|--------|
| Is the allocator UMA or Sony-custom? | freebsd-exploit-research: standard UMA | aio-object-forensics: Sony custom (zone RVAs are data-segment addresses) | High — determines whether cross-subsystem spray can work at all |
| Is cross-subsystem spray possible? | probe-result-mining: proven dead | freebsd-exploit-research: Lapse used socket options + evf | High — Lapse works, so either the allocator IS UMA or Sony's allocator shares zones |
| Are 65l "doubles" actual double-frees? | Assumed yes by 7 agents | aio-object-forensics: may be double-success-reports | Medium — actual UAF requires submit-during-delete |

**Resolution:** The Lapse exploit's existence proves that the double-free IS exploitable and that socket/evf spray CAN reclaim the freed slots. Either:
- (a) The allocator is UMA-compatible enough that socket/evf allocations land in the same zone, OR
- (b) Lapse uses a different technique we haven't replicated (e.g., IPv6 routing headers for zone crossing)

## Immediate Probe Queue (Priority Order)

### Priority 1: Replicate Lapse Stage 2 (KASLR)

**Probe 69a: SO_LINGER spray + getsockopt readback**
1. Fire double-free (67i2 recipe: socketpair-gated, 16 IDs)
2. Create 200 TCP sockets
3. `setsockopt(SO_LINGER)` on each with sentinel pattern
4. `getsockopt(SO_LINGER)` on each — check for non-sentinel bytes
5. Any `0xFFFF8xxx` pattern is a kernel pointer leak

**Probe 69b: evf_create(538) spray + evf query**
1. Fire double-free
2. Create 200 event flags via 538
3. Query via 543 (trywait) or 546 (wait with timeout=0)
4. Check returned bit patterns for kernel-shaped values

### Priority 2: Untested Readback Paths

**Probe 69c: aio_get_data(665) with valid IDs**
- 665 kills on zeros but has never been tested with valid AIO IDs
- Try: `665(valid_aio_id, output_buffer, size)` with various sizes
- If it returns completion record data, it's the direct readback path

**Probe 69d: 663 mode parameter sweep**
- 663's 13.60 handler takes 6 args, param_5 is a mode
- Try modes 0-7 with valid IDs
- Non-default modes might copy tracking data

### Priority 3: Socket-level ioctl KASLR (Praetorian lead)

**Probe 69e: SIOC* ioctls on socket fds**
- Our ioctl sweep tested /dev nodes but NOT socket-level ioctls
- SIOCGIFCONF, SIOCGIFFLAGS, SIOCGIFDSTADDR, etc. on socket fds with oversized output buffers
- Praetorian's undisclosed bug was in a VNET-jail-accessible subsystem

### Priority 4: New Probes Already Written

Run probes 68a/68b/68c (written by next-probes-writer agent):
- 68a: cross-type spray detection via 663 status corruption
- 68b: socket/sendmsg spray with UMA cache drain
- 68c: systematic zone-size identification sweep (16-128B)

## Key Insight

**The gap between our probes and Lapse is the readback path.** Our probes read back through AIO (663/664/666/667) which returns status dwords. Lapse reads back through socket/evf interfaces which expose raw object fields. The next probes must shift readback from AIO to socket/evf.

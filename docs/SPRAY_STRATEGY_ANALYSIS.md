# Cross-Subsystem Spray Strategy Analysis — PS5 14.10

> **2026-10-25 correction:** The per-type-zone conclusion in this historical analysis is unsupported. Direct 13.60 allocator disassembly identifies `func_0x00c08b50` as a size-class `malloc(size, type, flags)` wrapper; the second argument is a malloc-type descriptor. A valid 56-byte `IPV6_RTHDR` was sprayed on 64 sockets and read back exactly on 14.10. See [76_64B_SPRAY_REASSESSMENT.md](2026-10-25/76_64B_SPRAY_REASSESSMENT.md) for the evidence and the unresolved backing-zone question.

> **Date:** 2026-10-25.
> **Status:** Analysis of existing spray attempts and new candidates.
> **Scope:** Which kernel subsystems can reclaim the AIO double-freed slots, and why
> existing attempts (65o-67m) have failed to detect observable overlap.

---

## 0. Why Current Spray Attempts Have Not Detected Overlap

After 20+ probes (65o through 67m), the double-free is confirmed at ~13-87% hit rate
per iteration, but **zero observable overlap** has been detected. Every approach returns
normal AIO status values. This section identifies why.

### Root cause: Sony's custom allocator zones are per-type, not per-size

The 13.60 decompile shows five different zone descriptor addresses (`0x1ab5900`,
`0x1ab5970`, `0x1ab59e0`, `0x1ab5890`, `0x1ab5a50`). These are passed as the second
argument to `func_0x00c08b50` (alloc) and `func_0x00c08df0` (free).

**Critical insight from the failed sprays:** If Sony's allocator routes allocations by
zone-descriptor address (not by size), then a namedobj, EVF, kqueue, or socket
allocation goes to a **different zone** than the AIO tracking structure, even if both
are 48 or 64 bytes. The allocator keeps per-type free lists, making cross-type reclaim
impossible without either:

1. Finding another caller of the **same zone** (`0x1ab59e0` or `0x1ab5900`)
2. Forcing the allocator to fall back to a shared backing pool
3. Using AIO self-spray (same zone by definition) with a detectable readback

### Evidence supporting per-type isolation

| Probe | Spray type | Count | Result |
|-------|-----------|-------|--------|
| 65o | kqueue(362) + namedobj(557) | 200+200 | Zero crashes, zero anomalies |
| 65v | EVF(538) + namedobj(557) + AIO(669) | 128+256 | Zero EVF value corruption |
| 65w | namedobj(557) 24/31-char | 64+32+64 | Zero delete failures, zero anomalies |
| 66c | socketpair(135) + setsockopt(105) + AIO(669) | 64+64+32 | Zero unusual status |
| 66e | EVF(538) + namedobj(557) + socketpair(135) + AIO(669) | 32+32+32+16 | Zero anomalies |
| 66f | Massive AIO self-spray | 256 | Zero delete errors or crashes |
| 67d-67e | AIO self-spray + 663 readback | 128+128 | 663 status unchanged (0x10003→0x10003) |
| 67f | namedobj cross-zone | 32 | namedobj lookup broken; no overlap |
| 67k | CPU-pinned AIO spray | 80+80 | All deletes clean, zero anomalies |
| 67l | socketpair AIO dual spray | 24+24 | Zero sentinel changes |

**Conclusion:** The allocator is zone-isolated. Cross-type spray cannot reclaim AIO
objects, and AIO self-spray writes the same status at the same offset, making overlap
undetectable through the AIO query API.

---

## 1. Candidate Analysis (Revised)

### a. pipe(42) from child thread

**Status: DEAD.** `pipe(42)` returns `-1` from both main thread and child thread
(probes 384b, 386a confirm child gets -1 for pipe). `pipe2(542)` also dead. Sony
blocked the pipe family entirely. Cannot spray with pipe buffers.

### b. socketpair(135)

**Status: WORKS but wrong zone.** socketpair creates AF_UNIX `struct socket` objects
(~512-1024 bytes) plus `struct unpcb` (~256 bytes). These are far too large for the
64B zone where AIO tracking lives. The probe results (66c, 67l) confirm zero overlap.

Socketpair is useful as a **data channel** (confirmed: write/read/kevent pipeline in
271i), not as a spray vector.

### c. shm_open(482)

**Status: WORKS but too large.** shm_open creates `struct shmfd` (~256-512 bytes in
the FreeBSD kernel). Even the `vm_object` it creates is ~192 bytes. Neither fits in
the 48-64B zone. Confirmed working (391a-391d) but not a spray candidate.

### d. namedobj_create(557)

**Status: WORKS but different zone.** 557 creates objects with handles from the shared
table. Names ≤31 chars work (65w). But the kernel struct goes to Sony's `namedobj`
allocator zone, not the AIO zone. Probe results (65w, 67f) show zero cross-corruption.

### e. evf_create(538)

**Status: WORKS but different zone.** EVF objects are in the same shared handle table
as AIO, but the kernel struct uses a different zone. 65v confirmed: EVF set/tryWait
returns -1 with create handle (unusable for readback without an open handle via 540).
65w showed mode=0 works for tryWait, but zero overlap detected.

### f. kqueue(362) + kevent(363)

**Status: WORKS but different zone.** `struct knote` is ~64-96B in FreeBSD 11.
Even if the size matched, kqueue uses `knlist_alloc` which routes to `M_KQUEUE`, a
different malloc type than AIO. Zero overlap in 65o (200 kqueue spray).

### g. setsockopt(105)

**Status: WORKS but may not heap-allocate.** Most socket options write to inline
fields in the socket struct (4-byte integer at a fixed offset), not to a separately
allocated buffer. The Sony custom options (0x2000, 0x10000, etc.) accepted 256-byte
writes, but this may be a `copyin` to a fixed field, not a variable-size allocation.

The exceptions that DO allocate:
- `TCP_CONGESTION` — allocates a cc_algo name string (~16B)
- `IP_OPTIONS` — allocates ip_opts (max 40B)
- `SO_ACCEPTFILTER` — allocates accept_filter struct

**Untested: IP_OPTIONS with exact 40B payload.** This would allocate from `M_IPMOPTS`
zone — again, different from AIO.

### h. AIO self-spray (669)

**Status: WORKS but same status value.** This is the only spray that hits the correct
zone. New AIO submissions allocate from the same zone descriptors. But 663/664/666/667
all return status integers from a structured lookup, not from raw freed memory.

The 67m characterization proves 663 returns distinct dword status codes per state:
- Immediate: `0x00000003`
- Polled: `0x00010003`
- Deleted: `0x80020003`

The status is a **computed value** from the tracking object's state field, not a raw
memory read. Self-spray writes the same state → identical readback.

### i. mlock(203)

**Status: WORKS but doesn't allocate 48-64B objects.** mlock pins existing pages; it
modifies `vm_map_entry` flags but doesn't allocate new 48B kernel objects.

### j. UMTX ops (454)

**Status: PARTIAL.** ops 5/21 work (56i2, 152k). The kernel mutex struct (`umutex`)
is 56B in FreeBSD 11 — tantalizingly close to the 0x58 target. But:
- UMTX kernel objects use their own zone (`M_UMTX`)
- op 6 (trylock) always returns -1 from child threads (385a)
- Even if the size matched, the zone is different

---

## 2. The Fundamental Problem and New Approaches

The failed sprays prove that **Sony's allocator uses typed zones** (like FreeBSD UMA
zones, but per-subsystem). Cross-type spray is structurally impossible.

### The three remaining paths forward:

### Path 1: AIO self-spray + file refcount manipulation

The `entry_dispose` function at RVA `0x3b3e90` atomically decrements `*(*(I+0x40)+0x28)`
— the file object's reference count. The double-free causes this decrement to happen
**twice**. If we can bring the refcount to exactly 1 before the race, the double-
decrement reaches -1, triggering a premature `fdrop` → **UAF on the file object**.

**Design:**
1. Open `/dev/zero` (or another fd)
2. Submit N AIO requests against that fd (each increments refcount by 1)
3. Delete N-1 of them normally (each decrements refcount by 1)
4. Race-delete the last one: both threads decrement → refcount goes from 1 to -1
5. Now the file object is freed while the fd table still holds a reference
6. Spray with a different object to reclaim the file struct's memory
7. Any I/O operation on the fd now operates on the replacement object

**Key advantage:** The file struct (`struct file` ≈ 128B) is allocated from `M_FILE`
which is a **general-purpose zone**, not AIO-specific. Other file allocations (open,
socketpair, kqueue) go to the same zone.

**Measurement needed:** What is the actual refcount of the AIO-targeted fd after the
race? If it's still positive (>1 due to other references), this doesn't trigger UAF.

### Path 2: AIO submit-during-delete (interleaved race)

The 13.60 analysis (AIO_OBJECT_FORENSICS.md §2) notes: "The vulnerability becomes a
real double-free when... concurrent submit-during-delete" occurs. If we submit NEW
AIO requests while the delete race is in progress, a new request may **reuse the freed
descriptor slot** before Thread B's re-lookup. Thread B then operates on the NEW
request's objects, potentially freeing them while they're still active.

**Design:**
1. Submit 16 AIO requests, poll them
2. Start child A: 662(ids, 16, states_A)
3. **Immediately** submit 16 new AIO requests from main thread (or child C)
4. Child B starts: 662(ids, 16, states_B)
5. If child B's re-lookup finds a new request at the old slot → it frees the new
   request's live objects → the new request is now operating on freed memory

**Key advantage:** The new request is **live** (actively performing I/O). When its
tracking structure is freed by Thread B, the completion callback writes status into
freed memory. If that freed memory has been reclaimed by a different object, the
write corrupts it.

**Risk:** High crash probability. The new request holds file references; its tracking
structure being freed while active causes a UAF on the file pointer path.

### Path 3: Brute-force KASLR bypass via double-free crash oracle

Since each TCP connection gets a fresh userland process but kernel ASLR is per-boot,
we can use the double-free to create a **crash oracle**:

1. For each candidate kernel base address K:
   a. Connect, trigger double-free
   b. AIO self-spray with controlled data containing K
   c. If the spray reclaimed the freed slot, the second delete's `entry_dispose`
      will dereference `K + 0x28` for the refcount decrement
   d. If K points to mapped kernel memory → decrement succeeds, process survives
   e. If K points to unmapped memory → kernel page fault → process or system crash

This doesn't require observing the overlap through AIO queries — the crash/survival
is the signal. With 10-12 bits of KASLR entropy, this is 2^12 = 4096 attempts.

**Risk:** Each failed guess may cause a kernel panic, requiring a PS5 reboot. The
attempt budget is limited by patience and console availability.

---

## 3. Top 3 Probe Designs

### Probe 68d: File Refcount UAF (Path 1)

```
[A] Measure fd refcount baseline
    - Open /dev/zero → fd
    - Submit 1 AIO request on fd, delete normally
    - How many references does the fd have? (Count: fd table=1, AIO=+1 per submit)

[B] Refcount targeting
    - Submit exactly 1 AIO on the fd
    - Race-delete it (both threads decrement)
    - Check: does close(fd) crash? Does a new open() return the same fd number?

[C] File object reclaim
    - If fd is freed: spray with socketpair(135) to reclaim the struct file
    - Attempt read/write/ioctl on the old fd number → type-confused I/O
```

### Probe 68e: Submit-During-Delete Interleave (Path 2)

```
[A] Concurrent submit + delete
    - Submit 16, poll
    - Start child A: 662(ids, 16, ...)
    - Main thread: immediately submit 16 new requests
    - Start child B: 662(ids, 16, ...)

[B] Check new requests
    - Are the new request IDs valid? (663 query)
    - Do any share handle indices with the old IDs?
    - Delete new requests: any failures/crashes = overlap

[C] Result buffer corruption check
    - Read result words from new requests → any unexpected values?
    - Especially check if new request result contains a kernel pointer
      from a freed tracking structure
```

### Probe 68f: Crash Oracle KASLR Sweep (Path 3)

```
[A] Single-iteration probe
    - Trigger double-free
    - AIO self-spray with I+0x40 set to candidate kernel address
    - Survive or crash → maps one bit of information per connection

[B] Scripted sweep (run via send_probe.py loop)
    - Each connection tests one candidate kernel base
    - Binary search: start at common FreeBSD kernel base (0xFFFF800000200000)
    - Step by 2MB (typical KASLR alignment)
    - Record: crash = miss, survive = possible hit

[C] Verification
    - On a surviving candidate: repeat 10 times to filter noise
    - Use the confirmed base for subsequent exploitation stages
```

---

## 4. Recommendation

**Priority 1: File refcount UAF (Path 1).**
The double-free definitely decrements the file refcount twice (`entry_dispose` reads
I+0x40 and decrements *(file+0x28)). If the refcount reaches zero, the file object is
freed from a general-purpose zone where we CAN do cross-type spray. This sidesteps
the per-type zone isolation entirely.

Measure the refcount first: submit 1 AIO request, and see if the fd's file struct
shows a refcount of exactly 2 (fd table + AIO). If so, the race drops it to 0.

**Priority 2: Submit-during-delete (Path 2).**
This is the 14.20 patch's actual target — generation counter revalidation. The fact
that Sony explicitly patched this suggests it's exploitable. The key is getting a new
submit to reuse a freed handle slot before the second thread re-validates.

**Priority 3: Crash oracle (Path 3).**
Last resort. Slow, risky, but doesn't require solving the zone isolation problem.

---

## 5. What NOT to Try Again

- More cross-type spray (namedobj, EVF, kqueue, setsockopt, socketpair) — the zone
  isolation is structural, not a timing issue. 20+ probes have confirmed this.
- AIO self-spray with 663/664/667 readback — these return computed status values, not
  raw memory. More probes in this direction are wasted.
- CPU pinning to force same-cache spray — kills the race (67j: 0 doubles on
  single-CPU pin), and cross-CPU cache is what enables the race in the first place.

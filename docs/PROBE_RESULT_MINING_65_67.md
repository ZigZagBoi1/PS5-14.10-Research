# Probe Result Mining: 65*–67* (AIO Double-Free Exploitation)

## Scope

56 result files across probes 65d–67m, covering the full AIO `aio_multi_delete` (syscall 662) TOCTOU double-free discovery and exploitation attempts.

---

## Key Findings

### 1. Double-Free Reproducibility Is Process-Dependent

The double-free is real but its hit rate varies wildly by process instance:

| Run | Process | Result |
|-----|---------|--------|
| 65l (first) | pid=626 | 65/480 (13.5%) — CONFIRMED |
| 65l (re-run 1) | pid=642 | 0/480 — no doubles |
| 65l (re-run 2) | pid=88 | 0/480 — no doubles |
| 65l (re-run 3) | pid=95 | 17/480 (3.5%) |
| 65t (64 victims) | pid=633 | 40-51/64 (63-80%) — best rate |
| 65u (main+child) | pid=633 | 345/480 (72%) — extremely reliable |
| 67i2 (gated) | pid=102 | 60/480 (12.5%) |
| 67k (combined) | pid=118 | 28/128 (22%) |
| 67f/67g/67h | pid=88 | 0/all — completely dead |

**Process pid=633 is the gold standard** — it hit doubles in nearly every trial. Pid=88 never hit once across hundreds of attempts. The difference may be due to CPU core assignment, scheduling quantum, or memory layout at process startup.

### 2. CPU Pinning Kills the Race (67b)

When both threads are pinned to CPU 0 (`setaffinity mask=0x01`), **zero doubles in 200 cycles**. The double-free requires two physical CPU cores executing concurrently. This is not a scheduling race — it's a true multi-core TOCTOU.

### 3. Batch Size Directly Controls Race Window

- **1 ID**: deterministic (one thread always wins) — 0 doubles across 65h/65i/65j
- **16 IDs**: the sweet spot — 65l and 67i2 both work
- **32 IDs**: very reliable — 65u gets 72% consistently
- **64 IDs**: overwhelming — 65t gets 63-80% per iteration
- **128 IDs**: maximum practical (669 rejects count≥129)

The 662 loop processes IDs sequentially, dropping and reacquiring the lock for each ID. More IDs = more lock-drop windows = more interleaving opportunities.

### 4. The `0x10000` Status Bit Is a Poll Flag, NOT Overlap (67e Control)

This was a critical misinterpretation corrected by 67e's control experiment:
- `663` returns `0x00000003` before poll, `0x00010003` after poll
- `666` always returns `0x00000003` regardless of poll state
- `663` returns `0x80020003` after delete

The 512 "overlaps" in 67c were actually just the poll flag being set on spray objects that went through the poll step during their setup. **The overlay oracle based on the `0x10000` bit does not work.**

### 5. The Freed Object Is in a Dedicated Zone

Every cross-subsystem spray attempt failed to produce corruption:
- kqueue fds: 0 corruption (65n, 65o)
- namedobjects: 0 corruption (65n, 65v, 65w, 66e)
- socketpairs: 0 corruption (65o, 65t, 65v)
- setsockopt(IP_OPTIONS): 0 corruption (65t)
- EVF objects: 0 corruption (66e)
- shm objects: 0 corruption (65m)
- pipe buffers: not tested directly

The freed AIO sub-object is almost certainly in its own UMA zone or a zone whose size is not shared with any of the tested primitives.

### 6. AIO-on-AIO Self-Overlap WORKS (65p)

After double-free, new AIO submit calls reclaim the freed slots. **Two AIO requests get the same kernel memory.** Probe 65p confirmed:
- `killed=6/6` and `cross_killed=3` — deleting one AIO request invalidates its overlapping partner
- `wait_anom=6` — wait (663) on overlapping IDs returns anomalous results

This is the most promising exploitation path: use AIO requests themselves to reclaim the double-freed memory, creating two handles to the same kernel object.

### 7. fd Refcount Is NOT Affected (65r)

100 double-frees on the same fd did not drain the fd refcount — the fd remains valid. The double-freed object is a per-request tracking structure internal to the AIO subsystem, **not** the file descriptor.

### 8. The AIO Budget Is 512 Concurrent Requests (66f)

66f measured this directly. 669 (submit) also only creates 1 request per call regardless of the `count` parameter (66g). Count≥129 returns -1.

### 9. Socketpair AIO Reads Real Data (67k Section E)

AIO submit on a socketpair fd, followed by writing data to the paired fd, produces:
- `result` field changes from sentinel to `0x10` (16 bytes = amount read)
- `data` field contains the written bytes (`0x41424344`)

This is a confirmed data readback path through AIO. Combined with the self-overlap from 65p, this could enable: submit AIO_A and AIO_B on the same double-freed slot → write to A's socketpair → check if B's data buffer also gets filled.

### 10. Overlap Readback Did NOT Leak Kernel Data (67d)

67d (third run, spray=128) achieved 64/64 overlap pairs. It then:
1. Deleted first members of pairs
2. Queried second members via 663/666
3. Reclaimed with different fd/sizes
4. Re-queried second members

Status stayed `00010003` throughout — no change after partner deletion or reclaim. The 663/666 query only returns the 4-byte status value — there is no wider data readback through these syscalls. The "wide read check" showed only the status dword followed by sentinel bytes.

### 11. 663 vs 666 vs 667 Characterization (67a, 67m)

| Syscall | After submit | After poll | After delete |
|---------|-------------|------------|--------------|
| 663 | `0x00000003` | `0x00010003` | `0x80020003` |
| 666 | `0x00000003` | `0x00000003` | `0x80020003` |
| 667 | always -1 | always -1 | always -1 |

663 tracks poll state, 666 does not. 667 never works. None write data to the output buffer.

### 12. Gated Race (Socketpair Synchronization) Is Most Reliable (67i2)

Using socketpair write/read as a gate to synchronize child thread startup produces the most consistent doubles:
- 67i2: 60 doubles in 30 iters (22/30 iters hit, 73%)
- 67k: 28 doubles in 8 iters (7/8 iters hit, 88%)

The gate ensures both children reach the 662 call at approximately the same time.

### 13. Namedobj Lookup Is Broken (67f)

`namedobj_create` returns a handle, but `namedobj_lookup` (540) returns -1 for the same name. Cannot use namedobjects as an overlap detection oracle.

### 14. Status Code Catalog

| Code | Meaning |
|------|---------|
| `0x00000000` | Delete succeeded |
| `0x00000003` | Request exists (not yet polled for 663) |
| `0x00010003` | Request polled (663 only) |
| `0x80020003` | Unknown/deleted ID |
| `0x80020010` | Delete path poisoned (670 was called, or not polled) |
| `0x00000002` | Socket AIO pending (65e) |

---

## Missed Signals and Anomalies

### A. The `0x00010003` vs `0x00000003` Discrepancy in 66d

66d's spray showed ALL 32 spray IDs with state `0x00010003` (anomalous), while normal un-polled IDs should be `0x00000003`. If the spray procedure didn't poll them, this could indicate the double-freed tracking structure retained its polled flag through reallocation — meaning the allocator did NOT zero the memory. **This deserves re-testing with explicit verification that no poll was called on spray IDs.**

### B. The 65p `wait_anom=6` Detail

65p reported `wait_anom=6` when using 663 on overlapping IDs. The probe output doesn't detail what the anomalous wait result was. This should be investigated: if 663 returns data from the overlapping request's buffer, it could be a readback primitive.

### C. 65s Section C "weird=30"

The second 65s run reported `weird=30` in the targeted overlap section but `crashes=0`. The exact nature of the weirdness is not detailed in the output. The corresponding source code should clarify what "weird" means.

### D. A=16 B=N Pattern

In every successful race, A gets all or nearly all 16 (A=15 or 16), while B gets 1-7. Thread A always "wins" the majority. The interleaving favors the first thread, with B catching stragglers in A's lock-drop windows. This limits the double-free to at most ~7 out of 16 IDs per iteration.

### E. The 65k Batch Submit Bug

65k submitted 16 IDs as a batch (count=16) but only the first succeeded — IDs 2-15 got state `0x80020003`. Combined with 66g (count=128 creates only 1 ID), this confirms: **669 with a multi-element reqs array only processes the first element.** The stride or layout of the `reqs` buffer may be wrong, or the submit handler intentionally processes one at a time.

### F. 67l Socketpair AIO Overlap — Clean Separation

67l's most important negative result: after double-free with two sets of socketpair AIO requests, triggering set A's socketpairs did NOT affect set B. The AIO completion mechanism correctly routes data to the originating request. Cross-contamination through the AIO read path is not achievable this way.

### G. No Process Crash in 56 Runs

Despite hundreds of double-frees, not a single process crash occurred. The kernel handles the double-free gracefully — the freed object is returned to the zone freelist twice, and subsequent allocations consume it twice. No panic, no KASAN-like detection. This means the double-free is "safe" from the process's perspective and can be repeated many times.

---

## What Has NOT Been Tried

1. **Pipe buffer spray** — pipes allocate `sf_buf` or `pipe_buffer` structs that may match the AIO sub-object size. Never tested.

2. **setsockopt with controlled sizes** — `SO_RCVBUF`/`SO_SNDBUF` trigger `sbappend` allocations. The IP_OPTIONS spray (65t, 40 bytes) didn't overlap, but different option types or sizes might.

3. **AIO write (cmd=2) instead of read (cmd=1)** — all probes used read. A write request might fill different fields in the tracking structure, enabling data injection into reclaimed objects.

4. **AIO with different request sizes** — the reqs struct is 0x28 bytes. Changing the read/write length might affect the sub-object allocation size.

5. **sendmsg with MSG_PEEK for zero-copy read** — could interact differently with the AIO completion buffer.

6. **Timing the double-free via clock_gettime** — the AIO operation itself might have measurable timing differences when operating on a double-freed vs normal object.

7. **Triple-free** — spawning three children instead of two. With 64 victims and 3 children, the third child might reclaim objects freed by the first two while the second is still processing.

8. **AIO on `/dev/rng` instead of `/dev/zero`** — `/dev/rng` provides random data; the kernel side might use different buffers or code paths.

---

## Recommended Follow-Up Probes

### Priority 1: Determine Freed Object Size
Submit a single AIO request on `/dev/zero`, then spray allocations of sizes 32, 48, 64, 96, 128, 192, 256, 512 bytes using `setsockopt(SO_IP_OPTIONS)` or `sendmsg` ancillary data. For each size, create 500+ allocations, then check if the AIO delete or poll shows corruption. The size that causes corruption reveals the AIO sub-object's UMA zone.

### Priority 2: AIO Write (cmd=2) Self-Overlap
After double-free, submit two AIO write requests that both map to the same kernel memory. Write different data through each. If the writes interfere (one overwrites the other's data), this confirms writable overlap and may enable controlled kernel memory writes through the second request's completion path.

### Priority 3: Explore 663's Full Output Contract
The 67a/67d probes only showed the status dword. But 663 has an output buffer (arg 3). Test with larger output buffers (4KB) and different layouts to see if 663 copies any additional data — especially kernel pointers from the request tracking structure.

### Priority 4: Consistent Race via Process Selection
The race success is extremely process-dependent (pid=633 worked, pid=88 never did). Try launching multiple connections in succession and racing on each — the first connection that produces doubles is the one to exploit. The race should be tested within the first 5-10 seconds of a connection.

### Priority 5: AIO Request Struct Field Manipulation
The 0x28-byte `reqs` struct passed to 669 has known fields (cmd, buf, size, fd). Try varying the `buf` pointer to point into different memory regions, or the `size` to non-page-aligned values. A request with `size=0` or `buf=NULL` might trigger different allocation or deallocation paths.

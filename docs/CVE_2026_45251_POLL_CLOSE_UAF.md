# CVE-2026-45251 poll/close Race UAF — PS5 14.10

## Status: CONFIRMED LIVE — exploitation in progress

The `seldrain()` fix is absent on PS5 14.10 (FreeBSD 11 r230171, build Sep 2026).
`close(fd)` while another thread blocks in `poll(fd)` frees the underlying file
object without waking the poller. When `poll` times out, `seltdclear` reads
`si_mtx` from freed memory — a kernel use-after-free reachable from an
unprivileged game process via `thr_new(455)` child threads.

## The Vulnerability

**Advisory:** FreeBSD-SA-26:19.file — "all supported versions of FreeBSD"

When a thread calls `poll(fd, POLLIN, timeout)`, the kernel:

1. Resolves `fd` → `struct file *fp`
2. Calls `fo_poll(fp)` → e.g. `sopoll()` for sockets
3. Inside `sopoll`: `selrecord(td, &so->so_rcv.sb_sel)` — links the thread's
   `selfd` into the socket's `selinfo.si_tdlist` (a TAILQ)
4. Thread sleeps until an event or timeout

When a second thread calls `close(fd)`:

1. Removes the fd from the descriptor table
2. `fdrop(fp)` → `fo_close()` → frees the socket (and its embedded `selinfo`)
3. **Missing:** should call `seldrain(&so->so_rcv.sb_sel)` to wake all sleeping
   pollers and detach them before freeing

Without `seldrain`, the sleeping thread's `selfd` still points into the freed
`selinfo`. On timeout, `seltdclear(td)` traverses its `selfd` list and for each
entry:

- Reads `sfd->sfd_si` → pointer into freed memory
- Calls `mtx_lock(si->si_mtx)` → reads `si_mtx` from freed memory
- Performs `TAILQ_REMOVE` on `si->si_tdlist` → writes into freed memory

This is a read + write UAF in the kernel. With controlled reclaim of the freed
zone, `si_mtx` can be an attacker-chosen pointer → arbitrary kernel mutex
lock/unlock, or `TAILQ_REMOVE` can corrupt kernel linked lists.

## Probe Results

### 500b — Ungated control (POLLNVAL baseline)

Single child thread (`thr_new`) calls `close(fd)`, main thread immediately calls
`poll(fd)`. 20 iterations × 5 fd types.

**Result:** `ret=1/rev=0x20 (POLLNVAL)` × 100/100. Close always completes before
poll enters the kernel because Lua pcall + make_syscall overhead is slower than
the native ROP child. This is the "not racing" baseline — the fd is already gone
when poll checks it.

### 500c — Gated race (seldrain absent — CVE confirmed)

Two child threads via `thr_new(455)` with socketpair gate synchronization:

- **Child A (poller):** reads gate_A → `poll(fd, POLLIN, 5000)` → writes marker
- **Child B (closer):** reads gate_B → `close(fd)` → writes marker
- **Main:** opens gate_A (poller enters kernel), 5ms delay, opens gate_B (close fires)

**Result:** `poll=0/rev=0x0` × **150/150** across all 5 fd types:

| fd type            | iterations | poll return | revents |
|--------------------|-----------|-------------|---------|
| AF_UNIX dgram pair | 30/30     | 0           | 0x0     |
| TCP socket         | 30/30     | 0           | 0x0     |
| UDP socket         | 30/30     | 0           | 0x0     |
| kqueue fd          | 30/30     | 0           | 0x0     |
| shm_open ANON      | 30/30     | 0           | 0x0     |

Total runtime: 762 seconds = ~5.08s per iteration = exactly the poll timeout.

**Interpretation:** `poll=0` means timeout with no events; `revents=0x0` means the
kernel never set POLLHUP or POLLNVAL. On a patched kernel, `seldrain()` would
wake the poller, which would recheck the fd, find it closed, and return with
POLLHUP or POLLNVAL (as in the 500b ungated case). The consistent 5-second
timeout proves `close()` does NOT notify the sleeping poller.

### 500d — Same-type spray (zone reclaim confirmed)

Same gated architecture as 500c, but Child B also calls `socket()` × 20 of the
same type after `close()` to reclaim the freed UMA zone.

**Result:** Process survived all 60 iterations (20 each: UDP, TCP, AF_UNIX).
Spray sockets allocated successfully (fd numbers 23–532 returned). The new
socket's `selinfo` is cleanly initialized (empty TAILQ), so `seltdclear` finds
no entries and returns without incident.

This confirms the freed zone IS reclaimed by same-type spray, but the reclaiming
object's clean initialization prevents a crash. Exploitation requires placing
**controlled non-zero data** at the `selinfo` offsets.

### 500e — Double-poll confusion

Three child threads: A polls target, B closes + sprays, C polls the spray socket.
Goal: Thread C's poll linkage in the reclaimed `selinfo` confuses Thread A's
`seltdclear`.

**Result:** `a=0/ar=0x0/c=0/cr=0x0` × 30/30. Both threads timed out without
interference. The TAILQ operations are idempotent when each thread is the sole
entry in its respective era — A's linkage was in the freed copy (now replaced by
spray), and C's linkage is in the fresh copy. `seltdclear` for A reads the
replaced memory (spray socket's clean selinfo) and finds nothing to remove.

## Exploitation Path

### Confirmed primitives

1. **Race window is 100% reliable** — gated architecture ensures poll blocks
   before close fires. 150/150 success rate.
2. **UMA zone reclaim works** — same-type spray returns valid fd numbers,
   confirming the freed socket slot is reused.
3. **seltdclear reads freed memory** — the timeout path touches `si_mtx` and
   `si_tdlist` from the (now-reclaimed) selinfo address.

### RETRACTED claims (500h — Lua double precision false positive)

~~Cross-zone reclaim CONFIRMED~~, ~~SMAP OFF~~ — **RETRACTED (500j/500k)**.

500h reported canary modification (`0xDEAD0001DEAD0001` → `0xDEAD0001DEAD0000`)
as proof of kernel write into userland. 500j proved this was a **Lua 5.1 double
precision artifact**: `uint64(0xDEAD0001DEAD0001)` exceeds the 53-bit mantissa
and rounds to `0xDEAD0001DEAD0000` at write time. The canary was NEVER modified
by the kernel — it was written rounded.

500k crash oracle (unmapped `0x100` at ALL 32 qword positions in spray buffer)
survived 2/2 iterations → **NO RECLAIM**. The iov spray (`malloc(M_IOV)`,
general 256B zone) does NOT reclaim freed kqueue slots because kqueue uses a
**dedicated UMA zone** (`kq_zone` via `uma_zcreate`), not the general malloc
allocator. SMAP status remains **UNVERIFIED** (no kernel access to userland
memory was ever observed).

### Current exploitation status

The UAF is real (500c: 150/150 seldrain absent) and same-type reclaim works
(500d), but placing controlled data in the freed slot requires **page-level
UMA reclamation**: exhaust `kq_zone` → force slab page release to the page
allocator → general malloc zone reuses the page → iov spray lands in former
kqueue memory. This is probe 500l.

### 500f — IPv6 sockopt spray (DEAD)

IPv6 socket creation works (fd=23), but `setsockopt(IPPROTO_IPV6, opt, 248B)`
returns -1 for ALL extension header options: HOPOPTS(49), DSTOPTS(50), RTHDR(51).

### 500g — setsockopt spray sweep (DEAD)

Full sweep of options 0-255 at levels IPPROTO_IPV6(41), IPPROTO_UDP(17),
IPPROTO_TCP(6), IPPROTO_IP(0), SOL_SOCKET(0xFFFF) with 248B buffer: **zero
hits**. Sony blocked all setsockopt options that accept large buffers.

### 500h — recvmsg iov spray (FALSE POSITIVE — RETRACTED)

**Target:** kqueue fd. Originally claimed `malloc(M_KQUEUE)` = general allocator.
Actually kqueue uses `uma_zcreate("kqueue", ...)` = **dedicated UMA zone**.

**Result:** Canary "modification" was Lua 5.1 double precision loss, not kernel
write. See 500j precision proof and 500k crash oracle (NO RECLAIM).

### 500j — Precision retest (diagnostic)

Proved `uint64(0xDEAD0001DEAD0001)` rounds to `0xDEAD0001DEAD0000` in Lua 5.1.
Re-ran 500h race with string-constructor canaries (`uint64("0xDEAD...")`): all
canaries unchanged across 3 iterations. Zero kernel pointers caught in tight
mtx_lock polling loop. **500h was a false positive.**

### 500k — Crash oracle (NO RECLAIM)

All 32 qword positions in spray buffer set to `0x100` (unmapped userland VA).
If spray reclaimed the freed kqueue and seltdclear dereferenced any qword as
`si_mtx`, the kernel would page-fault → panic → PS5 reboot.

**Result:** Both iterations survived. **NO RECLAIM.** The iov spray (general
256B zone) does not reach `kq_zone` (dedicated).

### Spray mechanism details (REVISED)

The iov spray (`malloc(M_IOV)`, general 256B zone) does NOT reach `kq_zone`
(dedicated UMA zone). Cross-zone spray requires **page-level reclamation**:

1. Exhaust `kq_zone` — create 128+ kqueues to fill multiple slab pages
2. Free ALL kqueues — return slots to kq_zone per-CPU buckets and slabs
3. Trigger `uma_reclaim` — VM pressure (large mmap/munmap) or wait for timer
4. `kq_zone` releases empty slab pages to the page allocator
5. Spray with iov (`malloc(M_IOV)`, general 256B zone) — general zone requests
   new slab pages from page allocator → gets former kq_zone pages
6. `seltdclear` reads `si_mtx` from iov data at the old kqueue's VA

### struct selinfo layout (FreeBSD 11)

```
struct selinfo {
    TAILQ_HEAD(, selfd) si_tdlist;   /* +0x00: 16 bytes (tqh_first, *tqh_last) */
    struct knlist       si_note;     /* +0x10: ~48 bytes (kl_list, lock fn ptrs) */
    struct mtx         *si_mtx;      /* +0x40: 8 bytes — THE TARGET */
};
```

### struct kqueue estimated layout

```
kq_lock:    +0x00  (24B struct mtx)
kq_refcnt:  +0x18  (4B + 4B pad)
kq_list:    +0x20  (16B TAILQ_ENTRY)
kq_head:    +0x30  (16B TAILQ_HEAD)
kq_count:   +0x40  (4B + 4B pad)
kq_sel:     +0x48  (struct selinfo, ~72B)
  si_tdlist:  +0x48 (16B)
  si_note:    +0x58 (48B knlist)
  si_mtx:     +0x88 (8B) ← THE TARGET
kq_sigio:   +0x90  (8B)
kq_fdp:     +0x98  (8B)
kq_state:   +0xA0  (4B+4B)
kq_knlist:  +0xA8  (8B+4B+4B)
kq_knhash:  +0xB8  (8B)
kq_task:    +0xC0  (~32B)
kq_cred:    +0xE0  (8B)
Total: ~0xE8 = 232B → 256B malloc zone
```

`seltdclear` calls `mtx_lock(si->si_mtx)`. If `si_mtx` points to
attacker-controlled memory shaped like a valid `struct mtx`, the lock acquire
succeeds and subsequent `TAILQ_REMOVE` writes to the attacker-chosen list
pointers → arbitrary kernel write.

## Remaining Work

- [x] ~~Test cross-zone reclaim (iov spray)~~ — DEAD (500h false positive, 500k no reclaim)
- [ ] **Page-level UMA reclamation** (500l): exhaust kq_zone → force slab
      release → general zone reclaims pages → iov spray lands in kqueue memory
- [ ] Verify SMAP status — UNVERIFIED (500h claim retracted)
- [ ] Determine exact `si_mtx` offset within `struct kqueue` (requires
      working reclaim first)
- [ ] Build the kernel write primitive from TAILQ_REMOVE
- [ ] Find a kernel R/W target: modify `ucred` for privilege escalation
- [ ] Combine with KASLR defeat (fault oracle, probes 1199a-c)

## References

- FreeBSD-SA-26:19.file (CVE-2026-45251)
- `probes/phase23_cve_2026/500b_poll_close_minimal.lua`
- `probes/phase23_cve_2026/500c_poll_close_gated.lua`
- `probes/phase23_cve_2026/500d_poll_close_spray.lua`
- `probes/phase23_cve_2026/500e_poll_close_doublepoll.lua`
- `probes/phase23_cve_2026/500f_kqueue_crosszone_spray.lua` (IPv6 sockopt — DEAD)
- `probes/phase23_cve_2026/500g_sockopt_spray_sweep.lua` (full sweep — DEAD)
- `probes/phase23_cve_2026/500h_recvmsg_iov_spray.lua` (★ CONFIRMED)
- `results/phase23_cve_2026/500b_poll_close_minimal_20261106_000923.txt`
- `results/phase23_cve_2026/500c_poll_close_gated_20261106_002340.txt`
- `results/phase23_cve_2026/500d_poll_close_spray_20261106_002740.txt`
- `results/phase23_cve_2026/500e_poll_close_doublepoll_20261106_003546.txt`
- `results/phase23_cve_2026/500f_kqueue_crosszone_spray_20261106_011110.txt`
- `results/phase23_cve_2026/500g_sockopt_spray_sweep_20261106_011530.txt`
- `results/phase23_cve_2026/500h_recvmsg_iov_spray_20261106_012529.txt` (FALSE POSITIVE)
- `probes/phase23_cve_2026/500i_si_mtx_offset_scan.lua` (no hits — correct)
- `probes/phase23_cve_2026/500j_precision_retest.lua` (★ proved false positive)
- `probes/phase23_cve_2026/500k_crash_oracle.lua` (★ proved NO RECLAIM)
- `probes/phase23_cve_2026/500l_page_level_spray.lua` (page-level reclaim attempt)
- `results/phase23_cve_2026/500i_si_mtx_offset_scan_20261106_014631.txt`
- `results/phase23_cve_2026/500j_precision_retest_20261106_015755.txt`
- `results/phase23_cve_2026/500k_crash_oracle_20261106_021322.txt`

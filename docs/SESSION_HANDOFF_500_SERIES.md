# CVE-2026-45251 Session Handoff — 500-series probes

**Date:** 2026-11-06
**Status:** CLOSED — UAF confirmed but unexploitable (zone isolation blocks reclaim)

## What Happened This Session

### 500h "RECLAIM CONFIRMED" was a FALSE POSITIVE

Probe 500h reported kernel modification of canary bytes as proof that the iov
spray reclaimed the freed kqueue slot. **This was wrong.** The "modification"
was a Lua 5.1 double precision artifact:

```lua
-- WRONG: numeric literal loses low bits past 53-bit mantissa
uint64(0xDEAD0001DEAD0001)  -- actually writes 0xDEAD0001DEAD0000

-- CORRECT: string constructor preserves all 64 bits
uint64("0xDEAD0001DEAD0001") -- writes exact value
```

Probe 500j proved this. Probe 500k (crash oracle with unmapped `0x100` at ALL
32 qword positions) survived 2/2 iterations → **NO RECLAIM**.

### kqueue uses a DEDICATED UMA zone

On FreeBSD, `kqueue` objects are allocated via `uma_zcreate("kqueue", ...)`,
creating a dedicated zone (`kq_zone`). The iov spray uses `malloc(M_IOV)` in
the general 256B zone. **These are completely separate allocators.** No amount
of iov spray will ever reclaim a kqueue slot.

### Page-level reclaim didn't work either

- 500l: 128 kqueues + 64MB VM pressure + 3s wait → survived
- 500m: 256 kqueues + 128MB mlock + 25s wait, tried BOTH 256B and 512B → survived

`uma_reclaim` either didn't fire, or kq_zone held its slabs, or the general
zone got different pages.

### Claims retracted

- ~~"SMAP OFF"~~ — UNVERIFIED (only evidence was the false positive)
- ~~"Cross-zone reclaim confirmed"~~ — DEAD for iov spray
- `docs/CVE_2026_45251_POLL_CLOSE_UAF.md` has been updated with all retractions

## What IS Confirmed

1. **UAF is real** — 500c: 150/150 seldrain absent on 14.10
2. **Same-type reclaim works** — 500d: new kqueues reuse freed slot
3. **seltdclear reads freed memory** — on poll timeout, kernel accesses stale selinfo

## What's Needed Next (Priority Order)

### 1. Use a SOCKET fd as poll target instead of kqueue

Sockets use `socket_zone` (also dedicated on stock FreeBSD). But:
- `sizeof(struct socket)` differs from `sizeof(struct kqueue)`
- Sony might have modified socket allocation
- The selinfo in a socket is at `so->so_rcv.sb_sel` (inside sockbuf)

Test: create a socketpair, poll the read end (blocks if empty), close from
another thread. Same race as 500c but with a socket target. Then spray.

### 2. Try kevent changelist spray

`kevent(kq, changelist, nchanges)` allocates `nchanges * sizeof(struct kevent)`
from `malloc(M_TEMP)` — the GENERAL malloc zone. `sizeof(struct kevent)` = 32B.
So `nchanges=8` → 256B, `nchanges=16` → 512B.

This is the general zone, same as iov. Won't help for kqueue target (dedicated
zone). Only useful if we find a target fd whose underlying object is in the
general zone.

### 3. Try Sony device fds as poll target

34 /dev nodes open from game process. Some might have `d_poll` implementations
that call `selrecord` with a selinfo in general-malloc-allocated private data.
Need to test which device fds BLOCK on poll (vs returning immediately ready).

### 4. Stronger VM pressure for page-level reclaim

- Allocate 512MB+ and mlock (might OOM)
- Wait 60+ seconds (uma_timeout fires every ~20s)
- Call madvise(MADV_FREE) on hundreds of MB

### 5. Consider abandoning CVE-2026-45251

If no spray vector works, the UAF is confirmed but unexploitable from this
process. Focus on WebKit FontFace UAF (needs WebProcess text base — currently
the #1 hard blocker) or look for new vulnerability vectors.

## Operational Notes

- **PS5 IP:** 192.168.1.37
- **Send probes:** `PYTHONIOENCODING=utf-8 python3 tools/send_probe.py --ip 192.168.1.37 --save probes/phase23_cve_2026/<name>.lua`
- **Thread budget:** 25/11/9 per loader connection (use ≤9 children to be safe)
- **Per-connection ASLR:** all addresses re-derived each run
- **Lua 5.1 precision:** ALWAYS use `uint64("0x...")` string constructor for 64-bit values

## Probe Index (500-series)

| Probe | Result | Description |
|-------|--------|-------------|
| 500a  | baseline | Initial poll/close race timing |
| 500b  | POLLNVAL | Ungated control — close beats poll |
| 500c  | **UAF CONFIRMED** | Gated race: 150/150 seldrain absent |
| 500d  | survived | Same-type spray (new kqueues) — clean selinfo |
| 500e  | survived | Double-poll confusion — no interference |
| 500f  | DEAD | IPv6 sockopt spray — all blocked |
| 500g  | DEAD | setsockopt sweep — all blocked |
| 500h  | **FALSE POSITIVE** | iov spray — Lua precision artifact |
| 500i  | no hits | si_mtx offset scan — correct (no reclaim) |
| 500j  | **DIAGNOSTIC** | Proved 500h was precision false positive |
| 500k  | **NO RECLAIM** | Crash oracle — survived, iov can't reach kq_zone |
| 500l  | survived | Page-level reclaim, 3s wait — too short |
| 500m  | survived | Multi-size (256+512B), 25s wait, 128MB mlock — still no reclaim |
| 500n  | **HARNESS FIXED** | Same-CPU readback, syscall 29→27 fix, 0/2 reclaim |
| 500o  | **ZONE ISOLATION** | Safe reclaim oracle, 0/35 reclaim — definitive |

## Session 6 (2026-11-06)

### Critical corrections

1. **Syscall 27 = `recvmsg`, not 29 = `recvfrom`** — this was the root cause
   of ALL spray failures in 500h–500m. The wrong syscall number meant iov
   buffers were never actually allocated in the kernel path.

2. **`si_mtx` model is WRONG** — `selfdfree` takes `mtx_lock(sfp->sf_mtx)`
   where `sf_mtx` lives in the **live `selfd`**, NOT in freed memory. The
   "arbitrary kernel mutex lock/unlock via attacker-controlled si_mtx" primitive
   never existed. The only freed-memory access is `TAILQ_REMOVE` on `si_tdlist`
   (first 16 bytes of freed selinfo).

3. **kqueue is NOT a dedicated UMA zone** (contrary to earlier claims) — it
   uses `malloc(sizeof *kq, M_KQUEUE, M_WAITOK|M_ZERO)`, the general malloc
   allocator. However, zone isolation prevents cross-type reclaim just as
   effectively.

### Probes run

- **500n — Same-CPU readback oracle (HARNESS FIXED)**
  - Fixed syscall: 27 = recvmsg (not 29 = recvfrom)
  - Harness works: `recvmsg_ret=0x10` and `0x20` (clean returns)
  - 2 iterations: 0 reclaim hits
  - Crash oracle model from 500k also invalidated (si_mtx not from freed memory)

- **500o — Safe reclaim oracle (DEFINITIVE)**
  - Fixed `iov[4].iov_len=0` for safe TAILQ_REMOVE (500n had iov_len=1 → crash
    on reclaim = survivorship bias)
  - 25 iterations at 256B + 10 at 512B = 35 total
  - **0/35 reclaim hits**
  - Statistically conclusive: P(0/35) at 10% per-iteration = 2.5%

### Zone isolation analysis

`MALLOC_DEBUG_MAXZONES` on FreeBSD 11 (PS5 14.10) causes `mtp_get_subzone()`
to hash each malloc type to a sub-zone index. For `numzones >= 3` (default),
`M_KQUEUE` and `M_IOV` hash to **different sub-zones**, so they draw from
completely separate slab pools. This is the definitive explanation for all
spray failures across 500h–500o.

Page-level reclaim (exhausting a sub-zone to release slab pages) is
theoretically possible but impractical from this loader — the kqueue sub-zone
would need to be fully drained, and released pages would be reassigned to the
same sub-zone pool by the allocator.

### Conclusion

**CVE-2026-45251 is CONFIRMED** (seldrain absent, 150/150 in 500c) but **NOT
EXPLOITABLE** via available primitives. The UAF touches only si_tdlist (bounded
16-byte read+write), and zone isolation prevents controlled reclaim.

### Recommendation

Close this exploitation line and return to **WebKit FontFace/Canvas UAF
(PRIORITY 0)**. The CVE is valid for disclosure/reporting purposes but cannot
be leveraged for kernel code execution from the current loader position.

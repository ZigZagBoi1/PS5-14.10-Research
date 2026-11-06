# CVE-2026-45251 Session Handoff — 500-series probes

**Date:** 2026-11-06
**Status:** BLOCKED on cross-zone spray — needs different target fd type or stronger reclaim

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

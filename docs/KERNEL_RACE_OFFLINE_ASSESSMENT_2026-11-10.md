# Kernel Race Condition Offline Assessment — 2026-11-10

## Summary

After reviewing all phase34_shm_race results (56 captures, never previously examined),
all kernel race probes, source-level analysis of FreeBSD 11 (r230171) socket code,
and the full exploit surface documentation, the assessment is:

**The Lua-side kernel race attack surface is essentially exhausted.**

## Phase34 SHM Race Results (First Read This Session)

| Probe | Type | Result |
|-------|------|--------|
| 94a | SHM ftruncate race | 0 anomalies |
| 1100d | SHM race single | 0 anomalies, 0 kptrs, 0 faults |
| 93c7 | pipe2+SHM race | 0 anomalies |
| 93c8 | deep socket races | rcvbuf 0 anomalies, close 0 anomalies |
| 93d2 | VM race deep | mprotect 0, madvise 0 |
| 1114a | read+ftruncate race | 0 kptrs |
| 1111a | sendfile+ftruncate | child stopped round 1 |
| 93c9 | poll/close UAF | crashed during UDP race (void) |
| 97a, 98a, 1100a | various | void captures (binary crash output) |
| 93e2 | poll/close race | "anomalies" are POLLHUP (0x0020) = expected behavior |

**Zero exploitable anomalies across all 56 captures.**

## IPv6 Setsockopt Race (1402a) — WEAKENED

Source analysis of FreeBSD 11 `ip6_setpktopt()`:

```c
case IPV6_PKTINFO:
    pktopt->ip6po_pktinfo = *pktinfo;  // STRUCT COPY, not pointer
```

`ip6po_pktinfo` is an **embedded struct** inside `ip6_pktopts`, not a dynamically
allocated pointer. Racing two `setsockopt(IPV6_PKTINFO)` calls produces a **torn
struct write** of our own data, NOT a use-after-free. Similarly, IPV6_TCLASS is a
simple int assignment.

The options that DO use pointer alloc/free:
- **RTHDR** — `ip6po_rhi_rthdr` is malloc'd — but len>0 returns -1 on 14.10
- **DSTOPTS/HOPOPTS** — headers are malloc'd — BLOCKED on 14.10
- **2292PKTOPTIONS** — `ip6_pcbopts()` alloc/free — BLOCKED on 14.10

**Conclusion:** The CVE-2020-7457 race pattern requires freeing/reallocating a pointer.
All options with pointer semantics are blocked on 14.10. The working options (PKTINFO,
TCLASS) only do value copies. The race probes should still run for completeness, but
a UAF is not expected.

## SO_SNDBUF TOCTOU (1402b) — Logical Overflow Only

The `sosend_generic` race window:
1. Read `sbspace` (= sb_hiwat - current) under SOCKBUF_LOCK
2. Drop lock
3. Allocate mbufs for `sbspace` bytes
4. Reacquire lock
5. `sbappendstream()` — append mbufs to linked list

If SO_SNDBUF shrinks `sb_hiwat` between steps 2 and 4, the append puts more data
in the buffer than the new limit allows. But the send buffer is an **mbuf chain**
(linked list), not a contiguous buffer. The "overflow" is logical (exceeding the
high-water mark), not a memory corruption. This is DoS-class, not exploitable.

## Close-vs-Setsockopt — Already Ruled Out

Per 1402a header: `fget()` at the start of `kern_setsockopt` takes a reference on
`struct file`. `close()` calls `fdrop()` which only frees when refcount hits zero.
While setsockopt holds the fd, close cannot free the underlying socket/inpcb.

## Remaining Kernel-Side Vectors

| Vector | Status | Viability |
|--------|--------|-----------|
| IPv6 PKTINFO dual race | Written (1402a) | LOW — value copy, not pointer |
| SO_SNDBUF TOCTOU | Written (1402b) | LOW — logical overflow in mbuf chain |
| PKTINFO + TCLASS cross | Written (1405a) | LOW — both are value copies |
| Multi-process TCP PCB race | Not written | MEDIUM — untested, harder to coordinate |
| Device ioctl deep dive | Swept 32M calls | DEAD — nothing found |
| All 400+ syscalls | Exhausted | DEAD — zero kernel pointers |

## Path Forward

The kernel R/W primitive will come through WebKit, not Lua syscalls:

1. **FontFace UAF chain** — 100% reclaim, forge write, GC destructor all confirmed
2. **Blocker: WebProcess text base** — VP (vtable pointer) leaked but RVA unknown
3. **With base known:** forged vtable → code reuse chain → kernel syscall
4. **Info leak candidates:** CVE-2026-64718 (different Canvas UAF), splice corruption,
   JIT CodeBlock residue (IF DFG active — but DFG is OFF, so this is dead too)

The Lua infrastructure (child thread ROP, 5-arg syscalls, fault oracle KASLR) is
the second stage: once WebKit provides kernel R/W, the Lua side patches credentials.

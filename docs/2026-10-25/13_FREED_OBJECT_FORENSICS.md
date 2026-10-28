# Freed Object Forensics — Consolidated

**Date:** 2026-10-25 (Session 2)
**Source:** aio-object-forensics + 13-60-kernel-mining agents

## Object Hierarchy

`aio_multi_delete` (syscall 662) frees these per AIO request:

```
  R  ────── 0x30 bytes (48B) ── zone 0x1ab59e0 ── FREED FIRST
  │   Contains: thread/process/credential kernel pointers
  │   KASLR leak target (stale kernel pointer at R+0x10 or R+0x08)
  │
  I  ────── 0x58 bytes (88B) ── zone 0x1ab5900 ── FREED SECOND
  │   +0x10: obfuscated pointer ((val >> 4) ^ val)
  │   +0x18: → R pointer
  │   +0x20: → Q pointer
  │   +0x28: split-info pointer (warns if non-null)
  │   +0x40: file object pointer (REFCOUNTED)
  │          entry_dispose: lock xadd [*(I+0x40)+0x28], -1
  │          → ARBITRARY KERNEL ATOMIC DECREMENT
  │
  Q  ────── 0x58 bytes (88B) ── zone 0x1ab5970 ── freed on last-ref only
  │   +0x00: total count (dword)
  │   +0x04: pending count (dword)
  │   +0x08: state (3=completed, 4=cancelled)
  │   +0x0C: completion flag
  │   +0x20: lock header (lockmgr, op 0x80000/0x100000)
  │   +0x50: waiter-list head
  │
  D  ────── varies ── zone 0x1ab5a50 ── freed on last-ref only
       Descriptor payload + pointer table + descriptor itself
```

## The Atomic Decrement Primitive

`entry_dispose` (RVA 0x3b3e90) does:
1. Check I+0x28: warn if non-null ("split info")
2. If I+0x40 non-null: `lock xadd [*(I+0x40)+0x28], -1`
   - Atomically decrements refcount at (file_object + 0x28)
   - If reaches zero: calls release routine
3. Free I to zone 0x1ab5900

**Exploitation:** If attacker controls I+0x40 after reclaim, `entry_dispose` decrements `*(attacker_value + 0x28)` — arbitrary kernel atomic decrement. Targeting any refcounted kernel object's refcount creates underflow → UAF cascade.

## UMA Zone Mapping (Estimated)

| Zone RVA | Alloc size | Likely UMA bucket | Objects per 16KB slab |
|----------|------------|--------------------|-----------------------|
| 0x1ab59e0 | 0x30 (48B) | 64B | 256 |
| 0x1ab5900 | 0x58 (88B) | 128B | 128 |
| 0x1ab5970 | 0x58 (88B) | 128B | 128 |
| 0x1ab5890 | variable | varies | — |
| 0x1ab5a50 | variable | varies | — |

**Caveat:** These are Sony-custom allocator zone addresses, not standard UMA zone descriptors. Whether they map to UMA's generic `malloc-64`/`malloc-128` zones or dedicated AIO zones cannot be determined without a 14.10 kernel image. The Lapse exploit's success with socket/evf spray suggests they DO share zones with other subsystems.

## The TOCTOU Window (Annotated)

```
Step 5:  Acquire Q+0x20 lock (0xbf1770, op 0x80000)
Step 6:  Check Q+0x0C completion flag and Q+0x50 waiter
Step 7:  *** RELEASE Q+0x20 lock ***          ← WINDOW OPENS
         ─────────────────────────────────────
Step 8:  Release D read lock (0x399eb0)       │ Both threads can
Step 9:  Acquire D EXCLUSIVE lock (0x39a2a0)  │ pass validation
         ─────────────────────────────────────  ← WINDOW CLOSES
Step 10: Re-read I from D's table
Step 11: Free I, R, Q, D via entry_dispose
Step 12: Clear I's table slot
Step 13: Release D exclusive lock
```

Window duration: lock release + lock acquire latency, typically hundreds of nanoseconds. On two CPUs executing concurrently, the second thread passes validation in the window ~14% of the time per ID (65l measurement).

## Allocator Behavior

- `func_0x00c08b50(size, zone, flags)` — allocation
- `func_0x00c08df0(ptr, zone)` — deallocation
- Flags `0x102`: bit 0x100 triggers zero-fill on allocation
- Newly allocated I/R/Q objects are zero-initialized

FreeBSD UMA has NO double-free detection. Freed objects return to LIFO bucket caches. Two allocations from the same zone after a double-free both receive the same pointer.

## File Refcount Double-Decrement

`entry_dispose` decrements `*(file_object+0x28)` — the file's refcount. Double-free means double-decrement. Probe 65r showed the fd survives 100 double-frees, so either:
- The refcount starts high enough (fd table holds one + each AIO request holds one)
- The double-freed object is an internal tracker, not the primary file reference

## 670 Poison Mechanism

Calling `670 (aio_init)` permanently poisons the 662 delete path. After 670, all delete attempts return `0x80020010`. The initialization installs a different validation path that rejects deletes. **NEVER call 670 before the race.**

This was the root cause of probes 65d-65g failing.

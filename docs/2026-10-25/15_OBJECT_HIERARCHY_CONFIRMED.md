# Finding 15: AIO Freed Object Hierarchy — Sizes, Zones, and Kernel Pointers

> **Date:** 2026-10-25 Session 3
> **Agents:** aio-object-forensics, 13-60-kernel-analysis
> **Confidence:** HIGH (from 13.60 Ghidra decompile, cross-validated by two agents)

---

## Object Tree Per AIO Request ID

```
D (Descriptor, handle table entry)
 +-- +0x10 --> A (Payload, 0x30 bytes, zone 0x1ab5890)
      +-- +0x10 --> completion header pointer
      +-- +0x28 --> T (pointer table, count x 8 bytes, zone 0x1ab5a50)
      |    +-- T[slot] --> I (Queue entry, 0x58 bytes, zone 0x1ab5900)  <<< PRIMARY TARGET
      |         +-- +0x10 --> obfuscated pointer ((val >> 4) ^ val)
      |         +-- +0x18 --> R (Request metadata, 0x30 bytes, zone 0x1ab59e0)
      |         |    +-- +0x10 --> credential-like reference
      |         +-- +0x20 --> Q (Completion header, 0x58 bytes, zone 0x1ab5970)
      |         |    +-- +0x08 --> state (must be 3 or 4 for deletion)
      |         |    +-- +0x0C --> completion flag
      |         |    +-- +0x20 --> lock (lockmgr)
      |         |    +-- +0x50 --> waiter-list head
      |         +-- +0x28 --> split-info (warns if non-null on free)
      |         +-- +0x40 --> F (refcounted file object, kernel pointer)  <<< ATOMIC DECREMENT
      |         +-- +0x48/+0x50 --> list links
      +-- +0x20 --> descriptor copy (from 0x1a7d800, count x 0x28 bytes)
```

## Freed Objects Per Delete (662)

| Order | Object | Size | Zone (13.60) | Kernel Pointers | Double-Free Role |
|-------|--------|------|-------------|-----------------|------------------|
| 1 | **R** (request metadata) | 0x30 (48B) | `0x1ab59e0` | +0x10 credential-like ref | Freed first; credential release if +0x10 non-null |
| 2 | **I** (queue entry) | 0x58 (88B) | `0x1ab5900` | +0x10 obfusc ptr, +0x18→R, +0x20→Q, +0x40→file | **PRIMARY** — entry_dispose does refcount decrement on I+0x40 |
| 3 | Q lock | — | — | — | Lock destroyed |
| 4* | **Q** (completion) | 0x58 (88B) | `0x1ab5970` | +0x50 waiter-list head | Only on last-ref (count==1) |
| 5* | **A** (payload) | 0x30 (48B) | `0x1ab5890` | +0x28→T, +0x10→Q | Only on last-ref |
| 6* | **T** (ptr table) | N×8 | `0x1ab5a50` | Each entry→I | Only on last-ref |
| 7* | **D** (descriptor) | variable | `0x1ab5a50` | +0x10→A, +0x08 ctx | Only on last-ref |

*Steps 4-7 only execute when `psVar6[1] == 1` (single-entry descriptor).

## The Atomic Decrement Primitive

`entry_dispose` (RVA 0x3b3e90) at step 2:
```asm
lock xadd dword ptr [rax + 0x28], ecx   ; ecx = 0xFFFFFFFF = -1
```
This atomically decrements `*(*(I+0x40) + 0x28)`. If an attacker controls I+0x40 after reclaiming the freed slot, this becomes **arbitrary kernel atomic decrement** at `attacker_value + 0x28`.

## TOCTOU Window

Race between Q lock release (step 12 in full sequence) and D exclusive lock acquire (step 14):
```
Thread A: release Q lock --> release D read lock --> [WINDOW] --> acquire D exclusive
Thread B: enters same window, sees valid Q in state 3/4, proceeds to free
```
Both threads pass validation, both reach the free path.

## Key Unknown

Does thread B actually reach `entry_dispose` on the same I, or does the exclusive re-lookup return NULL? If NULL → "double success" but no double-free. A TRUE UAF requires **submit-during-delete** where handle recycling causes Thread B to operate on a NEW object (exactly what the 14.20 patch fixes with generation revalidation).

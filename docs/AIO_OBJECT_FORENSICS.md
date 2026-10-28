# AIO Double-Free Object Forensics — PS5 14.10

## Status: Analysis complete (2026-10-25)

This document identifies the kernel objects freed by syscall 662 (`aio_multi_delete`),
their sizes, allocation zones, internal pointers, and which fields an attacker
would want to control after reclaiming the double-freed memory. All code references
are from the 13.60 Ghidra decompile (`results/kernel_handlers/decompiled/sys_662.c`)
and the AIO ownership analysis (`evidence/2026-10-18-implementation-followup/`).
14.10 behavioral match is strong but identical code is not proven.

---

## 1. Object inventory

The 662 deletion path (`adjacent_3af920`, 525 instructions) processes each ID by
looking up a descriptor D, then resolving an indexed object I via D's pointer
table. The deletion frees I and its sub-objects. When I is the last reference in
D (count field == 1), the descriptor and all its infrastructure are also freed.

### I — Indexed object ("queue entry")

| Property | Value |
|---|---|
| **Size** | **0x58 bytes (88 bytes)** |
| **Zone** | `0x1ab5900` |
| **Allocator** | `func_0x00c08b50(0x58, 0x1ab5900, 0x102)` (sys_662.c lines 2622/2636) |
| **Free** | `entry_dispose` at RVA 0x3b3e90 → tail-jumps `func_0x00c08df0(I, 0x1ab5900)` |
| **Diagnostic** | `"free_queue_entry"` at line 0xb35 if I+0x28 is non-null |

**Internal fields:**

| Offset | Size | Content | Source |
|---:|---:|---|---|
| +0x10 | 8 | Obfuscated pointer (`(val >> 4) ^ val`) | sys_662.c line 596: `(long)*(ulong *)(lVar8 + 0x10) >> 4 ^ *(ulong *)(lVar8 + 0x10)` |
| +0x18 | 8 | Pointer to R (sub-object, 0x30 bytes) | sys_662.c line 641: `lVar5 = *(long *)(lVar8 + 0x18)` |
| +0x20 | 8 | Pointer to Q (aggregate, 0x58 bytes) | sys_662.c line 598: `psVar1 = *(short **)(lVar8 + 0x20)` |
| +0x28 | 8 | Split-info pointer (warning if non-null on free) | entry_dispose.asm.txt line 5: `cmp qword ptr [rdi + 0x28], 0` |
| +0x40 | 8 | File object pointer (refcounted) | entry_dispose.asm.txt line 13: `mov rax, qword ptr [rbx + 0x40]` |

`entry_dispose` (RVA 0x3b3e90) does the following:
1. Warns if I+0x28 is non-null ("split info")
2. If I+0x40 is non-null: `lock xadd [*(I+0x40)+0x28], -1` — atomically decrements
   refcount. If it reaches zero, calls `func_0x0072b380(*(I+0x40), gs:[0])` (likely
   vnode/file release). Then clears I+0x40.
3. Tail-jumps to `func_0x00c08df0(I, 0x1ab5900)` — deallocates I from zone 0x1ab5900.

### R — Request metadata (at I+0x18)

| Property | Value |
|---|---|
| **Size** | **0x30 bytes (48 bytes)** |
| **Zone** | `0x1ab59e0` |
| **Allocator** | `func_0x00c08b50(0x30, 0x1ab59e0, 0x102)` (sys_662.c line 2607) |
| **Free** | `func_0x00c08df0(R, 0x1ab59e0)` (sys_662.c line 649) |

**Internal fields:**

| Offset | Size | Content | Source |
|---:|---:|---|---|
| +0x10 | 8 | Sub-pointer (cleared and released via `func_0x002a9670` before free) | sys_662.c lines 643-646 |

R is freed BEFORE I in the deletion path. If R+0x10 is non-null, it is released
through `func_0x002a9670()` and zeroed, then R itself is freed from zone 0x1ab59e0.

### Q — Request aggregate

| Property | Value |
|---|---|
| **Size** | **0x58 bytes (88 bytes)** |
| **Zone** | `0x1ab5970` |
| **Allocator** | `func_0x00c08b50(0x58, 0x1ab5970, 0x102)` or `count * 0x58` for per-element |
| **Free** | `func_0x00c08df0(Q, 0x1ab5970)` (sys_662.c line 702) |
| **Freed when** | Descriptor count reaches 0 (last ID deleted) |

**Internal fields (from AIO_OWNERSHIP_ANALYSIS.md):**

| Offset | Size | Content |
|---:|---:|---|
| +0x00 | 4 | Total count (dword) |
| +0x04 | 4 | Pending/active count (dword) |
| +0x08 | 4 | State: 1=active, 2=in-progress, 3/4=completed (delete requires 3 or 4) |
| +0x0C | 1 | Completion flag |
| +0x0D | 1 | Mode flag (determines 3-vs-4 terminal state) |
| +0x20 | ~0x20 | Lock header (lockmgr, operation 0x80000/0x100000) |
| +0x50 | 8 | Waiter-list head (singly linked via W+0x30) |

Q can be either shared (one Q for all I's in a descriptor) or per-element (one Q
per I), depending on the construction branch chosen by the submit path. On 14.10,
individual submits (count=1) create one I with one Q.

### D — Descriptor and infrastructure (freed only on last-reference delete)

| Object | Size | Zone |
|---|---|---|
| A (descriptor payload) | ~0x30+ | `0x1ab5890` |
| T (pointer table) | count × 8 | `0x1ab5a50` |
| D (descriptor itself) | varies | `0x1ab5a50` |

These are freed at sys_662.c lines 702-710 only when `psVar6[1] == 1` (last reference).

---

## 2. The TOCTOU race mechanics

The 662 handler processes IDs in a loop. For each ID:

```
1. Look up descriptor D (READ lock via 0x399ee0)
2. Resolve I from D's table at index = ID >> 16
3. Follow I+0x20 → Q
4. Check Q state (must be 3 or 4 = completed)
5. ACQUIRE Q lock (0xbf1770, op 0x80000)
6. Check completion flag (Q+0x0C) and waiter pointer (Q+0x50)
7. *** RELEASE Q lock (0xbf1770, op 0x100000) ***     ← TOCTOU window opens
8. Release D read lock (0x399eb0)
9. Acquire D EXCLUSIVE lock (0x39a2a0)               ← TOCTOU window closes
10. Re-read I from D's table
11. Free I and sub-objects via entry_dispose + individual frees
12. Clear I's table slot
13. Release D exclusive lock
```

**The window (steps 7-9):** Q lock is released, then D read lock is released, then
D exclusive lock is requested. During this window, a second thread can:
1. Acquire D read lock
2. Find the same I, follow to Q
3. See Q in a valid deletable state (still 3 or 4)
4. Acquire/release Q lock
5. Proceed to its own exclusive D lock request

The D exclusive lock serializes steps 9-13, so in the simple case (65l probe with
separate descriptors), Thread B finds a null table entry after Thread A clears it.
Thread B reports success (per-item status = 0) without freeing anything.

**The 65l "double delete" count (65/480) measures the RACE WINDOW being hit, not
actual double-frees.** In the 65l scenario, each of the 16 IDs has its own
descriptor, so when Thread A frees and deregisters D, Thread B's exclusive lookup
returns null → success without free.

### When actual double-free occurs

The vulnerability becomes a real double-free when:

1. **Concurrent submit-during-delete:** Main thread submits new AIO requests while
   children race on 662. A new request could reuse the freed descriptor slot. Thread
   B's exclusive lookup finds the NEW descriptor and operates on its objects.

2. **Missing generation revalidation (the 14.20 patch):** The 14.10 handler does NOT
   revalidate the ID's generation counter after the lock-drop. The 14.20 patch adds
   this check. Without it, a recycled handle passes validation.

3. **Shared descriptors (batch submit):** If multiple IDs share one descriptor (batch
   submit with count>1), deleting different IDs under the same descriptor creates
   cross-ID interference. However, 14.10 batch submit (count>1 in 669) only creates
   one request per call (confirmed in 65k), so this path may not be directly reachable.

---

## 3. Exploitation targets

### Primary: I+0x40 → arbitrary kernel decrement

`entry_dispose` atomically decrements `*(*(I+0x40) + 0x28)`. If an attacker:
1. Triggers the double-free of I (0x58 bytes, zone 0x1ab5900)
2. Sprays matching-size allocations containing a chosen value at I+0x40
3. The second thread's entry_dispose call decrements `*(attacker_value + 0x28)`

This is an **arbitrary kernel atomic decrement** primitive. Targeting a refcounted
kernel object's refcount creates a refcount underflow → UAF of that object.

### Secondary: I+0x18 → fake free primitive

I+0x18 points to R, which is freed from zone 0x1ab59e0. If the attacker controls
I+0x18 to point at a different 0x30-byte kernel object, the delete path frees it
from zone 0x1ab59e0 → **type confusion / cross-zone free**.

### Tertiary: I+0x20 → lock corruption

I+0x20 points to Q. The delete path acquires Q's lock at Q+0x20 (operation 0x80000).
If the attacker controls I+0x20 to point at attacker-controlled memory, the lock
manager operates on an arbitrary address → potential corruption.

---

## 4. Allocation zones (Sony custom allocator)

All AIO objects use `func_0x00c08b50` (alloc) / `func_0x00c08df0` (free) with
zone-descriptor addresses in kernel data. These are Sony's custom allocator, NOT
standard FreeBSD UMA zones. Cross-subsystem spray requires finding other kernel
objects allocated from the **same zone addresses**.

| Zone addr | Alloc size | Object | Purpose |
|---|---|---|---|
| `0x1ab5900` | 0x58 (88 B) | I (indexed object) | **Primary double-free target** |
| `0x1ab59e0` | 0x30 (48 B) | R (request metadata) | Freed before I; secondary target |
| `0x1ab5970` | 0x58 (88 B) | Q (aggregate) | Freed only on last-ref; same size as I |
| `0x1ab5890` | varies | A (descriptor payload) | Freed only on last-ref |
| `0x1ab5a50` | varies | T / D (table / descriptor) | Freed only on last-ref |
| `0x1a7d800` | count × 0x18 | Diagnostic array | Conditionally allocated; freed after loop |

**Flags 0x102:** Bit 0x100 triggers zero-fill on the small-allocation path
(`allocator_zero_path.asm.txt:0x43bedc`). So newly allocated I/R/Q objects are
zero-initialized.

### Cross-zone spray candidates

Since the AIO zones are Sony-custom, the best spray strategy is **self-spray within
the AIO subsystem**: submit new AIO requests to allocate new I/R/Q objects from the
same zones. This serves as both the TOCTOU trigger (recycling handles) and the spray
(filling freed slots with controlled data).

Other Sony subsystem objects of matching size (0x58 bytes) from zone 0x1ab5900:
- Unknown without a 14.10 kernel image. The zone address could be shared with
  other Sony subsystems that allocate 0x58-byte objects.
- The `namedobj` family (557/558) creates objects via the same handle table
  (`process+0xc48`) — worth testing if they use the same zones.
- EVF objects (538) also use the handle table — test for zone match.

For standard FreeBSD objects, the Sony allocator likely separates them from BSD
malloc/UMA zones, so pipe buffers, socket options, and knote structures are
unlikely to reclaim AIO objects. This needs verification.

---

## 5. Recommended next probes

### 5a. Measure the actual double-free (not just double-success)

The 65l probe counts double-success (both states = 0). To confirm an actual
double-free, the next probe should:
1. Submit 16 requests (as in 65l)
2. Race two children on 662 (as in 65l)
3. BETWEEN the two children, have the main thread submit NEW requests
4. After the race, check if any new request's I object contains stale data
   from the old request (proving the freed slot was reused)

### 5b. Self-spray: submit-during-delete

1. Submit N requests individually (IDs: A[0..N-1])
2. Poll all
3. Spawn child A: delete all N
4. Spawn child B: delete all N
5. While children race: main thread submits N new requests (IDs: B[0..N-1])
6. After race: read back B's objects via 664 poll — check for anomalies

If the new B requests reuse I objects freed by A, and child B's entry_dispose
operates on the recycled B objects, we have a confirmed UAF with controlled data.

### 5c. Cross-subsystem zone test

Submit an AIO request, delete it, then immediately create an EVF (538) or
namedobj (557) to see if the new object lands in the same memory as the freed I.
If it does, the zones overlap → cross-subsystem spray is possible.

### 5d. KASLR via I+0x40

If the double-free is confirmed and spray works:
1. Spray I objects containing a known kernel address at +0x40
2. Read the refcount at *(address + 0x28) before and after the decrement
3. The refcount value reveals whether the address is valid → KASLR oracle

---

## 6. Relationship to known exploits

### Relapse (fw ≤ 13.60, Jose Coixao)

The original Relapse exploit raced `aio_multi_wait` (663) against `aio_submit_cmd`
(669) to create a dangling waiter reference. 14.00 reportedly closed that specific
wait-vs-submit race. The 662 TOCTOU is a DIFFERENT vulnerability in the same
subsystem — it's in the delete path, not the wait path. Patched in 14.20 with a
post-lock-drop generation revalidation.

### Object comparison to FreeBSD AIO

PS5's AIO subsystem is a Sony replacement, not FreeBSD's native AIO. FreeBSD's
`struct aiocb`, `struct kaioinfo`, and `struct kaiocb` have different sizes and
layouts. The I/R/Q/D objects are Sony-specific structures with no direct FreeBSD
equivalent. The allocator zones are also Sony-custom, not FreeBSD UMA.

---

## 7. Evidence summary

| Claim | Evidence | Confidence |
|---|---|---|
| I is 0x58 bytes from zone 0x1ab5900 | sys_662.c lines 2622/2636 (alloc) + entry_dispose.asm (free) | High (13.60 static) |
| R is 0x30 bytes from zone 0x1ab59e0 | sys_662.c line 2607 (alloc) + line 649 (free) | High (13.60 static) |
| Q is 0x58 bytes from zone 0x1ab5970 | AIO_CONSTRUCTION_ANALYSIS.md + sys_662.c line 2559 (alloc) | High (13.60 static) |
| entry_dispose decrements *(I+0x40)+0x28 | entry_dispose.asm.txt:0x3b3ec8 `lock xadd` | High (13.60 static) |
| I+0x18 sub-object freed before I | sys_662.c lines 641-650 | High (13.60 static) |
| TOCTOU window exists between Q lock release and D exclusive acquire | sys_662.c lines 621-631 | High (13.60 static) |
| 65l "double deletes" are double-success, not necessarily double-frees | Code analysis: exclusive lookup returns null after first thread's cleanup | Medium (inference from 13.60 code; 14.10 behavior matches) |
| Sony custom allocator, not FreeBSD UMA | Zone addresses are kernel data pointers, not UMA zone names | High (13.60 static) |
| 14.10 objects match 13.60 sizes | Behavioral match: 662 accepts count 1-128, rejects ≥129 (probe 125a); same ID format | Medium (behavioral, not code-identical) |

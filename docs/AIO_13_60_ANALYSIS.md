# AIO Subsystem 13.60 Kernel Analysis — Exploitation Guide

> **Date:** 2026-10-25. Source: `results/kernel_handlers/decompiled/sys_662.c`,
> `results/kernel_handlers/analysis/sys_662.md`, `sys_669_deep.md`,
> `docs/AIO_FAMILY_13_60_DECODE.md`, `docs/AIO_DOUBLE_FREE_14_10.md`.
> This is static analysis of the 13.60 capture applied to the confirmed 14.10
> double-free. No 14.10 kernel image is available.

## 1. The TOCTOU Race — Exactly What Happens

From the decompiled `_aio_multi_delete` (`adjacent_3af920`, RVA `0x3af920`,
525 instructions):

```
for each ID in the batch:
  1. Look up handle via func_0x00399ee0(proc+0xc48, handle, 0x160)  // typed handle lookup
  2. Validate slot index: high16 < object->count
  3. Get queue entry: object->queue_entries[slot]                    // lVar8 at +0x14 array
  4. Check state+8 == 3 or 4 (completed/cancelled)
  5. Acquire sync on request+0x20 via func_0x00bf1770
  6. Check completion_flag+0xc and waiter_link+0x50
  7. Release sync on request+0x20 via func_0x00bf1770
  ────── WINDOW: lock dropped, object still in table ──────
  8. Re-acquire handle via func_0x0039a2a0                          // SECOND lookup
  9. Free sub-objects (see §2 below)
  10. Remove slot from pointer array, free object
  11. Release handle via func_0x00399e30
```

**The race is between steps 7 and 8.** Thread A drops the sync at step 7 and
proceeds to step 8. Thread B enters step 2 during this gap, sees the same
object still in the table, passes validation, and both threads proceed to
free the same sub-objects.

The analysis report confirms: "transitions between the initial lookup and
deletion reacquisition" is an explicit review boundary. A failed final
copyout "does not roll back already applied deletions."

## 2. What Gets Double-Freed — The Object Hierarchy

From the decompiled 662 cleanup path (lines 640-710 of sys_662.c) and the
669 allocation analysis:

### Allocation zones (13.60 RVA addresses)

| Zone RVA | Alloc size | Object type | Alloc call | Free call |
|---|---|---|---|---|
| `0x1ab5890` | variable (`count * 8`) | Queue entry pointer array | `func_0x00c08b50(count*8, 0x1ab5890, 0x102)` | `func_0x00c08df0(ptr, 0x1ab5890)` |
| `0x1ab5970` | `0x58` (88 bytes) | Queue entry / completion header | `func_0x00c08b50(0x58, 0x1ab5970, 0x102)` | `func_0x00c08df0(ptr, 0x1ab5970)` |
| `0x1ab59e0` | `0x30` (48 bytes) | AIO object (top-level) | `func_0x00c08b50(0x30, 0x1ab59e0, 0x102)` | `func_0x00c08df0(ptr, 0x1ab59e0)` |
| `0x1ab5900` | `0x58` (88 bytes) | Per-request queue entry | `func_0x00c08b50(0x58, 0x1ab5900, 0x102)` | `func_0x00c08df0(ptr, 0x1ab5900)` |
| `0x1a7d800` | variable (`count * 0x18`) | Temporary per-ID context | `func_0x00c08b50(count*0x18, 0x1a7d800, 0x102)` | `func_0x00c08df0(ptr, 0x1a7d800)` |

`func_0x00c08b50` is the allocator (`malloc`/`uma_zalloc`-like).
`func_0x00c08df0` is the deallocator (`free`/`uma_zfree`-like).
The second argument is the zone descriptor address.

### The 662 delete path frees these objects per request (in order):

1. **`lVar5` at `lVar8+0x18`** — saved execution context, 0x30 bytes,
   freed to zone `0x1ab59e0` (line 649). If `lVar5+0x10 != 0`, calls
   `func_0x002a9670()` first (reference release), then zeros it.

2. **Queue entries from `lVar8+0x20`** — when `object->count == 1` (single
   request), the pointer at `+0x20` is freed via `func_0x00bf1760`
   (sync destroy) then the entry at each slot in the pointer array at
   `+0x14` is freed via `func_0x003b3e90` (`free_queue_entry`). When
   `object->count > 1`, the `+0x20` sync is destroyed and entries
   individually freed.

3. **Three final frees per object** (lines 700-710):
   - `object+0x10` → zone `0x1ab5970` (completion header, 0x58 bytes)
   - `object+0x20` → zone `0x1ab5890` (queue entry pointer array)
   - `object+0x28` → zone `0x1ab5a50` (copied descriptor block)
   - `object` itself → zone `0x1ab5a50`

### What gets double-freed in the TOCTOU:

**Both threads free the same objects from the same zones.** The critical
double-frees are:

1. **Zone `0x1ab59e0` (0x30 bytes):** The saved execution context at
   `queue_entry+0x18`. This contains `thread/process/credential` values
   that were captured at submission time.

2. **Zone `0x1ab5970` (0x58 bytes):** The completion header at
   `object+0x10`. Contains sync object, completion state.

3. **Zone `0x1ab5890`:** The pointer array at `object+0x28`.

4. **Per-entry frees via `free_queue_entry` (0x1ab5900, 0x58 bytes):**
   Each queue entry. `free_queue_entry` at RVA `0x3b3e90` decrements
   a file refcount and invokes its release routine, then frees the 0x58
   entry storage.

## 3. Saved Execution Context — What's Inside the 0x30

From the 669 submission worker (`sys_669_deep.md`, step 7):

> a 0x30-byte saved execution context (current thread/process-related
> values and held credential-like reference)

The worker at `+0x2a20` (`aio_worker_entry2`):

> saves execution-related fields at `+0x31d5..+0x3225` and restores them
> near `+0x384f`; credential-like objects were held on submission and
> released by destruction.

**This 0x30-byte context almost certainly contains kernel pointers:**
- A pointer to the submitting thread's `struct thread`
- A pointer to the submitting process's `struct proc`
- A held credential reference (kernel pointer)
- Possibly the thread's `ucred` pointer

The double-free of this object is the most interesting for KASLR defeat:
if we can reclaim the 0x30-byte slot with controlled data, then trigger
a read-back through a surviving reference to the original object, we
leak kernel addresses.

## 4. The Lock Situation

The 662 delete path uses three different synchronization mechanisms:

1. **Handle table lock:** `func_0x00399ee0` (lookup) and `func_0x0039a2a0`
   (re-acquisition) bracket handle operations. The handle table is at
   `proc+0xc48` and uses type tag `0x160`.

2. **Per-request sync at `request+0x20`:** `func_0x00bf1770` with flags
   `0x80000` (acquire) and `0x100000` (release). This is a mutex-like
   sync that protects the completion state check. **But the TOCTOU
   window is between the release of THIS lock (step 7) and the
   re-acquisition of the handle table lock (step 8).**

3. **Per-queue-entry sync** (via `func_0x00bf1760`): destroyed during
   cleanup.

The race succeeds because:
- Thread A: releases request+0x20 sync, has not yet re-acquired handle
- Thread B: acquires request+0x20 sync, sees valid state, releases it
- Both threads then re-acquire the handle (still valid), both free

## 5. Reference Counting

From `free_queue_entry` at RVA `0x3b3e90`:

> decrements referenced file's atomic refcount and invokes its
> final-release routine if needed, then frees entry storage.

The queue entry holds a file reference (`fhold` at submit time). The
double-free means the file refcount is decremented TWICE. If the file
object (e.g., `/dev/zero` fd) has exactly refcount 2 when the double-free
hits, the second decrement reaches zero and triggers a premature
`fdrop`/close — a use-after-free on the file object itself.

**However**, the confirmed 65l behavior shows the process survives 30
iterations of double-frees, which suggests either:
- The refcount starts high enough that double-decrement doesn't reach zero
- The file is kept alive by other references (the fd table entry)
- The refcount path is not the primary corruption vector

## 6. Exploitation Strategy

### Path A: Reclaim the 0x30-byte context for KASLR

1. Trigger double-free on the 0x30-byte saved context (zone `0x1ab59e0`)
2. Spray matching 0x30-byte allocations with controlled content:
   - **`namedobj_create(557)`** — creates named objects; allocation size
     needs measurement but candidates fit this range
   - **`shm_open(482)`** — SHM metadata
   - **`setsockopt`** with a 48-byte option value
   - **Pipe buffers** — `pipe(42)` is dead, but `socketpair` internal
     buffers may match
3. One of the two dangling pointers still references the slot
4. Read back through AIO state query (664 poll or 663 wait) — if the
   returned state contains a field from the replacement object

**Problem:** 664/663 return per-item status words (32-bit Sony error
codes), not raw object contents. We need a path that reads THROUGH the
freed object's fields.

### Path B: Reclaim the 0x58-byte queue entry for kernel R/W

1. Trigger double-free on the 0x58-byte queue entry (zone `0x1ab5900`)
2. Spray 0x58-byte allocations with controlled content
3. The queue entry has a file object pointer at `+0x40` and list links
   at `+0x48/+0x50`. If a surviving reference walks the list or accesses
   the file pointer, we get type confusion.
4. The `free_queue_entry` function accesses `entry+0x18` (saved context
   pointer) and `entry+0x40` (file object) — if either now points to
   controlled data, we redirect kernel execution.

### Path C: File refcount manipulation

1. Submit AIO requests on a known fd (e.g., `/dev/zero` = fd 22)
2. Double-free the queue entries, double-decrementing the file refcount
3. Close fd 22 to bring refcount to zero, freeing the `struct file`
4. Spray to reclaim the file object with controlled data
5. Any remaining fd operation (read/write/ioctl) through the old fd
   number now operates on the replaced object

### The 670 Poison

**Critical operational note:** calling `670 (aio_init)` permanently breaks
the 662 delete path for the process. All subsequent deletes return
`0x80020010`. The initialization appears to install a different validation
path that rejects delete attempts.

The race MUST be run without ever calling 670. The 14.10 probes confirmed
this: 65d/65e failed because 670 had been called; 65f succeeded in a fresh
process that skipped 670; 65g failed because 65f's section C had called 670
in the same process.

## 7. Key Sizes for Spray Planning

| Target | Allocation size | Zone (13.60 RVA) | Sprint target |
|---|---|---|---|
| Saved context | **0x30 (48 bytes)** | `0x1ab59e0` | KASLR leak |
| Queue entry | **0x58 (88 bytes)** | `0x1ab5900` | Kernel R/W via type confusion |
| Completion header | **0x58 (88 bytes)** | `0x1ab5970` | State corruption |
| AIO object | **0x30 (48 bytes)** | `0x1ab59e0` | Handle table confusion |
| Pointer array | **count × 8** | `0x1ab5890` | Flexible size |

The 0x30 and 0x58 byte sizes are the most important for spray targeting.
FreeBSD UMA zones serve allocations rounded up to slab size boundaries.
On a FreeBSD 11-based kernel with 16KB pages:

- 48 bytes → likely in a 64-byte zone (16384/64 = 256 objects per slab)
- 88 bytes → likely in a 128-byte zone (16384/128 = 128 objects per slab)

**Spray candidates that match these sizes:**

For 64-byte zone (48-byte target):
- `setsockopt(SOL_SOCKET, SO_LINGER, ...)` — 8 bytes, too small
- `namedobj_create(557)` — creates objects, size needs live measurement
- `evf_create(538)` — type 0x110 objects, size needs measurement
- Custom pipe/socket metadata — size varies

For 128-byte zone (88-byte target):
- `kqueue knote` structures — created by `kevent(363)` with each filter
- `TCP control block` fields — via `setsockopt` with large option
- `sigaction` saved handlers — 120 bytes struct, close to zone
- AIO entries themselves (self-spray: submit more AIO requests to fill
  the freed slot with a new request whose fields we control)

## 8. Self-Spray: AIO Request as Spray Object

The most elegant spray is **using AIO itself**: after the double-free,
submit new AIO requests. The new 0x58-byte queue entry may land in the
same slot the old one occupied. Since we control the request descriptor
(`offset, count, data_ptr, result_ptr, fd`), we partially control the
queue entry's contents.

From the queue entry layout:
```
+0x00: operation (from cmd, 1=read/2=write)
+0x04: scheduling sequence
+0x08: ordering key
+0x10: descriptor pointer (kernel heap pointer — we don't control this)
+0x18: saved context pointer (kernel heap pointer)
+0x20: completion header pointer
+0x28: split-request context
+0x30: result/error
+0x38: state
+0x40: referenced file object (kernel pointer from fhold)
+0x48: list link (prev)
+0x50: list link (next)
```

We control: operation (+0x00), and indirectly the fd (+0x40 via file
lookup). The kernel fills the rest. So self-spray gives limited but
useful control — particularly the file object pointer, which is chosen
by which fd we submit the new request on.

## 9. Remaining Questions (Require Live Testing)

1. **Does 662's re-lookup (step 8) actually access the freed memory, or
   does it only consult the handle table?** If the handle table slot is
   cleared by thread A before thread B reaches step 8, thread B gets
   `NULL` and writes `0x80020003`. The 65l results show both threads
   reporting success (state=0), so both DO reach the free path.

2. **Are the four zones really separate, or do they alias to the same
   UMA zone?** If `0x1ab59e0` and `0x1ab5970` both serve from the same
   physical zone (both ≤64 or both ≤128), cross-object replacement
   becomes possible.

3. **Can we observe freed-object contents through any AIO query?** 664
   returns status words. 663 with timeout=0 returns status words. 667
   enumerates records `{composite_id, state, class, operation}` — 16
   bytes per entry but still structured, not raw memory.

4. **What exactly does the 14.20 patch add?** The description says
   "post-lock-drop generation revalidation." This suggests 14.20 adds
   a generation counter check between steps 7 and 8 — if the generation
   changed (because thread A freed it), thread B's re-lookup fails.

5. **Is the file refcount double-decrement exploitable?** Need to measure
   the actual refcount of an AIO-targeted fd after the double-free hits.

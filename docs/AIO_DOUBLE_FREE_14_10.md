# aio_multi_delete TOCTOU Double-Free — PS5 14.10

## Status: 663 WAIT + CHILD 669 CONFIRMED — 3-THREAD UAF VIABLE

65l (2026-10-23): 65 out of 480 AIO IDs got status=0 from BOTH threads
across 30 iterations. 26 of 30 iterations produced at least one "double."

**70e (2026-10-25) UPDATE:** 35 doubles across 30 rounds on a SHARED fd,
fstat(fd)=0 after every round, fd NEVER broke. This proves the concurrent
race is a **double-STATUS-report, NOT a double-free**. The D exclusive lock
serializes entry_dispose — only one thread frees the objects, the second
finds the slot cleared and skips.

**71a (2026-10-25) UPDATE:** AIO IDs are **generation-checked**:
`generation[15:13] | slot[12:0]`, 3-bit generation counter (0-7, wraps).
Old deleted IDs always return 0x80020003. This blocks the 3-thread
slot-reuse attack (Thread B's old-generation ID can't affect Thread C's
new entry in the same slot).

## The Vulnerability

`aio_multi_delete` (syscall 662) iterates an array of AIO request IDs. For each
ID it:

1. Acquires the AIO queue lock
2. Looks up the request object by ID
3. **Drops the lock** to free the request's sub-objects
4. Re-acquires the lock to continue with the next ID

A second thread calling 662 on the same ID array enters step 2 during the first
thread's step 3 gap. Both threads then free the same sub-objects → **double-free
/ use-after-free**.

This is the vulnerability described by Jose Coixao (@notnotzecoxao), patched in
firmware 14.20 with a post-lock-drop generation revalidation.

## Prerequisites (discovered through 65d–65l iteration)

| Requirement | Why |
|---|---|
| Submit via individual 669 calls (count=1 each) | Batch submit (count>1) only creates one request |
| Poll each ID via 664 before delete | Unpolled requests return state `0x80020010` on 662 |
| **Never call 670 (AIO init)** | 670 permanently poisons the 662 delete path for the process — all subsequent deletes return `0x80020010` |
| Two child threads via thr_new(455) | Both must run concurrently at native speed; Lua main thread is too slow |
| No sysarch needed for 662 | 662 returns `ret=0` with error in state buffer, never touches errno/%fs |

## Probe Progression

| Probe | Approach | Result |
|---|---|---|
| 65d | Single ID, /dev/zero, with 670 init | `0x80020010` — 670 poisons deletes |
| 65e | Single ID, socketpair (pending), with 670 | `0x80020010` — same poison |
| 65f | Three paths: no-670, cancel+delete, post-670 | **no-670 returns state=0** (success); cancel and 670 both break it |
| 65g | No 670, but same process as 65f | `0x80020010` — 65f's section [C] already called 670 |
| 65h | Poll before delete (fresh process) | **Works!** But child always beats main (native vs Lua speed) |
| 65i | Two child threads, both with sysarch | Child A always wins — sysarch serializes them |
| 65j | Two children, no sysarch, with jitter | A still always wins — scheduling too deterministic |
| 65k | Multi-ID batch (count=16) | Only 1 ID created — batch submit broken |
| **65l** | **16 individual submits + 2 children × 16-ID delete** | **65 DOUBLE DELETES across 30 iterations** |

## Race Mechanics

Each iteration:
1. Main thread: submit 16 AIO requests individually (16 × 669 calls)
2. Main thread: poll all 16 (16 × 664 calls)
3. Write shared ID array (both children read the same array)
4. Spawn child A: `662(ids, 16, states_A)` → `thr_exit(0)`
5. Spawn child B: `662(ids, 16, states_B)` → `thr_exit(0)`
6. Both children execute concurrently on different CPU cores
7. The 662 loop processes 16 IDs, giving 16 lock-drop windows per call
8. When both threads process the same ID in overlapping windows → double-free

Hit rate: ~13.5% per ID (65/480), ~87% per iteration (26/30).

Child A always gets all 16 (it processes the full array). Child B catches 1–5 of
the same IDs during A's lock-drop windows. The interleaving is non-deterministic,
proving true concurrent multi-core execution.

## Reproduction

```lua
-- Minimal reproduction (requires thr_new child thread infrastructure)
-- 1. Open /dev/zero, submit 16 AIO reads individually
-- 2. Poll all 16
-- 3. Spawn two child threads that both call 662(ids, 16, states)
-- 4. Both children report state=0 for overlapping IDs → double-free
```

Full probe: `probes/phase16_kwrite/65l_aio_race_fixed.lua`
Result: `results/phase16_kwrite/65l_aio_race_fixed_20261023_220628.txt`

## Why the Race is Not Exploitable (2026-10-25)

### 1. D Exclusive Lock Prevents Real Double-Free

The TOCTOU window is between Q lock release (step 7) and D exclusive lock
acquire (step 9). Both threads pass validation during this window. But the
actual free (entry_dispose) happens under D exclusive lock:

```
Thread A: acquire D excl → read I from slot → free R/I/Q → clear slot → release
Thread B: acquire D excl → read I from slot → finds NULL → SKIP → release
```

Thread B always finds the slot cleared by Thread A. **entry_dispose runs
exactly once.** The double-STATUS is because both threads write success to
the output array BEFORE the D exclusive lock, during the validation window.

### 2. Generation-Checked IDs Block 3-Thread Interleave

AIO ID format: `generation[15:13] | slot[12:0]`
- 3-bit generation (0-7), increments on each slot reuse
- After delete, the old ID is dead (0x80020003)
- New submission to the same slot gets a new generation
- Even if Thread C fills the slot between Thread A and Thread B, Thread B's
  old-generation ID can't match Thread C's new-generation entry

Tested: `662(old_id)` returns 0x80020003 after new submission fills same slot.
`666(old_id)` also returns 0x80020003. Cross-generation access is impossible.

### 3. Main Thread Too Slow for Interleaved Submissions

The Lua interpreter is orders of magnitude slower than kernel-speed child
threads. By the time the main thread submits new requests, both children
have finished their 662 calls (71b: B=0/8 in all 10 rounds).

### 4. ~~Child Thread C Can't Call 669~~ **OVERTURNED (71g)**

~~669 requires 5 arguments (cmd, reqs, count, class, ids_out). We only have
ROP gadgets for 4 registers (rdi, rsi, rdx, rcx). No pop_r8 gadget exists
in the 4.6MB eboot. Without r8 control, Thread C can't submit new AIO
requests from a child thread at kernel speed.~~

**71g (2026-10-25):** Child thread with sysarch(SET_FSBASE) + 4× 669 calls.
r8 was uncontrolled (IDs copyout buffer garbage), but **the kernel still
allocated the object**. Scan found 1 new AIO ID (`0x8205`, status `0x00000003`)
not created by the main thread. Only 1 of 4 succeeded (r8 garbage may cause
partial failures), but one allocation per burst is sufficient for slot
reclamation.

## 663 IS A WAIT CALL — BLOCKING RACE CONFIRMED (71h, 2026-10-25)

**71h proved 663 blocks on pending I/O and unblocks on completion:**

| Section | Test | 663 Result | 666 Result | Interpretation |
|---------|------|-----------|-----------|----------------|
| [A] | Completed + polled | `0x00010003` | `0x00000003` | Returns instantly, high word = 1 |
| [B] | Completed + unpolled | `0x00000003` | `0x00000003` | Returns instantly, same as 666 |
| [C] | **PENDING (socketpair)** | **BLOCKED** | `0x00000002` | **663 sleeps in kernel until I/O completes** |
| [D] | Completed + polled ×3 | `0x00010003` | `0x00000003` | Consistent: high word differs after poll |
| [E] | Unpolled completed ×4 | `0x00000003` | — | Consistent: returns instantly on complete |
| [F] | Deleted ID | `0x80020003` | — | Error, same as 666 |

**Section [C] detail:** AIO read submitted on socketpair fd (no data written).
Child thread called 663 on the pending ID. Marker stayed 0 (child blocked
inside kernel). Main thread wrote 8 bytes to the other socketpair fd. Child
unblocked: marker = `0xC663`, status = `0x00000003` (complete).

### 663 output format
- `0x0001SSSS` on polled requests (high word = wait count or "already complete" flag)
- `0x0000SSSS` on unpolled completed (same as 666)
- `0x80020003` on invalid/deleted IDs (same as 666)

## Revised 3-Thread UAF Attack

The 662-vs-662 race is a double-STATUS, not a double-free (D exclusive lock
serializes entry_dispose). But **662-vs-663 is a fundamentally different race**:

```
Thread W: 663(id) → acquires Q waiter reference → BLOCKS in kernel (sleeping)
Thread A: 662(id) → acquires D excl → frees R/I/Q → clears slot → releases
Thread C: 669(submit) → kernel allocates new objects → reclaims Q's memory
Thread W: wakes up → touches Q through dangling waiter reference → UAF
```

**Why this bypasses the D exclusive lock defense:**
- 663's waiter is inserted into Q's wait list BEFORE 662 takes D exclusive
- 662 frees Q while 663's waiter still points to it
- When 663 unblocks (I/O completes on the reclaimed object), it dereferences
  the freed/reclaimed Q address

**Why generation checks don't help:**
- Thread W's 663 holds a direct kernel pointer to Q, not an ID lookup
- The generation check only protects ID-to-object resolution
- Once 663 is sleeping with a Q pointer, no ID validation occurs on wakeup

### Attack sequence (concrete)

1. Create socketpair (sp0, sp1) — sp0 for AIO read, sp1 for triggering
2. Main thread: `669(1, req_on_sp0, 1, 1, ids)` → submit pending AIO read
3. Main thread: `664(id)` to poll (required for 662 to accept)
4. Spawn Thread W (child): `663(id, 1, states)` → **blocks** (no data on sp0)
5. Spawn Thread A (child): `662(id, 1, states)` → **frees R/I/Q**
6. Spawn Thread C (child): `669(1, req, 1, 1, ids)` × N → **reclaim Q's slot**
7. Main thread: `write(sp1, data, 8)` → **wakes Thread W** → UAF

### Timing requirements

- Thread W must enter 663 and block BEFORE Thread A calls 662
- Thread A must complete 662 (free objects) BEFORE Thread C submits
- Thread C must reclaim the slot BEFORE Thread W wakes
- Main thread controls wakeup timing (write to sp1 only after spray)

**This gives FULL ATTACKER CONTROL over timing** — unlike 662-vs-662 where
both threads race uncontrollably, the socketpair write is a manual trigger.

## 665/668 Are Dead (71f/71f2, 2026-10-25)

- **665:** kills on zero args (71e), kills on 662-shaped pointer args (71f).
  Present handler that faults inside for game process. Dead.
- **668:** kills on 669-shaped args, 662-shaped args, scalar args (71f2 [A]).
  Never reached sections [B]-[G]. Dead.

## Remaining Steps

1. **★ 69l: evf/namedobj object size measurement** — sys 624 oracle to check
   if spray objects land in R's 64B UMA bucket
2. **★ 69m: eboot read gadget scan** — find `mov rax,[rdi];ret` or equivalent
   for kernel memory reads after KASLR defeat
3. **★ 69d: R-object KASLR readback** — after reclaim, read R+0x00/R+0x08
   through spray object interface for kernel thread pointers

## 662-vs-663 Race Results (72a-72c, 2026-10-25)

**VERDICT: SAFE BY DESIGN — no UAF achievable via 662-vs-663 race.**

### 72a: First attempt (all A_REJECT)

Sequence: spawn W (663 blocks) → spawn A (662) → spray → write sp1.
Result: `A_sts=0x80020010` on all 10 iterations. 662 rejected the request
because it was still PENDING — 662 requires COMPLETED state to proceed.
Also had a marker bug: 663 returns 0 on success, so `mov [rdi],rax;ret`
wrote 0 to marker, falsely detected as "W stuck."

### 72b: Fixed timing (all CLEAN)

Fix: write to sp1 BEFORE spawning Thread A, so the request transitions to
COMPLETE before A enters 662. Result: `A_sts=0x00000000` (success) on all
15 iterations, but all CLEAN — W returned `0x00000003` normally, A deleted
successfully. Problem: A was spawned AFTER sp1 write, so W wakes from kernel
sleep and finishes removing its waiter from Q+0x50 long before A enters 662
(W stays in-kernel; A pays thr_new + sysarch + ROP gadgets overhead).

### 72c: Gate socketpair (all CLEAN)

Fix: pre-spawn A blocked on `read(gate_sp[0], buf, 1)` (kernel sleep).
Both W (663 on pending AIO) and A (gate read) confirmed blocked (`blk=Y/Y`).
Fired both triggers back-to-back: `write(sp_aio[1])` + `write(gate_sp[1])`.
Both threads woke from kernel sleep simultaneously.

Result: all 20 iterations CLEAN. `A_sts=0x00000000`, `W_sts=0x00000003`.
No crash, no garbage status, no kernel pointers.

### Why the race is safe

663's waiter holds a refcount on Q via the atomic `XADD.LOCK dword ptr
[RAX + 0x28], ECX` (confirmed at asm 0x3b3ec8). When 662 calls
`entry_dispose`, the XADD sees a non-zero refcount (waiter holds it) and
does NOT free Q. Q is only freed after 663 removes its waiter and drops
the refcount. By that point, 663 is done touching Q — no dangling pointer
is possible regardless of timing.

### Pivot: KASLR leak without a race

The KASLR leak through R does **NOT** need a UAF or any race condition.
R+0x00 (`curthread+0x390`) and R+0x08 (`curthread+0x08`) are kernel thread
addresses written during AIO submission and **NOT zeroed** before
`uma_zfree`. The approach:

1. Submit AIO request (allocates R with kernel pointers)
2. Poll + delete via 662 (frees R — pointers survive in freed memory)
3. Spray matching-size objects (64B UMA bucket) to reclaim R's slot
4. Read the reclaimed memory through the spray object's readback interface

No race is needed because UMA does not zero freed memory, and the zone
free list does not overwrite the full object. The critical unknowns:

- **Do evf/namedobj land in R's 64B zone?** → probe 69l (sys 624 oracle)
- **What bytes does the spray object's constructor overwrite?** → if it
  writes +0x00/+0x08, R's kernel pointers are lost; need a spray object
  whose constructor leaves those offsets untouched
- **What readback interface exposes those offsets?** → probe 69d

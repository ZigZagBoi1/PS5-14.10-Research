# aio_multi_delete TOCTOU Double-Free — PS5 14.10

## Status: CONFIRMED (probe 65l, 2026-10-23)

65 out of 480 AIO IDs double-freed across 30 iterations. 26 of 30 iterations
produced at least one double-delete. Process survived all iterations.

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

## Next Steps

1. **Identify the freed object** — what kernel structure does 662's sub-object
   release free? From the 13.60 decompile, `aio_multi_delete` frees per-request
   metadata (aiocb kernel copy). Size and slab zone determine the spray target.

2. **Heap spray** — after the double-free, spray matching-size allocations to
   reclaim the freed slot. Candidates:
   - Pipe buffer headers (~128-256 bytes)
   - Socket option buffers (setsockopt)
   - shm_open metadata
   - kqueue knote structures

3. **Dangling pointer read** — if the original object had a kernel pointer (e.g.
   back-pointer to the process struct), reading it through the reclaimed+attacker-
   controlled object leaks a kernel address → KASLR defeat.

4. **Kernel R/W** — overwrite a function pointer or linked-list pointer in the
   reclaimed object to redirect kernel execution or create an arbitrary read/write.

# GPU Dispatch TOCTOU Analysis — Probe 87b

## Context

sys 532 is the primary Sony GPU/compute dispatch syscall on PS5.  Decompiled 13.60 analysis reveals **9 commands that bypass `priv_check(td, 682)`**: 0x18–0x1E, 0x20, and 0x2F.  These are accessible from our unprivileged WebKit-spawned process.

## Vulnerability V2: TOCTOU in Handle Validation

The decompiled handler follows this sequence for GPU resource commands:

1. **Lookup** — resolve handle to internal object pointer via pool table
2. **Validate** — check object type/permission bits
3. **Operate** — execute the GPU resource operation on the resolved object

There is **no lock held between steps 1 and 3**.  If another thread replaces the backing object (by deleting and re-creating the handle) between lookup and operation, the command operates on a *different* object than the one that was validated.

### Why threading matters

Before PR #60, single-process TOCTOU was the only option: interleave create→use→delete in a tight loop and hope the kernel preempts between lookup and check.  The window is tiny (tens of instructions) and the chance of hitting it is low.

With `thr_create(430)` confirmed working (CS=0x43, SS=0x3B), we can run two threads concurrently:
- **Thread A** loops GPU commands (sys 532)
- **Thread B** loops handle mutation (sys 557 create / sys 558 delete)

True concurrent execution widens the race window because thread B can be *running on a different core* while thread A is inside the handler.  On the PS5's 8-core Zen 2, this is realistic.

### Practical limitation in 87b

The Lua loader's `thr_create` cycling-stack trick (157a) hard-codes the child to loop a single syscall number via the libkernel wrapper.  That wrapper encodes the syscall number in `mov rax, N` at a fixed address in XOM libkernel — we cannot change it.

87b works around this by:
- Running the GPU command loop in the **main** thread (which has full `native.fcall_with_rax` access)
- Running a **gettimeofday** child thread to add scheduling pressure (context switches widen the window)
- Also testing a single-threaded TOCTOU approximation (create→use→delete in a tight loop) as a baseline

## cmd 0x20 — KASLR Leak Potential

cmd 0x20 copies **48 bytes** (0x30) of GPU subsystem configuration back to userspace.  The decompiled handler shows:
- The source is a kernel-side config structure
- Fields include base addresses, pool sizes, and allocation metadata
- If any field contains a kernel `.text` or heap address, it leaks KASLR

87b section B dumps all 48 bytes and scans every qword for high-half values (≥ 0xFFFF800000000000).

## Handle Recycling (Section D)

If handle values are recycled after deletion (monotonic counter wraps, or a free-list is used), a stale handle from a previous operation can resolve to a *new* object.  This is the setup for:
- **Cross-subsystem confusion**: create event flag → delete → spray semaphores → signal stale event flag handle → writes into semaphore at wrong offsets
- **GPU type confusion**: GPU handle recycled into IPC object or vice versa

Section D runs 500 rapid create/delete cycles and records handle values.  It also tests cross-type confusion: create name X as type A, delete, create name X as type B, then try to open name X as type A — if the namespace doesn't isolate types, we get type confusion.

## Expected Outcomes

| Section | If ret=0 (success) | If all fail |
|---------|---------------------|-------------|
| A | GPU commands work unprivileged — surface confirmed | GPU subsystem not initialized (0x800D0219 as seen in 87a-B) |
| B | Scan output for kernel pointers → KASLR defeat | Config output is zero or contains only userspace addresses |
| C | `ret=0` on a GPU cmd during race → TOCTOU confirmed | All return error codes — window not hit in N iterations |
| D | Handle values repeat → stale-handle attacks viable | Handles are monotonic/random — recycling not practical |

## Risk Assessment

- **Section A/B**: LOW crash risk (read-only queries to unprivileged commands)
- **Section C**: MODERATE (object create/delete + GPU commands; unlikely to panic but child thread stall is possible — killed at exit as in 157a)
- **Section D**: LOW (IPC object lifecycle only; no GPU involvement)

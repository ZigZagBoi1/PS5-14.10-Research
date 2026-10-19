# Crash Event — thr_create(430) Kernel Panic — 2026-10-19

## Summary

Probes 58e, 76c, 76d, and 76e triggered reproducible PS5 console shutdowns
(full power-off, lights off) after calling `thr_create(430)` with valid-shaped
ucontext_t structures. The main Lua thread survived the syscall and printed its
output, but the console crashed seconds later — consistent with a delayed
kernel panic during child-thread execution or cleanup.

## Evidence

### 58e reachability (08:48:25 — safe, no thread creation)

- A: null ctx → rv=-1 (copyin fault, expected)
- B: zeroed ctx → rv=-1 (0x480 magic fails)
- C: zeroed ctx + id pointer → rv=-1 but id changed 0xDEADBEEF → 0x18A1F
  - **The id copyout occurs before machine-context validation.** A thread was
    allocated even with an invalid context. rv=-1 because the context consumer
    rejected the zeroed register block.

### 58e full ucontext (08:48:59 — CRASHED THE PS5)

- A/B: same as above
- C: rv=-1, id=0x18A1A (thread allocated, context rejected)
- **D: validated fields → rv=0, id=0x18A19** — thread CREATED with zeroed
  registers (RIP=0, RSP=0, all GPRs=0)
- **E: alt type 0x10002 → rv=0, id=0x18A1C** — second thread created
- Probe printed `COMPLETE`. Main thread survived. **PS5 crashed shortly after.**

### 76c safe longjmp (08:56:09 / 08:56:30)

- Run 1: rv=0, id=0x18E6A, canary passed, COMPLETE. Entry = longjmp.
- Run 2: **CONNECT_TIMEOUT** — 0 bytes, PS5 unreachable. Crashed between runs.

### 76d exit-only (09:03:57 / 09:04:22 / 09:06:57)

- Run 1: rv=0, id=0x18D02, canary ok, COMPLETE. Entry = Thrd_exit.
- Run 2: **EMPTY capture** — PS5 crashed.
- Run 3: rv=0, id=0x18D01, canary ok, COMPLETE. Entry = Thrd_exit.

### 76e exit-only with 250ms wait (09:11:46)

- Printed only `canary_getpid=80` then **IDLE_TIMEOUT after 15s**
- PS5 crashed during or immediately after the 430 call — before the return
  value could print.

## Crash Pattern

| Probe | Entry point | Probe output | PS5 behavior |
|-------|------------|--------------|--------------|
| 58e-full | RIP=0 (zeroed) | COMPLETE | Crashed after |
| 76c run 1 | longjmp | COMPLETE | Crashed between runs |
| 76c run 2 | longjmp | 0 bytes | Already crashed |
| 76d run 1 | Thrd_exit | COMPLETE | Crashed after |
| 76d run 2 | Thrd_exit | 0 bytes | Already crashed |
| 76d run 3 | Thrd_exit | COMPLETE | Crashed after |
| 76e | Thrd_exit + wait | Partial (2 lines) | Crashed during |

The pattern: **every thr_create(430) call that succeeds (rv=0) causes a delayed
PS5 shutdown.** The main thread prints its output normally, then the console
powers off seconds later.

## Analysis

1. **This is not a process crash.** A process-level fault stays in the sandbox
   and does not power off the console.

2. **This is consistent with a kernel panic.** The PS5 shuts down completely
   (lights off), which only happens when the kernel itself crashes.

3. **The panic is delayed.** The main thread continues executing after
   thr_create returns. The panic occurs when the child thread runs, faults,
   and the kernel's thread exception handler encounters a bug.

4. **Entry point does not matter.** The crash happens with RIP=0 (58e),
   longjmp (76c), and Thrd_exit (76d/76e). The bug is in the kernel's thread
   creation/scheduling/cleanup path, not in the child's userland code.

5. **Thread IDs are real.** Every successful call returns a unique, sequential
   TID in the 0x18xxx range, confirming the kernel fully allocated the thread.

## What This Means

The kernel has a bug in its thread lifecycle management for sandboxed processes.
When a thread is created via thr_create(430) in this sandbox context, something
goes wrong during thread scheduling, execution, or cleanup that causes a kernel
panic instead of a clean process kill.

Possible root causes:
- Null pointer dereference in kernel space when handling the child thread fault
- Use-after-free in thread teardown (thread struct freed while still referenced)
- Missing sandbox check in the thread fault handler (tries to access
  process structures that don't exist in the sandbox context)
- Stack corruption in the kernel's trap handler for the new thread

## Next Steps

1. **Map the panic boundary** — Vary RIP to non-zero values (valid addresses,
   kernel VA, unmapped regions) to determine which fault types trigger the panic.
2. **Control the crash** — Set RSP to GPU mmap region so the kernel's trap
   handler reads controlled data from our heap during the fault.
3. **Time the crash** — Use thr_kill/thr_suspend on the returned TID to catch
   the thread before it faults, then modify its context.
4. **Race the cleanup** — If the panic is in thread teardown, create multiple
   threads rapidly to race the cleanup path and corrupt kernel state.

## Raw Data

All probe sources and captures are in:
- `probes/phase16_thr_create_crash/`
- `results/phase16_thr_create_crash/`

User-reported crash behavior documented from live Discord conversation (Cruby):
- "the ps5 just shut down"
- "the light turns off and my ps5 closed"
- Reproducible: "when ever it runs the probe even if it exits the ps5 just crashes"

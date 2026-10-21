# Threading-Enhanced Type Confusion — Probe 88b Analysis

## Attack Summary

Five Sony IPC subsystems share a single handle namespace at `process+0xc48` with **zero credential/privilege checks** on any operation:

| Subsystem       | Type   | Syscalls  | Object size | Notes                           |
|-----------------|--------|-----------|-------------|----------------------------------|
| Event flags     | 0x110  | 538-546   | ~0x80       | create/delete/open/signal/poll  |
| Semaphores      | 0x120  | 549-556   | ~0x60       | create/delete/post/wait         |
| Generic objects | custom | 557       | 0x18        | ANY caller-chosen type code     |
| Handle deletion | —      | 558       | —           | deletes by handle+type          |
| AIO             | —      | 662-670   | varies      | also uses process+0xc48         |

## Why Threading Changes Everything

88a tested this single-threaded: create → delete → spray → signal stale. The kernel reclaims freed memory deterministically in that context, and handle invalidation may prevent stale access.

With **threading** (confirmed working via PR #60, probe 157a), the race window opens:

1. **Concurrent delete+spray**: Thread B deletes the event flag and sprays semaphores *while Thread A still holds the handle and is mid-syscall*. The kernel's handle lookup and the object's lifetime become two separate operations with no lock between them.

2. **Scheduler perturbation**: A child thread spinning in the kernel (gettimeofday loop) creates real scheduling contention. This perturbs the allocator's free-list ordering and increases the chance that a semaphore allocation reclaims the exact slab where the event flag lived.

3. **TOCTOU on handle lookup**: The kernel looks up the handle, checks the type, then operates on the object. If the object is freed and reallocated between lookup and operation, the kernel writes event-flag-shaped data into a semaphore-shaped buffer (or vice versa).

## Exploitation Chain

```
Phase 1: Reachability (Section A)
  → Confirm sys 538-546 / 549-556 work without credentials

Phase 2: Type confusion (Section B)
  → sys 557 creates 0x18-byte object with type 0x110
  → sys 540 (ef_open) looks up by name+type → finds the undersized object
  → ef_signal writes at offsets designed for ~0x80-byte struct into 0x18 bytes
  → HEAP OVERFLOW into adjacent allocations

Phase 3: Cross-subsystem UAF (Section C)
  → Create event flag (0x80 bytes) → delete → spray semaphores (0x60 bytes)
  → Signal stale event flag handle → writes event-flag-pattern into semaphore
  → Semaphore structure now contains attacker-controlled data at wrong offsets
  → Poll stale handle → may read kernel pointers from semaphore internals

Phase 4: Threaded handle recycling (Section D)
  → Child thread spins gettimeofday (proven 157a pattern)
  → Main thread churns: create EF → delete → create SEM → signal stale EF
  → Handle values may collide → type confusion on live objects
```

## Expected Outcomes

| Section | Best case                                      | Worst case                  |
|---------|------------------------------------------------|-----------------------------|
| A       | Confirm IPC syscalls live, handle values known  | All return EPERM           |
| B       | ef_open returns handle for 0x18-byte object     | Type mismatch rejected     |
| C       | Stale signal succeeds → heap write primitive    | Handle invalidated on free |
| D       | Handle collision → cross-type signal succeeds   | No collisions in 32 rounds |

## Kernel Pointer Leak Scenario

If stale ef_poll succeeds after semaphore spray, the poll output buffer may contain:
- Semaphore's internal `waitq` linked-list pointers (kernel heap addresses)
- Process credential pointer stored in the IPC object header
- Kernel ASLR slide derivable from any high-half pointer

## Probe Design Decisions

1. **Phase21-style helpers** (native.fcall_with_rax + make_syscall): matches the proven 172f/172g patterns
2. **Sequential C7 fallback**: since the child thread can only loop ONE syscall (libkernel wrapper limitation), Section C uses a timed sequential approach. True multi-syscall threading requires ropchain-based child threads (future probe 88c).
3. **Section D uses 157a's gettimeofday spinner**: the child thread doesn't directly participate in handle operations but perturbs kernel scheduling, which affects allocator behavior during the main thread's churn loop.
4. **32 rounds in Section D**: balances between detection probability and crash risk. Each round creates, deletes, and re-creates handles — 32 rounds gives ~96 kernel allocations under scheduling contention.

## Dependencies

- 88a Section A results (do event flags work at all on 14.10?)
- 157a confirmation (child thread runs, gettimeofday advances)
- Loader must expose `syscall.syscall_address` for Sections C/D

## Follow-up: 88c (ropchain-threaded)

Once ropchain-based threading is proven (gen_fcall_chain in child thread context), write 88c:
- Child thread runs the FULL delete+spray sequence via ropchain
- Main thread signals stale handles at random intervals
- True concurrent race with sub-microsecond windows

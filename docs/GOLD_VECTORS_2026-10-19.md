# Untested Gold Vectors — Offline Analysis 2026-10-19

## Executive Summary

After a full audit of 90+ probes, all result files, kernel handler RE data, CVE assessments, and the complete dead-ends list, the following vectors are **untested or critically under-investigated** and have the highest probability of yielding a kernel primitive on PS5 14.10.

---

## VECTOR 1: thr_* Family Syscalls on the Panicking Thread (HIGHEST PRIORITY)

**Status:** Probe 59b written, NEVER RUN.

**Why this is gold:** thr_create(430) gives us a kernel thread with a real TID. Before that thread panics the kernel, we have a window where the thread exists in the kernel's thread list. The thr_* family gives us syscalls to interact with that thread:

| Syscall | Number | What it does | Why it matters |
|---------|--------|-------------|----------------|
| thr_kill | 433 | Send signal to thread by TID | Could intercept the thread before it faults |
| thr_suspend | 442 | Suspend a thread | FREEZE the thread before it panics the kernel |
| thr_wake | 443 | Wake a suspended thread | Control when the thread resumes |
| thr_get_ucontext | 634 | Read thread's register state | Read kernel-populated register values |
| thr_set_ucontext | 635 | Write thread's register state | MODIFY the thread's registers before it runs |
| thr_suspend_ucontext | 632 | Suspend + read context | Combined freeze + read |
| thr_resume_ucontext | 633 | Resume + write context | Combined resume + write |

**The attack:** Create a thread via thr_create(430). Immediately call thr_suspend(442) on its TID before it executes. If suspend works, the thread is frozen in kernel space. Then call thr_set_ucontext(635) to set arbitrary register values. Then thr_wake(443) to resume it. The thread now executes with our controlled registers but in whatever kernel context it was suspended in.

**Even if suspend fails:** thr_get_ucontext(634) on the panicking thread might read kernel-populated values (trap frame data, kernel stack addresses) that leak KASLR.

**Kernel handler RE data:** sys_632 (thr_suspend_ucontext) RE shows a retry/relookup loop with object identity replacement and state/flag mutations. This is exactly the kind of code that has races — but we need the thread to exist long enough.

---

## VECTOR 2: CVE-2026-49418 msync UAF on GPU mmap (HIGH PRIORITY)

**Status:** Probe 58a written, NEVER RUN. Rated as "strongest CVE applicability" by assessment.

**Why this is gold:** This is a KNOWN FreeBSD vulnerability (FreeBSD-SA-26:37.vm) that was patched June 30, 2026. PS5 14.10 shipped Sep 16, 2026 — the fix timeline is tight. The bug:

1. msync(MS_INVALIDATE) on device-backed pages marks pages invalid
2. Pages stay on the device pager's page list (dangling reference)
3. Next access causes page re-insertion -> double-free on the page list
4. Kernel heap corruption

We have the exact trigger: GPU mmap creates device-backed pages (confirmed by probe 41c). msync was NEVER successfully tested — probe 42b crashed at the msync section header. Probe 58a isolates the msync call.

**If msync returns 0:** The vulnerability path is reachable. Next step is the double-invalidate trigger (probe 58b, not yet written).

**The exploit chain:** Double-free -> kernel heap corruption -> overwrite a kernel function pointer or object -> kernel code execution. No KASLR needed for heap corruption; KASLR only needed for the payload.

---

## VECTOR 3: thr_create + thr_suspend Race (Combining Vectors 1+Panic)

**Status:** Never conceived as a probe.

**Why this is gold:** The kernel panic from thr_create means the kernel's trap handler has a bug. If we can freeze the thread BEFORE it faults (via thr_suspend), we avoid the panic entirely and have a live kernel thread under our control. This turns a DoS (panic) into a potential code execution primitive.

**The race:** thr_create returns the TID *before* the thread runs (proven by 58e Section C — id changed from sentinel to real TID even with invalid context, rv=-1). So the sequence is:
1. thr_create(430, ctx, &id) with RIP=valid, RSP=our_stack
2. Kernel creates thread, writes TID to &id
3. Main thread immediately calls thr_suspend(442, tid)
4. If suspend wins the race: thread is frozen, no panic
5. Call thr_set_ucontext(635, tid) to set new RIP/RSP/registers
6. Resume with thr_wake(443, tid) — thread executes our code

**Even if the race is tight:** nanosleep(0) might give the scheduler enough time to make the thread runnable but not yet running. Or the thread might not be scheduled until the next timer tick, giving us milliseconds.

---

## VECTOR 4: kevent EVFILT_PROC on the Created Thread's Process

**Status:** EVFILT_PROC never tested. EVFILT_TIMER/USER/SIGNAL/READ all work (probes 20/21).

**Why this is gold:** kevent works on PS5. EVFILT_PROC monitors process events — including thread exit, fault signals, and child status changes. If we register an EVFILT_PROC filter before calling thr_create, we might receive a kernel event when the child thread faults. The event data (`kn_data`, `kn_fflags`) in older FreeBSD could contain kernel addresses (the faulting thread's `struct thread *` or trap frame address).

**Probe needed:** Register EVFILT_PROC with NOTE_EXIT|NOTE_FORK|NOTE_EXEC on our own PID, then thr_create, then kevent poll. Check if the event data contains any kernel pointers.

---

## VECTOR 5: sys 674 VM Map + CClosure Redirect for Targeted Writes

**Status:** VM map data collected (317 regions) but NEVER cross-referenced for exploitation.

**Why this is gold:** Probe 55e/55f dumped the complete process VM map with region names, addresses, sizes, and protection bits. This includes named regions like "SceIPMIClient2Heap" and GPU/device regions at 0x8-0xF range. If any region has RWX permissions or is a writable code-adjacent region, CClosure redirect can write to it.

**What to look for in the 55e/55f data:**
- Any region with protection 0x7 (RWX) — W^X bypass
- Device-mapped regions that might map to kernel-visible memory
- JIT/compiler regions that might have execute permissions
- Writable regions adjacent to code regions (overflow target)

---

## VECTOR 6: kldsym(337) Direct Call (Never Reached)

**Status:** Never directly tested. Previous attempts killed by kldnext(307) which runs first.

**Why this is gold:** kldsym resolves kernel symbols by name -> returns kernel addresses. kldnext and kldstat are lethal (probes 56k4/56k5), but kldsym is a DIFFERENT syscall number (337). It was never tested in isolation because probe 43b called kldnext first, which killed the process before reaching kldsym. Probe 57c (kldsym_direct) is written but NEVER RUN.

**If kldsym works:** Instant KASLR defeat. Resolve `prison0`, `allproc`, `copyin`, `copyout` — any kernel symbol. Combined with CClosure redirect = kernel R/W.

---

## VECTOR 7: pipe2(542) via make_syscall

**Status:** Tested via syscall.resolve() only (rv=-1). NEVER tested via make_syscall.

**Why this is gold:** pipe/pipe2 via resolve() returns -1. But sysctl via resolve() ALSO returns -1, yet works perfectly via make_syscall. pipe2 creates a kernel pipe object with two file descriptors. If it works via make_syscall, we get:
- Two new fds for read/write
- A kernel pipe object (potential UAF target with SCM_RIGHTS)
- Combined with the 27 ktimer objects = kernel object lifecycle attacks

---

## VECTOR 8: ktimer Signal Reentrancy

**Status:** Timers work (27 concurrent). Signal delivery via timer NEVER tested.

**Why this is gold:** POSIX timers with SIGEV_SIGNAL deliver a signal when the timer expires. If the signal handler itself manipulates timer state (arms another timer, calls ktimer_settime on the firing timer), this creates reentrancy. Since FreeBSD r230171 is from 2026, the timer callout code may have locking bugs when the expiry callback and settime overlap.

**Attack:**
1. Create 27 timers with SIGEV_SIGNAL delivering SIGUSR1
2. Signal handler calls ktimer_settime on a different timer
3. If the timer callout lock is not reentrant: deadlock or corruption
4. If the kernel's callout code races: callout structure corruption -> controlled kernel function pointer

---

## VECTOR 9: sys 662-670 Individual Testing

**Status:** NEVER individually tested. sys 661 kills, but 662-670 were never reached.

**Why this matters:** The AIO range 661-670 was labeled as "dead" based on sys 661 killing the process. But 661 kills at the FIRST call, preventing 662-670 from ever executing. Each number needs its own connection. The Relapse exploit's AIO prerequisite is in this range. Tool `tools/syscall_isolation_sweep.py` is written for this exact purpose but NEVER RUN.

---

## VECTOR 10: Kernel Heap Spray via Repeated thr_create

**Status:** Never tested. New idea from research.

**Why this is gold:** Each successful thr_create(430) allocates a real kernel `struct thread` (~1KB on FreeBSD amd64) from the thread slab allocator. TIDs are sequential (0x18A19, 0x18A1A, 0x18A1C seen in 58e). If we can create multiple threads before the first panic triggers, we fill specific kernel slab caches with controlled content. This is a classic heap feng shui setup:

1. Spray N threads via rapid thr_create calls (each with different controlled register values)
2. The slab allocator packs these `struct thread` objects adjacently
3. When one thread faults and triggers cleanup, the freed slot contains our controlled data
4. Neighboring thread objects (still alive) can read/corrupt the freed slot

**The key question:** How many threads can we create before the first one panics the kernel? If it's >1, this is a real heap spray primitive.

---

## VECTOR 11: Probe 50d Persistent Loader Crash (UNIQUE)

**Status:** Never debugged. Discovered by Agent 2.

**Why this is gold:** Probe 50d uniquely kills the Lua loader itself ACROSS connections (not just the per-process crash). No other probe does this. This means something in that probe corrupts kernel state in the PARENT process — the one that spawns new Lua workers. If we can isolate which packet construction triggers the persistent kill, we have evidence of cross-process kernel corruption. That's a kernel primitive hiding in plain sight.

**Next step:** Isolate the exact packet sequence in 50d that triggers the persistent crash via binary search of sections.

---

## VECTOR 12: thr_create Controlled Trap Frame → Kernel Stack Read

**Status:** Never tested. New idea from FreeBSD kernel internals research.

**Why this is gold:** When the child thread faults, the kernel's `trap()` handler reads the thread's trap frame: RIP, RSP, RDI, RSI, RFLAGS — all values WE control via the ucontext_t. If RSP points into our GPU mmap region, the kernel's signal delivery code or stack unwinding may READ from our controlled "stack." This turns a kernel crash into a controlled kernel write:

1. Set RSP to point into GPU mmap pages filled with crafted data
2. Set RIP to an address that faults (e.g., 0xDEAD)
3. Kernel processes the fault, reads RSP to set up signal delivery or unwind
4. Kernel writes signal frame data to the "stack" (our GPU pages) — leaking kernel addresses
5. OR: kernel reads return addresses from our fake stack during unwinding — following our controlled pointers

**Critical reference:** CVE-2024-43102 (PS5-UMTX exploit) proved kernel thread stacks are accessible and exploitable on PS5 hardware.

---

## Priority Ranking

1. **59b + 77a** — thr_* family on the panicking thread (highest probability of yielding kernel primitive)
2. **58a** — msync CVE-2026-49418 reachability (known CVE, precise trigger match)
3. **57c** — kldsym direct (instant KASLR defeat if alive)
4. **thr_create heap spray** — multiple threads before panic for heap feng shui (new probe needed)
5. **50d persistent loader crash** — cross-process kernel corruption, never debugged
6. **kevent EVFILT_PROC** — kernel event data from thread fault (new probe needed)
7. **thr_create controlled trap frame** — RSP→GPU mmap for kernel stack read/write
8. **662-670 sweep** — close the AIO question with isolation tool
9. **pipe2 via make_syscall** — potential new kernel object
10. **ktimer signal reentrancy** — kernel callout corruption
11. **55e/55f VM map analysis** — offline cross-reference for exploitation targets
12. **57a** — native sysent 677-734 survey (58 untested entries)

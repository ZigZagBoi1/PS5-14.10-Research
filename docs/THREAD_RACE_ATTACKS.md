# Thread Race Condition Attacks — PS5 14.10

**Date:** 2026-10-19
**Prerequisites:** thr_create(430) with CS=0x43/SS=0x3B produces executing threads with full register/ROP control (probes 80f-80j). Two or more concurrent threads can now race kernel paths.

---

## 1. UMTX Shared-Memory Refcount Race (CVE-2024-43102 class)

**Syscalls:** _umtx_op(454) with UMTX_OP_SHM(25) create/destroy ops
**Race window:** Thread A calls SHM destroy (refcount--) while Thread B calls SHM lookup (refcount read + use). If the refcount drops to zero between B's check and B's use, the backing shm object is freed while B holds a reference.
**Corruption:** Use-after-free on `umtx_shm_reg` allocation. The freed slab can be reclaimed via controlled allocation (e.g., sendmsg with crafted cmsg data) to overlay a fake object with a known kernel function pointer.
**Detection:** Thread B's lookup returns a valid fd to freed memory. Read via getsockopt/fstat on that fd; if it returns unexpected data or crashes, the UAF landed. Sys 624 (VM op counter) can detect unexpected kernel allocations.
**Status:** UMTX_OP_SHM has NEVER been exercised on syscall 454 (all prior "umtx" probes called 557). Probe 110a is prepared for reachability. Must confirm SHM create/destroy work before racing.
**Priority:** HIGHEST — if SHM ops are reachable, this is the most direct path to kernel UAF on FreeBSD 11.

## 2. Socket Close-vs-Read/Write Race (fd double-close / UAF)

**Syscalls:** close(6), read(3)/write(4)/recvmsg(27)/sendmsg(28), socket(97), socketpair(135)
**Race window:** Thread A calls close(fd) on a socket while Thread B is blocked or mid-execution in read/write on the same fd. Between close releasing the file structure and the VFS layer returning, a third thread can open a new socket that reuses the same fd number. Thread B then operates on the wrong file object.
**Corruption:** The kernel's `so_rcv`/`so_snd` socket buffer is freed by close while read/write holds a reference to it. If the fd is recycled to a different socket type, the read/write operates on mismatched kernel structures — type confusion leading to kernel memory corruption.
**Detection:** After the race, read from fd returns data from the wrong socket (cross-talk). Or: write to fd corrupts the new socket's kernel state, detectable via getsockopt returning unexpected values or subsequent operations crashing.
**Status:** All required syscalls are confirmed working. socketpair(135) provides paired fds. No threading was available before; this is now testable.
**Priority:** HIGH — classic FreeBSD vulnerability class, all syscalls available, straightforward to set up.

## 3. Concurrent mmap/munmap Page Table Race

**Syscalls:** mmap(477), munmap(73), concurrent memory access from threads
**Race window:** Thread A calls munmap on a GPU mmap region while Thread B reads/writes the same virtual address. The kernel must tear down page table entries; if Thread B's access races the TLB flush / PTE removal, it can access a physical page that has been returned to the free pool and reallocated for a different purpose (e.g., a kernel page table page).
**Corruption:** Stale TLB entry allows R/W to a recycled physical page. If that page is now used for kernel metadata (page tables, slab allocations), we get kernel R/W.
**Detection:** Thread B reads the region immediately after Thread A's munmap. If the read succeeds (no SIGSEGV) and returns data different from what was written, the stale mapping hit a recycled page. Compare bytes before/after across thousands of iterations; any mismatch = race won.
**Status:** mmap(477) and munmap(73) both work. GPU mmap allocates 256+ contiguous pages. MAP_FIXED works for targeted remapping. Sys 624 VM op counter can confirm kernel-side page operations.
**Priority:** HIGH — 16KB page size on PS5 makes TLB invalidation slower, widening the race window. GPU mmap gives large contiguous regions to race over.

## 4. Signal Handler Reentrancy Race

**Syscalls:** sigaction(416), ktimer_create(235), ktimer_settime(236/237)
**Race window:** A timer signal fires while the main thread is inside a syscall. The signal handler itself calls the same or related syscall (e.g., ktimer_settime on the firing timer). The kernel's callout subsystem and the timer manipulation path may share state (the `callout` structure) without locking against reentrancy from the signal handler context.
**Corruption:** Double-free or list corruption in the callout wheel if the timer expiry callback races its own reconfiguration. With 27 timers firing near-simultaneously, collision probability increases.
**Detection:** After aggressive timer arming, check ktimer_getoverrun values for anomalies. A kernel panic or unexpected overrun count indicates corruption. Can also use sys 624 to detect unexpected VM operations triggered by callout corruption.
**Status:** ktimer_create/settime/getoverrun all work. sigaction works for SIG_IGN/SIG_DFL. Signal delivery to handlers has caveats (sigaltstack copyout validation). Must test whether timer signals reach handlers without sigaltstack.
**Priority:** MEDIUM — does not strictly require threads (signal reentrancy suffices), but threads let us also race timer operations from two contexts simultaneously, widening the window.

## 5. SCM_RIGHTS fd-Passing Race

**Syscalls:** socketpair(135), sendmsg(28) with SCM_RIGHTS, recvmsg(27), close(6)
**Race window:** Thread A sends an fd via SCM_RIGHTS on a Unix socket while Thread B closes that same fd. The kernel must increment the file's reference count in the SCM_RIGHTS path before the close decrements it. If close wins, the fd's file structure is freed, but the SCM_RIGHTS message still carries a pointer to it — the receiver gets a dangling file reference.
**Corruption:** Use-after-free on `struct file`. The receiver can then operate on freed kernel memory via read/write/ioctl on the received fd.
**Detection:** Receiver calls fstat or getsockopt on the received fd. Garbage data or a crash indicates UAF. Run thousands of iterations; any single corruption is exploitable.
**Status:** socketpair and sendmsg/recvmsg with SCM_RIGHTS require testing (probe 108b began this — sendmsg returned 1). dup/dup2 are blocked, but SCM_RIGHTS uses a different kernel path (`unp_internalize`/`unp_externalize`).
**Priority:** MEDIUM — depends on SCM_RIGHTS working end-to-end, which is only partially tested.

---

## Recommended Test Order

1. **Probe 110a** — confirm UMTX_OP_SHM reachability on syscall 454
2. **Socket close/read race** — simplest to set up, all syscalls confirmed
3. **mmap/munmap race** — all primitives available, 16KB pages favor the attacker
4. **SCM_RIGHTS race** — complete the 108b sendmsg/recvmsg validation first
5. **Signal/timer reentrancy** — can test without threads as a bonus

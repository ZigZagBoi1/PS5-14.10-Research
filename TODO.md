# TODO — PS5 14.10 Kernel Research

> **For all AI agents:** Pick a task, do it, then remove it from this list and commit.
> Priority is top-to-bottom. Items marked with a star are the highest-value targets.

---

## ★★★ PRIORITY 0 — KERNEL PANIC VIA thr_create(430) (CONFIRMED GOLD)

**STATUS: thr_create(430) with zeroed-register ucontext CRASHES THE ENTIRE PS5.**
Reproducible kernel panic from sandbox. rv=0, real TID returned, then full console shutdown (lights off). Confirmed by multiple independent runs (probes 58e sections D/E, 76d). This is NOT a process crash — it's a kernel panic in the thread fault/cleanup handler.

- [ ] ★ **Run probe 77a on console** — thr_create panic boundary map (WRITTEN, committed). Tests 7 RIP classes one per run: null, misaligned, unmapped, eboot ret, GPU NX, kernel VA, control. Change TEST_SECTION=1-7, reboot between runs. Start with section 7 (control) to confirm setup alone is safe.
- [ ] ★ **Write probe 77b** — thr_create with controlled register state. Set RSP to GPU mmap region, RIP to a known gadget. If the kernel copies our register values into the new thread's trap frame before the fault, we may get kernel-context register control.
- [ ] ★ **Write probe 77c** — thr_create timing attack. Create thread, immediately call thr_kill/thr_suspend on the returned TID before it faults. If we can catch the thread before it runs, we can modify its context.
- [ ] **Write probe 77d** — thr_create + heap spray. Spray GPU mmap pages around address 0 or the faulting address to catch the kernel's fault handler reading controlled data.
- [ ] **Analyze the panic path** — The kernel panics instead of cleanly killing the thread. This means the exception handler has a bug (null deref in kernel space, missing error check, or use-after-free during thread teardown). Understanding WHY it panics tells us HOW to exploit it.

## ★★ PRIORITY 0.5 — NEW GOLD VECTORS (Offline Analysis 2026-10-19)

See full write-up: `docs/GOLD_VECTORS_2026-10-19.md` — 12 ranked untested vectors.

- [ ] ★ **Write probe 78a** — thr_create + immediate thr_suspend race. Create thread, instantly suspend by TID before it faults. If suspend wins: frozen kernel thread under our control. If it loses: try thr_get_ucontext for KASLR leak.
- [ ] ★ **Write probe 78b** — thr_create heap spray. Rapid-fire multiple thr_create calls to spray kernel `struct thread` objects (~1KB each) in slab cache. Count how many succeed before first panic.
- [ ] ★ **Write probe 78c** — thr_create controlled RSP. Set RSP→GPU mmap region filled with crafted data. Kernel trap handler reads our fake stack during fault processing. Check GPU pages for kernel-written data (signal frame, return addresses).
- [ ] ★ **Write probe 78d** — kevent EVFILT_PROC on thr_create fault. Register EVFILT_PROC with NOTE_EXIT on own PID before thr_create. Poll kevent after thread faults. Check event data/udata for kernel pointers.
- [ ] ★ **Debug probe 50d** — persistent loader crash. Isolate which packet/section kills the loader ACROSS connections. Binary search of sections. This is cross-process kernel corruption.
- [ ] **Write probe 78e** — pipe2(542) via make_syscall. Never tested via make_syscall (only via resolve). If it works: new kernel object for UAF/lifecycle attacks.
- [ ] **Write probe 78f** — ktimer SIGEV_SIGNAL reentrancy. Create 27 timers with signal delivery, manipulate timer state from signal handler. Test for callout corruption.

## PRIORITY 1 — Exploit the CClosure Redirect Primitive

- [ ] **Write and run probe 56d** — ROP via CClosure +0x20 redirect to eboot gadgets
- [ ] **Expand CClosure redirect to gadget chains** — chain gadgets for ROP primitive
- [ ] **Test CClosure redirect with machine-register arguments** — control rdi/rsi/rdx

## PRIORITY 2 — Run These Probes on Console (CRITICAL BACKLOG)

- [x] ~~**Run probe 58e** (`thr_create_ucontext`)~~ — **CONFIRMED: rv=0, real TID, KERNEL PANIC**
- [ ] ★ **Run probe 59b** (`thr_family_survey`) — 11 thr_* syscalls, CRITICAL for panic exploitation
- [ ] ★ **Run probe 58a** (`msync_reachability`) — CVE-2026-49418 device pager UAF
- [ ] ★ **Run probe 57c** (`kldsym_direct`) — instant KASLR defeat if alive
- [ ] **Run probe 59a** (`linux_abi_detection`) — Linuxulator presence for KASLR defeat
- [ ] **Run probe 58d** (`shm_sendfile_reachability`) — CVE-2026-49427/49428 path
- [ ] **Run probe 57e** (`jail_reachability`) — CVE-2026-49419 jail refcount
- [ ] **Run probe 57a** (`native_survey_677_734`) — 58 untested native syscalls
- [ ] **Measure sys 662-670** — use `tools/syscall_isolation_sweep.py`, one connection per number

## PRIORITY 3 — Evidence-Audit Retests

- [ ] **Retest 53c** — kldstat/kldsym for KASLR defeat
- [ ] **Analyze 55e/55f VM map data** — cross-reference 317 regions for RWX, device-mapped, or code-adjacent targets

## PRIORITY 4 — Conditional Follow-Ups

- [ ] **If 58a Section E returns 0:** Write msync double-free trigger (CVE-2026-49418)
- [ ] **If 59a detects Linuxulator:** Write Linux waitid(260) KASLR leak
- [ ] **If 58d shm_open works:** Write sendfile + fspacectl for CVE-2026-49427/49428
- [ ] **If 59b thr_suspend works:** Write thr_set_ucontext register injection probe

## PRIORITY 5 — Research & Analysis

- [ ] **Find the C-level syscall dispatch** — may reveal writable function pointers
- [ ] **Syscall 624 as side channel** — VM operation counter, heap-state oracle
- [ ] PC-coordinated network attacks from external host
- [ ] **sys 596/606/640 deep probing** — all return 0 but tested with trivial args only

## PRIORITY 6 — Prepared Probes Not Yet Run

- [ ] Run probe 57b/57d — deep tests, loader dispatch
- [ ] Run probe 56l (`corrected_mib_probe`) / 50e (`ipv6_msfilter_reach`)

## PRIORITY 7 — Documentation Housekeeping

- [ ] Update ATTACK_SURFACE.md with thr_* syscalls
- [ ] Update STRATEGY.md — thr_create kernel panic is now #1 exploit candidate
- [ ] Cross-reference CVE assessment docs against FINDINGS.md

---

*Last updated: 2026-10-19 — thr_create(430) KERNEL PANIC confirmed by live console testing*

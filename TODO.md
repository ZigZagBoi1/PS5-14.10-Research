# TODO — PS5 14.10 Kernel Research

> **For all AI agents:** Pick a task, do it, then remove it from this list and commit.
> Priority is top-to-bottom. Items marked with a star are the highest-value targets.

---

## ★★★ PRIORITY 0 — KERNEL PANIC VIA thr_create(430) (CONFIRMED GOLD)

**STATUS: thr_create(430) with zeroed-register ucontext CRASHES THE ENTIRE PS5.**
Reproducible kernel panic from sandbox. rv=0, real TID returned, then full console shutdown (lights off). Confirmed by multiple independent runs (probes 58e sections D/E, 76d). This is NOT a process crash — it's a kernel panic in the thread fault/cleanup handler.

- [ ] ★ **Write probe 77a** — thr_create kernel panic analysis. Vary the faulting RIP (0, 1, 0xDEAD, valid-but-unmapped, kernel VA range) to map the kernel's exception handler behavior. Which RIP values panic vs. clean-kill? This maps the vulnerable code path.
- [ ] ★ **Write probe 77b** — thr_create with controlled register state. Set RSP to GPU mmap region, RIP to a known gadget. If the kernel copies our register values into the new thread's trap frame before the fault, we may get kernel-context register control.
- [ ] ★ **Write probe 77c** — thr_create timing attack. Create thread, immediately call thr_kill/thr_suspend on the returned TID before it faults. If we can catch the thread before it runs, we can modify its context.
- [ ] **Write probe 77d** — thr_create + heap spray. Spray GPU mmap pages around address 0 or the faulting address to catch the kernel's fault handler reading controlled data.
- [ ] **Analyze the panic path** — The kernel panics instead of cleanly killing the thread. This means the exception handler has a bug (null deref in kernel space, missing error check, or use-after-free during thread teardown). Understanding WHY it panics tells us HOW to exploit it.

## PRIORITY 1 — Exploit the CClosure Redirect Primitive

- [ ] **Write and run probe 56d** — ROP via CClosure +0x20 redirect to eboot gadgets
- [ ] **Expand CClosure redirect to gadget chains** — chain gadgets for ROP primitive
- [ ] **Test CClosure redirect with machine-register arguments** — control rdi/rsi/rdx

## PRIORITY 2 — Run These Probes on Console

- [x] ~~**Run probe 58e** (`thr_create_ucontext`)~~ — **CONFIRMED: rv=0, real TID, KERNEL PANIC**
- [ ] **Run probe 58a** (`msync_reachability`) — CVE-2026-49418 device pager UAF
- [ ] **Run probe 59b** (`thr_family_survey`) — 11 of 16 thr_* syscalls undocumented
- [ ] **Run probe 59a** (`linux_abi_detection`) — Linuxulator presence for KASLR defeat
- [ ] **Run probe 58d** (`shm_sendfile_reachability`) — CVE-2026-49427/49428 path
- [ ] **Run probe 57e** (`jail_reachability`) — CVE-2026-49419 jail refcount

## PRIORITY 3 — Evidence-Audit Retests

- [ ] **Retest 53c** — kldstat/kldsym for KASLR defeat
- [ ] **Measure sys 662-670 individually** — use `tools/syscall_isolation_sweep.py`

## PRIORITY 4 — Conditional Follow-Ups

- [ ] **If 58a Section E returns 0:** Write msync double-free trigger (CVE-2026-49418)
- [ ] **If 59a detects Linuxulator:** Write Linux waitid(260) KASLR leak
- [ ] **If 58d shm_open works:** Write sendfile + fspacectl for CVE-2026-49427/49428

## PRIORITY 5 — Research & Analysis

- [ ] **Find the C-level syscall dispatch** — may reveal writable function pointers
- [ ] **Syscall 624 as side channel** — VM operation counter, heap-state oracle
- [ ] PC-coordinated network attacks from external host

## PRIORITY 6 — Prepared Probes Not Yet Run

- [ ] Run probe 57a (`native_survey_677_734`) — 58 untested native syscalls
- [ ] Run probe 57b/57c/57d — deep tests, kldsym, loader dispatch
- [ ] Run probe 56l (`corrected_mib_probe`) / 50e (`ipv6_msfilter_reach`)

## PRIORITY 7 — Documentation Housekeeping

- [ ] Update ATTACK_SURFACE.md with thr_* syscalls
- [ ] Update STRATEGY.md — thr_create kernel panic is now #1 exploit candidate
- [ ] Cross-reference CVE assessment docs against FINDINGS.md

---

*Last updated: 2026-10-19 — thr_create(430) KERNEL PANIC confirmed by live console testing*

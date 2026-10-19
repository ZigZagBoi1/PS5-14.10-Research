# TODO — PS5 14.10 Kernel Research

> **For all AI agents:** Pick a task, do it, then remove it from this list and commit.
> Priority is top-to-bottom. Items marked with a star are the highest-value targets.

---

## ★★★ PRIORITY 0 — KERNEL PANIC VIA thr_create(430) (CONFIRMED GOLD)

**STATUS: thr_create(430) with zeroed-register ucontext CRASHES THE ENTIRE PS5.**
Reproducible kernel panic from sandbox. rv=0, real TID returned, then full console shutdown (lights off). Confirmed by multiple independent runs (probes 58e sections D/E, 76d). This is NOT a process crash — it's a kernel panic in the thread fault/cleanup handler.

- [ ] ★ **Run probe 77a on console** — thr_create panic boundary map (WRITTEN, committed). Tests 7 RIP classes one per run: null, misaligned, unmapped, eboot ret, GPU NX, kernel VA, control. Change TEST_SECTION=1-7, reboot between runs. Start with section 7 (control) to confirm setup alone is safe.
- [x] ~~**Write probe 78c**~~ — thr_create controlled RSP → GPU mmap (WRITTEN). Kernel's sendsig() writes signal frame to tf_rsp-128 including pcb_fsbase/gsbase (confirmed by FreeBSD source analysis).
- [x] ~~**Write probe 78b**~~ — thr_create heap spray (WRITTEN). Tests up to 20 rapid threads, counts how many succeed before panic.
- [ ] ★ **Run probe 78c on console** — controlled RSP trap frame. Check GPU pages for kernel-written signal frame data after thr_create fault.
- [ ] **Analyze the panic path** — The kernel panics instead of cleanly killing the thread. This means the exception handler has a bug (null deref in kernel space, missing error check, or use-after-free during thread teardown). Understanding WHY it panics tells us HOW to exploit it.

## ★★ PRIORITY 0.5 — NEW GOLD VECTORS (Offline Analysis 2026-10-19)

See full write-up: `docs/GOLD_VECTORS_2026-10-19.md` — 12 ranked untested vectors.

- [x] ~~**Write probe 78a**~~ — thr_create + thr_suspend race (WRITTEN). 5 sections: suspend, thr_kill(SIGSTOP), suspend_ucontext, get_ucontext.
- [x] ~~**Write probe 78d**~~ — kevent EVFILT_PROC on thr_create fault (WRITTEN). 2 sections: EVFILT_PROC + EVFILT_SIGNAL.
- [x] ~~**Write probe 79a**~~ — /dev/dsp + pipe2 + procctl (WRITTEN). 3 sections: CVE-2026-49417 prereq, pipe2(542), procctl(544) with ASLR_CTL.
- [x] ~~**Write probe 79b**~~ — AIO isolation sweep sys 662-670 (WRITTEN). One syscall per run, 4 arg patterns.
- [x] ~~**Write probe 79c**~~ — ktimer signal reentrancy (WRITTEN). 2 sections: SIGEV_SIGNAL basic + rapid create/delete race.
- [ ] ★ **Debug probe 50d** — persistent loader crash. Isolate which packet/section kills the loader ACROSS connections. Binary search of sections. This is cross-process kernel corruption.
- [ ] ★ **Run probes 78a-78d, 79a-79c on console** — all written, waiting for PS5 access

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

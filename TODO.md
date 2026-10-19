# TODO — PS5 14.10 Kernel Research

> **For all AI agents:** Pick a task, do it, then remove it from this list and commit.
> Priority is top-to-bottom. Items marked with a star are the highest-value targets.

---

## ★★★ PRIORITY 0 — KERNEL PANIC VIA thr_create(430) — ROOT CAUSE IDENTIFIED

**STATUS: ROOT CAUSE FOUND (13.60 decompile, PRs #30 + #31).**
The panic happens because `set_mcontext()` copies CS=0 from the zeroed ucontext into tf_cs. `ISPL(0) = 0` makes the kernel treat the child thread's fault as a KERNEL-MODE fault → `pcb_onfault == NULL` → `trap_fatal()` → `panic("page fault")`.

**THE FIX: Set `ctx+0xC0 = 0x43` (user CS) and `ctx+0x100 = 0x3B` (user SS).** This makes the kernel treat the fault as user-mode → SIGSEGV → clean kill instead of panic. With valid RIP/RSP + correct CS/SS, the child thread should ACTUALLY RUN — giving us THREADING on 14.10.

**Analysis by:** @Unkown607 (PR #31, 13.60 Ghidra decompile of 22 functions) and @cobrajet302gt (PR #30, independent iretq hypothesis + probes)

- [ ] ★★★ **Run probe 80a section 1 on console** — thr_create with CS=0x43/SS=0x3B + RIP=0. DECISIVE: no panic = CS=0x43 prevents it. Standalone (no dependency on 79a). HIGH crash class.
- [ ] ★★★ **Run probe seg/79a on console** — getmcontext(78) layout harvest. ZERO crash risk. Returns Sony's real mcontext field offsets + live CS/SS/RFLAGS values. Validates 80a's hardcoded offsets.
- [ ] ★★★ **Run probe seg/79b on console** — thr_create with real CS=0x43/SS=0x3B from 79a. DECISIVE: rv=0 + no panic = threading works. rv=0 + panic = hypothesis dead.
- [ ] ★★★ **Run probe 80a sections 2-4** — if section 1 survives: test ret gadget execution (2), controlled RSP via GPU mmap (3), ret-sled busy loop with thr_suspend interaction (4).
- [ ] ★★ **Run probe race/79c on console** — AIO race ingredients (Relapse prereqs). Zero crash risk.
- [ ] ★ **Run probe 77a on console** — thr_create panic boundary map. NOTE: cobrajet302gt says 77a will panic in ALL sections because it carries CS=0/SS=0. Needs rebasing on 79a's real selectors.
- [x] ~~**Write probe 78c**~~ — thr_create controlled RSP → GPU mmap (WRITTEN).
- [x] ~~**Write probe 78b**~~ — thr_create heap spray (WRITTEN).
- [ ] ★ **Run probe 78c on console** — controlled RSP trap frame. Check GPU pages for kernel-written signal frame data.
- [x] ~~**Analyze the panic path**~~ — ROOT CAUSE IDENTIFIED: CS=0 → kernel-mode fault → no pcb_onfault → trap_fatal → panic. See `docs/THR_CREATE_PANIC_PATH_13.60.md` and `docs/ANALYSIS_thr_create_panic_2026-10-19.md`.

## ★★★ PRIORITY 0.4 — SYS 601 DECOMPILED VULNERABILITIES (2026-10-19)

**NEW VECTOR:** 13.60 decompiled sys_601 handler (`results/kernel_handlers/analysis/sys_601_deep.md`) reveals CRITICAL structural bugs:
- **Cmd 0x0c:** Hardcoded auth backdoor — XOR bytes 0xCD/0x41 pass authentication
- **Cmd 0x12:** Unchecked process structure write to proc+0x578/+0x580 — zero credential checks, these are kfree'd kernel heap ptrs → arbitrary kfree primitive
- **Cmd 0x10:** 0x1000-byte kernel page copyout without zeroing → kernel info leak
- **Ring buffer:** Signed comparison bypass at handler+0x2288 → heap underflow write

Probe 55d tested but got -1 on critical commands ("process lacks initialization"). Cmd 0x00 DID return 0. The re-probe needs proper init sequencing + exact decompiled auth bytes.

- [x] ~~**Write probe 83a**~~ — sys 601 deep retest (WRITTEN). 4 sections: A=systematic init+survey, B=hardcoded backdoor with exact 0xCD/0x41 bytes, C=unchecked process write (arbitrary kfree), D=device name matching+config write.
- [ ] ★★★ **Run probe 83a section A** — init survey: which commands succeed after cmd 0x00? Scan all outputs for kernel pointers. MODERATE crash risk.
- [ ] ★★★ **Run probe 83a section B** — backdoor auth with exact decompiled bytes + offset variations. If accepted: kernel access via cmd 0x10/0x12.
- [ ] ★★ **Run probe 83a section C** — process structure write test. If ret=0: arbitrary kfree primitive confirmed.
- [x] ~~**Write probe 84a**~~ — sys 653 GPU PTE modifier reachability (WRITTEN). 3 sections: A=basic reachability (arg0 values, struct pointer, GPU addr), B=sys 630 mount enumeration (info leak), C=GPU PTE attribute modification on mmap pages.
- [ ] ★★★ **Run probe 84a section A** — sys 653 has NO priv_check: test reachability. If ret=0: potential W^X bypass via GPU PTE modification!
- [ ] ★★★ **Run probe 84a section B** — sys 630 mount enumeration: zero auth on ALL read functions. List all kernel mount points, cross-PID lookup. Info leak minimum.
- [ ] ★★ **Run probe 84a section C** — if A succeeds: try PTE attribute changes on GPU mmap pages (protection modification).

## ★★ PRIORITY 0.5 — NEW GOLD VECTORS (Offline Analysis 2026-10-19)

See full write-up: `docs/GOLD_VECTORS_2026-10-19.md` — 12 ranked untested vectors.

- [x] ~~**Write probe 78a**~~ — thr_create + thr_suspend race (WRITTEN). 5 sections: suspend, thr_kill(SIGSTOP), suspend_ucontext, get_ucontext.
- [x] ~~**Write probe 78d**~~ — kevent EVFILT_PROC on thr_create fault (WRITTEN). 2 sections: EVFILT_PROC + EVFILT_SIGNAL.
- [x] ~~**Write probe 79a**~~ — /dev/dsp + pipe2 + procctl (WRITTEN). 3 sections: CVE-2026-49417 prereq, pipe2(542), procctl(544) with ASLR_CTL.
- [x] ~~**Write probe 79b**~~ — AIO isolation sweep sys 662-670 (WRITTEN). One syscall per run, 4 arg patterns.
- [x] ~~**Write probe 79c**~~ — ktimer signal reentrancy (WRITTEN). 2 sections: SIGEV_SIGNAL basic + rapid create/delete race.
- [x] ~~**Write probe 82a**~~ — umtx_op exploitation vectors (WRITTEN). 5 sections: NWAKE overflow, ROBUST_LISTS info leak, RW lock first test, SHM UAF via thr_create, NWAKE kernel oracle.
- [ ] ★★ **Run probe 82a section A** — NWAKE_PRIVATE integer overflow boundary testing. MODERATE crash risk.
- [ ] ★★ **Run probe 82a section C** — RW lock ops NEVER TESTED before. First coverage of ops 12/13/14.
- [ ] ★★ **Run probe 82a section D** — SHM UAF setup (single-threaded); full race needs 80a threading.
- [ ] ★ **Debug probe 50d** — persistent loader crash. Isolate which packet/section kills the loader ACROSS connections. Binary search of sections. This is cross-process kernel corruption.
- [ ] ★ **Run probes 78a-78d, 79a-79c on console** — all written, waiting for PS5 access

## ★★★ PRIORITY 0.8 — SROP (Sigreturn-Oriented Programming)

**NEW VECTOR (2026-10-19):** sigreturn(417) resolved OK in probe 22 but was NEVER CALLED. getcontext(421) and setcontext(422) exist in 13.60 sysent but have ZERO probe coverage.

If set_mcontext() doesn't force SEL_RPL_MASK, sigreturn/setcontext give: controlled RIP, RSP, and all GPRs. This is a one-shot path to ROP without the chain infrastructure.

- [x] ~~**Write probe 81a**~~ — SROP probe (WRITTEN). 5 sections: A=getcontext harvest, B=layout comparison, C=setcontext identity, D=sigreturn crafted frame, E=full SROP via setcontext + GPU mmap.
- [ ] ★★★ **Run probe 81a section A** — getcontext(421) register harvest. ZERO crash risk. Returns live CS/SS/RFLAGS + determines correct mcontext layout.
- [ ] ★★★ **Run probe 81a section B** — compare getcontext output against 3 layout hypotheses (vanilla FreeBSD, Sony 13.60, probe 80a). Determines correct offsets.
- [ ] ★★ **Run probe 81a sections C-E** — actual SROP execution tests. HIGH crash risk.

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

## Contributors

| GitHub | Contribution |
|--------|-------------|
| @ZigZagBoi1 | Lead researcher, all probes 01-79f, findings, tooling |
| @Unkown607 | thr_create panic root-cause analysis (13.60 Ghidra decompile, PR #31) |
| @cobrajet302gt | CS=0/iretq hypothesis, probes seg/79a-79b, race/79c, Ghidra scripts (PR #30) |

---

*Last updated: 2026-10-19 — thr_create root cause IDENTIFIED: CS=0 → kernel-mode fault (PRs #30, #31)*

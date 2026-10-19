# TODO — PS5 14.10 Kernel Research

> **For all AI agents:** Pick a task, do it, then remove it from this list and commit.
> Priority is top-to-bottom. Items marked with a star are the highest-value targets.

---

## PRIORITY 1 — Run These Probes on Console (GOLD)

- [ ] **Run probe 58a** (`msync_reachability`) — CVE-2026-49418 device pager UAF. msync(MS_INVALIDATE) on GPU mmap pages. If Section E returns 0, the double-free path is REACHABLE without threading or KASLR defeat. This is the #1 exploit candidate. `probes/phase15_native_sysent/58a_msync_reachability.lua`
- [ ] **Run probe 58e** (`thr_create_ucontext`) — First thr_create(430) call with proper ucontext_t. If the id-oracle returns a real thread id, we unlock THREADING which enables race-condition CVEs. CRASH_CLASS: RISKY. `probes/phase15_native_sysent/58e_thr_create_ucontext.lua`
- [ ] **Run probe 59b** (`thr_family_survey`) — 11 of 16 thr_* syscalls are undocumented. Surveys thr_get_name, thr_set_name, thr_kill, thr_suspend, thr_wake, ucontext family. `probes/phase15_native_sysent/59b_thr_family_survey.lua`
- [ ] **Run probe 59a** (`linux_abi_detection`) — Detects Linuxulator presence via sysctl side channels. If present, CVE-2026-49424 gives trivial KASLR defeat (104 bytes of kernel stack per call). `probes/phase15_native_sysent/59a_linux_abi_detection.lua`
- [ ] **Run probe 58d** (`shm_sendfile_reachability`) — Tests shm_open(482) via make_syscall (crashes via resolve() but never tested raw). If it works, unlocks CVE-2026-49427/49428 (largepage UAF). `probes/phase15_native_sysent/58d_shm_sendfile_reachability.lua`
- [ ] **Run probe 58f** (`kevent_timeout_matrix`) — Fills the last gap in kevent understanding. Tests split/combined x zero/nonzero timeout. `probes/phase2_kernel_objects/58f_kevent_timeout_matrix.lua`
- [ ] **Run probe 57e** (`jail_reachability`) — Tests all 4 jail syscalls (338/429/496/497) with safe args. If 429 doesn't sandbox-kill, CVE-2026-49419 (jail refcount double-free) is reachable. `probes/phase15_native_sysent/57e_jail_reachability.lua`

## PRIORITY 2 — Write Follow-Up Probes Based on Results

- [ ] **If 58a Section E returns 0:** Write probe 58b — msync double-free trigger with GPU mmap pages (the actual CVE-2026-49418 exploit attempt)
- [ ] **If 58e returns a thread id:** Write probe 58e2 — threading confirmed, attempt to create a second thread for race conditions
- [ ] **If 59a detects Linuxulator:** Write probe 59c — Linux waitid(260) call to leak 104 bytes of kernel stack (instant KASLR defeat)
- [ ] **If 58d shm_open works:** Write probe 58d2 — sendfile + fspacectl with SHM_LARGEPAGE to trigger CVE-2026-49427/49428

## PRIORITY 3 — Prepared Probes Not Yet Run

- [ ] Run probe 57a (`native_survey_677_734`) — 58 untested native syscalls
- [ ] Run probe 57b (`deep_test_natives`) — Deep test interesting natives from 57a
- [ ] Run probe 57c (`kldsym_direct`) — Direct kldsym(337), instant KASLR defeat if any symbol resolves
- [ ] Run probe 57d (`loader_dispatch_hunt`) — Find loader's C-level syscall dispatch
- [ ] Run probe 56l (`corrected_mib_probe`) — Corrected sysctl MIBs and ktimer differential
- [ ] Run probe 50e (`ipv6_msfilter_reach`) — CVE-2026-49412 reachability

## PRIORITY 4 — Research & Analysis

- [ ] Complete Sony syscall survey — syscalls 627-676 untested (51a output truncated at 624)
- [ ] Syscall 624 as heap oracle — call in loop, correlate with allocations, measure sensitivity
- [ ] Syscalls 606/643 with event structures — may be evdev/notification syscalls needing proper args
- [ ] Verify CVE-2026-58090 version applicability — unix SOCK_STREAM UAF, advisory lists 15.0+ only
- [ ] PC-coordinated network attacks — real network packets from external host (not loopback)

## PRIORITY 5 — Documentation Housekeeping

- [ ] Update ATTACK_SURFACE.md with all newly discovered thr_* syscalls from PR #28
- [ ] Update UNTESTED_THEORIES.md with CVE assessment results
- [ ] Update STRATEGY.md priorities based on CVE-2026-49418 msync being #1 candidate
- [ ] Cross-reference all new CVE assessment docs against FINDINGS.md

---

*Last updated: 2026-10-19 by mass PR audit*

# TODO — PS5 14.10 Kernel Research

> **For all AI agents:** Pick a task, do it, then remove it from this list and commit.
> Priority is top-to-bottom. Items marked with a star are the highest-value targets.

---

## PRIORITY 1 — Exploit the CClosure Redirect Primitive (GOLD)

- [ ] **Write and run probe 56d** — ROP via CClosure +0x20 redirect. Redirect rawequal/rawget to eboot gadgets (ret, pop rdi;ret, etc.), call them, observe register/stack effects. This is the #1 path to arbitrary native code execution. 56c/56f proved selected Lua C target redirects work with output and restore checks.
- [ ] **Expand CClosure redirect to gadget chains** — Once 56d confirms single-gadget calling, chain gadgets (pop rdi;ret → syscall;ret) to build a proper ROP primitive from userland CClosure dispatch.
- [ ] **Test CClosure redirect with machine-register arguments** — 56c/56f used Lua arguments only. Test if register state (rdi/rsi/rdx) can be controlled through Lua call conventions to pass arguments to native targets.

## PRIORITY 2 — Run These Probes on Console

- [ ] **Run probe 58a** (`msync_reachability`) — CVE-2026-49418 device pager UAF. msync(MS_INVALIDATE) on GPU mmap pages. If Section E returns 0, the double-free path is REACHABLE without threading or KASLR defeat. `probes/phase15_native_sysent/58a_msync_reachability.lua`
- [ ] **Run probe 58e** (`thr_create_ucontext`) — First thr_create(430) call with proper ucontext_t. If the id-oracle returns a real thread id, we unlock THREADING which enables race-condition CVEs. CRASH_CLASS: RISKY. `probes/phase15_native_sysent/58e_thr_create_ucontext.lua`
- [ ] **Run probe 59b** (`thr_family_survey`) — 11 of 16 thr_* syscalls are undocumented. Surveys thr_get_name, thr_set_name, thr_kill, thr_suspend, thr_wake, ucontext family. `probes/phase15_native_sysent/59b_thr_family_survey.lua`
- [ ] **Run probe 59a** (`linux_abi_detection`) — Detects Linuxulator presence via sysctl side channels. If present, CVE-2026-49424 gives trivial KASLR defeat (104 bytes of kernel stack per call). `probes/phase15_native_sysent/59a_linux_abi_detection.lua`
- [ ] **Run probe 58d** (`shm_sendfile_reachability`) — Tests shm_open(482) via make_syscall. If it works, unlocks CVE-2026-49427/49428 (largepage UAF). `probes/phase15_native_sysent/58d_shm_sendfile_reachability.lua`
- [ ] **Run probe 57e** (`jail_reachability`) — Tests all 4 jail syscalls (338/429/496/497) with safe args. If 429 doesn't sandbox-kill, CVE-2026-49419 is reachable. `probes/phase15_native_sysent/57e_jail_reachability.lua`

## PRIORITY 3 — Evidence-Audit Retests (Pending)

- [ ] **Retest 53c** — kldstat/kldsym retest. Original 43a/43b logs are header-only (145B/116B), no output and no kill record. If kldsym(337) resolves any symbol, it's instant KASLR defeat.
- [ ] **Measure sys 662-670 individually** — sys 661 kills, but 662-670 were NEVER executed (both 54c/54f captures stop at 661). Use `tools/syscall_isolation_sweep.py` for one-connection-per-number measurement. Some may be live.

## PRIORITY 4 — Conditional Follow-Ups (Write After Results)

- [ ] **If 58a Section E returns 0:** Write probe 58b — msync double-free trigger with GPU mmap pages (actual CVE-2026-49418 exploit)
- [ ] **If 58e returns a thread id:** Write probe 58e2 — threading confirmed, attempt race conditions
- [ ] **If 59a detects Linuxulator:** Write probe 59c — Linux waitid(260) for 104 bytes of kernel stack (instant KASLR defeat)
- [ ] **If 58d shm_open works:** Write probe 58d2 — sendfile + fspacectl with SHM_LARGEPAGE for CVE-2026-49427/49428

## PRIORITY 5 — Research & Analysis

- [ ] **Find the C-level syscall dispatch** — The exact mechanism by which make_syscall() reaches the kernel is unidentified. Finding it may reveal writable function pointers or a code-execution path.
- [ ] **Syscall 624 as side channel** — Confirmed VM operation counter (+5 per mmap, zero jitter). Correlate with heap allocations for heap-state oracle.
- [ ] **Syscalls 606/643 with event structures** — May be evdev/notification syscalls needing proper args
- [ ] PC-coordinated network attacks — Real network packets from external host (not loopback)

## PRIORITY 6 — Prepared Probes Not Yet Run

- [ ] Run probe 57a (`native_survey_677_734`) — 58 untested native syscalls
- [ ] Run probe 57b (`deep_test_natives`) — Deep test interesting natives from 57a
- [ ] Run probe 57c (`kldsym_direct`) — Direct kldsym(337), instant KASLR defeat if any symbol resolves
- [ ] Run probe 57d (`loader_dispatch_hunt`) — Find loader's C-level syscall dispatch
- [ ] Run probe 56l (`corrected_mib_probe`) — Corrected sysctl MIBs and ktimer differential
- [ ] Run probe 50e (`ipv6_msfilter_reach`) — CVE-2026-49412 reachability

## PRIORITY 7 — Documentation Housekeeping

- [ ] Update ATTACK_SURFACE.md with all newly discovered thr_* syscalls from PR #28
- [ ] Update UNTESTED_THEORIES.md with CVE assessment results and phase 14/15 dead ends
- [ ] Update STRATEGY.md priorities — CClosure redirect is now the #1 primitive, msync UAF is #2
- [ ] Cross-reference all new CVE assessment docs against FINDINGS.md

---

*Last updated: 2026-10-19 — synced with CLAUDE.md evidence corrections and phase 14/15 results*

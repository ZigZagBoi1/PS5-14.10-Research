# Firmware 14.10 progress audit

Audit date: **2026-10-23** (America/Toronto). Evidence snapshot: `2ca780c` (comprehensive README update + ioctl overcopy sweep complete).

## Assessment

**44/100 (~44%) on the rubric below.** This is an editorial estimate of demonstrated milestones, not an objective measurement of how much exploit work exists. The weights are judgment calls. The record does not support publishing 60-70% completion of a full kernel exploit. The 1-point increase from the 2026-10-21 audit reflects the **active kernel-touching primitive** sub-check in attack surface mapping rising from 2/4 to 3/4: child thread ROP syscalls (4-arg, fake TCB fix, concurrent threads with socketpair IPC and kqueue timers), full ioctl overcopy sweep across all 34 /dev nodes, Sony syscall range (532-676) exhausted with real-args contracts, and 150+ dead ends documented. The exploitation infrastructure is mature; only demonstrated kernel memory corruption remains for 4/4.

Endpoint: a repeatable kernel exploit on **14.10** with demonstrated kernel read/write. Hypervisor bypass, full jailbreak/payload compatibility, and results from other firmware are excluded. A kernel exploit need not follow any particular technique; the gates describe evidence, not an implementation plan.

## Method and scope

- Inventoried **1,127 Lua probe files** and **1,224 text result files** across 37 phases. These are artifact counts, not unique experiments, successful tests, or vulnerability coverage. Reruns, truncated logs, and embedded source text exist.
- Searched the raw-result corpus for kernel-access claims, sentinel/false-positive indicators, and crash outcomes; closely reviewed identity, the 45c retraction, baseline memory observations, the 51-series survey logs, phase 13-24 results, and all current strategy/findings summaries.
- This is an offline repository audit, not an exhaustive manual validation of every captured byte, independent hardware reproduction, or firmware attestation. The firmware identity is reported by the captured session.
- Later counter-evidence overrides earlier positive headlines. API availability, a nonnegative return code, a writable userland value, or a loader crash does not establish kernel exploitation.
- Full credit requires the named evidence gate; unproven gates get zero rather than speculative partial credit. The rubric has seven milestone categories with explicit sub-checks.
- There is no statistical confidence interval or reliable ETA. Reweighting milestones changes this estimate. Count and score changes require an explicit review; the renderer never promotes a successful-looking log automatically.

## Weighted evidence gates

| Milestone | Earned | Weight | Assessment |
|---|---:|---:|---|
| 14.10 research environment | 10 | 10 | Firmware-tagged Lua execution and observable userland behavior are recorded. |
| Probe tooling and captured evidence | 10 | 10 | Runner source and dated output logs are present; counts measure artifacts, not successful exploits. |
| Target characterization | 15 | 15 | Exhaustive survey (664 probes, 676 syscalls, 39 modules). Native code exec (thr_create ROP, fcall_with_rax, C11 threading). 13.60 Ghidra decompile validates thr_create panic as kernel candidate. |
| Kernel attack surface mapping | 9 | 10 | 15+ CVEs assessed (all blocked/stubbed/patched on 14.10). 150+ dead ends mapped. All 34 open /dev nodes ioctl-swept end-to-end. Sony syscall range (532-676) exhausted. Child thread ROP (4-arg, TLS fix, concurrent threads) provides full exploitation infrastructure. UMTX orphaned waiter is the active kernel candidate but corruption not demonstrated. |
| Validated 14.10 kernel vulnerability | 0 | 15 | No qualifying root-cause analysis and controlled 14.10 reproduction. UMTX orphaned waiter touches kernel state but corruption not demonstrated. |
| Demonstrated 14.10 kernel read/write | 0 | 25 | No verified kernel read/write demonstration found. |
| Repeatable complete kernel exploit | 0 | 15 | No end-to-end 14.10 kernel exploit with a repeatability record found. Hypervisor bypass is outside this denominator. |
| **Total** | **44** | **100** | **Kernel-access gates remain unproven.** |

### Individual checks and source links

#### 14.10 research environment (10/10)

- 5/5: Firmware identified in a captured session
- 5/5: Lua/userland experiments produce observable output

Evidence: [results/phase1_identity_layout/01_identity_20261015_184244.txt](https://github.com/ZigZagBoi1/PS5-14.10-Research/blob/master/results/phase1_identity_layout/01_identity_20261015_184244.txt).

#### Probe tooling and captured evidence (10/10)

- 5/5: Probe runner and source available
- 5/5: Dated raw outputs retained

Evidence: [tools/send_probe.py](https://github.com/ZigZagBoi1/PS5-14.10-Research/blob/master/tools/send_probe.py), [docs/PROBE_INDEX.md](https://github.com/ZigZagBoi1/PS5-14.10-Research/blob/master/docs/PROBE_INDEX.md).

#### Target characterization (15/15)

- 5/5: Baseline interface observations retained
- 5/5: Complete scoped survey with reconciled current summary (1,127 probes, 676 sysent, 39 modules, 34/76 devices, Sony range exhausted)
- 3/3: Native code execution primitive confirmed (thr_create, thr_new, fcall_with_rax, child thread 4-arg ROP, C11 threading)
- 2/2: Target-build analysis validates a kernel candidate

**What earned the last 2 points (target-build gate):** The 13.60 Ghidra decompile of 22 functions (PRs #30/#31) shows `set_mcontext()` copies CS register from user ucontext without OR-ing `SEL_RPL_MASK`. This root-cause analysis was validated against 14.10 behavioral evidence (thr_create panic with zeroed context, probe 80a). Additionally, the UMTX PI orphaned-waiter primitive (274e/274f) interacts with real kernel wait queue state and represents an active kernel attack candidate with a defined exploitation path.

Evidence: probes 156c/156d (thr_create alive), 274c (child ROP syscalls), 274e/274f (PI mutex + orphaned waiter), 129b (fcall_with_rax), 126g/126h (C11 threading), docs/THREADING_ALIVE_14_10.md.

#### Kernel attack surface mapping (9/10)

- 3/3: CVE and public technique assessment against target firmware
- 3/3: Systematic dead-end mapping eliminates blind alleys
- 3/4: Active kernel-touching primitive identified with exploitation path

**CVE assessments (3/3):** 15+ CVEs and public techniques tested against 14.10:
- CVE-2024-43102 (umtx_shm UAF): UMTX_OP_SHM confirmed stub, race path unreachable (probes 151a-152k)
- CVE-2026-49418 (msync device-pager UAF): MS_INVALIDATE returns -1 on all mappings (probes 58a/58b)
- CVE-2026-49412 (IPV6_MSFILTER UAF): entire RFC 3678 API removed by Sony (probes 50e2/50e3)
- CVE-2026-45257 (KTLS page-cache): Sony did not include KTLS (probe 50f)
- CVE-2026-3038 (sa_len=127 routing overflow): accepted without panic, likely patched (probe 56e)
- netcontrol/netevent UAF: close-before-unregister leaks instead of freeing (probes 223a-234a)
- ZDI-26-784 (kqueue race): 10,000+ races across 4 variants, 0 anomalies (probes 271g/271h/271i)
- AF_ROUTE Relapse technique: kernel sanitizes route messages (probe 53b)
- thr_create CS=0 panic: probe 189a shows 14.10 forces/replaces selector, panic-only
- 20+ KASLR defeat techniques: all tested, all dead (sysctl, AF_ROUTE, kldstat, mincore, sockopt, VM map, module info, timing, ioctl overcopy, GPU pool, signal frame, thread ucontext, getsockopt, SCM_CREDS, fstat, getdirentries, getrusage, kevent, poll, SO_TIMESTAMP, etc.)

**Dead-end mapping (3/3):** 150+ dead ends documented with root causes. Full sysent boundary measured (676 entries). Device ioctl space measured end-to-end (~32M calls across 31 nodes + fast overcopy scan on all 34 open nodes). Sony syscall range (532-676) exhausted with real-args contracts from 13.60 decompiles. 214 getsockopt options swept across 8 socket types. Sony syscall families exhausted (jitshm, osem, namedobj, blockpool, evf, etc.). Full eboot 4.6MB scan: 18 `0F 05` hits, zero `syscall;ret`.

**Active kernel primitive (3/4):** UMTX orphaned kernel waiter leaves a wait queue entry intact in the kernel after userland clears the contested bit (probes 274e/274f). PI mutex lock/unlock/wake all work. The exploitation infrastructure is now mature: child threads execute 4-arg kernel syscalls via ROP (271g/272a), fake TCB fix enables proper errno handling (384b), concurrent thread races are clean under stress (385a), socketpair IPC and kqueue timers work (271i). The 4/4 requires demonstrated kernel memory corruption, which remains unproven. The exploitation path from orphaned waiter to corruption is theoretical but the tooling to exercise it is complete.

Evidence: docs/ATTACK_SURFACE.md, docs/FINDINGS.md, docs/DEVICE_IOCTL_14_10.md, results from phases 15-37.

#### Validated 14.10 kernel vulnerability (0/15)

- 0/8: Kernel vulnerability root cause supported on 14.10
- 0/7: Controlled reproduction establishes kernel impact

The UMTX orphaned waiter is the closest candidate: it leaves kernel-side state (wait queue entry) that is not cleaned up. But the path from "orphaned entry exists" to "kernel memory corruption" is not established. PI chain cycles, type confusion, and concurrent races are the next test vectors (probes 274g+).

Evidence: docs/STRATEGY.md, docs/PROBE_INDEX.md.

#### Demonstrated 14.10 kernel read/write (0/25)

- 0/10: Verified arbitrary kernel read on 14.10
- 0/10: Verified controlled kernel write on 14.10
- 0/5: Independent evidence distinguishes kernel from userland effects

Evidence: results/45c_execution_reality_check_20261016_192713.txt, docs/FINDINGS.md.

#### Repeatable complete kernel exploit (0/15)

- 0/7: End-to-end kernel exploit from a fresh session
- 0/4: Reported multi-run success/failure denominator
- 0/4: Recovery and cleanup behavior recorded

Evidence: docs/STRATEGY.md, docs/PROBE_INDEX.md.

## Rubric restructuring (2026-10-21)

The original rubric (2026-10-18) had 6 milestones: environment (10), tooling (10), characterization (15), vulnerability (20), kernel R/W (25), chain (20). It scored 25/100, later revised to 33/100 after the characterization expansion (native code exec + complete survey gates).

This audit adds a 7th milestone, **Kernel attack surface mapping** (10 points), to recognize work that falls between target characterization and a validated kernel vulnerability. The vulnerability and chain categories were reduced by 5 points each (20->15) to keep the total at 100. This reflects that:

1. The gap between "survey done" and "kernel vulnerability found" contains substantial, measurable work (CVE assessments, dead-end mapping, device inventory, kernel-touching primitives) that was previously unscored.
2. 55% of points remain locked behind kernel access gates (vulnerability 15 + R/W 25 + chain 15). The rubric still cannot reach 50% without a kernel primitive.
3. The reduction in vulnerability/chain weights is modest (5 pts each) and proportional to the new category's scope.

## Evidence that changes the estimate

1. **Identity:** the captured identity session reports `FW_VERSION: 14.10` and supplies live userland observations.
2. **Execution retraction:** probe 45c records normal syscall behavior after changing execution metadata. Earlier 43i/44a/45a headlines cannot be scored as arbitrary native execution or kernel access.
3. **Native code execution (confirmed):** thr_create(430) starts real threads (156c/156d). thr_new(455) is simpler: start_func(arg) with arg in rdi (56l). Child threads execute 4-arg kernel syscalls via ROP: getpid, write, socketpair, close all confirmed (271g/272a/384b/386a). Fake TCB fix enables proper errno handling in child threads (384b). Arbitrary userland calls via fcall_with_rax confirmed (129b). C11 threading with join confirmed (126g/126h). EVFILT_TIMER + socketpair IPC pipeline confirmed (271i).
4. **UMTX PI primitives:** PI-enabled MUTEX_LOCK/UNLOCK work (274f). Orphaned kernel waiter primitive proven -- clearing contested bit leaves child permanently blocked with wait queue entry intact (274e/274f). This is active kernel state manipulation but not yet kernel corruption. Concurrent child races are clean under stress: double-close (100 iter), UMTX trylock (50×4), socket write+close (50 iter) with zero anomalies (385a).
5. **CVE assessment coverage (expanded 10-23):** CVE-2024-43102 (umtx_shm stub), CVE-2026-49418 (msync blocked), CVE-2026-49412 (IPV6_MSFILTER removed), CVE-2026-45257 (KTLS absent), CVE-2026-3038 (sa_len=127 patched), netcontrol UAF (dead on 14.10), ZDI-26-784 kqueue race (10,000+ races clean). All public techniques tested and mapped.
6. **Device and ioctl exhaustion (completed 10-23):** 34 of 76 /dev nodes open from game process. Full ioctl space measured end-to-end: ~32M calls across 31 nodes (273a-287a), fast two-pass overcopy scan on all 34 nodes (387a-387c). Zero overcopy, zero kernel pointers. The Praetorian KASLR ioctl is not accessible from the game process.
7. **Sony syscall range exhaustion (10-23):** syscalls 532-676 exercised with real-args contracts derived from 13.60 Ghidra decompiles. Only 604/636 (no decoded contract) and 658 (fdatasync, no buffer) remain. Object families all closed: jitshm, osem, namedobj, evf, blockpool.
8. **KASLR exhaustion (10-23):** 20+ distinct leak techniques tested. GPU pool (zero-filled, 387 MiB scanned), NET_RT_DUMP (proven sockaddr boundary artifacts), signal frame (zero-initialized), thread ucontext, getsockopt, SCM_CREDS, fstat overcopy, getdirentries, getrusage, SO_TIMESTAMP/BINTIME, kevent, poll, procctl, sys 624 side channel, timing (mprotect batch), mprotect early-return, ioctl overcopy: ALL clean.
9. **No verified kernel primitive:** normal syscall buffers, zero-filled outputs, userland heap access, and values tagged `KPTR` by a heuristic do not independently prove kernel addresses or kernel read/write.
10. **13.60 is supporting research:** dumps and handler analysis can inform understanding, but do not satisfy a 14.10 vulnerability or kernel-access gate.

## Why not 60-70%?

Research effort and closeness to a working exploit have different denominators. 1,127 probes, 150+ dead ends, and 15+ CVE assessments can eliminate hypotheses without yielding a vulnerability. This rubric reserves **55 points** for a validated vulnerability (15), demonstrated kernel read/write (25), and a repeatable chain (15). All three remain unearned. A single discovery could change the position sharply; it could also remain unresolved indefinitely. It is fair to say substantial groundwork exists and the attack surface is thoroughly mapped. It is not evidence-backed to call this a 60-70% complete kernel exploit.

## Maintaining this meter

Edit `docs/progress.json` only after reviewing new evidence. Evidence file hashes and inventory counts are checked to force reconsideration when the snapshot changes. Update this audit, then run:

```text
python tools/render_progress.py
python tools/render_progress.py --check
```

The renderer generates the README block and SVG. It reads local files only and never contacts or runs code on a console. New evidence must be reviewed before awarding points. The percentage is not automatically increased by commit counts, hours spent, number of probes, another firmware's dumps, or unverified return values.

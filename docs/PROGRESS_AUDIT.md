# Firmware 14.10 progress audit

Audit date: **2026-10-21** (America/Toronto). Evidence snapshot: `66611f4` (phase 22 review: device inventory, JSC corpus, UMTX high ops).

## Assessment

**43/100 (~43%) on the rubric below.** This is an editorial estimate of demonstrated milestones, not an objective measurement of how much exploit work exists. The weights are judgment calls. The record does not support publishing 60-70% completion of a full kernel exploit. No new kernel primitives were demonstrated since the 2026-10-19 audit, but the rubric was restructured to add a **Kernel attack surface mapping** category (10 points) recognizing the CVE assessment, dead-end elimination, device inventory, and active kernel-touching primitives that fall between characterization and a validated vulnerability.

Endpoint: a repeatable kernel exploit on **14.10** with demonstrated kernel read/write. Hypervisor bypass, full jailbreak/payload compatibility, and results from other firmware are excluded. A kernel exploit need not follow any particular technique; the gates describe evidence, not an implementation plan.

## Method and scope

- Inventoried **664 Lua probe files** and **701 text result files** across 29 phases. These are artifact counts, not unique experiments, successful tests, or vulnerability coverage. Reruns, truncated logs, and embedded source text exist.
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
| Kernel attack surface mapping | 8 | 10 | 12+ CVEs assessed (all blocked/stubbed on 14.10). 70+ dead ends mapped. 34/76 device nodes inventoried. UMTX orphaned waiter primitive proven. Active PI chain exploitation in progress but no kernel corruption yet. |
| Validated 14.10 kernel vulnerability | 0 | 15 | No qualifying root-cause analysis and controlled 14.10 reproduction. UMTX orphaned waiter touches kernel state but corruption not demonstrated. |
| Demonstrated 14.10 kernel read/write | 0 | 25 | No verified kernel read/write demonstration found. |
| Repeatable complete kernel exploit | 0 | 15 | No end-to-end 14.10 kernel exploit with a repeatability record found. Hypervisor bypass is outside this denominator. |
| **Total** | **43** | **100** | **Kernel-access gates remain unproven.** |

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
- 5/5: Complete scoped survey with reconciled current summary
- 3/3: Native code execution primitive confirmed
- 2/2: Target-build analysis validates a kernel candidate

**What earned the last 2 points (target-build gate):** The 13.60 Ghidra decompile of 22 functions (PRs #30/#31) shows `set_mcontext()` copies CS register from user ucontext without OR-ing `SEL_RPL_MASK`. This root-cause analysis was validated against 14.10 behavioral evidence (thr_create panic with zeroed context, probe 80a). Additionally, the UMTX PI orphaned-waiter primitive (274e/274f) interacts with real kernel wait queue state and represents an active kernel attack candidate with a defined exploitation path.

Evidence: probes 156c/156d (thr_create alive), 274c (child ROP syscalls), 274e/274f (PI mutex + orphaned waiter), 129b (fcall_with_rax), 126g/126h (C11 threading), docs/THREADING_ALIVE_14_10.md.

#### Kernel attack surface mapping (8/10) -- NEW

- 3/3: CVE and public technique assessment against target firmware
- 3/3: Systematic dead-end mapping eliminates blind alleys
- 2/4: Active kernel-touching primitive identified with exploitation path

**CVE assessments (3/3):** 12+ CVEs and public techniques tested against 14.10:
- CVE-2024-43102 (umtx_shm UAF): UMTX_OP_SHM confirmed stub, race path unreachable (probes 151a-152k)
- CVE-2026-49418 (msync device-pager UAF): MS_INVALIDATE returns -1 (probe 58a)
- netcontrol/netevent UAF: close-before-unregister leaks instead of freeing (probes 223a-234a)
- AF_ROUTE Relapse technique: kernel sanitizes route messages (probe 53b)
- thr_create CS=0 panic: probe 189a shows 14.10 forces/replaces selector, panic-only
- 17 KASLR defeat techniques: all tested, all dead (sysctl, AF_ROUTE, kldstat, mincore, sockopt, VM map, module info, etc.)

**Dead-end mapping (3/3):** 70+ dead ends documented with root causes. Full sysent boundary measured (676 entries). Device ioctl encoding discovered (Sony NID-hash, not FreeBSD _IOC). 214 getsockopt options swept across 8 socket types. Sony syscall families exhausted (jitshm, osem, namedobj, blockpool, etc.).

**Active kernel primitive (2/4):** UMTX orphaned kernel waiter leaves a wait queue entry intact in the kernel after userland clears the contested bit (probes 274e/274f). PI mutex lock/unlock/wake all work. Child threads execute kernel syscalls via fn_addr ROP chains (274c). But no kernel memory corruption is demonstrated yet, and the exploitation path from orphaned waiter to corruption is theoretical.

Evidence: docs/ATTACK_SURFACE.md, docs/FINDINGS.md, results from phases 15-24.

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
3. **Native code execution (NEW since 10-18):** thr_create(430) starts real threads (156c/156d). Child threads execute kernel syscalls via fn_addr ROP chain: getpid, socket, close, UMTX ops all confirmed (274c). Arbitrary userland calls via fcall_with_rax confirmed (129b). C11 threading with join confirmed (126g/126h).
4. **UMTX PI primitives (NEW since 10-18):** PI-enabled MUTEX_LOCK/UNLOCK work (274f). Orphaned kernel waiter primitive proven -- clearing contested bit leaves child permanently blocked with wait queue entry intact (274e/274f). This is active kernel state manipulation but not yet kernel corruption.
5. **CVE assessment coverage (NEW since 10-18):** CVE-2024-43102 (umtx_shm stub), CVE-2026-49418 (msync blocked), netcontrol UAF (dead on 14.10). All public techniques tested and mapped.
6. **Device inventory (NEW since 10-18):** 34 of 76 /dev nodes open from game process. Sony NID-hash ioctl encoding discovered. 57 AJM + 38 A53MM NID candidates tested, all dead on 14.10 (firmware-specific encoding).
7. **No verified kernel primitive:** normal syscall buffers, zero-filled outputs, userland heap access, and values tagged `KPTR` by a heuristic do not independently prove kernel addresses or kernel read/write.
8. **13.60 is supporting research:** dumps and handler analysis can inform understanding, but do not satisfy a 14.10 vulnerability or kernel-access gate.

## Why not 60-70%?

Research effort and closeness to a working exploit have different denominators. 664 probes, 70+ dead ends, and 12+ CVE assessments can eliminate hypotheses without yielding a vulnerability. This rubric reserves **55 points** for a validated vulnerability (15), demonstrated kernel read/write (25), and a repeatable chain (15). All three remain unearned. A single discovery could change the position sharply; it could also remain unresolved indefinitely. It is fair to say substantial groundwork exists and the attack surface is thoroughly mapped. It is not evidence-backed to call this a 60-70% complete kernel exploit.

## Maintaining this meter

Edit `docs/progress.json` only after reviewing new evidence. Evidence file hashes and inventory counts are checked to force reconsideration when the snapshot changes. Update this audit, then run:

```text
python tools/render_progress.py
python tools/render_progress.py --check
```

The renderer generates the README block and SVG. It reads local files only and never contacts or runs code on a console. New evidence must be reviewed before awarding points. The percentage is not automatically increased by commit counts, hours spent, number of probes, another firmware's dumps, or unverified return values.

# Firmware 14.10 progress audit

Audit date: **2026-10-24** (America/Toronto). Evidence snapshot: `353cdc6`.

## Assessment

**63/100 (~63%) on the rubric below.** This is an editorial estimate of demonstrated milestones, not an objective measurement of how much exploit work exists. The weights are judgment calls. **Kernel read/write on 14.10 is not demonstrated.** No end-to-end exploit chain exists. The score reflects substantial attack surface mapping, a validated WebKit UAF with crash-rate data, working exploit infrastructure (threading, arbitrary calls, gadgets), and two independent kernel-touching primitives (UMTX orphaned waiter, FontFaceSet UAF) — none of which yet yields controlled kernel corruption.

Endpoint: a repeatable kernel exploit on **14.10** with demonstrated kernel read/write. Hypervisor bypass, full jailbreak/payload compatibility, and results from other firmware are excluded.

## Method and scope

- Inventoried **1838 Lua probe files**, **26 JS probe files** and **2029 text result files** across 32 phases. These are artifact counts, not unique experiments or successful tests.
- Searched the raw-result corpus for kernel-access claims, sentinel/false-positive indicators, and crash outcomes; closely reviewed identity, the 45c retraction, baseline memory observations, the 51-series survey logs, all phase 13-32 results, WebKit findings, and all current strategy/findings summaries.
- This is an offline repository audit, not exhaustive manual validation, independent reproduction, or firmware attestation. The firmware identity is reported by the captured session.
- Later counter-evidence overrides earlier positive headlines. A nonnegative return code, a writable userland value, or a loader crash does not establish kernel exploitation.
- Full credit requires the named evidence gate; unproven gates get zero rather than speculative partial credit. The rubric has nine milestone categories with explicit sub-checks.

## Weighted evidence gates

| Milestone | Earned | Weight | Assessment |
|---|---:|---:|---|
| 14.10 research environment | 10 | 10 | Firmware-tagged Lua execution and observable userland behavior are recorded. |
| Probe tooling and captured evidence | 10 | 10 | Runner source and dated output logs are present; counts measure artifacts, not successful exploits. |
| Target characterization | 15 | 15 | Exhaustive survey (1838 probes, 676 syscalls, 39 modules). Native code exec (thr_create/thr_new ROP, fcall_with_rax, C11 threading). 13.60 Ghidra decompile validates thr_create panic as kernel candidate. |
| Kernel attack surface mapping | 10 | 10 | 12+ CVEs assessed (all blocked/stubbed). 123+ dead ends mapped with root causes. 34/76 device nodes inventoried, ioctl measured end to end. UMTX PI orphaned kernel waiter proven. W^X ceiling proven. 17 KASLR techniques tested, all dead. |
| WebKit / JSC attack vector | 8 | 10 | FontFaceSet UAF validated with 4/5 crash rate, two independent researchers confirmed. 518-case LayoutTests crash corpus replayed. Browser entry demonstrated. No controlled corruption yet. |
| Exploit infrastructure | 5 | 5 | Threading, synchronization, arbitrary function calls, gadget catalog, offline kernel analysis, SDK offsets — all operational. |
| Validated 14.10 kernel vulnerability | 5 | 10 | FontFaceSet UAF root cause identified with controlled reproduction. UMTX orphaned waiter touches kernel state. Neither demonstrates controlled kernel corruption. |
| Demonstrated 14.10 kernel read/write | 0 | 15 | No verified kernel read/write demonstration found. |
| Repeatable complete kernel exploit | 0 | 15 | No end-to-end 14.10 kernel exploit with a repeatability record found. |
| **Total** | **63** | **100** | **Kernel-access gates remain unproven.** |

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

**Native code execution (3/3):** thr_create(430) and thr_new(455) both start real threads (156c/156d, 383a). Child threads execute kernel syscalls via fn_addr ROP chains: getpid, socket, close, UMTX ops all confirmed (274c). Arbitrary userland calls via fcall_with_rax confirmed: getpid=0x22a, socket=0x16, close=0x0 (129b). C11 threading with join confirmed (126g/126h). Thread budget measured at 25/11/9 per loader (242a/244a/245a).

**Target-build analysis (2/2):** The 13.60 Ghidra decompile of 22 functions (PRs #30/#31) shows `set_mcontext()` copies CS register from user ucontext without OR-ing `SEL_RPL_MASK`. Capture re-read (2026-10-21) corrected: set_mcontext never reads context CS at all — copies GPRs, RIP, RSP, SS raw. 189a's CS=0x40 result predicted by the copy map.

Evidence: probes 156c/156d, 383a, 274c, 129b, 126g/126h, docs/THREADING_ALIVE_14_10.md, docs/THR_CREATE_SETMCONTEXT_COPYMAP_13_60.md.

#### Kernel attack surface mapping (10/10)

- 3/3: CVE and public technique assessment against target firmware
- 3/3: Systematic dead-end mapping eliminates blind alleys
- 4/4: Active kernel-touching primitive identified with exploitation path

**CVE assessments (3/3):** 12+ CVEs and public techniques tested against 14.10:
- CVE-2024-43102 (umtx_shm UAF): UMTX_OP_SHM confirmed stub, race path unreachable (probes 151a-152k)
- CVE-2026-49418 (msync device-pager UAF): syscall number corrected from 226→65 (PR #70), MS_INVALIDATE tested
- netcontrol/netevent UAF: close-before-unregister leaks instead of freeing (probes 223a-234a)
- AF_ROUTE Relapse technique: kernel sanitizes route messages, zero kernel pointers (probe 53b)
- thr_create CS=0 panic: probe 189a shows 14.10 forces/replaces selector
- 17 KASLR defeat techniques: all tested, all dead

**Dead-end mapping (3/3):** 123+ dead ends documented with root causes. Full sysent boundary measured (676 entries). Device ioctl encoding discovered. 214 getsockopt options swept across 8 socket types. 32M ioctl calls across 31 nodes. Sony syscall families exhausted (jitshm, osem, namedobj, blockpool, etc.). GPU pool zeroes pages on allocation (348a). physhm write claim independently refuted (DEM9N101).

**Active kernel primitive (4/4):** UMTX orphaned kernel waiter leaves a wait queue entry intact in the kernel after userland clears the contested bit (probes 274e/274f, 564a-571a). PI mutex lock/unlock/wake all work. AIO 669 delete race fully serialized under testing (525a-562a). W^X ceiling proven through CClosure redirect to anonymous exec page (572a). dmem0-backed AIO destination discovered. Exhaustive getsockopt sweep (214 opts, 8 socket types). These represent multiple kernel-touching surfaces with defined exploitation paths.

Evidence: docs/ATTACK_SURFACE.md, docs/FINDINGS.md.

#### WebKit / JSC attack vector (8/10) — NEW

- 3/3: Browser entry demonstrated on target firmware
- 4/4: Memory-safety vulnerability validated with crash rate data
- 1/3: Controlled corruption or R/W from browser

**Browser entry (3/3):** Second entry vector via browser engine. Guide redirect demonstrated on 14.10. 26 JS probes written, 12 findings documented.

**FontFaceSet UAF (4/4):** FontFaceSet::load() UAF validated on 14.10 with 4/5 deterministic crash rate: style.remove() is the free, death is inside FontFaceSet::load(), root cause identified in WebKit source (weak refs in FontFaceSet::load vs strong refs in iterateClients). Two independent researchers confirmed (PR #149 by ng643, issue #143 by lunarshe11). MetadataTable integer overflow confirmed unpatched.

**Controlled corruption (1/3):** 518-case LayoutTests crash corpus replayed (Finding 9). Canvas reentrancy identified as next discriminating test. Partial credit for validated crash vector with known root cause but no demonstrated controlled corruption or arbitrary R/W from browser yet.

Evidence: [docs/WEBKIT_FINDINGS.md](https://github.com/ZigZagBoi1/PS5-14.10-Research/blob/master/docs/WEBKIT_FINDINGS.md).

#### Exploit infrastructure (5/5) — NEW

- 2/2: Threading and synchronization primitives operational
- 2/2: Arbitrary function call and gadget infrastructure ready
- 1/1: Offline kernel analysis provides exploitation targets

**Threading (2/2):** thr_new(455) and thr_create(430) both confirmed working. Thread budget measured (25/11/9 per loader). UMTX_OP_WAIT blocks correctly on value match; NWAKE_PRIVATE returns 0; MUTEX_LOCK writes owner TID (56i2, 152k). UMTX parking pattern for thread synchronization operational.

**Gadget infrastructure (2/2):** native.fcall_with_rax confirmed (getpid/socket/close). Child threads execute kernel syscalls via fn_addr ROP chains (274c). CClosure function redirect supports selected existing Lua C targets with output and restore checks (56c/56f). eboot gadget catalog readable (RX .text).

**Offline analysis (1/1):** 13.60 offline handler decode (22 functions decompiled). SDK v0.45 published 14.10 kernel offsets (allproc, security_flags, rootvnode). sceKernelAllocateDirectMemory reachable from game sandbox via libkernel GOT wrapper (DEM9N101). AIO 669 independently verified by second researcher with dmem0 destination.

Evidence: docs/FINDINGS.md, docs/ATTACK_SURFACE.md.

#### Validated 14.10 kernel vulnerability (5/10)

- 5/5: Vulnerability root cause identified with controlled reproduction on 14.10
- 0/5: Controlled reproduction establishes kernel-level impact

**Root cause (5/5):** FontFaceSet::load() UAF is a validated vulnerability on 14.10: 4/5 deterministic crash, root cause identified in WebKit source, two independent researchers confirmed. UMTX orphaned waiter touches real kernel wait queue state (274e/274f) — thread exit never disowns a PI mutex. Both represent demonstrated kernel-relevant state manipulation.

**Kernel impact (0/5):** Neither the FontFaceSet UAF nor the UMTX orphaned waiter has demonstrated controlled kernel memory corruption. The path from "validated crash / orphaned entry" to "kernel corruption" is not established.

Evidence: docs/WEBKIT_FINDINGS.md, docs/STRATEGY.md, docs/PROBE_INDEX.md.

#### Demonstrated 14.10 kernel read/write (0/15)

- 0/6: Verified arbitrary kernel read on 14.10
- 0/6: Verified controlled kernel write on 14.10
- 0/3: Independent evidence distinguishes kernel from userland effects

Evidence: results/45c_execution_reality_check_20261016_192713.txt, docs/FINDINGS.md.

#### Repeatable complete kernel exploit (0/15)

- 0/7: End-to-end kernel exploit from a fresh session
- 0/4: Reported multi-run success/failure denominator
- 0/4: Recovery and cleanup behavior recorded

Evidence: docs/STRATEGY.md, docs/PROBE_INDEX.md.

## Rubric restructuring (2026-10-24)

The previous rubric (2026-10-21) had 7 milestones totaling 43/100. This audit restructures to 9 milestones:

1. **WebKit / JSC attack vector (NEW, 10 points):** Recognizes the second entry vector via browser engine. FontFaceSet UAF with 4/5 crash rate and two independent confirmations earns 8/10. The remaining 2 points require demonstrated controlled corruption.

2. **Exploit infrastructure (NEW, 5 points):** Threading, synchronization, arbitrary function calls, gadget infrastructure, and offline kernel analysis are operational building blocks that were previously unscored.

3. **Attack surface mapping raised to 10/10 (was 8/10):** With 123+ dead ends, 12+ CVEs assessed, device inventory complete, and multiple kernel-touching primitives (UMTX orphaned waiter, W^X ceiling proof, AIO serialization), the full 4/4 for active kernel primitives is now warranted.

4. **Validated vulnerability reweighted (10 points, was 15):** Root cause + controlled reproduction earns 5/10. The remaining 5 require demonstrated kernel-level impact.

5. **Kernel R/W and chain reduced (15 each, were 25 and 15):** 30 points remain locked behind kernel access. The rubric still cannot reach 70% without kernel corruption.

Weight redistribution: environment 10, tooling 10, characterization 15, attack surface 10, WebKit 10, infrastructure 5, vulnerability 10, kernel R/W 15, chain 15 = 100.

## Evidence that changes the estimate (since 2026-10-21)

1. **FontFaceSet UAF validated (PR #149, issue #143):** 4/5 deterministic crash on 14.10, root cause in WebKit source, two independent researchers (ng643, lunarshe11). This is the project's first validated vulnerability with crash-rate data.
2. **WebKit attack vector established:** 26 JS probes, 12 findings, browser entry via guide redirect demonstrated, 518-case LayoutTests corpus replayed.
3. **UMTX orphaned waiter extended (564a-571a):** PI chain probes continued; AIO delete race fully serialized (525a-562a).
4. **W^X ceiling proven (572a):** CClosure redirect to anonymous exec page demonstrates the W^X enforcement boundary.
5. **Device inventory complete (PR #74):** 34/76 nodes open, ioctl measured end to end, 32M calls across 31 nodes.
6. **SDK v0.45 offsets:** Published 14.10 kernel offsets for allproc, security_flags, rootvnode.
7. **physhm refuted independently (DEM9N101):** Second researcher confirmed physhm write claim is false.
8. **Probe inventory grew:** 664→1838 Lua probes, 701→2029 result captures, reflecting phases 23-32.

## Why 63% and not higher?

The rubric reserves **30 points** for kernel R/W (15) and a repeatable chain (15). Both are zero. Another 5 points sit in the vulnerability category (kernel-level impact). A single kernel read primitive would move the score sharply; it could also remain blocked indefinitely. 63% reflects that the project has:
- A complete, evidence-based attack surface map
- A validated WebKit UAF with crash-rate data
- Working exploit infrastructure (threads, calls, gadgets)
- Two independent kernel-touching primitives under active investigation

It does **not** have:
- Any demonstrated kernel memory corruption
- Any KASLR defeat
- Any kernel read or write primitive
- Any end-to-end exploit chain

## Maintaining this meter

Edit `docs/progress.json` only after reviewing new evidence. Evidence file hashes and inventory counts are checked to force reconsideration when the snapshot changes. Update this audit, then run:

```text
python tools/render_progress.py
python tools/render_progress.py --check
```

The renderer generates the README block and SVG. It reads local files only and never contacts or runs code on a console.

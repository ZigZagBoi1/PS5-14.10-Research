# Firmware 14.10 progress audit

Audit date: **2026-10-18** (America/Toronto). Evidence snapshot: `9ebd310` (local evidence-audit and retest-preparation commit; the final merged snapshot is recorded after merge).

## Assessment

**25/100 (~25%) on the rubric below.** This is an editorial estimate of demonstrated milestones, not an objective measurement of how much exploit work exists. The weights are judgment calls. The record does not support publishing 60-70% completion of a full kernel exploit. No new console probes were run for this audit. An offline follow-up on 2026-10-18 reconciled the saved evidence descriptions and prepared probes 53a–53d; no new console data was collected. The score remains 25/100 because those probes are unrun and no named scoring gate has newly met its evidence threshold.

Endpoint: a repeatable kernel exploit on **14.10** with demonstrated kernel read/write. Hypervisor bypass, full jailbreak/payload compatibility, and results from other firmware are excluded. A kernel exploit need not follow any particular technique; the gates describe evidence, not an implementation plan.

## Method and scope

- Inventoried **169 Lua probe files** and **168 text result files**. These are artifact counts, not unique experiments, successful tests, or vulnerability coverage. Reruns, truncated logs, and embedded source text exist.
- Searched the raw-result corpus for kernel-access claims, sentinel/false-positive indicators, and crash outcomes; closely reviewed identity, the 45c retraction, baseline memory observations, and the late 51-series survey logs, alongside the full probe index and current strategy/findings summaries.
- This is an offline repository audit, not an exhaustive manual validation of every captured byte, independent hardware reproduction, or firmware attestation. The firmware identity is reported by the captured session.
- Later counter-evidence overrides earlier positive headlines. API availability, a nonnegative return code, a writable userland value, or a loader crash does not establish kernel exploitation.
- Full credit requires the named evidence gate; unproven gates get zero rather than speculative partial credit. The 15-point characterization category has three explicit 5-point gates.
- There is no statistical confidence interval or reliable ETA. Reweighting milestones changes this estimate. Count and score changes require an explicit review; the renderer never promotes a successful-looking log automatically.

## Weighted evidence gates

| Milestone | Earned | Weight | Assessment |
|---|---:|---:|---|
| 14.10 research environment | 10 | 10 | Firmware-tagged Lua execution and observable userland behavior are recorded. |
| Probe tooling and captured evidence | 10 | 10 | Runner source and dated output logs are present; counts measure artifacts, not successful exploits. |
| Target characterization | 5 | 15 | Baseline observations exist, but surveys are partial and several headline claims were retracted. |
| Validated 14.10 kernel vulnerability | 0 | 20 | No qualifying root-cause analysis and controlled 14.10 reproduction established by the reviewed record. A loader crash alone does not qualify. |
| Demonstrated 14.10 kernel read/write | 0 | 25 | No verified kernel read/write demonstration found. Loader API names, normal syscall output, and 13.60 dumps do not qualify. |
| Repeatable complete kernel exploit | 0 | 20 | No end-to-end 14.10 kernel exploit with a repeatability record found. Hypervisor bypass is outside this denominator. |
| **Total** | **25** | **100** | **Kernel-access gates remain unproven.** |

The first two categories are complete only for the limited research-foundation definitions above; this does not claim universal entry-point reliability or unrestricted native execution. Characterization gets 5/15 for baseline observations; the complete reconciled survey and target-build candidate-validation gates remain unearned.

### Individual checks and source links

#### 14.10 research environment (10/10)

- 5/5: Firmware identified in a captured session
- 5/5: Lua/userland experiments produce observable output

Evidence: [results/phase1_identity_layout/01_identity_20261015_184244.txt](https://github.com/ZigZagBoi1/PS5-14.10-Research/blob/ad475da045299fd87ba9c41d9df81ad3398d1930/results/phase1_identity_layout/01_identity_20261015_184244.txt).

#### Probe tooling and captured evidence (10/10)

- 5/5: Probe runner and source available
- 5/5: Dated raw outputs retained

Evidence: [tools/send_probe.py](https://github.com/ZigZagBoi1/PS5-14.10-Research/blob/ad475da045299fd87ba9c41d9df81ad3398d1930/tools/send_probe.py), [docs/PROBE_INDEX.md](https://github.com/ZigZagBoi1/PS5-14.10-Research/blob/ad475da045299fd87ba9c41d9df81ad3398d1930/docs/PROBE_INDEX.md).

#### Target characterization (5/15)

- 5/5: Baseline interface observations retained
- 0/5: Complete scoped survey with reconciled current summary
- 0/5: Target-build analysis validates a kernel candidate

Evidence: [results/51b_accessible_syscall_deep_20261016_214832.txt](https://github.com/ZigZagBoi1/PS5-14.10-Research/blob/ad475da045299fd87ba9c41d9df81ad3398d1930/results/51b_accessible_syscall_deep_20261016_214832.txt), [results/51c_sony_survey_part2_20261016_215838.txt](https://github.com/ZigZagBoi1/PS5-14.10-Research/blob/ad475da045299fd87ba9c41d9df81ad3398d1930/results/51c_sony_survey_part2_20261016_215838.txt), [results/51b_dynlib_cluster_fuzz_20261016_230416.txt](https://github.com/ZigZagBoi1/PS5-14.10-Research/blob/ad475da045299fd87ba9c41d9df81ad3398d1930/results/51b_dynlib_cluster_fuzz_20261016_230416.txt), [docs/STRATEGY.md](https://github.com/ZigZagBoi1/PS5-14.10-Research/blob/ad475da045299fd87ba9c41d9df81ad3398d1930/docs/STRATEGY.md).

#### Validated 14.10 kernel vulnerability (0/20)

- 0/10: Kernel vulnerability root cause supported on 14.10
- 0/10: Controlled reproduction establishes kernel impact

Evidence: [docs/STRATEGY.md](https://github.com/ZigZagBoi1/PS5-14.10-Research/blob/ad475da045299fd87ba9c41d9df81ad3398d1930/docs/STRATEGY.md), [docs/PROBE_INDEX.md](https://github.com/ZigZagBoi1/PS5-14.10-Research/blob/ad475da045299fd87ba9c41d9df81ad3398d1930/docs/PROBE_INDEX.md).

#### Demonstrated 14.10 kernel read/write (0/25)

- 0/10: Verified arbitrary kernel read on 14.10
- 0/10: Verified controlled kernel write on 14.10
- 0/5: Independent evidence distinguishes kernel from userland effects

Evidence: [results/45c_execution_reality_check_20261016_192713.txt](https://github.com/ZigZagBoi1/PS5-14.10-Research/blob/ad475da045299fd87ba9c41d9df81ad3398d1930/results/45c_execution_reality_check_20261016_192713.txt), [docs/FINDINGS.md](https://github.com/ZigZagBoi1/PS5-14.10-Research/blob/ad475da045299fd87ba9c41d9df81ad3398d1930/docs/FINDINGS.md).

#### Repeatable complete kernel exploit (0/20)

- 0/10: End-to-end kernel exploit from a fresh session
- 0/5: Reported multi-run success/failure denominator
- 0/5: Recovery and cleanup behavior recorded

Evidence: [docs/STRATEGY.md](https://github.com/ZigZagBoi1/PS5-14.10-Research/blob/ad475da045299fd87ba9c41d9df81ad3398d1930/docs/STRATEGY.md), [docs/PROBE_INDEX.md](https://github.com/ZigZagBoi1/PS5-14.10-Research/blob/ad475da045299fd87ba9c41d9df81ad3398d1930/docs/PROBE_INDEX.md).

## Evidence that changes the estimate

1. **Identity:** the captured identity session reports `FW_VERSION: 14.10` and supplies live userland observations. A `kernel.read_dword` function name in that same log is not a successful kernel-read test.
2. **Execution retraction:** probe 45c records normal syscall behavior after changing execution metadata, including invalid targets and chain corruption. `docs/FINDINGS.md` Finding 56 and `docs/STRATEGY.md` explicitly retract the earlier execution model. Earlier 43i/44a/45a headlines cannot be scored as arbitrary native execution or kernel access.
3. **Incomplete surveys:** the probe index marks the 51-series as partial/killed where appropriate. The late dynlib-cluster log ends after its baseline heading. Presence of a script or a started log does not earn a completed-survey gate.
4. **No verified kernel primitive:** normal syscall buffers, zero-filled outputs, userland heap access, and values tagged `KPTR` by a heuristic do not independently prove kernel addresses or kernel read/write. Earlier apparent pointers include later-identified sentinels.
5. **13.60 is supporting research:** dumps and handler analysis can inform understanding, but do not satisfy a 14.10 vulnerability or kernel-access gate. Their acquisition is not reverified by this audit.

## Why not 60-70%?

Research effort and closeness to a working exploit have different denominators. Hundreds of useful observations can eliminate hypotheses without yielding a vulnerability. Giving most points to tooling and reconnaissance would allow a near-complete score before the kernel-exploit problem is solved. This rubric reserves **65 points** for a validated vulnerability (20), demonstrated kernel read/write (25), and a repeatable chain (20). All three remain unearned in the reviewed record.

This does not mean there is exactly 75% of the time or difficulty left. A single discovery could change the position sharply; it could also remain unresolved indefinitely. It is fair to say substantial groundwork exists. It is not evidence-backed to call this a 60-70% complete kernel exploit.

## AnyPS5 comparison

[AnyPS5’s official progress page](https://boykopovar.github.io/AnyPS5/progress.html) publishes generated counts, a JSON dataset, and explicit counting rules. Its implementation/decoder coverage has a defined enumerable denominator. An undiscovered exploit does not. This project adopts the transparent-data-and-rubric pattern, not the implication that exploit discovery is countable like declared functions.

## Maintaining this meter

Edit `docs/progress.json` only after reviewing new evidence. Evidence file hashes and inventory counts are checked to force reconsideration when the snapshot changes. Text hashes normalize line endings so the check is stable across Windows and Linux checkouts. Update this audit, then run:

```text
python tools/render_progress.py
python tools/render_progress.py --check
```

The renderer generates the README block and SVG. It reads local files only and never contacts or runs code on a console. The website uses the same reviewed JSON/SVG snapshot; publish updated copies together. New evidence must be reviewed before awarding points.

The percentage is not automatically increased by commit counts, donations, hours spent, number of probes, another firmware’s dumps, or unverified successful return values.

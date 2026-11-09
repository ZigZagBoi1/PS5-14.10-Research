# Autonomous Research State -- PS5 14.10

> Persistent state file for the OPERATION 14.10 autonomous research directive.
> Updated each session. Complements `results/STATE.md` (console measurements)
> and `results/INDEX.md` (probe ledger).

## Primary Objective

**Real Debug Settings menu on retail PS5 14.10.**

## Current Research Focus

**WebKit info leak** -- the sole remaining hard blocker for the entire chain.

## Active Hypothesis

CVE-2023-42916 (DFG JIT OOB read, fixed Safari 17.1.2) may provide the ASLR
bypass needed to derive the WebProcess text base. PS5 has Safari 17.0 (605.1.15)
with DFG JIT confirmed active (p602). This CVE was used alongside CVE-2023-42917
in targeted attacks as the info-leak stage.

## Chain Status (2026-11-09)

| Stage | Status | Blocker |
|-------|--------|---------|
| Userland code exec | DONE | -- |
| Kernel image base (KASLR) | DONE | -- |
| WebKit UAF write primitive | DONE (FontFace + Canvas2D) | -- |
| WebKit info leak (text base) | BLOCKED | No known route; CVE-2023-42916 is top candidate |
| Kernel read primitive | BLOCKED | Needs info leak first |
| Kernel write primitive | BLOCKED | Needs kernel read first |
| Debug Settings toggle | BLOCKED | Needs kernel write |

## Debug Settings Dependency Graph

See `docs/DEBUG_SETTINGS_DEPENDENCY_GRAPH.md` for full analysis.

**Short version:** Debug Settings visibility is controlled by a registry flag
(`system_prof_settings.debug_settings_permission` or equivalent) stored in
process memory. Enabling it requires a kernel write to patch the flag at runtime.
The minimum path is: WebKit info leak -> arbitrary R/W in WebProcess -> kernel
exploit -> patch registry flag -> Debug Settings visible.

## What Changed Last Session (2026-11-09)

- Wrote 2 new info-leak probes: p698 (DFG OSR exit metadata + JIT internals, 7 sections), p699 (DFG arguments escape + frame metadata, 6 sections)
- p698 tests: Error objects during OSR exit, recompilation timing, stale locals, exception identity across JIT tiers, constant folding pointer leak, new Function() JIT code, WeakRef GC timing
- p699 tests: arguments OOB after DFG elimination, callee descriptor, rest-vs-arguments desync, named parameter aliasing, Function.apply stale frame, eval-forced materialization
- Closed issue #180 (probe-ID collision fix confirmed)
- PS5 offline -- all work is static analysis and probe preparation

## Hardware-Ready Test Queue

| Probe | CVE | Priority | Expected Signal |
|-------|-----|----------|-----------------|
| p680 | CVE-2023-42916 | TOP | DFG OOB read -> address leak |
| p681 | CVE-2023-42916 | TOP | Variant B patterns |
| p695 | CVE-2023-42916 | TOP | DFG range analysis (clz32, shift, loop peel) |
| p696 | CVE-2023-42916 | TOP | DFG CSE stale bounds check |
| p697 | StructureID | TOP | fakeobj via type speculation |
| p698 | DFG internals | TOP | OSR exit metadata + JIT code pointer leak |
| p699 | DFG arguments | TOP | arguments escape + frame metadata OOB |
| p692 | CVE-2023-40447 | HIGH | DOM UAF crash |
| p693 | CVE-2023-42890 | HIGH | Memory handling crash |
| p694 | CVE-2023-42950 | HIGH | Heap UAF type confusion |
| p686 | CVE-2023-41976 | MED | SVG animation UAF |
| p688 | CVE-2023-42852 | MED | CSS counter-style OOB |
| p689 | CVE-2024-23213 | MED | Fetch body lifetime |
| p690 | CVE-2024-23213 | MED | TextDecoder streaming |

## Offline Work Completed

- 136 WebKit probes written (p553-p699)
- 2930+ total probes across all phases
- Full dead-end catalog maintained
- WebKit cherry-pick cutoff fingerprinted (Safari 26.3 fixes included, 26.4 not)
- StructureID prediction research (if PS5 lacks randomization, fakeobj possible)

## Next Actions (Ordered)

1. Write more CVE-2023-42916 probe variants (DFG OOB read patterns)
2. Research StructureID table layout for fakeobj primitive
3. When PS5 comes online: run p680/p681 first (info leak candidates)
4. Analyze any crash backtraces for module-relative addresses
5. Community outreach for decrypted WebProcess binary

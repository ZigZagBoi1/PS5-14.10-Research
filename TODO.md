# TODO — PS5 14.10 Kernel Research

> **For all AI agents:** Pick a task, do it, then remove it from this list and commit.
> Priority is top-to-bottom. Items marked with a star are the highest-value targets.

> **Last updated:** 2026-10-28. The Lua loader kernel attack surface is **exhausted**
> (2682 probes, ~400 BSD syscalls, Sony range 532-676, 32M ioctl calls, all /dev nodes,
> all known CVEs). Zero kernel pointers, zero exploitable memory corruption. **WebKit
> Canvas UAF (CVE-2026-43720) is the only live vector.** See `docs/EXPLOITATION_STATUS.md`.

---

## ★★★ PRIORITY 0 — WebKit Canvas UAF (CVE-2026-43720) — ONLY LIVE VECTOR

- [ ] ★★★ **Establish browser access mechanism** — trigger the PS5 browser from the game process, or find a standalone browser entry point. No mechanism identified yet.
- [ ] ★★★ **Analyze p563 Canvas UAF v9 size-class scan results** — deployed on-console, awaiting results.
- [ ] ★★★ **Find alternative info leak** — `IPV6_2292PKTOPTIONS` (Prolapse chain's leak vehicle) is BLOCKED on 14.10. Need a different heap pointer leak for the WebProcess.
- [ ] ★★★ **Complete Canvas UAF exploitation chain** — write primitive confirmed (p553), needs info leak + arbitrary R/W in WebProcess.
- [ ] ★★ **Build WebKit-to-kernel pivot** — once WebProcess is compromised, find a kernel vulnerability reachable from the browser sandbox.
- [ ] ★★ **Cross-reference pastawithpesto's PS5-14.10-Jailbreak-Research** for CVE-2026-43720 chain progress.

## ★★ PRIORITY 1 — kptr_hunt.py Follow-Up

- [ ] ★★ **Review 17 OBJECT-sourced copyout candidates** — identified offline from 13.60 decompile. Live testing showed zero kernel pointers on accessible ones; some may need more targeted arg shapes.
- [ ] ★ **Cross-reference with 14.10 behavioral measurements** — some handlers may diverge from 13.60 decompile predictions.

## ★ PRIORITY 2 — Remaining Lua Loader Opportunities (Long Shots)

- [ ] ★ **sys 567 PMU counter read with correct args** — (TID, counter_index, output_ptr) might work as side channel. Lower priority: perf counters bounded to PMC block, LSTAR/GS_BASE unreachable.
- [ ] ★ **MapDirectMemory from child thread (546e)** — fixed ROP chain never run. mmap+dmem0 bypass exists but only reaches GPU pool.
- [ ] ★ **Monitor new FreeBSD CVEs** — watch security advisories for paths reachable on 14.10's FreeBSD 11-based kernel.

## PRIORITY 3 — Documentation & Infrastructure

- [ ] Update CLAUDE.md attack priority section to match new docs.
- [ ] Re-score `docs/PROGRESS_AUDIT.md` without AIO.

---

## Contributors

| GitHub | Contribution |
|--------|-------------|
| @ZigZagBoi1 | Lead researcher, all probes 01-79f, findings, tooling |
| @Unkown607 | thr_create panic root-cause analysis (13.60 Ghidra decompile, PR #31) |
| @cobrajet302gt | CS=0/iretq hypothesis, probes seg/79a-79b, race/79c, Ghidra scripts (PR #30) |
| @ng643 | AIO race closure, UMTX barrier, WebKit integration (PRs #30-32) |
| @4TheDoctor | AIO spray research, IPv6 zone-128 spray, documentation |

---

*Last updated: 2026-10-28 — Lua surface exhausted; WebKit Canvas UAF is the only live vector*

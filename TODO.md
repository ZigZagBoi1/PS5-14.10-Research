# TODO — PS5 14.10 Kernel Research

> **For all AI agents:** Pick a task, do it, then remove it from this list and commit.
> Priority is top-to-bottom. Items marked with a star are the highest-value targets.

> **Last updated:** 2026-11-03. The Lua loader kernel attack surface is **exhausted**
> (2682 probes, ~400 BSD syscalls, Sony range 532-676, 32M ioctl calls, all /dev nodes,
> all known CVEs). Zero kernel pointers, zero exploitable memory corruption. **WebKit
> is the only live vector.** The p563 v9 size-class scan is analyzed
> (`docs/WEBKIT_CROSSREF_2026-11-03.md`): the 160B crash is a candidate, not a
> measurement; upstream's measured freed-context size is **768B**. The 17 kptr_hunt
> copyout candidates are reviewed and closed (`docs/KPTR_HUNT_COPYOUT_REVIEW_14_10.md`).
> Cross-reference with pastawithpesto recorded in the same document — their V674 APNG
> ASLR-defeat is CONFIRMED upstream but **unreplicated here** (our local v674 run used a
> reconstructed probe and leaked zero). See `docs/EXPLOITATION_STATUS.md`.

---

## ★★★ PRIORITY 0 — WebKit — ONLY LIVE VECTOR

- [ ] ★★★ **Establish browser access mechanism** — trigger the PS5 browser from the game process, or find a standalone browser entry point. No mechanism identified yet.
- [ ] ★★★ **Re-run upstream's verbatim V674 APNG overread probe** — pastawithpesto reports CONFIRMED (1651 heap pointers); our local run used a reconstructed probe and found zero. Pull their `tools/v674.html` unchanged and test before treating the technique as dead or confirmed here.
- [ ] ★★★ **Find alternative info leak** — `IPV6_2292PKTOPTIONS` (Prolapse chain's leak vehicle) is BLOCKED on 14.10. Upstream's crash oracle (forged `m_stateStack`) is a candidate vehicle; the FontFace lane already leaks two live heap pointers (+0x58/+0x68). Note the DAZ law: read pointer-sized values via BigUint64Array, never float64.
- [ ] ★★★ **Complete Canvas UAF exploitation chain** — same-type alias R/W confirmed (p553); upstream's lineDash Vector forge design is the arbitrary R/W step; live vtable offset on 14.10 remains unknown.
- [ ] ★★ **Build WebKit-to-kernel pivot** — once WebProcess is compromised, find a kernel vulnerability reachable from the browser sandbox.

## ★ PRIORITY 2 — Remaining Lua Loader Opportunities (Long Shots)

- [ ] ★ **sys 567 PMU counter read with correct args** — (TID, counter_index, output_ptr) might work as side channel. Lower priority: perf counters bounded to PMC block, LSTAR/GS_BASE unreachable.
- [ ] ★ **MapDirectMemory from child thread (546e)** — fixed ROP chain never run. mmap+dmem0 bypass exists but only reaches GPU pool.
- [ ] ★ **Monitor new FreeBSD CVEs** — watch security advisories for paths reachable on 14.10's FreeBSD 11-based kernel.

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

*Last updated: 2026-11-03 — v9 scan analyzed, kptr_hunt candidates closed, upstream cross-referenced; V674 replication is the top new console task*

# TODO — PS5 14.10 Kernel Research

> **For all AI agents:** Pick a task, do it, then remove it from this list and commit.
> Priority is top-to-bottom. Items marked with a star are the highest-value targets.

> **Last updated:** 2026-10-28. The Lua loader kernel attack surface is **exhausted**
> (2682 probes, ~400 BSD syscalls, Sony range 532-676, 32M ioctl calls, all /dev nodes,
> all known CVEs). Zero kernel pointers, zero exploitable memory corruption. **WebKit
> Canvas UAF (CVE-2026-43720) is the only live vector.** See `docs/EXPLOITATION_STATUS.md`.

---

## ★★★ PRIORITY 0 — WebKit Info Leak (SOLE REMAINING BLOCKER)

Canvas UAF write primitive confirmed (p553). FontFace reclaim disclosure confirmed (p563/p564). The gap is **self-address**: FontFace gives engine heap pointers, not the address of our own buffers. See `docs/WEBKIT_INFO_LEAK_STRATEGY.md`.

- [x] ~~**Run probe 57a** (`native_survey_677_734`)~~ — closed: 677-734 are outside the 14.10 dispatch table (measured absent with SIG_IGN, `results/phase17_new_vectors/1248a*`).
- [ ] ★★★ **P567: WebKit feature detection** — determine if BigUint64Array, WebAssembly, SharedArrayBuffer, OffscreenCanvas, Workers available. BigUint64Array/Wasm i64 would bypass DAZ for pointer reads. Ready: `probes/phase23_info_leak/p567_feature_detect.js`.
- [ ] ★★★ **P568: 768B ArrayBuffer reclaim** — spray 768-byte ArrayBuffers to reclaim freed Canvas2D context, read raw bytes via DataView/BigUint64Array (integer path bypasses DAZ). Ready: `probes/phase23_info_leak/p568_arraybuffer_768_reclaim.js`.
- [ ] ★★★ **P569: FontFace + Canvas UAF combo** — combine FontFace heap disclosure with Canvas UAF R/W in one page. If both land in same bmalloc region, compute relative offsets to solve self-address gap. Ready: `probes/phase23_info_leak/p569_fontface_canvas_combo.js`.
- [ ] ★★★ **P565: FontFace self-address probe** — groom heap with 192B buffers, trigger FontFace reclaim, measure distance from leaked engine pointer to groomed buffers. If predictable, self-address is derivable.
- [ ] ★★★ **P566: Canvas2D 768B layout mapping** — write sentinels to all 13 numeric fields, probe pixel-backing aliasing through stale wrapper. Check if stale getImageData reads struct bytes rather than pixel data.
- [ ] ★★★ **Investigate pastawithpesto's APNG ASLR defeat** — their stages 5/8 confirm APNG-based ASLR defeat, but V674/V674b could not replicate. Hypothesis: APNG + Canvas UAF combo (decoder writes into UAFed context).
- [ ] ★★ **APNG malformed decoder probe** — craft APNG with truncated IDAT mid-row, missing CRC, missing IEND. V674b may have tested conforming truncation only.
- [ ] ★★ **OffscreenCanvas readback** — Workers + Canvas 2D confirmed available, but OffscreenCanvas never tested. May have different zero-init behavior.
- [ ] ★★ **FontFace controlled dereference** — p564 showed engine accepts template at +0x58/+0x68 (dereferenced). Redirect to fake WeakHashSet → potential arbitrary read.
- [ ] ★★ **Build WebKit-to-kernel pivot** — once WebProcess is compromised, find a kernel vulnerability reachable from the browser sandbox.
- [ ] ★ **Cross-reference pastawithpesto's PS5-14.10-Jailbreak-Research** for CVE-2026-43720 chain progress and vtable offset issue (#47).

## ★★ PRIORITY 1 — Syscall Errno Capture + Deep Probes

- [ ] ★★ **572a: Errno capture probe** — captures SCE error codes (1=gate, 3=handle, 0x16=size) from all -1 returns. Tests sys 572 deep with zeroed buffers (571a sentinel may have masked writes). Covers 591/599/656/660/572. Ready to run: `probes/phase23_info_leak/572a_errno_deep.lua`.
- [ ] ★ **sys 572 VM info** — returns 0 for 3 shapes but zero data output. 572a tests different sizes, cmds 0-15, and byte-level sentinel patterns.
- [ ] ★ **Review 17 OBJECT-sourced copyout candidates** — from 13.60 decompile. Most accessible ones showed zero kernel pointers; errno capture may reveal which gate blocks each.

## ★ PRIORITY 2 — Remaining Lua Loader Opportunities (Long Shots)

- [ ] ★ **sys 567 PMU counter read with correct args** — (TID, counter_index, output_ptr) might work as side channel. Lower priority: perf counters bounded to PMC block, LSTAR/GS_BASE unreachable.
- [ ] ★ **MapDirectMemory from child thread (546e)** — fixed ROP chain never run. mmap+dmem0 bypass exists but only reaches GPU pool.
- [ ] ★ **Monitor new FreeBSD CVEs** — watch security advisories for paths reachable on 14.10's FreeBSD 11-based kernel.

## PRIORITY 3 — Documentation & Infrastructure

- [x] Update CLAUDE.md attack priority section to match new docs.
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

*Last updated: 2026-10-31 — Lua surface exhausted; WebKit info leak is the sole remaining blocker (Canvas UAF R/W + FontFace disclosure both confirmed)*

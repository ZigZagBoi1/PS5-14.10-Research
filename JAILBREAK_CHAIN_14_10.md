# PS5 14.10 jailbreak chain: evidence gates

Last updated: 2026-10-22. This is a working map, not an exploit claim.

## Goal and gates

| Gate | Required result | Current state |
|---|---|---|
| 0. Userland entry | Repeatable code execution in the game process | **Proven:** Lua loader on TCP 9026, when its worker answers |
| 1. Kernel bug | A reachable kernel handler with a reproducible security defect | **Open.** `netcontrol` shows socket-lifetime behavior, not memory corruption |
| 2. Exploitation primitive | Controlled kernel information disclosure, out-of-bounds access, use-after-free, or equivalent | **Open.** A crash or `-1` return is insufficient |
| 3. Address knowledge | A kernel pointer/slide, or an exploit that does not require one | **Open.** Tested leak routes failed; KASLR is not proven impossible |
| 4. Kernel read/write | Demonstrated read and write to selected kernel addresses | **Open** |
| 5. Persistent privilege/policy effect | Demonstrated controlled permission change and recovery-safe validation | **Open** |
| 6. Full jailbreak | User-requested capability across the required kernel/hypervisor barriers | **Open**; define the exact feature set only after gates 1–5 |

The order of gates 2 and 3 may swap. A memory-corruption bug can yield the first pointer leak. Userland heap R/W, SROP syscall invocation, and CClosure redirection do not by themselves satisfy either gate.

## Current first test

The current gate-1 candidate is `probes/phase11_network_attacks/50f_ipv6_msfilter_aligned.lua`, extended by `50g_ipv6_msfilter_source_sizes.lua`. They check whether Sony's 14.10 IPv6 multicast filter behaves like the handler implicated in [FreeBSD-SA-26:29](https://lists.freebsd.org/archives/freebsd-security/2026-June/000486.html). The 2026-10-22 captures show valid source-list calls up to 128 entries (16 KiB) returning `0`; 256 entries and malformed mode/size/family return `-1`. This establishes reachability through a sizable source-list copy path, not vulnerable lock ordering or a use-after-free. FreeBSD's advisory remains a lead, not evidence that Sony carries the bug.

Probe 50h then proved a child thread can issue that filter request successfully. The first child result of `-1` was an incorrect R10 context offset, fixed from `0x90` to `0x98`; the corrected child returned `0` and exited cleanly. Probe 50i ran 16 filter/leave pairs, all successful. Probe 50k used a socketpair read gate so the child waited for parent release; 16 released filter/leave pairs also succeeded. These results establish working concurrency controls but do not show the leave happened inside the kernel's source-list copy window. Probe 50j's mutex gate failed its own control and is inconclusive. See `docs/CVE-2026-49412-PS5-14.10.md` and the saved captures.

Probes 50l/50m established filter-first and leave-first controls on independently gated children. Probe 50p recorded concurrent progress, but its child ROP chain failed to restore syscall argument registers. The `50q` census found only 1 success in 4,096 child filter calls, and the no-parent `50t` control reproduced that distribution. The corrected `50v` control restored RDI, RSI, RDX, RCX, and R8 and got 16/16 successes. The corrected `50w` race recorded 173 accepted and 1,875 rejected child filter calls alongside 2,048 successful parent leave/rejoin pairs; the process remained alive. Matched no-parent `50x` recorded 2,048/2,048 accepted child calls, so the rejected `50w` calls require concurrent membership changes in these controls. This proves concurrent valid calls are possible, but does not prove a particular leave intersected a vulnerable lock-drop window or produce a kernel primitive. Continue with kernel-side ordering evidence or a discriminating corruption/leak signal before promoting this candidate.

The first 50e send connected but timed out with zero output while the loader canary was false. Once the loader answered, 50e completed with all filter calls rejected; its structure was four bytes short and misaligned. Corrected 50f capture: `results/phase11_network_attacks/50f_ipv6_msfilter_aligned_20261022_183727.txt` and matching JSON metadata.

## Operational recovery

1. Compare the handler and locking behavior against the available 13.60 kernel capture, clearly separating that firmware's static evidence from 14.10 runtime evidence.
2. If the vulnerable lock-drop pattern is plausible, build a bounded two-thread test with explicit success/failure controls and stop at the first discriminating result.
3. Require a demonstrated kernel primitive before treating the path as an exploit chain.

Remote Play status: the Chiaki window showed the loader screen, but the computer-use MCP timed out twice while capturing its window on 2026-10-22. Its recovery procedure says to stop UI input after that failure. A previous keyboard helper reached Windows instead of the PS5; do not reuse it without a verified target window.

## Publication rule

- Candidate kernel findings and any working primitive stay in the **private staging** remote until the evidence and disclosure decision are settled.
- A dead end goes to the public remote only when the tested claim is narrow, repeatable, and contains no unpublished exploit component or private data. Do not publish a merely unsuccessful probe as proof that an entire subsystem is safe.
- No new kernel finding has been established in this pass, so there is nothing to push to either remote now.

## Known note correction

`docs/AUTONOMOUS_SESSION_ANALYSIS_20261022.md` describes a prepared POSIX-shm largepage race probe numbered 148a, but no such probe is present in the checkout; the existing 148a is a socket-option race. `probes/phase15_native_sysent/58d_shm_sendfile_reachability.lua` also treats `SHM_LARGEPAGE` as an ordinary `shm_open` flag, whereas FreeBSD's documented interface uses largepage object configuration through `FIOSSHMLPGCNF`/`shm_open2`. Treat this path as unverified reachability.

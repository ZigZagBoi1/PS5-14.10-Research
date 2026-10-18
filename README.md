# PS5 Firmware 14.10 - Kernel Research

Open community kernel exploit research on PlayStation 5 firmware **14.10**, conducted via a userland Lua 5.1 loader on TCP 9026.

> **Goal:** Establish a reproducible 14.10 kernel primitive, then assess whether it can support kernel R/W and hypervisor research. None of those kernel-side stages is currently demonstrated.

**Contributors welcome.** Whether you have the hardware or just want to analyze FreeBSD kernel code - there’s work to do. See [CONTRIBUTING.md](CONTRIBUTING.md) to get involved.

## Support This Research

> **Hardware status:** The V13.60 research console has been acquired and produced the range-based captures documented in the companion repository. Those files are not complete kernel sections, and no verified 14.10 kernel image is available here.

**Recorded funding target: $250 CAD (funded).**

**Recorded funding progress: $369.26 / $250 CAD (funded).** Funding totals are separate from the evidence-weighted research progress below.

[![Donate via PayPal](https://img.shields.io/badge/Donate-PayPal-blue?logo=paypal)](https://www.paypal.me/SalwanStudios)

Every dollar helps, but no pressure — this research stays open and free regardless.

## Exploit Chain Overview

```mermaid
graph LR
    A["Hamidashi Creative<br/>(Artemis Engine)"] -->|modified save file| B["Lua 5.1 Loader<br/>TCP 9026"]
    B -->|memory.* / syscall.*| C["Confirmed userland behavior<br/>Heap R/W, module info,<br/>syscall wrapper"]
    C -->|tested syscall numbers| D["Individual syscall observations<br/>results vary by call and arguments"]
    D -->|"No kernel primitive established"| E["KASLR / kernel R/W<br/>not demonstrated"]
    E -->|requires separate evidence| F["Hypervisor research<br/>not demonstrated on 14.10"]

    style A fill:#2d5016,stroke:#4a8c2a,color:#fff
    style B fill:#2d5016,stroke:#4a8c2a,color:#fff
    style C fill:#2d5016,stroke:#4a8c2a,color:#fff
    style D fill:#6b4c00,stroke:#b8860b,color:#fff
    style E fill:#8b0000,stroke:#cd5c5c,color:#fff
    style F fill:#8b0000,stroke:#cd5c5c,color:#fff
```

> Green = confirmed working. Yellow = partially open. Red = not yet achieved.

## Status

Confirmed userland capabilities include Lua execution, heap access, module-base discovery, and tested syscall invocation through `make_syscall()`. Probe 45c showed that `make_syscall()` bypasses the loader's ROP chain; writable ROP metadata does not establish native code execution. Probes 43a–43p have already been sent. The 2026-10-17 evidence audit found that several follow-up claims were inconclusive; probes 53a–53d are prepared for controlled retests.

**Current milestone:** Establish a reproducible kernel primitive on 14.10. The prepared 53a–53d tests revisit specific incomplete observations; passing one test would still require independent validation before claiming a disclosure or exploit.

Research progress is tracked by evidence-backed milestones rather than a single completion percentage: userland behavior has been extensively probed; four evidence-audit retests are prepared but not run; kernel disclosure, KASLR defeat, kernel read/write, native code execution, and hypervisor bypass remain unestablished. A verified 14.10 kernel-code artifact is also unavailable, so a direct handler diff is not currently supported.

See [CHANGELOG.md](CHANGELOG.md) for a detailed timeline.

## Related V13.60 Research

The companion [PS5 V13.60 Research](https://github.com/ZigZagBoi1/PS5-V13.60-Research) repository maintains the firmware 13.60 Relapse and Byepervisor-Reborn research, its local browser site, and observed stage evidence. This V14.10 project retains `docs/ps5_13.60_sysent.json` for existing strategy and probe tooling; the source copy and attribution are maintained in the companion repository. Relapse's 13.60 support does not imply support on 14.10.

## Architecture

```mermaid
graph TD
    subgraph Userland ["Userland (Game Process)"]
        LUA["Lua 5.1 Script<br/>(our probes)"]
        RESOLVE["syscall.resolve()<br/>FILTERED - blocks many syscalls"]
        MAKESYS["make_syscall(N)<br/>bypasses Lua resolver filter;<br/>kernel restrictions still apply"]
        HEAP["GPU mmap Heap<br/>256+ pages R/W"]
        ROP["Writable ROP metadata<br/>not used by make_syscall"]
        ASLR["dynlib_get_info<br/>39 module bases leaked"]
    end

    subgraph Kernel ["FreeBSD Kernel"]
        SYSCALL["Syscall Handler"]
        SYSCTL["sysctl (202)"]
        ROUTE["AF_ROUTE socket"]
        AIO["AIO subsystem"]
        NET["Network Stack<br/>ip_input / tcp_input"]
        KOBJ["Kernel Objects<br/>ktimer, fd table"]
    end

    LUA -->|blocked path| RESOLVE
    RESOLVE -.->|"BLOCKED"| SYSCALL
    LUA -->|bypass path| MAKESYS
    MAKESYS -->|direct| SYSCALL
    LUA --> HEAP
    LUA --> ROP
    LUA --> ASLR
    SYSCALL --> SYSCTL
    SYSCALL --> ROUTE
    SYSCALL --> AIO
    SYSCALL --> NET
    SYSCALL --> KOBJ

    style RESOLVE fill:#8b0000,stroke:#cd5c5c,color:#fff
    style MAKESYS fill:#2d5016,stroke:#4a8c2a,color:#fff
    style HEAP fill:#2d5016,stroke:#4a8c2a,color:#fff
    style ROP fill:#6b4c00,stroke:#b8860b,color:#fff
    style ASLR fill:#2d5016,stroke:#4a8c2a,color:#fff
    style ROUTE fill:#6b4c00,stroke:#b8860b,color:#fff
    style AIO fill:#6b4c00,stroke:#b8860b,color:#fff
```

## Confirmed Userland Capabilities

| Primitive | How | Probe |
|-----------|-----|-------|
| Raw syscall invocation | `make_syscall(N)` bypasses the Lua `syscall.resolve()` filter for tested numbers; kernel-side restrictions still apply | 41w |
| Heap R/W (256+ pages) | GPU mmap adjacency, no guard pages | 41c |
| ASLR bypass | `dynlib_get_info(593)` leaks all 39 module bases | 41o |
| eboot gadget catalog | Gadget bytes were read from the RX eboot segment; no working execution path was established | 41r–t |
| Writable ROP metadata | `fn_addr`, chain, and argument slots are writable, but probe 45c showed `make_syscall()` does not use them | 41z, 45c |
| Kernel info via sysctl | FreeBSD r230171, securelevel=1024, 16KB pages | 42a |

These results establish userland memory control and syscall invocation. They do **not** establish kernel read/write, native code execution, or an arbitrary function-call primitive.

## Key Constraints

- **W^X enforced** - `mmap(RWX)` gives RW only; `mprotect(EXEC)` always fails
- **Execute-only memory (XOM)** - system lib .text is XO (reading crashes); eboot is RX
- **No threading** - `fork`, `rfork`, and `thr_new` were blocked or crashed in tested paths, including raw-syscall checks
- **AIO — inconclusive (retest 53a pending)** - 43p's log stops at the first call without a kill record; 19g shows `aio_error` returned `rv=-1` (2026-10-17 audit)
- **Per-connection ASLR** - fresh process per TCP connection
- **No kernel pointers observed in examined outputs** - several candidate paths were incomplete or invalidly exercised; see the evidence audit
- **/dev/dmem0** - GPU aperture only, cannot access CPU/kernel physical memory

## Current Research Status

The repository contains results for probes 43a–43p, 44a–44d, and 45a–45c. Treat raw result files as authoritative: 45c disproved the `fn_addr`/ROP execution path. The 2026-10-17 evidence audit found that 43p does not establish an AIO kill and 43o does not establish that AF_ROUTE leaks are patched: its RTM_GET write failed and the read echoed the request. The 43a/43b kldstat/kldsym logs are truncated before any result, and 47b did not write-test CClosure offset +0. These four questions have dedicated retests in `probes/phase13_53batch/`; they remain open until results are captured and independently reviewed.

The V13.60 syscall baseline is useful for mapping, but it is not a 14.10 kernel image. A kernel vulnerability on 14.10 has not been demonstrated in this repository. See [the evidence audit](docs/EVIDENCE_AUDIT_2026-10-17.md) for the remaining gaps and the 13.60 table reconciliation.

## Repository Structure

```
probes/
  phase1_identity_layout/    # 01–08: system ID, syscalls, memory layout
  phase2_kernel_objects/     # 09–21: UMTX, nwake, dmem, AIO, kqueue
  phase3_signals_codexec/    # 22–26: signals, sigaltstack, W^X, XOM
  phase4_ipc_network/        # 27–31: threading, fd passing, socket opts
  phase5_buffer_io/          # 32–33: buffer stress, MSG_DONTWAIT
  phase6_raw_packets/        # 34–39: RAW sockets, fragments, IP options
  phase7_heap_exploitation/  # 40–41: GPU mmap, heap R/W, ROP, ASLR bypass
  phase8_live_network/       # 40tcp, 42: TCP fuzz, ktimer, live testing
  phase9_kaslr_defeat/       # 42b–42j: KASLR attempts, ROP architecture
  phase10_untested_theories/ # 43a–43p: theory-driven probes (results recorded)
  phase13_52batch/           # 52a–52b: Sony syscall survey and syscall 624 oracle
  phase13_53batch/           # 53a–53d: evidence-audit retests
  42f2–42i (root)            # Physical memory & ROP chain analysis probes
results/                     # Raw output logs (mirrored phase structure)
tools/                       # send_probe.py, send_probe.ps1, run_session40.py
docs/
  ATTACK_SURFACE.md          # Complete syscall status map
  FINDINGS.md                # 25 detailed technical findings
  PROBE_INDEX.md             # Every probe with status and key result
  STRATEGY.md                # Exploit strategy and dead ends
  UNTESTED_THEORIES.md       # 17 theories ranked by priority
```

## Environment

| Property | Value |
|----------|-------|
| Firmware | 14.10 |
| Kernel | FreeBSD r230171 (Sep 28 2026) |
| Entry point | Lua 5.1 loader on TCP 9026 |
| Page size | 16 KB (0x4000) |
| CPU | Zen 2, 8C/16T (16 logical cores) |
| Securelevel | 1024 (PS5-specific) |

## Quick Start

```bash
# Send a probe (Python)
PYTHONIOENCODING=utf-8 python tools/send_probe.py --save probes/phase10_untested_theories/43a_kldstat_kaslr.lua

# Send a probe (PowerShell, no Python required)
.\tools\send_probe.ps1 probes\phase10_untested_theories\43a_kldstat_kaslr.lua -Save

# TCP connect-back fuzz session
python tools/run_session40.py --ps5-ip 10.0.0.96 --fake-ip 10.0.0.250
```

See [tools/README.md](tools/README.md) for details.

## Key Findings

1. **ROP Chain Architecture Decoded** - Full 0x300-byte chain mapped: gadget sequence (pop rax → deref → pop rdi → write), 13 argument slots, stack pivot at eboot+0x9A2
2. **Sandbox Bypass** - `make_syscall(N)` reaches the kernel directly; `syscall.resolve()` filter is Lua-side only
3. **39 Module ASLR Bypass** - `dynlib_get_info(593)` leaks text/data bases for every loaded module
4. **GPU Heap Primitive** - 256+ adjacent 16KB pages via GPU mmap, no guard pages between allocations
5. **Physical Memory Isolation** - `/dev/dmem0` maps only GPU GDDR6 aperture, not CPU DRAM

See [docs/FINDINGS.md](docs/FINDINGS.md) for all 25 findings.

## Lua 5.1 Constraints

1. **uint64 for addresses >32 bits**: `uint64(string.format("0x%X%08X", hi, lo))`
2. **pcall wrapping**: `pcall(function() return memory.read_qword(addr) end)`
3. **Lua 5.1 only**: no `goto`/labels - use `repeat...until true` + `break`
4. **XO pages bypass pcall**: reading execute-only memory kills the process
5. **Fresh ASLR per connection**: re-derive all addresses each run

## Userland Entry

The exploit chain uses **Hamidashi Creative** (a Japanese visual novel on the Artemis/Lua engine) as the entry point. A modified save file embeds the Lua loader, which starts a TCP listener on port 9026.

```mermaid
graph TD
    A["PS5: Play game, create save"] -->|USB| B["Find PSN Account ID<br/>(hex, from save folder)"]
    B -->|USB| C["Jailbroken PS4: Apollo activates<br/>profile with MATCHING Account ID"]
    C --> D["Decrypt save under<br/>matched profile"]
    D -->|USB| E["PC: Embed Lua loader"]
    E -->|USB| F["Jailbroken PS4: Re-encrypt save"]
    F -->|USB| G["PS5: Import save, launch game"]
    G --> H["Black screen + notification:<br/>'lua loader is loaded'<br/>Listening on TCP 9026"]
    H -->|"LAN: send_probe.py"| I["PC sends Lua probes<br/>over TCP"]

    style B fill:#8b0000,stroke:#cd5c5c,color:#fff
    style C fill:#8b0000,stroke:#cd5c5c,color:#fff
    style H fill:#2d5016,stroke:#4a8c2a,color:#fff
    style I fill:#2d5016,stroke:#4a8c2a,color:#fff
```

> Red = critical step (Account ID must match or PS5 rejects the save)

- **Game:** Hamidashi Creative (はみだしクリエイティブ) - free demo on Japanese PSN
- **Loader:** Based on [shahrilnet/remote_lua_loader](https://github.com/shahrilnet/remote_lua_loader)
- **Kernel offsets:** From [@hammer-83](https://github.com/hammer-83)'s [ps5-jar-loader](https://github.com/hammer-83/ps5-jar-loader) (fw 1.00–10.01 only - 14.10 offsets TBD)
- **Entry method:** Save file exploit via PS4 backwards compatibility

See [docs/USERLAND_ENTRY.md](docs/USERLAND_ENTRY.md) for the full setup guide, save file chain walkthrough, and supported games list.

## Documentation

| Document | Contents |
|----------|----------|
| [CHANGELOG.md](CHANGELOG.md) | Phase-by-phase progress timeline |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute to this project |
| [docs/USERLAND_ENTRY.md](docs/USERLAND_ENTRY.md) | Userland exploit setup guide and game details |
| [docs/PROBE_INDEX.md](docs/PROBE_INDEX.md) | Full probe-by-probe breakdown |
| [docs/EVIDENCE_AUDIT_2026-10-17.md](docs/EVIDENCE_AUDIT_2026-10-17.md) | Claim-by-claim evidence review, contradictions, failed runs, provenance, and gaps |
| [docs/INDEPENDENT_EVIDENCE_AUDIT_2026-10-17.md](docs/INDEPENDENT_EVIDENCE_AUDIT_2026-10-17.md) | Full ledger adjudication, artifact hashes, log counts, and missing-evidence register |
| [docs/RETEST_PLAN_53.md](docs/RETEST_PLAN_53.md) | Run order, evidence requirements, and interpretation rules for the prepared retests |
| [docs/ATTACK_SURFACE.md](docs/ATTACK_SURFACE.md) | Complete syscall status map |
| [docs/FINDINGS.md](docs/FINDINGS.md) | 25 detailed technical findings |
| [docs/STRATEGY.md](docs/STRATEGY.md) | Exploit strategy and dead ends |
| [docs/UNTESTED_THEORIES.md](docs/UNTESTED_THEORIES.md) | 17 ranked exploit theories and 3 attack chains |
| [docs/RESEARCH_PAPER.md](docs/RESEARCH_PAPER.md) | Full technical research paper covering methodology and findings |

## Use AI to Help

All research data is in this repo specifically so anyone can feed it to their AI model of choice. Here's how to get the most out of it:

**Give your AI this context:**
1. Start with `README.md` and `CLAUDE.md` for the full picture
2. Feed it `docs/STRATEGY.md` for what's been tried and what's next
3. Feed it `docs/FINDINGS.md` for all 25 technical findings
4. Feed it `docs/UNTESTED_THEORIES.md` for the current theory queue
5. Point it at specific probe results in `results/` for raw data analysis

**Ask your AI to:**
- Analyze probe results for kernel pointer patterns we missed
- Cross-reference our findings against FreeBSD kernel source code
- Suggest new attack vectors based on the confirmed primitives
- Review the `make_syscall` bypass for syscalls we haven't tried yet
- Write new probes following the template in `CLAUDE.md`
- Look for timing side-channels or information leaks in the syscall results

**What we need AI help with most:**
- **KASLR defeat** - AF_ROUTE (43o) and kldstat/kldsym (43a/43b) remain inconclusive; retests 53b/53c are prepared, and other approaches can be assessed separately
- **FreeBSD r230171 kernel source analysis** - Find exploitable code paths reachable from our ~40 working syscalls
- **AIO behavior** - Probe 43p is inconclusive; retest 53a records each call separately. A returned call alone does not establish a usable race primitive.

The more models looking at this data from different angles, the faster we crack KASLR.

## Credits

- Userland loader: [@shahrilnet](https://github.com/shahrilnet) via [remote_lua_loader](https://github.com/shahrilnet/remote_lua_loader)
- Kernel offsets (fw 1.00-10.01): [@hammer-83](https://github.com/hammer-83) via [ps5-jar-loader](https://github.com/hammer-83/ps5-jar-loader)
- PS4 jailbreak: [GoldHEN](https://github.com/GoldHEN/GoldHEN) by [@SiSTRo](https://github.com/SiSTRo) and the GoldHEN team
- Save file management: [Apollo Save Tool](https://github.com/bucanero/apollo-ps4) by [@bucanero](https://github.com/bucanero)
- Relapse exploit research (fw 7.00-13.60): AF_ROUTE KASLR defeat technique and AIO race condition methodology
- Artemis engine Lua research: the PS5 homebrew scene

## License

This research is for educational and authorized security research purposes only.

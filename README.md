# PS5 Firmware 14.10 - Kernel Research

Open community kernel exploit research on PlayStation 5 firmware **14.10**, conducted via a userland Lua 5.1 loader on TCP 9026.

> **Goal:** Establish a reproducible 14.10 kernel primitive, then assess whether it can support kernel R/W and hypervisor research. None of those kernel-side stages is currently demonstrated.

---

## This Project Needs Funding

<a href="https://www.paypal.me/SalwanStudios">
<img src="https://img.shields.io/badge/DONATE-PayPal-blue?style=for-the-badge&logo=paypal&logoColor=white" alt="Donate via PayPal" height="60"/>
</a>

**Current goal: $250 CAD** for the Claude Max 20x plan — a 1-million-token context window that can ingest the entire research corpus at once and find novel kernel vulnerabilities that smaller context windows miss.

**Current progress: $112.74 / $250 CAD**

### Why I need this

I've spent **two weeks** on this project — roughly 4 hours every weekday and 10-15 hours each weekend day. Here's what I've spent out of pocket so far:

| Expense | Cost |
|---------|------|
| Claude Pro subscription (maxed out) | $150 CAD |
| Claude API credits (maxed out) | $100 CAD |
| ChatGPT Plus / Codex accounts × 3 (all maxed) | ~$80 CAD |
| PS5 console for v13.60 kernel dumps | $450 CAD |
| **Total personal investment** | **~$780 CAD** |

I have a full-time job. I've exhausted my personal AI subscriptions and API credits. The research has produced **230 probes**, **247 result captures**, a confirmed **CClosure arbitrary code redirect primitive**, and the most comprehensive PS5 14.10 syscall surface map that exists publicly. But I've hit a wall: every known KASLR defeat path is dead on 14.10, and finding a novel one requires the kind of deep cross-referencing and creative analysis that only a large-context AI can do efficiently.

The $250 Claude Max 20x plan would give me enough resources to feed the **entire** research corpus (all probes, all results, all 13.60 kernel dumps, all documentation) into a single context and have it reason about novel exploit paths that no one has tried before. I'm confident this would be enough to find the kernel bug and get it working **before the GTA 6 release**.

**Every dollar helps.** This research stays open and free regardless of funding.

[![Donate via PayPal](https://img.shields.io/badge/Donate-PayPal-blue?logo=paypal)](https://www.paypal.me/SalwanStudios)

### Thank You to Our Donors

These people believed in this research and put their money where their mouth is. It means the world &lt;3

- **Ivan Milinski**
- **Felix Dietz**
- **Brian Alejandro Camacho**
- **Jonathan Moreau**

---

**Contributors welcome.** Whether you have the hardware or just want to analyze FreeBSD kernel code - there's work to do. See [CONTRIBUTING.md](CONTRIBUTING.md) to get involved.

<!-- RESEARCH_PROGRESS:START -->
## Research progress

[![14.10 evidence-weighted milestone estimate: 30/100](docs/images/research_progress.svg)](docs/PROGRESS_AUDIT.md)

**30/100 (~30%) on a subjective, evidence-weighted milestone rubric.** This is not a measured percentage of unknown exploit work, time remaining, or probability of success. **Kernel read/write on 14.10 is not demonstrated.** Hypervisor bypass is excluded from this score.

| Milestone | Points earned / weight |
|---|---:|
| 14.10 research environment | 10/10 |
| Probe tooling and captured evidence | 10/10 |
| Target characterization | 10/15 |
| Validated 14.10 kernel vulnerability | 0/20 |
| Demonstrated 14.10 kernel read/write | 0/25 |
| Repeatable complete kernel exploit | 0/20 |

Audited 2026-10-18. [Evidence and counting rules](docs/PROGRESS_AUDIT.md) · [Machine-readable rubric](docs/progress.json) · [Website](https://marwanmohamed.ca/researchps5#research-progress)

**Update 2026-10-18:** Target characterization raised from 5 to 10/15. Phase 14 (probes 54a-56k5) completed an exhaustive Sony syscall survey, confirmed CClosure +0x20 as a controlled dispatch primitive, mapped the full 317-region process VM, tested all KASLR defeat paths (all dead), and analyzed 13.60 kernel dumps. The "complete scoped survey" gate is now earned. The "target-build kernel candidate" gate remains unearned (no 14.10 kernel image available).
<!-- RESEARCH_PROGRESS:END -->

## Current Status: KASLR Wall

**At this time, I am unable to find a v14.10 kernel exploit.** Every conventional and unconventional KASLR defeat technique has been exhaustively tested and confirmed dead on firmware 14.10. Sony has hardened every known information leak path. The confirmed userland primitives (CClosure redirect, heap R/W, syscall invocation) are powerful but cannot reach the kernel without knowing where it is.

### What's confirmed dead on 14.10

| KASLR Technique | Result | Probe |
|----------------|--------|-------|
| AF_ROUTE kernel pointer leak (Relapse) | Sanitized — zero kernel pointers | 53b |
| mincore/msync/madvise oracle | Lethal — instantly kills process | 56k |
| Timing side-channel via CClosure redirect | SMAP — no differentiation between mapped/unmapped | 56j |
| Signal handler fault recovery oracle | Handler bypasses pcall, no in-process oracle | 56k2, 56k3 |
| RDMSR (sys 626, 567) | Returns -1 for all MSR indices | 54k |
| kldstat/kldnext (sys 307, 308) | Lethal — instantly kills process | 56k4, 56k5 |
| mod* syscalls (sys 300-302) | All return -1 | 56k5 |
| kldsym (sys 337) | Never reached (kldnext kills first) | 56k4 |
| sysctl kernel pointer scan | All values are sentinels, not pointers | multiple |
| sys 674 VM map (317 regions) | All userland VA, zero kernel pointers | 55e, 55f |
| sys 649 module members | Userland addresses only | 54k |
| kinfo_proc full dump | Only sentinels (0xFFFFFFFF_*) | multiple |
| net.route.iflistl scan | sockaddr/MAC structures, no kernel pointers | 54f |
| sys 593 deep struct scan | NID hashes, not kernel pointers | 54f |
| sys 639/638 memory region | Returns -1 for all address ranges | 54f |
| sys 588 (13.60 exploit path) | No-op on 14.10 | 54d |
| AIO (sys 661-670, 13.60 exploit path) | Lethal — sys 661 instantly kills process | 54c, 54f |

### What IS working (strong userland primitives)

| Primitive | Status | Probe |
|-----------|--------|-------|
| CClosure +0x20 arbitrary dispatch | Redirect any non-VM function to any executable address | 55g, 56c |
| Heap R/W (256+ pages) | GPU mmap adjacency, no guard pages | 41c |
| Arbitrary syscall invocation | make_syscall(N) for tested numbers | 41w |
| Userland ASLR bypass (39 modules) | dynlib_get_info(593) | 41o |
| Full process VM map (317 regions) | sys 674 with protections and names | 55e |
| Signal handler install | sigaction(416) returns 0 | 56k |
| Network packet injection | RAW socket + IP_HDRINCL | 34-39 |
| sys 624 VM operation counter | +5 per mmap, zero jitter, monotonic | 52b |

## Exploit Chain Overview

```mermaid
graph LR
    A["Hamidashi Creative<br/>(Artemis Engine)"] -->|modified save file| B["Lua 5.1 Loader<br/>TCP 9026"]
    B -->|memory.* / syscall.*| C["Confirmed userland primitives<br/>CClosure redirect, Heap R/W,<br/>syscall invocation, VM map"]
    C -->|"ALL PATHS DEAD"| D["KASLR Defeat<br/>BLOCKED"]
    D -->|requires KASLR defeat| E["Kernel R/W<br/>not demonstrated"]
    E -->|requires kernel R/W| F["Hypervisor bypass<br/>not demonstrated"]

    style A fill:#2d5016,stroke:#4a8c2a,color:#fff
    style B fill:#2d5016,stroke:#4a8c2a,color:#fff
    style C fill:#2d5016,stroke:#4a8c2a,color:#fff
    style D fill:#8b0000,stroke:#cd5c5c,color:#fff
    style E fill:#8b0000,stroke:#cd5c5c,color:#fff
    style F fill:#8b0000,stroke:#cd5c5c,color:#fff
```

## Architecture

```mermaid
graph TD
    subgraph Userland ["Userland (Game Process)"]
        LUA["Lua 5.1 Script<br/>(our probes)"]
        RESOLVE["syscall.resolve()<br/>FILTERED - blocks many syscalls"]
        MAKESYS["make_syscall(N)<br/>bypasses Lua resolver filter;<br/>kernel restrictions still apply"]
        HEAP["GPU mmap Heap<br/>256+ pages R/W"]
        CCLOSURE["CClosure +0x20 redirect<br/>CONFIRMED: arbitrary dispatch<br/>to any executable address"]
        ASLR["dynlib_get_info<br/>39 module bases leaked"]
    end

    subgraph Kernel ["FreeBSD Kernel"]
        KASLR["KASLR<br/>ALL DEFEAT PATHS DEAD"]
        SYSCALL["Syscall Handler"]
        NET["Network Stack<br/>ip_input / tcp_input"]
    end

    LUA -->|blocked path| RESOLVE
    RESOLVE -.->|"BLOCKED"| SYSCALL
    LUA -->|bypass path| MAKESYS
    MAKESYS -->|direct| SYSCALL
    LUA --> HEAP
    LUA --> CCLOSURE
    LUA --> ASLR
    SYSCALL --> KASLR

    style RESOLVE fill:#8b0000,stroke:#cd5c5c,color:#fff
    style MAKESYS fill:#2d5016,stroke:#4a8c2a,color:#fff
    style HEAP fill:#2d5016,stroke:#4a8c2a,color:#fff
    style CCLOSURE fill:#2d5016,stroke:#4a8c2a,color:#fff
    style ASLR fill:#2d5016,stroke:#4a8c2a,color:#fff
    style KASLR fill:#8b0000,stroke:#cd5c5c,color:#fff
```

## Key Constraints

- **W^X enforced** - `mmap(RWX)` gives RW only; `mprotect(EXEC)` always fails
- **Execute-only memory (XOM)** - system lib .text is XO (reading crashes); eboot is RX
- **No threading** - `fork`, `rfork`, and `thr_new` were blocked or crashed in tested paths
- **AIO — confirmed hard wall** - sys 661 instantly kills the process on 14.10
- **kldstat/kldnext — confirmed hard wall** - sys 307/308 instantly kill the process
- **Per-connection ASLR** - fresh process per TCP connection
- **SMAP enforced** - no timing differentiation between mapped/unmapped kernel VA
- **No kernel pointers found** - extensive scanning across every accessible interface
- **AF_ROUTE KASLR (Relapse technique) — confirmed dead** - kernel sanitizes route messages
- **RDMSR blocked** - sys 626 and sys 567 return -1 for all MSR indices
- **/dev/dmem0** - GPU aperture only, cannot access CPU/kernel physical memory

## Repository Structure

```
probes/                          # 230 Lua probe scripts
  phase1_identity_layout/        # 01–08: system ID, syscalls, memory layout
  phase2_kernel_objects/         # 09–21: UMTX, nwake, dmem, AIO, kqueue
  phase3_signals_codexec/        # 22–26: signals, sigaltstack, W^X, XOM
  phase4_ipc_network/            # 27–31: threading, fd passing, socket opts
  phase5_buffer_io/              # 32–33: buffer stress, MSG_DONTWAIT
  phase6_raw_packets/            # 34–39: RAW sockets, fragments, IP options
  phase7_heap_exploitation/      # 40–41: GPU mmap, heap R/W, ROP, ASLR bypass
  phase8_live_network/           # 40tcp, 42: TCP fuzz, ktimer, live testing
  phase9_kaslr_defeat/           # 42b–42j: KASLR attempts, ROP architecture
  phase10_untested_theories/     # 43a–43p: theory-driven probes
  phase13_52batch/               # 52a–52b: Sony syscall survey + 624 oracle
  phase13_53batch/               # 53a–53d: evidence-audit retests
  phase14_final_push/            # 54a–56k5: deep syscall survey, CClosure, KASLR
results/                         # 247 raw output captures
tools/                           # send_probe.py, send_probe.ps1, kaslr_bruteforce.py
docs/
  ALL_RESULTS.md                 # Every result file in one document
  ALL_PROBES.md                  # Every probe file in one document
  ATTACK_SURFACE.md              # Complete syscall status map
  FINDINGS.md                    # Detailed technical findings
  PROBE_INDEX.md                 # Every probe with status and key result
  STRATEGY.md                    # Exploit strategy and dead ends
  UNTESTED_THEORIES.md           # Ranked exploit theories
  RESEARCH_PAPER.md              # Full technical research paper
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
PYTHONIOENCODING=utf-8 python tools/send_probe.py --save probes/phase14_final_push/56c_redirect_nonvm.lua

# Send a probe (PowerShell, no Python required)
.\tools\send_probe.ps1 probes\phase14_final_push\56c_redirect_nonvm.lua -Save

# KASLR brute force driver (multi-connection)
python tools/kaslr_bruteforce.py --ps5-ip YOUR_PS5_IP --step 0x200000
```

See [tools/README.md](tools/README.md) for details.

## Use AI to Help

All research data is in this repo specifically so anyone can feed it to their AI model of choice. For the best results, use a model with the largest possible context window.

**For maximum-context models (1M+ tokens):**
- Feed `docs/ALL_RESULTS.md` + `docs/ALL_PROBES.md` + `CLAUDE.md` — this is the entire research corpus in three files
- Ask the model to find novel KASLR defeat paths that haven't been tried
- Ask it to cross-reference 13.60 kernel dumps against 14.10 behavior

**For smaller context models:**
1. Start with `README.md` and `CLAUDE.md` for the full picture
2. Feed it `docs/STRATEGY.md` for what's been tried and what's next
3. Feed it `docs/FINDINGS.md` for all technical findings
4. Point it at specific probe results in `results/` for raw data analysis

**What we need help with most:**
- **Novel KASLR defeat** — every known path is dead. We need something no one has tried before. The CClosure redirect primitive can call any executable address; there may be an eboot function that leaks kernel info when called with the right arguments.
- **13.60 → 14.10 kernel diff analysis** — the companion repo has 13.60 kernel dumps. Finding what changed between versions could reveal new attack surface.
- **FreeBSD r230171 source analysis** — find exploitable code paths reachable from our ~40 working syscalls
- **Loader internals reverse engineering** — the Lua loader's C-level syscall dispatch may have writable function pointers

The more models looking at this data from different angles, the faster we find a kernel primitive.

## Related V13.60 Research

The companion [PS5 V13.60 Research](https://github.com/ZigZagBoi1/PS5-V13.60-Research) repository maintains the firmware 13.60 Relapse and Byepervisor-Reborn research, its local browser site, and observed stage evidence. This V14.10 project retains `docs/ps5_13.60_sysent.json` for existing strategy and probe tooling; the source copy and attribution are maintained in the companion repository. Relapse's 13.60 support does not imply support on 14.10.

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
| [docs/ALL_RESULTS.md](docs/ALL_RESULTS.md) | Every result file in one document (for large-context AI) |
| [docs/ALL_PROBES.md](docs/ALL_PROBES.md) | Every probe file in one document (for large-context AI) |
| [docs/USERLAND_ENTRY.md](docs/USERLAND_ENTRY.md) | Userland exploit setup guide and game details |
| [docs/PROBE_INDEX.md](docs/PROBE_INDEX.md) | Full probe-by-probe breakdown |
| [docs/EVIDENCE_AUDIT_2026-10-17.md](docs/EVIDENCE_AUDIT_2026-10-17.md) | Claim-by-claim evidence review |
| [docs/ATTACK_SURFACE.md](docs/ATTACK_SURFACE.md) | Complete syscall status map |
| [docs/FINDINGS.md](docs/FINDINGS.md) | Detailed technical findings |
| [docs/STRATEGY.md](docs/STRATEGY.md) | Exploit strategy and dead ends |
| [docs/RESEARCH_PAPER.md](docs/RESEARCH_PAPER.md) | Full technical research paper |

## Credits

- Userland loader: [@shahrilnet](https://github.com/shahrilnet) via [remote_lua_loader](https://github.com/shahrilnet/remote_lua_loader)
- Kernel offsets (fw 1.00-10.01): [@hammer-83](https://github.com/hammer-83) via [ps5-jar-loader](https://github.com/hammer-83/ps5-jar-loader)
- PS4 jailbreak: [GoldHEN](https://github.com/GoldHEN/GoldHEN) by [@SiSTRo](https://github.com/SiSTRo) and the GoldHEN team
- Save file management: [Apollo Save Tool](https://github.com/bucanero/apollo-ps4) by [@bucanero](https://github.com/bucanero)
- Relapse exploit research (fw 7.00-13.60): AF_ROUTE KASLR defeat technique and AIO race condition methodology
- Artemis engine Lua research: the PS5 homebrew scene

## License

This research is for educational and authorized security research purposes only.

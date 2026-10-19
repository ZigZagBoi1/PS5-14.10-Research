# Contributing

This is an open community research project. Everyone is welcome to contribute.

## What We Need

### High Priority
- **Evidence review** — 43a–43p have saved records, including incomplete runs. Check the current probe index and existing audits before proposing a retest.
- **KASLR evidence** — No kernel base is established. Review later AF_ROUTE/KLD records as well as the earlier incomplete 43o/43a captures; do not treat a missing result as a diagnosed kill cause.
- **Kernel offset discovery for fw 14.10** — Existing offsets only cover 1.00-10.01. Once KASLR is defeated, we need to map 14.10 symbols.
- **New exploit vectors** — Review the attack surface and dead ends in `docs/STRATEGY.md`. Fresh eyes catch things.

### Always Welcome
- **Analysis of probe results** — Cross-reference against FreeBSD source, find things we missed
- **New probe scripts** — Follow the template in `CLAUDE.md`, test via `tools/send_probe.py`
- **Documentation improvements** — Typos, clarity, missing details
- **Tool improvements** — Better send/receive tooling, result parsers, automation

## How to Contribute

1. Fork the repo
2. Create a branch for your work
3. Write your probe or changes
4. Test if you can (see below)
5. Open a PR with a clear description of what you're testing and why

## Writing Probes

See the probe template and Lua 5.1 constraints in `CLAUDE.md`. Key rules:

- **Use `make_syscall(N)`** for tested raw syscall invocation; it bypasses the Lua resolver filter, while kernel authorization still applies
- **Always use `pcall()`** around risky operations
- **Never hardcode addresses** — ASLR changes every connection
- **Never read XO (execute-only) pages** — kills the process past pcall
- **Use `uint64()` for all 64-bit values** — Lua 5.1 numbers are doubles
- **Print everything** — results go to the TCP socket, more output = better analysis

## Testing

If you have the setup (PS5 fw 14.10 + userland exploit):

```bash
# Send a probe
PYTHONIOENCODING=utf-8 python tools/send_probe.py --save probes/<phase>/<name>.lua

# PowerShell alternative
.\tools\send_probe.ps1 probes\<phase>\<name>.lua -Save
```

If you don't have the hardware, you can still:
- Write probes based on FreeBSD kernel source analysis
- Analyze existing results in `results/`
- Review the attack surface and suggest new approaches
- Improve tooling

## Project Structure

```
probes/     — Lua probe scripts organized by phase
results/    — Raw output from probe runs
tools/      — Send/receive scripts and session tools
docs/       — Technical documentation and strategy
```

Read `docs/PROBE_INDEX.md` for what's been tested and `docs/STRATEGY.md` for the current game plan.

## Code of Conduct

Be respectful. We're all here because we love this stuff. Disagree on technical merits, not personality. This is security research for educational purposes.

## Contributors

Thanks to everyone who has contributed research, probes, analysis and corrections:

| Contributor | GitHub | Contributions |
|---|---|---|
| **Rithik Janarthanan** (ng643) | [@ng643](https://github.com/ng643) | PRs #6-8, #11-18, #21-27 — Evidence corrections, sysctl MIB fixes, handler claim audits (Tier 1/2/3), CVE assessments (49412, 49419), kevent/430 corrections, kldsym probe, thr_create decode, kevent timeout matrix, sys 622 bitmap correction, CVE triage |
| **The Doc** (4TheDoctor) | [@4TheDoctor](https://github.com/4TheDoctor) | PRs #19-20, #28 — CVE-2026-49418 msync UAF assessment (top gold find), CVE-2026-58093/49427/49428 assessments, CVE-2026-49424 Linuxulator assessment, thr_* family survey, probes 58a/58d/59a/59b |
| **pastawithpesto** | [@pastawithpesto](https://github.com/pastawithpesto) | PRs #4-5 — Complete kernel handler RE (145/145 syscalls fw 13.60), WebKit entry vector analysis |
| **kaydzer0305-png** | [@kaydzer0305-png](https://github.com/kaydzer0305-png) | PR #10 — Offline evidence auditing, scoped execution claim reconciliation |
| **Unkown607** | [@Unkown607](https://github.com/Unkown607) | PR #9 — 13.60 syscall name maps, compat-table capture identification |
| **Cruby** | — | Live console testing — first confirmed thr_create(430) kernel panic on fw 14.10 (probes 58e/76c/76d/76e) |
| **wsjardijn** | [@wsjardijn](https://github.com/wsjardijn) | Early research contributions |

## Credits

- Userland loader: [@shahrilnet](https://github.com/shahrilnet) via [remote_lua_loader](https://github.com/shahrilnet/remote_lua_loader)
- Kernel offsets (fw 1.00-10.01): [@hammer-83](https://github.com/hammer-83) via [ps5-jar-loader](https://github.com/hammer-83/ps5-jar-loader)
- PS4 jailbreak: [GoldHEN](https://github.com/GoldHEN/GoldHEN) by [@SiSTRo](https://github.com/SiSTRo) and the GoldHEN team
- Save file management: [Apollo Save Tool](https://github.com/bucanero/apollo-ps4) by [@bucanero](https://github.com/bucanero)
- Relapse exploit research (fw 7.00-13.60): AF_ROUTE KASLR technique and AIO race condition methodology

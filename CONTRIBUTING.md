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

### Hardware-free verification

The required CI command is standard-library-only and has an explicit, sorted
module list:

```bash
python3 tools/verify_offline.py
```

Use `python3 tools/verify_offline.py --list` to review that exact list. It runs
only read-only evidence/audit/parser tests plus temporary-file fixtures. It does
not import or invoke sender, sweep, watchdog, swarm, Lua probe, or network
transport code; it opens no console connection. A nonzero test result is
returned as the process status, and an empty selected module is rejected rather
than silently skipped. GitHub Actions runs this bounded command on Python 3.10
and 3.11.

The verifier needs Python 3.10+ and the tracked research inputs it reads,
including `docs/dumps_13.60/`, `docs/`, `probes/`, and `results/`. It needs no
PS5, loader endpoint, credentials, or package installation. Its intentionally
empty dependency manifest is `requirements-offline.txt`.

### Loopback capture CLI CI

The separate `Capture CLI verification` workflow exercises
`tools/test_send_probe.py` on Linux, macOS, and Windows with PowerShell 7
(`pwsh`), plus Windows PowerShell (`powershell`). Each matrix entry selects its
runtime explicitly and fails if that executable is missing, the selected suite
is empty, or any selected test is skipped. All jobs run the core Python and
PowerShell CLI cases; POSIX jobs additionally run duplicate-`realpath` and failed
canonicalizer regressions, which do not apply on Windows. These tests launch
the real sender CLIs against a fake loader bound to `127.0.0.1` on an
OS-assigned port, check framing and raw
response bytes, and write only temporary fixtures. They never contact a console
or execute the fixture Lua source. No third-party Python packages are needed.
This transport test tier does not expand the network-free verifier above.

Run the default available PowerShell runtime locally with:

```bash
python -m unittest discover -s tools -p 'test_send_probe.py' -v
```

### Optional broader local checks

The broader tool suite is not part of the no-console gate. It includes
artifact disassembly and Lua stub-loader tests, which need pinned optional
packages, and some tests that use an isolated loopback socket fixture. Those
fixtures never contact a console, but they are deliberately outside the
network-free verifier.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-offline-optional.txt
python -m unittest discover -s tools -p 'test_*.py' -v
```

`requirements-offline-optional.txt` pins `capstone` for committed-artifact
disassembly and `lupa` for in-process Lua 5.1 stubs. Both require compatible
wheels for the selected Python/platform. Do not suppress a failing or missing
test: report the command, dependency state, and failure separately from the
bounded CI result.

### Console testing (optional, hardware required)

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
| **Cruby** | [@cruby](https://github.com/cruby) | Live console testing — first confirmed thr_create(430) kernel panic on fw 14.10 (probes 58e/76c/76d/76e) |
| **wsjardijn** | [@wsjardijn](https://github.com/wsjardijn) | Early research contributions |

## Credits

- Userland loader: [@shahrilnet](https://github.com/shahrilnet) via [remote_lua_loader](https://github.com/shahrilnet/remote_lua_loader)
- Kernel offsets (fw 1.00-10.01): [@hammer-83](https://github.com/hammer-83) via [ps5-jar-loader](https://github.com/hammer-83/ps5-jar-loader)
- PS4 jailbreak: [GoldHEN](https://github.com/GoldHEN/GoldHEN) by [@SiSTRo](https://github.com/SiSTRo) and the GoldHEN team
- Save file management: [Apollo Save Tool](https://github.com/bucanero/apollo-ps4) by [@bucanero](https://github.com/bucanero)
- Relapse exploit research (fw 7.00-13.60): AF_ROUTE KASLR technique and AIO race condition methodology

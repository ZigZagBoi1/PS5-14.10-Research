# Contributing

This is an open community research project. Everyone is welcome to contribute.

## Where contributors talk

Discord: **[discord.gg/aznssydKrx](https://discord.gg/aznssydKrx)**

Use it for anything that needs a human faster than a pull request: asking for console time on a 14.10 machine, checking whether a capture has already been mined before writing a probe, or flagging a claim that contradicts a saved result. Each console accepts one connection at a time and an unknown syscall can take the game process down, so a few messages before a run are cheaper than a relaunch.

Chat is not the record. A finding still lands in this repository as a probe, a capture, a ledger row and a graded claim — see [docs/RESEARCH_EVIDENCE.md](docs/RESEARCH_EVIDENCE.md).

## What We Need

### High Priority
- **WebKit FontFace chain review** — The FontFace UAF (CVE-2026-43720) is the only live exploit vector. PRs #300–#304 contain oracle semantics, vptr guard bypass, cross-firmware layout corrections, and an engine-driven free primitive. Reviewing beacon evidence, verifying claims against captures, and catching bugs in probe code is the most impactful work right now.
- **Cross-firmware validation** — The chain is being developed on 14.10 and ported to 14.00. Contributors with either firmware can run data-gather probes and submit beacon captures. VP-relative vtable offsets transfer across firmwares; base-relative offsets do not. More landings strengthen the evidence.
- **Alternative info leak** — `IPV6_2292PKTOPTIONS` is blocked on 14.10. The Canvas UAF write primitive exists but cannot be aimed without a heap pointer leak. Finding an alternative leak mechanism is the critical-path blocker. Fresh eyes on the WebKit attack surface (`docs/STRATEGY.md`) are welcome.
- **KASLR / kernel offset discovery** — No kernel base is established on 14.10, and existing offsets only cover 1.00–10.01. This is blocked until the WebKit chain delivers a kernel read primitive, but offline source analysis of FreeBSD 11.0 kernel structures can start now.

### Always Welcome
- **Beacon evidence review** — Cross-reference beacon logs and JSONL captures against probe code and session docs. Check that claimed results match the raw data. Prior reviews on #303 and #304 include offline test harnesses as examples.
- **WebKit probe development** — HTML/JS probes run in the PS5's User Guide browser via DNS redirect. See `probes/phase13_webkit/` for examples. Follow the beacon contract (server-timestamped HTTP POST) so results are independently verifiable.
- **Lua probe development** — Lua probes run via the TCP loader on port 9026. See `CLAUDE.md` for the template and Lua 5.1 constraints. The kernel syscall surface is exhausted, but prepared probes in the index still need on-device runs.
- **FreeBSD source analysis** — The PS5 kernel is a fork of FreeBSD 11.0. Offline analysis of kernel structures, allocator internals, and syscall handlers helps even without hardware.
- **Tooling and documentation** — Better beacon parsers, capture analyzers, result cross-referencing tools. Typo and clarity fixes.

## How to Contribute

1. Fork the repo
2. Create a branch for your work
3. Write your probe or changes
4. Test if you can (see below)
5. Open a PR with a clear description of what you're testing and why

## Evidence Grades

Claims in result docs and PR descriptions carry a grade tag:

- **[M]** — Measured on device (beacon log, capture file)
- **[I]** — Inferred (arithmetic, source analysis, interpretation of [M] data)
- **[S]** — Source-derived (from published firmware source or WebKit code)
- **[R]** — Referenced (from an external data source, not measured in this run)

Grade your own claims honestly — overclaiming [M] on inferred results erodes trust. See [docs/RESEARCH_EVIDENCE.md](docs/RESEARCH_EVIDENCE.md) for the broader evidence and ledger rules.

## Writing Probes

There are two probe paths, targeting different layers of the PS5 stack.

### Kernel probes (Lua)

Kernel probes run on the remote Lua loader (`tools/send_probe.py`). See the template and Lua 5.1 constraints in `CLAUDE.md`. Key rules:

- **Use `make_syscall(N)`** for tested raw syscall invocation; it bypasses the Lua resolver filter, while kernel authorization still applies
- **Always use `pcall()`** around risky operations
- **Never hardcode addresses** — ASLR changes every connection
- **Never read XO (execute-only) pages** — kills the process past pcall
- **Use `uint64()` for all 64-bit values** — Lua 5.1 numbers are doubles
- **Print everything** — results go to the TCP socket, more output = better analysis

### WebKit probes (HTML/JS)

WebKit probes are single-page HTML files that run in the PS5's built-in browser (User Guide menu). This is the current active research front (FontFace UAF, oracle reads, vtable walks, COOP dispatch).

1. Point the PS5's DNS at the host beacon server
2. Open the User Guide on the console — the custom DNS routes it to the probe page
3. The probe sends HTTP beacon POSTs back to the host as it runs
4. Results land as server-timestamped `.log` and `.jsonl` capture files

Key differences from kernel probes:
- **No loader connection needed** — the browser is the execution environment
- **Beacons are the evidence** — every observable state change should emit a beacon tag. Server timestamps and JSONL captures with SHA256 provenance are the audit trail
- **One probe per page load** — the console's WebKit process can crash on UAF-dependent paths, requiring a reboot between runs

Existing WebKit probes live in `probes/phase13_webkit/`. The data-gather crowdsourcing rig is in `probes/phase13_webkit/data-gather/`.

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

The same workflow runs `tools/test_capture_collision_safety.py`,
`tools/test_send_probe_helpers.py` and the tests for the drivers that import the
loader lifecycle helpers (`bounds_fuzz`, `ioctl_isolation_sweep` and
`restart_pressure`). The capture suite pins timestamp-collision routing,
atomic no-replace publication and the symlinked-directory refusal; the helper
suite covers a port that accepts without a live Lua thread, the readiness
marker, wait budgets and generated-source transcripts; the driver suites fail
at import time if one of those public helpers disappears again. All fixtures
are loopback-only or temporary-directory-only.

Run the loopback batches locally with:

```bash
python -m unittest discover -s tools -p 'test_send_probe.py' -v
python -m unittest -v tools.test_capture_collision_safety \
  tools.test_send_probe_helpers tools.test_bounds_fuzz \
  tools.test_ioctl_isolation_sweep tools.test_restart_pressure
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

### Console testing (hardware required)

There are two probe paths, depending on the exploit stage.

**Lua probes (kernel-side)** — if you have the Lua loader endpoint running:

```bash
# Send a probe
PYTHONIOENCODING=utf-8 python tools/send_probe.py --save probes/<phase>/<name>.lua

# PowerShell alternative
.\tools\send_probe.ps1 probes\<phase>\<name>.lua -Save
```

**WebKit probes (browser-side)** — this is where most active work happens:

1. Set up a beacon server — either a VPS (`tools/vps_setup.sh`) or locally via `tools/browser_runner/beacon_server.py`
2. Point your PS5's DNS at the beacon server so `manuals.playstation.net` resolves to it (`tools/browser_runner/dns_hijack.py` handles this locally)
3. Open the User Guide on the PS5 — the hijacked DNS serves the probe HTML
4. Beacon logs land on the server. Parse with `tools/parse_beacons.py` or read the raw JSONL directly

See `tools/browser_runner/README.md` for the capture API and JSONL schema.

**If you don't have the hardware**, you can still:
- Write probes based on FreeBSD kernel source or WebKit source analysis
- Review beacon evidence and verify claims in open PRs
- Analyze existing results in `results/`
- Improve tooling

## Project Structure

```
probes/     — Probe scripts organized by phase (Lua kernel + HTML/JS WebKit)
results/    — Raw captures, beacon logs, JSONL evidence, and results INDEX
tools/      — Send/receive scripts, beacon parsers, offline verifiers
docs/       — Technical documentation, strategy, and evidence ledger
```

Read `results/INDEX.md` for the evidence ledger, `docs/PROBE_INDEX.md` for what's been tested, and `docs/STRATEGY.md` for the current game plan.

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
| **hex0x42424242** | [@hex0x42424242](https://github.com/hex0x42424242) | PRs #298, #302, #303 — Independent 14.10 walk, FontFace chain session, p693 yield killer + engine-driven free primitive |
| **Rajkamal** (jsrkamal2002) | [@jsrkamal2002](https://github.com/jsrkamal2002) | PRs #285, #296, #304 — p817 magic-gated base discovery, parse_beacons analyzer, boundary() polarity fix |
| **Arjun Dhir** (ArjunD717) | [@ArjunD717](https://github.com/ArjunD717) | PRs #252–260, #264, #287–292 — Browser runner, DNS resolver, capture collision safety, ioctl sweep |
| **Siva** (sivatheja10) | [@sivatheja10](https://github.com/sivatheja10) | PR #299 — FW 14.00 VP-to-text distance measurement and vtable RVA |
| **Mart** (mja00) | [@mja00](https://github.com/mja00) | PRs #300, #301 — 14.00 import-GOT transfer boundary, WeakHashSet layout correction |
| **Couiz** | [@Couiz](https://github.com/Couiz) | PR #286 — AIO 14.10 lock-release predicate correction |
| **TFujiwara** | [@TFujiwara](https://github.com/TFujiwara) | PR #250 — 14.22 FontFace/FontProxy campaign |
| **cobrajet302gt** | [@cobrajet302gt](https://github.com/cobrajet302gt) | PR #280 — Chain plan corrections: IsoHeap blocker retirement, p600 observation scoping |
| **Sayan Manna** (MannA-001) | [@MannA-001](https://github.com/MannA-001) | PRs #278, #279 — Browser runner header time bound, JSC regression config |

## Credits

- Userland loader: [@shahrilnet](https://github.com/shahrilnet) via [remote_lua_loader](https://github.com/shahrilnet/remote_lua_loader)
- Kernel offsets (fw 1.00-10.01): [@hammer-83](https://github.com/hammer-83) via [ps5-jar-loader](https://github.com/hammer-83/ps5-jar-loader)
- PS4 jailbreak: [GoldHEN](https://github.com/GoldHEN/GoldHEN) by [@SiSTRo](https://github.com/SiSTRo) and the GoldHEN team
- Save file management: [Apollo Save Tool](https://github.com/bucanero/apollo-ps4) by [@bucanero](https://github.com/bucanero)
- Relapse exploit research (fw 7.00-13.60): AF_ROUTE KASLR technique and AIO race condition methodology

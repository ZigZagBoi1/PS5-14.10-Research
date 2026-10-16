# Contributing

This is an open community research project. Everyone is welcome to contribute.

## What We Need

### High Priority
- **Probe testing** — We have 16 probes ready to send (43a-43p). If you have a PS5 on firmware 14.10 with the userland exploit loaded, run them and share results.
- **KASLR defeat** — The biggest current blocker. Probes 43o (AF_ROUTE) and 43a (kldstat) are the most promising approaches.
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

- **Always use `make_syscall(N)`** for raw kernel access (bypasses the loader's sandbox)
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

## Credits

- Userland exploit loader: [shahrilnet/remote_lua_loader](https://github.com/shahrilnet/remote_lua_loader)
- Kernel offsets (fw 1.00-10.01): [@hammer-83](https://github.com/hammer-83) via [ps5-jar-loader](https://github.com/hammer-83/ps5-jar-loader)
- Relapse exploit intelligence (fw 7.00-13.60): AF_ROUTE KASLR technique and AIO race condition methodology

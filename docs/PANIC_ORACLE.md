# PANIC ORACLE — Reboot Detection as the Strongest Fuzzing Signal

Tool: `tools/ps5_watchdog.py` (stdlib-only, Windows host). Companion doc for
`docs/CHANGELOG.md` and `tools/README.md`. Status: methodology, 2026-10-16.

## Why a reboot beats a process kill

Our current fuzzing signal is process-level: a probe returns 0 bytes and we
conclude "crash" or "sandbox kill". That signal is ambiguous. Per the
changelog, the 43p AIO capture ends before its first call result and the
43a/43b KLD captures contain headers only; none records a kill. A truncated
capture alone does not establish a process or kernel kill. A process kill
also needs an independent signal before attributing it to the sandbox.

A full console reboot is a different class of event:

- The PS5 rebooted because the **kernel** panicked. No userland sandbox
  boundary sits between a fuzzed packet and a panic; the fault happened in
  kernel code operating on attacker-controlled input.
- A panic is unrecoverable from userland. A process kill can be caused by
  sandbox enforcement or loader corruption (probe 50d persistently killed
  the loader — even minimal test probes died after it). A reboot cannot be
  faked by the loader; the watchdog sees it over the network.
- Therefore: **no signal → weak. Reboot → strongest possible signal.** When
  the console reboots during a campaign, the packet sent immediately before
  is a real kernel bug hit — the prime replay and root-cause candidate.

## The classification ladder

The watchdog polls TCP 9026 (loader port) and, with `--ping`, ICMP:

| State       | Meaning                                            | Recovery        |
|-------------|----------------------------------------------------|-----------------|
| ALIVE       | Loader port accepts                                | —               |
| LOADER_DOWN | Host pings, port refused/timeout                   | Relaunch game   |
| REBOOTING   | Ping fails too — console is rebooting              | Power-cycle     |
| UNKNOWN     | No ping configured, port down                      | Ambiguous       |

Load-bearing distinction: LOADER_DOWN is recoverable by relaunching the
game from userland; REBOOTING is not (only a power-cycle recovers it), and
that irrecoverability is what makes it a kernel event rather than a loader
or game event.

## Recovery reality

- **Process kills**: recoverable by relaunching the game and the Lua loader
  (TCP 9026). This is the routine workflow after loader-killing probes
  (50c/50d required loader restarts).
- **Reboots**: the console reboots itself; if it hangs, power-cycle.
- **No save data is at risk** from fuzzing probes. Our probes are network
  packets and Lua scripts that never touch game saves. A reboot may lose an
  in-progress game session, never saved data.

## Bounded-batch protocol

1. **Watchdog runs during every packet campaign.** Start it in a second
   terminal before sending anything:
   `PYTHONIOENCODING=utf-8 python tools/ps5_watchdog.py --ps5-ip 10.0.0.96 --ping`
   (`--ping` is required — without it a reboot reads as UNKNOWN.)
2. **Send in bounded batches.** Note the exact packet/probe (name + content)
   sent immediately before each `STATE ...->REBOOTING` line in
   `results/watchdog_log.txt`. That probe is the replay candidate; rerun it
   alone to confirm reproducibility before crediting it as a finding.
3. **Max ~10 forced reboots per session.** Each reboot stresses the console
   (power cycling, thermal cycling, filesystem churn on the system
   partition). Beyond ~10, stop the session; continued rebooting of a
   console under test risks console-side corruption that we cannot verify
   or repair remotely. Ten panics in one session is already a strong result
   set.
4. **Correlate after each batch.** Match watchdog REBOOTING timestamps
   against the campaign terminal's send log. A batch with zero reboots is a
   negative result; record it in the changelog like any other sweep
   (cf. 700+ malformed packets in 48a-50a, zero kernel crashes).

## Session-runner integration

The watchdog is passive and stateless — it only watches. Run it as a
background monitor alongside any sender (`send_probe.py`,
`tcp_fuzz_server.py`, `run_session40.py`, injectors):

```bash
# Terminal 1: sender (existing workflow)
PYTHONIOENCODING=utf-8 python tools/send_probe.py probes/<phase>/<probe>.lua --save

# Terminal 2: watchdog (this doc's tool)
PYTHONIOENCODING=utf-8 python tools/ps5_watchdog.py --ps5-ip 10.0.0.96 --ping --interval 5
```

Watchdog log lines are timestamped to the second, so a REBOOTING entry can
be pinned to the exact probe by send-time. If the runner is automated,
append the watchdog log tail after each batch and abort the campaign on the
first REBOOTING event.

## Honest limits

- With `--ping` off, REBOOTING is undetectable: port-down is UNKNOWN.
- ICMP may be filtered even when the host is up; a persistent UNKNOWN on a
  console you can see is a ping-availability problem, not a panic.
- A reboot is a signal that a kernel bug exists, not a controlled fault —
  root-causing still needs the replay protocol above.

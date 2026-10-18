# Tools

Utilities for sending probes to the PS5 and running network-side attack sessions.

## send_probe.py / send_probe.ps1

Sends one Lua probe script to the PS5 loader over TCP. The sender never retries
automatically. The Python sender supports `--timeout` as an idle read timeout
and `--total-timeout` as an optional wall-clock cap. `--save` mirrors probe
subdirectories below this checkout's `probes/` directory into `results/`.
Use `--metadata` with the Python sender to add a JSON sidecar containing the
transport status, elapsed time, probe hash, and target address; it also records
silent/reset runs as empty captures.

```bash
PYTHONIOENCODING=utf-8 python tools/send_probe.py --save --metadata --strict \
    probes/<phase>/<probe_name>.lua
```

Native PowerShell alternative:

```powershell
.\tools\send_probe.ps1 probes\<phase>\<probe_name>.lua -Save
```

The loader expects an 8-byte little-endian uint64 length prefix followed by raw
Lua source on TCP port 9026. Results are relative to the current working
directory. A timeout/reset is a transport outcome only; correlate it with
`tools/ps5_watchdog.py` before calling it a process kill or console reboot.

## run_probe_batch.py

Runs a bounded list sequentially. It stops at the first timeout, reset, refusal,
or silent close unless `--continue-on-failure` is explicitly supplied. It does
not relaunch the game or retry a probe, and `--save` writes a batch JSON
manifest.

```bash
PYTHONIOENCODING=utf-8 python tools/run_probe_batch.py --save --strict \
    probes/phase14_final_push/54o_cfunc_redirect_controlled.lua \
    probes/phase14_final_push/54p_redirect_minimal.lua
```

For the current redirect probes, run only after the game and loader have been
restarted. Keep `--continue-on-failure` off so a wedged session cannot cause a
second probe to be sent automatically.

## Regression tests

Run the hardware-free sender regression suite against a local TCP loader:

```bash
python -m unittest discover -s tools -p "test_send_probe.py" -v
```

The suite exercises Python and an available PowerShell executable; PowerShell
cases are skipped when neither `powershell.exe` nor `pwsh` is installed.

## run_session40.py

PC-side raw-packet server for the TCP connect-back fuzz (probe 40). Impersonates a fake LAN host so the Windows stack doesn't RST the connection.

```bash
python tools/run_session40.py --ps5-ip 10.0.0.96 --fake-ip 10.0.0.250
```

Runs an ARP responder + raw packet sender from an unowned IP address. The PS5 connects back to the fake IP, then the script delivers malformed TCP segments through the established connection.

## tcp_fuzz_server.py

Standalone TCP fuzzing server for crafting and sending malformed TCP segments to the PS5.

## test_probe46a.lua

Offline Lua 5.1 regression harness for probe 46a's buffer-modification detector:

```bash
lua tools/test_probe46a.lua
```

Run from the repository root with a Lua 5.1 interpreter. With Python and Lupa's Lua 5.1 runtime installed, the equivalent command is:

```bash
python -c "from lupa.lua51 import LuaRuntime; LuaRuntime().globals().dofile('tools/test_probe46a.lua')"
```

The harness executes the actual probe in isolated memory/syscall sandboxes, checking unchanged zero/sentinel buffers, injected writes, and checked-range boundaries. It never connects to a console and does not validate kernel behavior. See [the 14.10 evidence correction](../docs/SYSCALL_557_14_10_EVIDENCE.md).

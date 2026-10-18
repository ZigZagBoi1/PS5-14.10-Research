# Tools

Utilities for sending probes to the PS5 and running network-side attack sessions.

## send_probe.py

Sends one Lua probe script to the PS5 loader over TCP. The sender never retries
automatically. `--timeout` is an idle read timeout; `--total-timeout` is an
optional wall-clock cap. With `--save`, it writes the raw response (including
zero-byte captures) and a JSON sidecar containing the status, elapsed time,
probe hash, and target address.

```bash
PYTHONIOENCODING=utf-8 python tools/send_probe.py --save --strict \
    probes/<phase>/<probe_name>.lua
```

The loader expects an 8-byte little-endian uint64 length prefix followed by raw Lua source on TCP port 9026. Results are saved to `results/<probe_name>_<timestamp>.txt` with a matching `.json` run record.

Statuses distinguish a completed response from a silent close, idle timeout,
connection reset, connection refusal, or connect timeout. A timeout/reset is evidence of
the transport outcome only; correlate it with `tools/ps5_watchdog.py` before
calling it a process kill or a console reboot.

## run_probe_batch.py

Runs a bounded list sequentially. It stops at the first timeout, reset, or
refusal unless `--continue-on-failure` is explicitly supplied. It does not
relaunch the game or retry a probe, and `--save` adds a batch JSON manifest.

```bash
PYTHONIOENCODING=utf-8 python tools/run_probe_batch.py --save --strict \
    probes/phase14_final_push/54o_cfunc_redirect_controlled.lua \
    probes/phase14_final_push/54p_redirect_minimal.lua
```

For the current redirect probes, run only after the game and loader have been
restarted. Keep `--continue-on-failure` off so a wedged session cannot cause a
second probe to be sent automatically.

## run_session40.py

PC-side raw-packet server for the TCP connect-back fuzz (probe 40). Impersonates a fake LAN host so the Windows stack doesn't RST the connection.

```bash
python tools/run_session40.py --ps5-ip 10.0.0.96 --fake-ip 10.0.0.250
```

Runs an ARP responder + raw packet sender from an unowned IP address. The PS5 connects back to the fake IP, then the script delivers malformed TCP segments through the established connection.

## tcp_fuzz_server.py

Standalone TCP fuzzing server for crafting and sending malformed TCP segments to the PS5.

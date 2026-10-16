# Tools

Utilities for sending probes to the PS5 and running network-side attack sessions.

## send_probe.py

Sends a Lua probe script to the PS5 loader over TCP.

```bash
PYTHONIOENCODING=utf-8 python tools/send_probe.py --save probes/<phase>/<probe_name>.lua
```

The loader expects an 8-byte little-endian uint64 length prefix followed by raw Lua source on TCP port 9026. Results are saved to `results/<phase>/<probe_name>_<timestamp>.txt`.

## run_session40.py

PC-side raw-packet server for the TCP connect-back fuzz (probe 40). Impersonates a fake LAN host so the Windows stack doesn't RST the connection.

```bash
python tools/run_session40.py --ps5-ip 10.0.0.96 --fake-ip 10.0.0.250
```

Runs an ARP responder + raw packet sender from an unowned IP address. The PS5 connects back to the fake IP, then the script delivers malformed TCP segments through the established connection.

## tcp_fuzz_server.py

Standalone TCP fuzzing server for crafting and sending malformed TCP segments to the PS5.

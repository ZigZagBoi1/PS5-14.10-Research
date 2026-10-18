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

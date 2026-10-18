# Tools

Utilities for sending probes to the PS5 and running network-side attack sessions.

## send_probe.py / send_probe.ps1

Sends a Lua probe script to the PS5 loader over TCP.

```bash
PYTHONIOENCODING=utf-8 python tools/send_probe.py --save probes/<phase>/<probe_name>.lua
```

Native PowerShell alternative:

```powershell
.\tools\send_probe.ps1 probes\<phase>\<probe_name>.lua -Save
```

The loader expects an 8-byte little-endian uint64 length prefix followed by raw Lua source on TCP port 9026.

With `--save` / `-Save`, both senders mirror subdirectories beneath this checkout's `probes/` into `results/`, creating missing directories. For example, `probes/<phase>/<probe_name>.lua` saves to `results/<phase>/<probe_name>_<timestamp>.txt`; nested phase directories are preserved too. Probes directly in `probes/` or outside this checkout's probe tree save to the `results/` root.

The `results/` base is relative to the current working directory, including when the probe argument is an absolute path. Historical captures are not moved. No result file is created without the save flag or when the loader returns no output.

Run the hardware-free sender regression suite against a local TCP loader:

```bash
python -m unittest discover -s tools -p "test_send_probe.py" -v
```

The suite exercises Python and an available PowerShell executable; PowerShell cases are skipped when neither `powershell.exe` nor `pwsh` is installed.

## run_session40.py

PC-side raw-packet server for the TCP connect-back fuzz (probe 40). Impersonates a fake LAN host so the Windows stack doesn't RST the connection.

```bash
python tools/run_session40.py --ps5-ip 10.0.0.96 --fake-ip 10.0.0.250
```

Runs an ARP responder + raw packet sender from an unowned IP address. The PS5 connects back to the fake IP, then the script delivers malformed TCP segments through the established connection.

## tcp_fuzz_server.py

Standalone TCP fuzzing server for crafting and sending malformed TCP segments to the PS5.

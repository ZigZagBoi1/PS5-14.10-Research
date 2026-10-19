# Tools

Utilities for sending probes to the PS5, reviewing saved output, and running network-side attack sessions.

## audit_research.py

Read-only, standard-library inventory and curated evidence checks (Python 3.10+):

```bash
python tools/audit_research.py
python tools/audit_research.py --output ../offline-audit.md
python -m unittest discover -s tests -v
```

Checks each expanded experiment ID against exact names or explicit terminal-`*`
prefixes, reports ambiguous membership without assigning coverage, and verifies
the ledger's evidence hashes/anchors. Inventory notices do not imply integrity
failure or scientific verdicts. No console contact or Lua evaluation. See the
[ledger guide](../docs/RESEARCH_EVIDENCE.md) for matching rules, exit codes,
provenance limits and how this complements the existing upstream audits.

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

## analyze_result.py

Reviews saved probe output locally, without connecting to a console:

```bash
python tools/analyze_result.py "results/*.txt"
```

Marked pointer lines use the same 64-bit value scan and address classifier as
ordinary data output. A buffer offset such as `kinfo+0x060` is not the pointer
value that follows it. Probe-reported marker alerts remain visible, including
summaries that print values on separate lines; those alerts are distinct from
parsed address candidates.

The report remains heuristic: a candidate or probe alert is not proof of a leak,
and the kernel-base/sysent estimates are not verified firmware 14.10 addresses.

## deep_result_scanner.py

Walks every `results/**/*.txt` capture and rewrites
`evidence/deep_result_scan.md` in place:

```bash
python tools/deep_result_scanner.py
```

Kernel-pointer and deobfuscated-pointer candidates require the same
data-output gate as `analyze_result.py`: hexdump rows, buffer views,
return values, or probe markers. Timing rows, verify echoes, and
arithmetic labels are excluded because they echo the probe's own inputs.
Other buckets, the report layout, and the entrypoint are unchanged.

## Regression tests

Run the hardware-free sender and analyzer regression suites:

```bash
python -m unittest discover -s tools -p "test_*.py" -v
```

Sender tests exercise the actual Python and available PowerShell CLIs against a
local TCP loader; PowerShell cases are skipped when neither `powershell.exe`
nor `pwsh` is installed. Analyzer tests use temporary synthetic captures and
check the reported pointer values, counts, and false-positive cases. Neither
suite contacts a console.

## run_session40.py

PC-side raw-packet server for the TCP connect-back fuzz (probe 40). Impersonates a fake LAN host so the Windows stack doesn't RST the connection.

```bash
python tools/run_session40.py --ps5-ip 10.0.0.96 --fake-ip 10.0.0.250
```

Runs an ARP responder + raw packet sender from an unowned IP address. The PS5 connects back to the fake IP, then the script delivers malformed TCP segments through the established connection.

## tcp_fuzz_server.py

Standalone TCP fuzzing server for crafting and sending malformed TCP segments to the PS5.

## test_probe46a.lua / test_probe56l.lua

Lua 5.1 regression harnesses for probe 46a's buffer-modification detector
and probe 56l's corrected-MIB/ktimer logic:

```bash
lua tools/test_probe46a.lua
lua tools/test_probe56l.lua
```

Run from the repository root with a Lua 5.1 interpreter. With Python and Lupa's Lua 5.1 runtime installed, the equivalent commands are:

```bash
python -c "from lupa.lua51 import LuaRuntime; LuaRuntime().globals().dofile('tools/test_probe46a.lua')"
python -c "from lupa.lua51 import LuaRuntime; LuaRuntime().globals().dofile('tools/test_probe56l.lua')"
```

The 46a harness executes the actual probe in isolated memory/syscall sandboxes, checking unchanged zero/sentinel buffers, injected writes, and checked-range boundaries. The 56l harness scripts three handlers (upstream-shaped, all-refused, all-empty) against the unmodified probe, asserting MIB bytes, call shapes, record parsing, and ktimer verdict text. Both harnesses never connect to a console and do not validate kernel behavior. See [the 14.10 evidence correction](../docs/SYSCALL_557_14_10_EVIDENCE.md) and [the corrected-MIB note](../docs/CORRECTED_MIB_14_10_EVIDENCE.md).

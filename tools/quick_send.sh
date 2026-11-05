#!/bin/bash
# Quick send + auto-analyze for PS5 probe results
# Usage: ./tools/quick_send.sh probes/phase14_final_push/54f_kaslr_deep.lua
#
# Sends the probe to the PS5, then immediately runs the analyzer
# on the newest result file.

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <probe_lua_file>"
    echo ""
    echo "Available phase14 probes (recommended order):"
    echo "  1. probes/phase14_final_push/54a2_rdmsr_precise.lua  (RDMSR/WRMSR)"
    echo "  2. probes/phase14_final_push/54f_kaslr_deep.lua      (8 KASLR attempts)"
    echo "  3. probes/phase14_final_push/54d_dmem_page_flip.lua   (W^X bypass)"
    echo "  4. probes/phase14_final_push/54b_jail_bypass.lua      (jail escape)"
    echo "  5. probes/phase14_final_push/54c_aio_full_attack.lua  (AIO exploit)"
    echo "  6. probes/phase14_final_push/54e_device_fuzz.lua      (device fuzz)"
    echo "  7. probes/phase13_53batch/53a_aio_retest.lua          (AIO survival)"
    echo "  8. probes/phase13_53batch/53b_afroute_retest.lua      (AF_ROUTE KASLR)"
    exit 1
fi

PROBE="$1"
if [ ! -f "$PROBE" ]; then
    echo "ERROR: Probe file not found: $PROBE"
    exit 1
fi
if [ -z "${PYTHON:-}" ]; then
    if command -v python3 >/dev/null 2>&1; then
        PYTHON=python3
    else
        PYTHON=python
    fi
fi

echo "=========================================="
echo " Sending: $PROBE"
echo "=========================================="
echo ""

# Send the probe
PYTHONIOENCODING=utf-8 "$PYTHON" tools/send_probe.py --save "$PROBE"

echo ""
echo "=========================================="
echo " Analyzing result..."
echo "=========================================="
echo ""

# Find the newest result file across all result directories. BSD/macOS find
# has no -printf, so use the Python runtime the script already needs.
LATEST=$("$PYTHON" - "$PROBE" <<'PY'
import sys
from pathlib import Path

probe = Path(sys.argv[1])
probe_mtime = probe.stat().st_mtime
results = [path for path in Path("results").rglob("*.txt") if path.is_file()]
newer = [path for path in results if path.stat().st_mtime > probe_mtime]
candidates = newer or results
if candidates:
    print(max(candidates, key=lambda path: path.stat().st_mtime))
PY
)

if [ -n "$LATEST" ]; then
    echo "Result file: $LATEST"
    echo ""
    "$PYTHON" tools/analyze_result.py "$LATEST"
else
    echo "WARNING: No result file found. Check results/ directory."
fi

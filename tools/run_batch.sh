#!/usr/bin/env bash
# Batch probe runner for PS5 14.10 research
# Usage: ./tools/run_batch.sh [--ip 192.168.1.35]
#
# Waits for the PS5 loader to be available, then runs all queued probes
# in sequence. Each probe gets its own TCP connection.

set -euo pipefail

IP="${1:---ip}"
if [ "$IP" = "--ip" ]; then
    IP="${2:-192.168.1.35}"
fi

PORT=9026
TIMEOUT=60
SENDER="python3 tools/send_probe.py"
SCRATCHPAD="/private/tmp/claude-501/-Users-ettore-Developer-personal-GoldHen/bd084a1d-d69e-40df-87df-403f83ed48b4/scratchpad"

echo "=== PS5 14.10 BATCH PROBE RUNNER ==="
echo "Target: $IP:$PORT"
echo ""

# Wait for loader
echo "Waiting for PS5 loader..."
until python3 -c "
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3)
try:
    s.connect(('$IP', $PORT))
    s.close()
    sys.exit(0)
except:
    s.close()
    sys.exit(1)
"; do
    sleep 5
done
echo "CONNECTED!"
echo ""

run_probe() {
    local label="$1"
    local probe="$2"
    echo "=== [$label] ==="
    $SENDER "$probe" --ip "$IP" --save --metadata --timeout "$TIMEOUT" 2>&1
    local status=$?
    echo ""
    sleep 0.5
    # Check if loader is still alive
    if ! python3 -c "
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3)
try:
    s.connect(('$IP', $PORT))
    s.close()
    sys.exit(0)
except:
    s.close()
    sys.exit(1)
"; then
        echo "!!! LOADER CRASHED after $label — stopping batch"
        exit 1
    fi
    return $status
}

echo "--- BATCH 1: Reachability probes ---"
run_probe "93a-A GPU VM range ops" "probes/phase17_new_vectors/93a_gpu_vm_range_ops.lua"
run_probe "96a-A sys 558 handle delete" "probes/phase17_new_vectors/96a_handle_namespace_uaf.lua"
run_probe "89a-B MSR PMC observation" "$SCRATCHPAD/89a_B.lua"
run_probe "92a-D Combined PMU+L2" "$SCRATCHPAD/92a_D.lua"

echo "--- BATCH 2: Deeper investigation ---"
run_probe "98a-C PTE attribute sweep" "$SCRATCHPAD/98a_C.lua"
run_probe "97a-A GPU dispatch unpriv" "probes/phase17_new_vectors/97a_gpu_dispatch_unpriv.lua"

echo ""
echo "=== BATCH COMPLETE ==="

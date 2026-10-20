#!/bin/bash
# Auto-send probes in sequence when port 9026 opens
PS5_IP="10.0.0.96"
PORT=9026
CD_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CD_DIR"

PROBES=(
    "probes/phase17_new_vectors/129b_native_test.lua"
    "probes/phase17_new_vectors/119a_evfilt_proc_leak.lua"
    "probes/phase17_new_vectors/139a_sysent_677_734.lua"
    "probes/phase17_new_vectors/140a_pipe2_fd_spray.lua"
    "probes/phase17_new_vectors/135a_umtx_shm_race.lua"
    "probes/phase17_new_vectors/136a_umtx_pi_race.lua"
    "probes/phase17_new_vectors/137a_scm_rights_race.lua"
    "probes/phase17_new_vectors/138a_timer_reentry_race.lua"
    "probes/phase17_new_vectors/133a_socket_close_race.lua"
    "probes/phase17_new_vectors/132a_uaf_trampoline.lua"
)

echo "[auto_probe] Queue: ${PROBES[*]}"
for PROBE in "${PROBES[@]}"; do
    echo "[auto_probe] Waiting for port: $PROBE"
    while true; do
        if nc -z -w 2 "$PS5_IP" "$PORT" 2>/dev/null; then
            echo "[auto_probe] PORT OPEN! Sending $PROBE"
            sleep 2
            PYTHONIOENCODING=utf-8 python tools/send_probe.py --save "$PROBE" 2>&1
            echo "[auto_probe] Sent. Waiting 10s..."
            sleep 10
            break
        fi
        sleep 5
    done
done
echo "[auto_probe] All done."

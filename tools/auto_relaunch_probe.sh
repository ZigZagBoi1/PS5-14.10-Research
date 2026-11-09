#!/bin/bash
# Auto relaunch game and send probes
# Combines Chiaki CGEvent key injection with probe sending
PS5_IP="10.0.0.96"
PORT=9026
SK="/private/tmp/claude-501/-Users-marwanmohamed-Documents-GitHub-PS5-14-10-Research/8b07f461-a00f-4727-a87d-5841d5de249b/scratchpad/send_key"
CD_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$CD_DIR"

CHIAKI_PID=$(pgrep -f chiaki | head -1)
if [ -z "$CHIAKI_PID" ]; then echo "[auto] No Chiaki PID"; exit 1; fi
echo "[auto] Chiaki PID=$CHIAKI_PID"

PROBES=(
    "probes/phase17_new_vectors/147a_safe_ipv6_race.lua"
    "probes/phase17_new_vectors/145a_kaslr_spray_oracle.lua"
    "probes/phase17_new_vectors/119a_evfilt_proc_leak.lua"
    "probes/phase17_new_vectors/139a_sysent_677_734.lua"
    "probes/phase17_new_vectors/140a_pipe2_fd_spray.lua"
    "probes/phase17_new_vectors/135a_umtx_shm_race.lua"
    "probes/phase17_new_vectors/136a_umtx_pi_race.lua"
    "probes/phase17_new_vectors/137a_scm_rights_race.lua"
    "probes/phase17_new_vectors/138a_timer_reentry_race.lua"
    "probes/phase17_new_vectors/133a_socket_close_race.lua"
)

relaunch_game() {
    echo "[auto] Relaunching game..."
    # Dismiss any error dialog
    $SK $CHIAKI_PID 36 2>/dev/null
    sleep 3
    # Press PS button to go home
    $SK $CHIAKI_PID 53 2>/dev/null
    sleep 3
    # Press Enter to select/launch game
    $SK $CHIAKI_PID 36 2>/dev/null
    sleep 15
    # Press through splash screens
    for i in $(seq 1 10); do
        $SK $CHIAKI_PID 36 2>/dev/null
        sleep 5
        if nc -z -w 2 "$PS5_IP" "$PORT" 2>/dev/null; then
            echo "[auto] PORT OPEN at splash attempt $i"
            sleep 1
            $SK $CHIAKI_PID 36 2>/dev/null  # dismiss loader dialog
            sleep 1
            return 0
        fi
    done
    echo "[auto] Failed to get port open"
    return 1
}

for PROBE in "${PROBES[@]}"; do
    echo ""
    echo "[auto] === $PROBE ==="

    # Ensure port is open
    if ! nc -z -w 2 "$PS5_IP" "$PORT" 2>/dev/null; then
        echo "[auto] Port closed, relaunching..."
        if ! relaunch_game; then
            echo "[auto] Relaunch failed, retrying once..."
            sleep 10
            if ! relaunch_game; then
                echo "[auto] Second relaunch failed, skipping probe"
                continue
            fi
        fi
    fi

    echo "[auto] Sending $PROBE"
    sleep 2
    PYTHONIOENCODING=utf-8 python3 tools/send_probe.py --save "$PROBE" 2>&1
    echo "[auto] Done. Waiting 5s..."
    sleep 5
done

echo "[auto] All probes sent."

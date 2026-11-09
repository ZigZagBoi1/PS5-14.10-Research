#!/bin/bash
# Relaunch game on PS5 via Chiaki CGEvent key injection
# Usage: ./tools/relaunch_game.sh [chiaki_pid]
SK="$(dirname "$0")/../scratchpad/send_key"
if [ ! -f "$SK" ]; then
    SK="/private/tmp/claude-501/-Users-marwanmohamed-Documents-GitHub-PS5-14-10-Research/8b07f461-a00f-4727-a87d-5841d5de249b/scratchpad/send_key"
fi
PID=${1:-$(pgrep -f chiaki | head -1)}
if [ -z "$PID" ]; then echo "No Chiaki PID"; exit 1; fi

echo "[relaunch] Chiaki PID=$PID"

# Dismiss any error dialog
$SK $PID 36  # Enter/Cross
sleep 3

# Press Enter to select game on home screen
$SK $PID 36
sleep 15

# Press through splash screens
for i in 1 2 3 4 5 6 7 8 9 10; do
    $SK $PID 36
    sleep 5
    if nc -z -w 2 10.0.0.96 9026 2>/dev/null; then
        echo "[relaunch] PORT OPEN at attempt $i"
        # Dismiss loader OK dialog
        sleep 1
        $SK $PID 36
        exit 0
    fi
done

echo "[relaunch] PORT DID NOT OPEN"
exit 1

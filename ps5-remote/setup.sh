#!/bin/bash
# PS5 Remote Control — Mac Setup
set -e

echo "=== PS5 Remote Control Setup ==="
echo ""

# Check for Homebrew
if ! command -v brew &>/dev/null; then
    echo "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

# Install Chiaki (Remote Play client)
if ! brew list chiaki-ng &>/dev/null 2>&1 && ! brew list --cask chiaki-ng &>/dev/null 2>&1; then
    echo "Installing chiaki-ng (open-source PS Remote Play)..."
    brew install --cask chiaki-ng 2>/dev/null || brew install chiaki-ng 2>/dev/null || {
        echo ""
        echo "Auto-install failed. Install chiaki-ng manually:"
        echo "  1. Go to https://github.com/streetpea/chiaki-ng/releases"
        echo "  2. Download the latest macOS .dmg"
        echo "  3. Drag to /Applications"
        echo ""
    }
else
    echo "chiaki-ng already installed"
fi

# Install Python deps
echo "Installing Python dependencies..."
pip3 install -r "$(dirname "$0")/requirements.txt"

# Create config if needed
CONFIG="$(dirname "$0")/config.json"
if [ ! -f "$CONFIG" ]; then
    echo ""
    read -p "PS5 IP address [10.0.0.50]: " PS5_IP
    PS5_IP=${PS5_IP:-10.0.0.50}
    read -p "PS5 MAC address (for Wake-on-LAN) [00:00:00:00:00:00]: " PS5_MAC
    PS5_MAC=${PS5_MAC:-00:00:00:00:00:00}

    cat > "$CONFIG" <<CONF
{
  "ps5_ip": "$PS5_IP",
  "ps5_mac": "$PS5_MAC",
  "capture_device": "auto",
  "screenshot_interval": 2.0,
  "api_port": 8888,
  "api_host": "0.0.0.0",
  "game_title_id": "",
  "crash_timeout": 30,
  "freeze_timeout": 15,
  "probe_port": 9026,
  "dns_server": "10.0.0.80",
  "dualsense_usb": true,
  "screenshot_dir": "screenshots",
  "log_file": "ps5_remote.log"
}
CONF
    echo "Config saved to $CONFIG"
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "IMPORTANT — One-time Chiaki pairing:"
echo "  1. Open Chiaki-ng"
echo "  2. Your PS5 should appear on the local network"
echo "  3. Go to PS5 Settings > System > Remote Play > Enable Remote Play"
echo "  4. Go to PS5 Settings > System > Remote Play > Link Device"
echo "  5. Note the 8-digit code shown on PS5"
echo "  6. In Chiaki, click your PS5 and enter the code"
echo "  7. Once paired, Chiaki connects directly over LAN (no PSN needed)"
echo ""
echo "  NOTE: Initial pairing needs PSN access. Temporarily change DNS"
echo "  from 10.0.0.80 to automatic, pair, then switch DNS back."
echo "  After pairing, Chiaki works on LAN without PSN servers."
echo ""
echo "To start the 24/7 loop:"
echo "  python3 ps5-remote/loop/autonomous.py"
echo ""
echo "To start the API server (for AI agent access):"
echo "  python3 ps5-remote/api/server.py"
echo ""
echo "For AI-powered screen analysis, set:"
echo "  export ANTHROPIC_API_KEY=your-key-here"

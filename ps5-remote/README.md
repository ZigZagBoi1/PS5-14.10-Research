# PS5 Remote Control

Fully automated PS5 control system for 24/7 kernel research. Uses **Chiaki** (open-source Remote Play) for screen capture and controller input — no capture card or extra hardware needed.

## What It Does

- **Sees the PS5 screen** via Chiaki Remote Play (LAN, no PSN servers)
- **Sends button presses** as keyboard input to the Chiaki window
- **Detects crashes/freezes** via screenshot analysis (pixel + optional AI vision)
- **Auto-relaunches** the game when it crashes or freezes
- **Wakes the PS5** from rest mode via Wake-on-LAN
- **REST API** for AI agents to control everything programmatically
- **24/7 autonomous loop** that handles all recovery automatically

## Requirements

- **Chiaki-ng** (free, open-source): [github.com/streetpea/chiaki-ng](https://github.com/streetpea/chiaki-ng/releases)
- **Python 3.8+**
- PS5 on the same LAN with Remote Play enabled

## Quick Start

### Mac
```bash
chmod +x ps5-remote/setup.sh
./ps5-remote/setup.sh
```

### Windows
```powershell
.\ps5-remote\setup.ps1
```

### One-Time Chiaki Pairing

1. **Temporarily** change PS5 DNS from `10.0.0.80` to automatic
2. On PS5: Settings > System > Remote Play > Enable Remote Play
3. On PS5: Settings > System > Remote Play > Link Device (note the 8-digit code)
4. Open Chiaki-ng on your computer, click your PS5, enter the code
5. **Switch DNS back** to `10.0.0.80` — Chiaki connects over LAN directly after pairing

### Run

```bash
# Check status
python3 ps5-remote/run.py status

# Start 24/7 autonomous loop
python3 ps5-remote/run.py loop

# Start API server (for AI agent access)
python3 ps5-remote/run.py api

# Start both loop + API
python3 ps5-remote/run.py both
```

## REST API

Default: `http://localhost:8888`

| Endpoint | Method | Description |
|---|---|---|
| `/status` | GET | PS5 state, Chiaki status, last screen state |
| `/screenshot` | GET | Take + return screenshot (PNG) |
| `/screenshot/latest` | GET | Latest screenshot |
| `/analyze` | GET | Analyze screen (add `?ai` for Claude vision) |
| `/button/{name}` | POST | Press button (cross, circle, up, down, etc.) |
| `/hold/{name}?duration=1.0` | POST | Hold button |
| `/combo` | POST | `{"buttons": ["l1", "r1"]}` |
| `/sequence` | POST | `{"steps": ["up", "cross", {"action":"wait","duration":2}]}` |
| `/relaunch` | POST | Relaunch game after crash |
| `/wake` | POST | Wake PS5 from rest mode |
| `/chiaki/start` | POST | Start Chiaki |
| `/chiaki/restart` | POST | Restart Chiaki |
| `/probe/send` | POST | `{"file": "probes/path/to/probe.lua"}` |

## For AI Agents

The API is designed for AI agents to drive the PS5. Example workflow:

```python
import requests

BASE = "http://localhost:8888"

# Check what's on screen
r = requests.get(f"{BASE}/analyze?ai")
state = r.json()["state"]

if state == "game_crashed":
    requests.post(f"{BASE}/relaunch")
elif state == "game_running":
    requests.post(f"{BASE}/probe/send", json={"file": "probes/phase14/probe_80a.lua"})
elif state == "home_screen":
    # Navigate to the game and launch it
    requests.post(f"{BASE}/button/cross")
```

## How It Works with DNS Blocker

Your DNS at `10.0.0.80` blocks PSN URLs to keep the PS5 on exploitable firmware. This system is fully compatible:

- **Chiaki connects directly over LAN** (IP-to-IP, no DNS resolution needed after initial pairing)
- **Wake-on-LAN** is a raw ethernet packet, no DNS involved
- **All control** happens on the local network
- **One-time exception**: initial Chiaki pairing needs PSN briefly (switch DNS to auto, pair, switch back)

## Architecture

```
ps5-remote/
  config.py              — Settings (config.json)
  run.py                 — Main entry point
  capture/
    hdmi.py              — Screenshot capture (Chiaki window)
    chiaki_manager.py    — Chiaki process management
  controller/
    dualsense.py         — Button input (keyboard -> Chiaki)
  power/
    wake.py              — Wake-on-LAN, PS5 state detection
  analyzer/
    screen.py            — Screenshot analysis (pixel + AI)
  api/
    server.py            — REST API server
  loop/
    autonomous.py        — 24/7 autonomous control loop
```

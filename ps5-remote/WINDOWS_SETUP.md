# PS5 Remote Control — Windows Setup Guide

## Prerequisites

- Windows 10/11
- Python 3.9+ ([python.org](https://www.python.org/downloads/))
- PS5 on the same local network

## Quick Setup

Open PowerShell and run:

```powershell
cd ps5-remote
.\setup.ps1
```

This installs chiaki-ng, Python dependencies, and creates `config.json`.

## Manual Setup

### 1. Install chiaki-ng

```powershell
winget install streetpea.chiaki-ng
```

Or download from [chiaki-ng releases](https://github.com/streetpea/chiaki-ng/releases).

### 2. Install Python dependencies

```powershell
pip install Pillow pyautogui pygetwindow
```

### 3. Create config

Edit `ps5-remote/config.json`:

```json
{
  "ps5_ip": "10.0.0.96",
  "ps5_mac": "AA:BB:CC:DD:EE:FF",
  "probe_port": 9026,
  "screenshot_interval": 2.0,
  "api_port": 8888,
  "screenshot_dir": "screenshots",
  "log_file": "ps5_remote.log"
}
```

Set `ps5_mac` to your PS5's MAC address (for Wake-on-LAN). Find it in PS5 Settings > System > Console Information.

### 4. Pair Chiaki with PS5 (one-time)

1. Open Chiaki-ng
2. On PS5: Settings > System > Remote Play > Enable Remote Play
3. On PS5: Settings > System > Remote Play > Link Device — note the 8-digit code
4. In Chiaki, click your PS5 and enter the code

**If using a DNS blocker:** Temporarily set PS5 DNS to automatic, pair, then switch back. After pairing, Chiaki connects directly over LAN without PSN.

### 5. Launch the game

Start the game that has the Lua loader (port 9026). Verify the loader is ready:

```powershell
python -c "import socket; s=socket.socket(); s.settimeout(2); print('OPEN' if s.connect_ex(('10.0.0.96',9026))==0 else 'CLOSED'); s.close()"
```

## Running

### Start the Game Keeper

Keeps the game running and port 9026 open. Does NOT send probes — that's the AI's job.

```powershell
python ps5-remote\loop\autonomous.py
```

Leave this running in a terminal. It will:
- Check port 9026 every 5 seconds
- If the game crashes, automatically dismiss the error dialog and relaunch
- If Chiaki disconnects, restart it
- If PS5 goes to sleep, send Wake-on-LAN

### Send probes (AI or manual)

```powershell
python tools\send_probe.py --save probes\phase17_new_vectors\my_probe.lua
```

### Start the API server (optional)

```powershell
python ps5-remote\api\server.py
```

API endpoints:
- `GET /status` — PS5 state
- `GET /screenshot` — take and return screenshot
- `POST /button/{name}` — press a button (cross, circle, up, down, etc.)
- `POST /probe/send` — send a probe script (body = Lua source)

## How It Works on Windows

- **No focus stealing:** Button presses use `PostMessage` Win32 API to send keystrokes directly to the Chiaki window handle. Your other windows stay focused.
- **Screenshots:** Uses `pyautogui` to capture the Chiaki window region without focusing it.
- **Recovery:** When the game crashes, the keeper sends the recovery button sequence via PostMessage — you won't see any window switching.

## Troubleshooting

**Chiaki not found:** Make sure chiaki-ng is installed and `chiaki.exe` is in one of these paths:
- `%LOCALAPPDATA%\Programs\chiaki-ng\chiaki.exe`
- `C:\Program Files\chiaki-ng\chiaki.exe`
- Or anywhere on your PATH

**Keys not reaching PS5:** Make sure Chiaki is connected to the PS5 and the stream is active. PostMessage only works when the Chiaki window exists.

**Port 9026 closed:** The game may have crashed. The keeper should auto-recover. If not, manually relaunch the game.

**Wake-on-LAN not working:** Set the correct MAC address in `config.json`. On PS5, enable Settings > System > Power Saving > Features Available in Rest Mode > Stay Connected to the Internet.

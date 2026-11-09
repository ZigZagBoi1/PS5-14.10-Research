# macOS Console Control Setup

Port of PR #46's Linux unattended PS5 control for macOS.

## Prerequisites

1. **chiaki-ng** (recommended) or Sony PS Remote Play app
   ```bash
   brew install --cask chiaki-ng
   ```

2. **Python 3** (system Python is fine — no pip dependencies needed)

3. **Accessibility permissions**: macOS requires explicit permission for synthetic keyboard events.
   - System Settings → Privacy & Security → Accessibility
   - Add your Terminal app (Terminal.app, iTerm2, or whichever you use)
   - If running from a script/cron, add the parent process too

4. **chiaki-ng keyboard input**: Add to `~/Library/Preferences/Chiaki/Chiaki.conf` (or configure via GUI):
   ```ini
   keyboard_enabled=true
   mouse_touch_enabled=true
   ```

## Files

| File | Role |
|------|------|
| `kbd_macos.py` | CGEvent keyboard injector — `python3 kbd_macos.py return` |
| `ps5_key_macos` | Focus chiaki + inject — `./ps5_key_macos return` = Cross on PS5 |
| `ps5_watchdog_macos` | 5-min loop: stale beacons → reload → PS wake dance → relaunch |

## chiaki-ng Keyboard Mapping

| Key | PS5 Button | Key | PS5 Button |
|-----|-----------|-----|-----------|
| Return | Cross | C | Triangle |
| Escape | PS | arrows | D-pad |
| Space | Options | T | Touchpad press |

## Quick Test

```bash
# 1. Open chiaki-ng and connect to PS5
# 2. Test key injection:
./ps5_key_macos return    # should press Cross on PS5
./ps5_key_macos down      # D-pad down
./ps5_key_macos c         # Triangle (reload page in guide app)

# 3. Start watchdog (background):
export PS5_BEACON_LOG="$HOME/ps5-lab/https.log"
nohup ./ps5_watchdog_macos &
```

## Environment Variables (for watchdog)

| Variable | Default | Description |
|----------|---------|-------------|
| `PS5_BEACON_LOG` | `~/ps5-lab/https.log` | Path to beacon log file |
| `PS5_WATCHDOG_LOG` | `~/ps5-lab/watchdog.log` | Watchdog's own log |
| `PS5_CHIAKI_CMD` | (none) | chiaki binary path for auto-relaunch |
| `PS5_IP` | `10.0.0.96` | PS5 IP for stream relaunch |
| `PS5_CHIAKI_PROFILE` | `PS5` | chiaki profile name |

## Differences from Linux Version

- **Input injection**: AppleScript `keystroke`/`key code` via osascript (no pip deps) instead of uinput
- **Window focus**: AppleScript via `osascript` instead of KWin DBus scripting
- **Date parsing**: macOS `date -j -f` instead of GNU `date -d`
- **No X11/Wayland workarounds needed**: macOS CGEvent works globally
- **Accessibility permission required**: must be granted in System Settings

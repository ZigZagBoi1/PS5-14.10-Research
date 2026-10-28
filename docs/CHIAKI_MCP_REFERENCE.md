# Chiaki-ng MCP Server Reference

How to control the PS5 remotely using the custom chiaki-ng build with its built-in MCP server.

## Quick start

The MCP server is an HTTP JSON-RPC 2.0 endpoint at **http://localhost:9339**. The chiaki-ng app must be running (there's a shortcut on the Desktop: `chiaki-ng (AI control).lnk`).

Call pattern (PowerShell):
```powershell
$body = @{
    jsonrpc = "2.0"
    id = 1
    method = "tools/call"
    params = @{
        name = "<tool_name>"
        arguments = @{ <key> = <value> }
    }
} | ConvertTo-Json -Depth 5
$r = Invoke-WebRequest -Uri "http://localhost:9339" -Method POST -Body $body -ContentType "application/json" -TimeoutSec 30
$r.Content | ConvertFrom-Json
```

## Source location

Custom chiaki-ng with MCP: `C:\Users\Marwan's Laptop\Desktop\chiaki-ng\`

Key source files:
- `gui/src/mcpchiakitools.cpp` — all PS5/controller MCP tools
- `gui/src/mcpserver.cpp` — HTTP JSON-RPC server
- `gui/src/mcpuitools.cpp` — UI tools (screenshots, clicks, key presses)
- `gui/src/mcproutines.cpp` — saved routine system
- `gui/src/mcprecorder.cpp` — routine recorder
- `scripts/mcp/chiaki-mcp-stdio.py` — stdio bridge for MCP clients

## Available tools

### Discovery & connection
| Tool | Description |
|------|-------------|
| `get_app_state` | Chiaki state: stream status, consoles, video, bitrate, packet loss |
| `list_hosts` | List known PS5/PS4 consoles with index, name, address, state |
| `connect_host` | Start Remote Play stream. Args: `{index: 0}` or `{name: "PS5-054"}` |
| `wake_host` | Wake a manual console from rest mode |
| `disconnect_stream` | End stream. Optional: `{sleep_console: true}` |
| `wait_for_stream` | Wait for stream state. Args: `{state: "video", timeout_ms: 15000}` |

### Controller
| Tool | Description |
|------|-------------|
| `controller_input` | Press buttons, move sticks. Args: `{buttons: ["cross"]}`, `{sequence: ["dpad_down","cross"]}`, or `{steps: [...]}` with `hold_ms`, `wait_ms` |
| `release_controller` | Release all held buttons/sticks |

Button names: `cross`, `circle`, `square`, `triangle`, `dpad_up`, `dpad_down`, `dpad_left`, `dpad_right`, `l1`, `r1`, `l2`, `r2`, `l3`, `r3`, `options`, `share`, `touchpad`, `ps`

### Screenshots & UI
| Tool | Description |
|------|-------------|
| `take_screenshot` | Capture current screen |
| `match_checkpoints` | Check which known screen is showing (no screenshot needed) |
| `get_ui_tree` | Get chiaki's own UI element tree |
| `click_element` | Click a chiaki UI element by id |
| `press_key` | Send keyboard key to chiaki |

### Routines
| Tool | Description |
|------|-------------|
| `list_routines` | List saved routines |
| `run_routine` | Run a saved routine by name |
| `save_routine` | Save a new routine |
| `save_checkpoint` | Save a screen checkpoint for matching |

### Diagnostics
| Tool | Description |
|------|-------------|
| `mcp_self_check` | Full diagnostic: window, capture, UI, consoles, stream |
| `get_action_history` | Recent tool calls with outcomes |
| `get_usage_guide` | Full usage guide. `{topic: "ps5"}` for PS5-specific playbook |

## PS5 details

- **PS5 name:** PS5-054
- **PS5 IP:** 10.0.0.96
- **Game:** Hamidashi Creative (PS4 version running on PS5)
- **Lua loader port:** 9026 (check with `Test-NetConnection -ComputerName 10.0.0.96 -Port 9026`)

## Common workflows

### Check if game is running
```powershell
Test-NetConnection -ComputerName 10.0.0.96 -Port 9026 -WarningAction SilentlyContinue
```

### Relaunch game after crash
1. `list_hosts` — confirm PS5 is visible (state "ready" = no game running)
2. Wait 5s (discovery→connect race condition)
3. `connect_host {index: 0}`
4. `wait_for_stream {state: "video", timeout_ms: 15000}`
5. Check screenshot — if crash dialog (CE-108255-1): press `cross` to dismiss
6. Press `ps` (hold 500ms) to go to home screen
7. Confirm home screen shows Hamidashi Creative with "Play Game"
8. Press `cross` to launch
9. Wait 60s for game to load
10. Verify port 9026 is reachable

### Quick relaunch (stream drops are normal during launch)
```powershell
# Connect and immediately launch (game tile should already be selected)
Start-Sleep -Seconds 8
# connect_host index=0
# wait_for_stream state=video
# controller_input buttons=["cross"]  (launches game)
Start-Sleep -Seconds 60
Test-NetConnection -ComputerName 10.0.0.96 -Port 9026
```

### Saved routines available
Run `list_routines` to see all. Known routines include:
- `relaunch_game` — full relaunch sequence
- `ensure_game_running` — check and relaunch if needed
- `recover_and_launch` — recover from crash + launch
- `recover_to_home` — get back to home screen
- `launch_game` — launch from home screen
- `close_game` — close running game
- `wait_loader_ready` — wait for Lua loader on port 9026

## Important notes

- The PS5 Remote Play stream **drops frequently** during game launch transitions — this is normal PS5 behavior, not an error
- Always add a **5-second delay** between `list_hosts` and `connect_host` to avoid the index race condition
- `controller_input` requires an active stream — if stream dropped, reconnect first
- The `last_session_error` "Server shut down" is normal when the PS5 transitions between states
- **Never update firmware** — the PS5 is on fw 14.10 for security research
- The chiaki-ng app must be running with `--mcp` flag (the Desktop shortcut does this)

"""stdio MCP server for observed, one-button-at-a-time Chiaki Remote Play control."""

from __future__ import annotations

import json
import os

from mcp.server.fastmcp import FastMCP, Image

from chiaki_bridge import ChiakiBridge, DEFAULT_KEYS, Frame
from recovery import restart_hamidashi as run_restart_hamidashi

mcp = FastMCP("Chiaki PS5 Remote Play", instructions=(
    "Observe the PS5 frame before every button. Use the frame_token returned by observe_ps5 "
    "with press_ps5_button. Each press returns a fresh frame and token. Interpret that frame "
    "before the next input. Never infer success from a TCP port or an unchanged frame alone. "
    "Never press buttons blindly after capture, focus, or stream failure."
))
bridge = ChiakiBridge(os.getenv("CHIAKI_MCP_KEYMAP"))


def frame_result(frame: Frame):
    metadata = {
        "frame_token": frame.token,
        "width": frame.width,
        "height": frame.height,
        "sha256": frame.sha256,
        "brightness": frame.brightness,
        "variation": frame.variation,
        "warning": "Frame is nearly uniform; verify that the stream is displaying a real PS5 screen" if frame.variation < 2 else None,
    }
    return [json.dumps(metadata), Image(data=frame.png, format="png")]


@mcp.tool()
def chiaki_status() -> dict:
    """Read Chiaki window/process state without touching the PS5. Does not prove loader health."""
    return bridge.status()


@mcp.tool()
def focus_chiaki() -> dict:
    """Bring the existing Chiaki stream window forward. Does not launch, close, or reconnect it."""
    return bridge.focus()


@mcp.tool()
def observe_ps5():
    """Capture the visible Chiaki client area. Returns PNG and a short-lived frame token."""
    return frame_result(bridge.capture())


@mcp.tool()
def press_ps5_button(button: str, frame_token: str, hold_ms: int = 90, repeat: int = 1):
    """Press one named PS5 button via Chiaki's keyboard mapping, then return a fresh frame.

    Requires a frame token issued within 10 seconds by observe_ps5 or the previous press.
    Inspect each returned image before issuing another press. No macros or blind sequences.
    """
    return frame_result(bridge.press(button, frame_token, hold_ms, repeat))


@mcp.tool()
def controls_guide() -> dict:
    """Explain Chiaki's default PS5 button mapping and the observe/act/verify workflow."""
    return {
        "buttons": DEFAULT_KEYS,
        "active_mapping": bridge.keymap,
        "workflow": ["chiaki_status", "focus_chiaki if needed", "observe_ps5", "press_ps5_button with frame_token", "inspect returned image and repeat"],
        "notes": [
            "Cross confirms, Circle backs out, PS opens the control center; PS5 menu behavior depends on screen context.",
            "Keys reflect Chiaki's default mapping; CHIAKI_MCP_KEYMAP can supply a local JSON override.",
            "Capture uses the visible Windows desktop. Chiaki must be in foreground and unobscured.",
            "Never close or disconnect Chiaki to recover the Lua loader; navigate the PS5 UI using observed frames.",
        ],
    }


@mcp.tool()
def restart_hamidashi() -> list:
    """Close and relaunch Hamidashi Creative using calibrated visual checks, then framed-ping Lua.

    Use only for this PS5 and its observed home layout. Aborts before a game
    action when the tile or Close Game selection is not confidently matched.
    Closing the game intentionally ends its current loader process.
    """
    status, frame = run_restart_hamidashi(bridge)
    return [json.dumps(status), *frame_result(frame)]


@mcp.prompt()
def recover_lua_loader(game_name: str = "Hamidashi Creative") -> str:
    """Teach an AI to relaunch the PS5 Lua loader game using observed frames."""
    return (
        f"Relaunch {game_name} through the existing Chiaki stream. First call chiaki_status. "
        "If needed, focus_chiaki, then observe_ps5. Interpret each PNG before using "
        "press_ps5_button with its frame_token. Use PS to reach the home/control center, "
        "navigate based on the visible UI, use Options on the game's tile to close it if "
        "needed, then open the same game. Never assume the tile position or send a fixed "
        "button sequence. Wait for the game's loader notification on screen. Confirm loader "
        "health separately with a framed ping; TCP connect alone is insufficient. If any "
        "capture fails, stop pressing buttons and report the exact failure. Keep the Chiaki "
        "stream connected."
    )


if __name__ == "__main__":
    mcp.run(transport="stdio")

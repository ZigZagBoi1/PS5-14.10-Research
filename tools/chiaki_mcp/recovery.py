"""Guarded fast path for the observed Hamidashi Creative PS5 home layout."""

from __future__ import annotations

import socket
import struct
import time
from pathlib import Path

import cv2
import numpy as np

from chiaki_bridge import ChiakiBridge, ChiakiError, Frame

TEMPLATES = Path(__file__).with_name("templates")


def match(frame: Frame, name: str) -> float:
    image = cv2.imdecode(np.frombuffer(frame.png, dtype=np.uint8), cv2.IMREAD_GRAYSCALE)
    reference = cv2.imread(str(TEMPLATES / name), cv2.IMREAD_GRAYSCALE)
    if image is None or reference is None:
        raise ChiakiError("Could not decode PS5 frame or recovery template")
    if image.shape[0] < reference.shape[0] or image.shape[1] < reference.shape[1]:
        raise ChiakiError("Chiaki window is too small for the calibrated recovery templates")
    return float(cv2.matchTemplate(image, reference, cv2.TM_CCOEFF_NORMED).max())


def framed_ping(host: str = "10.0.0.96", port: int = 9026) -> bool:
    payload = b'print("=== PONG ===")\n'
    try:
        with socket.create_connection((host, port), timeout=1.0) as sock:
            sock.settimeout(1.5)
            sock.sendall(struct.pack("<Q", len(payload)) + payload)
            return b"=== PONG ===" in sock.recv(4096)
    except (OSError, TimeoutError):
        return False


def restart_hamidashi(bridge: ChiakiBridge, host: str = "10.0.0.96") -> tuple[dict, Frame]:
    """Close/relaunch only after verifying the expected tile and Close Game row.

    A failed screen check aborts before the next PS5 button. The loader is
    reported healthy only when a framed Lua ping returns PONG.
    """
    import win32con
    import win32gui

    started = time.monotonic()
    bridge.focus()
    win32gui.ShowWindow(bridge.find_window(), win32con.SW_MAXIMIZE)
    frame = bridge.capture()
    frame = bridge.press("ps", frame.token, hold_ms=1100)
    bridge.focus()
    frame = bridge.capture()
    tile_score = match(frame, "hamidashi_tile.png")
    if tile_score < 0.78:
        raise ChiakiError(f"Hamidashi game tile is not selected (match={tile_score:.2f}); stopped before Options")

    frame = bridge.press("options", frame.token)
    bridge.focus()
    frame = bridge.capture()
    frame = bridge.press("up", frame.token, repeat=9)
    bridge.focus()
    frame = bridge.capture()
    close_score = match(frame, "close_game_selected.png")
    if close_score < 0.78:
        raise ChiakiError(f"Close Game is not visibly selected (match={close_score:.2f}); stopped before Cross")

    frame = bridge.press("cross", frame.token)
    closing_started = time.monotonic()
    while time.monotonic() - closing_started < 8:
        time.sleep(0.25)
        bridge.focus()
        frame = bridge.capture()
        if match(frame, "hamidashi_tile.png") >= 0.78 and match(frame, "close_game_selected.png") < 0.7:
            break
    else:
        raise ChiakiError("Game did not visibly finish closing within 8 seconds; stopped before relaunch")

    frame = bridge.press("cross", frame.token)
    launched_at = time.monotonic()
    pong = False
    while time.monotonic() - launched_at < 12:
        time.sleep(0.5)
        if framed_ping(host):
            pong = True
            break
    bridge.focus()
    frame = bridge.capture()
    return {
        "loader_healthy": pong,
        "elapsed_seconds": round(time.monotonic() - started, 2),
        "launch_to_ping_seconds": round(time.monotonic() - launched_at, 2),
        "tile_match": round(tile_score, 3),
        "close_game_match": round(close_score, 3),
        "result": "framed PONG received" if pong else "no framed PONG within 12 seconds; game was relaunched but loader health is unverified",
    }, frame

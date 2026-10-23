"""Windows Chiaki window discovery, visible-frame capture, and guarded input."""

from __future__ import annotations

import hashlib
import io
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path

from PIL import ImageGrab, ImageStat

# Chiaki defaults from gui/src/settings.cpp, GetControllerMappingForDecoding.
DEFAULT_KEYS = {
    "cross": "enter", "circle": "backspace", "square": "\\", "triangle": "c",
    "up": "up", "down": "down", "left": "left", "right": "right",
    "l1": "2", "r1": "3", "l2": "1", "r2": "4",
    "l3": "5", "r3": "6", "options": "o", "share": "f",
    "touchpad": "t", "ps": "esc",
}


class ChiakiError(RuntimeError):
    pass


@dataclass(frozen=True)
class Frame:
    png: bytes
    width: int
    height: int
    sha256: str
    token: str
    captured_at: float
    brightness: float
    variation: float


class ChiakiBridge:
    def __init__(self, keymap_path: str | None = None):
        self.keymap = DEFAULT_KEYS.copy()
        if keymap_path:
            overrides = json.loads(Path(keymap_path).read_text(encoding="utf-8"))
            if not isinstance(overrides, dict) or any(k not in self.keymap or not isinstance(v, str) for k, v in overrides.items()):
                raise ValueError("keymap must be a JSON object of known button names to key strings")
            self.keymap.update(overrides)
        self.last_frame: Frame | None = None
        self.last_hwnd: int | None = None

    @staticmethod
    def _win():
        if os.name != "nt":
            raise ChiakiError("This bridge requires Windows with a visible Chiaki desktop session")
        # The MCP process can start DPI-unaware while Pillow captures physical
        # pixels. Align Win32 client coordinates with ImageGrab's pixel space.
        import ctypes
        ctypes.windll.user32.SetProcessDPIAware()
        import win32gui
        import win32process
        import psutil
        return win32gui, win32process, psutil

    def find_window(self) -> int:
        win32gui, win32process, psutil = self._win()
        matches: list[int] = []

        def visit(hwnd: int, _param: object) -> None:
            if not win32gui.IsWindowVisible(hwnd) or win32gui.GetWindow(hwnd, 4):
                return
            try:
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                proc = psutil.Process(pid)
                if proc.name().lower() == "chiaki.exe" and "chiaki" in win32gui.GetWindowText(hwnd).lower():
                    matches.append(hwnd)
            except (psutil.Error, OSError):
                return

        win32gui.EnumWindows(visit, None)
        if len(matches) != 1:
            raise ChiakiError(f"Expected one visible chiaki.exe window; found {len(matches)}. Keep one stream window open.")
        return matches[0]

    def status(self) -> dict:
        win32gui, _, psutil = self._win()
        hwnd = self.find_window()
        _, _, width, height = win32gui.GetClientRect(hwnd)
        _, pid = __import__("win32process").GetWindowThreadProcessId(hwnd)
        process = psutil.Process(pid)
        return {
            "chiaki_running": process.is_running(),
            "pid": pid,
            "window_title": win32gui.GetWindowText(hwnd),
            "foreground": win32gui.GetForegroundWindow() == hwnd,
            "minimized": bool(win32gui.IsIconic(hwnd)),
            "client_width": width,
            "client_height": height,
            "stream_mode": "stream" in process.cmdline(),
            "last_frame_age_seconds": round(time.monotonic() - self.last_frame.captured_at, 2) if self.last_frame else None,
        }

    def capture(self) -> Frame:
        win32gui, _, _ = self._win()
        hwnd = self.find_window()
        if win32gui.IsIconic(hwnd):
            raise ChiakiError("Chiaki is minimized; restore it before capture")
        if win32gui.GetForegroundWindow() != hwnd:
            raise ChiakiError("Chiaki is not foreground; use focus_chiaki, then capture again")
        left, top = win32gui.ClientToScreen(hwnd, (0, 0))
        right, bottom = win32gui.ClientToScreen(hwnd, win32gui.GetClientRect(hwnd)[2:])
        if right - left < 100 or bottom - top < 100:
            raise ChiakiError("Chiaki client area is too small to inspect")
        try:
            image = ImageGrab.grab(bbox=(left, top, right, bottom), all_screens=True)
        except Exception as exc:
            raise ChiakiError(f"Desktop frame capture failed: {exc}") from exc
        rgb = image.convert("RGB")
        # Detect a fully empty grab; a dark PS5 screen is valid and still returned.
        stats = ImageStat.Stat(rgb.resize((64, 64)))
        variation = sum(stats.stddev) / 3
        brightness = sum(stats.mean) / 3
        output = io.BytesIO()
        rgb.save(output, format="PNG")
        png = output.getvalue()
        digest = hashlib.sha256(png).hexdigest()
        frame = Frame(png, rgb.width, rgb.height, digest, os.urandom(12).hex(), time.monotonic(), round(brightness, 2), round(variation, 2))
        self.last_frame, self.last_hwnd = frame, hwnd
        return frame

    def focus(self) -> dict:
        win32gui, _, _ = self._win()
        hwnd = self.find_window()
        if win32gui.IsIconic(hwnd):
            win32gui.ShowWindow(hwnd, 9)
        try:
            win32gui.SetForegroundWindow(hwnd)
        except Exception:
            pass
        time.sleep(0.15)
        if win32gui.GetForegroundWindow() != hwnd:
            # Windows may deny programmatic foreground activation without
            # raising. Raise the existing window without activating it, then
            # click only if its own title bar is visibly at the target point.
            import win32con
            flags = win32con.SWP_NOMOVE | win32con.SWP_NOSIZE | win32con.SWP_NOACTIVATE
            win32gui.SetWindowPos(hwnd, win32con.HWND_TOPMOST, 0, 0, 0, 0, flags)
            try:
                left, top, right, _ = win32gui.GetWindowRect(hwnd)
                x, y = min(left + 80, right - 20), top + 15
                if win32gui.WindowFromPoint((x, y)) != hwnd:
                    raise ChiakiError("Chiaki title bar is covered; focus it manually before capture")
                import pyautogui
                pyautogui.click(x, y)
                time.sleep(0.15)
            finally:
                win32gui.SetWindowPos(hwnd, win32con.HWND_NOTOPMOST, 0, 0, 0, 0, flags)
        if win32gui.GetForegroundWindow() != hwnd:
            raise ChiakiError("Chiaki did not become foreground; no PS5 input was sent")
        return {"foreground": win32gui.GetForegroundWindow() == hwnd, "next": "Call observe_ps5 before pressing buttons"}

    def press(self, button: str, frame_token: str, hold_ms: int = 90, repeat: int = 1) -> Frame:
        button = button.lower().strip()
        if button not in self.keymap:
            raise ChiakiError(f"Unknown button {button!r}; use controls_guide")
        if not 40 <= hold_ms <= 2500:
            raise ChiakiError("hold_ms must be between 40 and 2500")
        if not 1 <= repeat <= 10 or (repeat > 1 and button not in {"up", "down", "left", "right"}):
            raise ChiakiError("repeat must be 1-10 and only directional buttons may repeat")
        before = self.last_frame
        if before is None or frame_token != before.token:
            raise ChiakiError("Frame token missing or stale; call observe_ps5 before each button")
        if time.monotonic() - before.captured_at > 10:
            raise ChiakiError("Frame is older than 10 seconds; observe again")
        win32gui, _, _ = self._win()
        hwnd = self.find_window()
        if hwnd != self.last_hwnd or win32gui.GetForegroundWindow() != hwnd or win32gui.IsIconic(hwnd):
            raise ChiakiError("Chiaki window or focus changed; observe again")
        # Consume the token before input, including failed injections. Never replay blindly.
        self.last_frame = None
        import pyautogui
        pyautogui.PAUSE = 0
        key = self.keymap[button]
        for _ in range(repeat):
            if win32gui.GetForegroundWindow() != hwnd:
                raise ChiakiError("Chiaki lost focus during input; remaining presses were cancelled")
            pyautogui.keyDown(key)
            try:
                time.sleep(hold_ms / 1000)
            finally:
                pyautogui.keyUp(key)
            if repeat > 1:
                time.sleep(0.055)
        time.sleep(0.2)
        if win32gui.GetForegroundWindow() != hwnd:
            self.focus()
        return self.capture()

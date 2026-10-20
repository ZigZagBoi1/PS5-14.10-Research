#!/usr/bin/env python3
"""
macOS keyboard injector using AppleScript keystroke/key code.
No external dependencies — uses osascript via subprocess.

Usage:
    python3 kbd_macos.py return        # Cross button
    python3 kbd_macos.py c             # Triangle
    python3 kbd_macos.py escape        # PS button
    python3 kbd_macos.py down          # D-pad down
    python3 kbd_macos.py ctrl+o        # modifier combo
    python3 kbd_macos.py --daemon      # read lines from stdin
"""

import subprocess
import sys
import time

# AppleScript key codes for non-character keys
KEYCODE = {
    "return": 36, "enter": 36,
    "escape": 53, "esc": 53,
    "down": 125, "up": 126, "left": 123, "right": 124,
    "space": 49,
    "backspace": 51, "delete": 51,
    "tab": 48,
    "f1": 122, "f2": 120, "f3": 99, "f4": 118,
    "f5": 96, "f6": 97, "f7": 98, "f8": 100,
    "insert": 114, "pageup": 116, "pagedown": 121,
}

# Keys that can use 'keystroke "X"' instead of 'key code N'
CHAR_KEYS = set("abcdefghijklmnopqrstuvwxyz0123456789")

MOD_APPLESCRIPT = {
    "shift": "shift down",
    "ctrl": "control down",
    "alt": "option down",
    "cmd": "command down",
    "command": "command down",
}


def tap(key, mods=()):
    mod_str = ""
    if mods:
        parts = [MOD_APPLESCRIPT.get(m) for m in mods]
        if None in parts:
            bad = [m for m in mods if m not in MOD_APPLESCRIPT]
            print(f"unknown modifier: {bad}", file=sys.stderr)
            return
        mod_str = " using {" + ", ".join(parts) + "}"

    if key in CHAR_KEYS:
        script = f'tell application "System Events" to keystroke "{key}"{mod_str}'
    elif key in KEYCODE:
        script = f'tell application "System Events" to key code {KEYCODE[key]}{mod_str}'
    else:
        print(f"unknown key: {key}", file=sys.stderr)
        return

    subprocess.run(["osascript", "-e", script], capture_output=True, timeout=5)


if __name__ == "__main__":
    args = sys.argv[1:]
    if args and args[0] == "--daemon":
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            parts = line.split("+")
            try:
                if len(parts) == 1:
                    tap(parts[0])
                else:
                    tap(parts[-1], mods=parts[:-1])
            except Exception as e:
                print(f"error: {e}", file=sys.stderr)
    else:
        for spec in args:
            parts = spec.split("+")
            if len(parts) == 1:
                tap(parts[0])
            else:
                tap(parts[-1], mods=parts[:-1])

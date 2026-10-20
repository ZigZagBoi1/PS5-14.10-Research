"""
Controller Input — Send button presses to the Chiaki window.

Two modes:
1. USB DualSense HID (if hidapi installed and controller plugged in)
2. Keyboard simulation to the Chiaki window (fallback, no extra hardware)

Chiaki's default keyboard mapping:
  Cross=Return, Circle=Backspace, Square=F, Triangle=R
  D-Pad=Arrow keys, L1=Q, R1=E, L2=1, R2=3
  Options=Escape, Share/Create=C, PS=Home, Touchpad=T
  Left stick=WASD, Right stick=IJKL
"""
import platform
import subprocess
import time
import logging

log = logging.getLogger("ps5remote.controller")

CHIAKI_KEYMAP = {
    "cross": "Return", "x": "Return",
    "circle": "BackSpace", "o": "BackSpace",
    "square": "f", "triangle": "r",
    "l1": "q", "r1": "e",
    "l2": "1", "r2": "3",
    "up": "Up", "down": "Down", "left": "Left", "right": "Right",
    "options": "Escape", "share": "c", "create": "c",
    "ps": "Home", "touchpad": "t", "mute": "m",
    "lstick_up": "w", "lstick_down": "s", "lstick_left": "a", "lstick_right": "d",
    "rstick_up": "i", "rstick_down": "k", "rstick_left": "j", "rstick_right": "l",
}

MAC_KEY_CODES = {
    "Return": 36, "BackSpace": 51, "Escape": 53, "Home": 115, "Tab": 48,
    "Up": 126, "Down": 125, "Left": 123, "Right": 124,
    "f": 3, "r": 15, "q": 12, "e": 14, "c": 8, "t": 17, "m": 46,
    "1": 18, "3": 20,
    "w": 13, "a": 0, "s": 1, "d": 2,
    "i": 34, "j": 38, "k": 40, "l": 37,
}


class ChiakiController:
    def __init__(self):
        self.system = platform.system().lower()
        self.connected = False

    def connect(self):
        self.connected = True
        log.info(f"Chiaki keyboard controller ready ({self.system})")
        return True

    def disconnect(self):
        self.connected = False

    def _send_key_mac(self, key_name, duration=0.1, hold=False):
        code = MAC_KEY_CODES.get(key_name)
        if code is None:
            log.warning(f"No Mac key code for: {key_name}")
            return False

        if hold:
            script = f'''
            tell application "System Events"
                tell process "Chiaki"
                    set frontmost to true
                end tell
                delay 0.1
                key down {code}
                delay {duration}
                key up {code}
            end tell
            '''
        else:
            script = f'''
            tell application "System Events"
                tell process "Chiaki"
                    set frontmost to true
                end tell
                delay 0.05
                key code {code}
            end tell
            '''
        try:
            subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=5)
            return True
        except Exception as e:
            log.error(f"AppleScript key send failed: {e}")
            return False

    def _send_key_windows(self, key_name, duration=0.1, hold=False):
        ps_script = f'''
        Add-Type @"
        using System;
        using System.Runtime.InteropServices;
        public class Win32 {{
            [DllImport("user32.dll")] public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
            [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
        }}
"@
        $procs = Get-Process | Where-Object {{ $_.MainWindowTitle -like '*Chiaki*' -or $_.ProcessName -like '*chiaki*' }}
        if ($procs) {{
            $hwnd = $procs[0].MainWindowHandle
            [Win32]::SetForegroundWindow($hwnd)
            Start-Sleep -Milliseconds 100
        }}
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.SendKeys]::SendWait("{{{key_name}}}")
        '''
        win_keymap = {
            "Return": "ENTER", "BackSpace": "BACKSPACE", "Escape": "ESC",
            "Home": "HOME", "Up": "UP", "Down": "DOWN", "Left": "LEFT", "Right": "RIGHT",
            "Tab": "TAB",
        }
        mapped = win_keymap.get(key_name, key_name)
        ps_script = ps_script.replace(f"{{{key_name}}}", f"{{{mapped}}}" if mapped != key_name else key_name)

        try:
            subprocess.run(["powershell", "-c", ps_script], capture_output=True, text=True, timeout=5)
            return True
        except Exception as e:
            log.error(f"PowerShell key send failed: {e}")
            return False

    def _send_key(self, key_name, duration=0.1, hold=False):
        if self.system == "darwin":
            return self._send_key_mac(key_name, duration, hold)
        elif self.system == "windows":
            return self._send_key_windows(key_name, duration, hold)
        else:
            log.error(f"Unsupported platform: {self.system}")
            return False

    def press(self, button, duration=0.1):
        key = CHIAKI_KEYMAP.get(button.lower())
        if not key:
            log.warning(f"Unknown button: {button}")
            return False
        ok = self._send_key(key, duration)
        time.sleep(0.05)
        return ok

    def hold(self, button, duration=1.0):
        key = CHIAKI_KEYMAP.get(button.lower())
        if not key:
            return False
        return self._send_key(key, duration, hold=True)

    def combo(self, buttons, duration=0.15):
        for b in buttons:
            self.press(b, duration)
            time.sleep(0.05)

    def ps_button(self):
        return self.press("ps", 0.3)

    def navigate_home(self):
        self.ps_button()
        time.sleep(1.5)

    def sequence(self, steps, gap=0.3):
        for step in steps:
            if isinstance(step, str):
                self.press(step)
            elif isinstance(step, (list, tuple)):
                self.combo(step)
            elif isinstance(step, dict):
                action = step.get("action", "press")
                if action == "press":
                    self.press(step["button"], step.get("duration", 0.1))
                elif action == "hold":
                    self.hold(step["button"], step.get("duration", 1.0))
                elif action == "wait":
                    time.sleep(step.get("duration", 1.0))
                    continue
            time.sleep(gap)


def get_controller():
    ctrl = ChiakiController()
    ctrl.connect()
    return ctrl

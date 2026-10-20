"""
Controller Input — Send button presses to Chiaki window.

Background-friendly: briefly focuses Chiaki, sends key, refocuses previous app.
Also stores saved recovery sequences for crash/freeze/loader-crash scenarios.
"""
import platform
import subprocess
import time
import logging

log = logging.getLogger("ps5remote.controller")

CHIAKI_KEYMAP = {
    "cross": 36, "x": 36,
    "circle": 51, "o": 51,
    "square": 3, "triangle": 15,
    "l1": 12, "r1": 14,
    "l2": 18, "r2": 20,
    "up": 126, "down": 125, "left": 123, "right": 124,
    "options": 53, "share": 8, "create": 8,
    "ps": 115, "touchpad": 17, "mute": 46,
}

CHIAKI_KEYMAP_WIN = {
    "cross": "ENTER", "x": "ENTER",
    "circle": "BACKSPACE", "o": "BACKSPACE",
    "square": "f", "triangle": "r",
    "l1": "q", "r1": "e",
    "l2": "1", "r2": "3",
    "up": "UP", "down": "DOWN", "left": "LEFT", "right": "RIGHT",
    "options": "ESC", "share": "c", "create": "c",
    "ps": "HOME", "touchpad": "t",
}

RECOVERY_SEQUENCES = {
    "game_crash": [
        {"action": "wait", "duration": 2},
        {"action": "press", "button": "cross"},
        {"action": "wait", "duration": 2},
        {"action": "press", "button": "cross"},
        {"action": "wait", "duration": 3},
        {"action": "press", "button": "cross"},
        {"action": "wait", "duration": 5},
        {"action": "press", "button": "cross"},
        {"action": "wait", "duration": 10},
    ],
    "loader_crash": [
        {"action": "press", "button": "ps"},
        {"action": "wait", "duration": 2},
        {"action": "press", "button": "options"},
        {"action": "wait", "duration": 1},
        {"action": "press", "button": "down"},
        {"action": "wait", "duration": 0.3},
        {"action": "press", "button": "down"},
        {"action": "wait", "duration": 0.3},
        {"action": "press", "button": "down"},
        {"action": "wait", "duration": 0.3},
        {"action": "press", "button": "cross"},
        {"action": "wait", "duration": 2},
        {"action": "press", "button": "cross"},
        {"action": "wait", "duration": 5},
        {"action": "press", "button": "cross"},
        {"action": "wait", "duration": 15},
    ],
    "relaunch_game": [
        {"action": "press", "button": "ps"},
        {"action": "wait", "duration": 2},
        {"action": "press", "button": "cross"},
        {"action": "wait", "duration": 5},
        {"action": "press", "button": "cross"},
        {"action": "wait", "duration": 3},
        {"action": "press", "button": "cross"},
        {"action": "wait", "duration": 15},
    ],
    "dismiss_dialog": [
        {"action": "press", "button": "cross"},
        {"action": "wait", "duration": 1},
    ],
    "freeze_recovery": [
        {"action": "press", "button": "ps"},
        {"action": "wait", "duration": 3},
        {"action": "press", "button": "options"},
        {"action": "wait", "duration": 1},
        {"action": "press", "button": "down"},
        {"action": "wait", "duration": 0.3},
        {"action": "press", "button": "down"},
        {"action": "wait", "duration": 0.3},
        {"action": "press", "button": "down"},
        {"action": "wait", "duration": 0.3},
        {"action": "press", "button": "cross"},
        {"action": "wait", "duration": 3},
        {"action": "press", "button": "cross"},
        {"action": "wait", "duration": 5},
        {"action": "press", "button": "cross"},
        {"action": "wait", "duration": 5},
        {"action": "press", "button": "cross"},
        {"action": "wait", "duration": 15},
    ],
}


class ChiakiController:
    def __init__(self):
        self.system = platform.system().lower()
        self.connected = False
        self._has_cliclick = False
        if self.system == "darwin":
            r = subprocess.run(["which", "cliclick"], capture_output=True)
            self._has_cliclick = r.returncode == 0

    def connect(self):
        self.connected = True
        log.info(f"Chiaki controller ready ({self.system})")
        return True

    def disconnect(self):
        self.connected = False

    def press(self, button, duration=0.1):
        name = button.lower()
        if self.system == "darwin":
            return self._press_mac(name, duration)
        elif self.system == "windows":
            return self._press_windows(name, duration)
        return False

    def _press_mac(self, button, duration=0.1):
        code = CHIAKI_KEYMAP.get(button)
        if code is None:
            log.warning(f"Unknown button: {button}")
            return False

        script = f'''
        tell application "System Events"
            set prevApp to name of first process whose frontmost is true
            set frontmost of (first process whose name is "chiaki") to true
            delay 0.15
            key code {code}
            delay {max(duration, 0.05)}
            try
                set frontmost of (first process whose name is prevApp) to true
            end try
        end tell
        '''
        try:
            subprocess.run(["osascript", "-e", script], capture_output=True, timeout=5)
            return True
        except Exception as e:
            log.error(f"Key send failed: {e}")
            return False

    def _press_windows(self, button, duration=0.1):
        key = CHIAKI_KEYMAP_WIN.get(button)
        if not key:
            return False
        ps_script = f'''
$procs = Get-Process | Where-Object {{ $_.MainWindowTitle -like '*Chiaki*' -or $_.ProcessName -like '*chiaki*' }}
if ($procs) {{
    $prevHwnd = (Get-Process | Where-Object {{$_.MainWindowHandle -ne 0}} | Where-Object {{$_.Id -eq (Get-CimInstance Win32_Process -Filter "ProcessId=$PID").ParentProcessId}})[0].MainWindowHandle
    Add-Type @"
    using System; using System.Runtime.InteropServices;
    public class W {{ [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h); }}
"@
    [W]::SetForegroundWindow($procs[0].MainWindowHandle)
    Start-Sleep -Milliseconds 100
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.SendKeys]::SendWait("{{{key}}}")
    Start-Sleep -Milliseconds 50
    if ($prevHwnd) {{ [W]::SetForegroundWindow($prevHwnd) }}
}}
'''
        try:
            subprocess.run(["powershell", "-c", ps_script], capture_output=True, timeout=5)
            return True
        except Exception as e:
            log.error(f"Key send failed: {e}")
            return False

    def hold(self, button, duration=1.0):
        return self.press(button, duration)

    def combo(self, buttons, duration=0.15):
        for b in buttons:
            self.press(b, duration)
            time.sleep(0.05)

    def ps_button(self):
        return self.press("ps", 0.3)

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

    def run_recovery(self, scenario):
        steps = RECOVERY_SEQUENCES.get(scenario)
        if not steps:
            log.warning(f"Unknown recovery scenario: {scenario}")
            return False
        log.info(f"Running recovery: {scenario}")
        self.sequence(steps, gap=0)
        return True


def get_controller():
    ctrl = ChiakiController()
    ctrl.connect()
    return ctrl

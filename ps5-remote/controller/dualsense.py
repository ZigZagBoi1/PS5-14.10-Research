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
    "square": 3, "triangle": 8,
    "l1": 12, "r1": 14,
    "l2": 18, "r2": 20,
    "up": 126, "down": 125, "left": 123, "right": 124,
    "options": 49, "share": 8, "create": 8,
    "ps": 53, "touchpad": 17, "mute": 46,
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
        # Error dialog with OK → dismiss → home screen → Play Game → wait for loader
        {"action": "press", "button": "cross"},
        {"action": "wait", "duration": 1},
        {"action": "press", "button": "cross"},
        {"action": "wait", "duration": 1},
        {"action": "press", "button": "cross"},
        {"action": "wait", "duration": 2},
        # Now on home screen, game selected, press cross for "Play Game"
        {"action": "press", "button": "cross"},
        {"action": "wait", "duration": 2},
        {"action": "press", "button": "cross"},
        {"action": "wait", "duration": 20},
        # Dismiss any loader OK dialog
        {"action": "press", "button": "cross"},
        {"action": "wait", "duration": 3},
    ],
    "loader_crash": [
        # Same as game_crash — probes crash the game, so we get error dialog
        {"action": "press", "button": "cross"},
        {"action": "wait", "duration": 1},
        {"action": "press", "button": "cross"},
        {"action": "wait", "duration": 1},
        {"action": "press", "button": "cross"},
        {"action": "wait", "duration": 2},
        {"action": "press", "button": "cross"},
        {"action": "wait", "duration": 2},
        {"action": "press", "button": "cross"},
        {"action": "wait", "duration": 20},
        {"action": "press", "button": "cross"},
        {"action": "wait", "duration": 3},
    ],
    "relaunch_game": [
        # Already on home screen with game selected
        {"action": "press", "button": "cross"},
        {"action": "wait", "duration": 2},
        {"action": "press", "button": "cross"},
        {"action": "wait", "duration": 20},
        {"action": "press", "button": "cross"},
        {"action": "wait", "duration": 3},
    ],
    "dismiss_dialog": [
        {"action": "press", "button": "cross"},
        {"action": "wait", "duration": 1},
    ],
    "freeze_recovery": [
        # Force close via PS button → options → close game → relaunch
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
        # Now relaunch
        {"action": "press", "button": "cross"},
        {"action": "wait", "duration": 2},
        {"action": "press", "button": "cross"},
        {"action": "wait", "duration": 20},
        {"action": "press", "button": "cross"},
        {"action": "wait", "duration": 3},
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
            set targetProcess to first process whose name is "chiaki-ng" or name is "chiaki"
            set frontmost of targetProcess to true
            delay 0.08
            key code {code}
            delay {max(duration, 0.03)}
        end tell
        '''
        try:
            result = subprocess.run(["osascript", "-e", script], capture_output=True,
                                    text=True, timeout=5)
            if result.returncode != 0:
                log.error("Key send failed: %s", result.stderr.strip())
                return False
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
        ok = True
        for b in buttons:
            ok = self.press(b, duration) and ok
            time.sleep(0.05)
        return ok

    def ps_button(self):
        return self.press("ps", 0.3)

    def sequence(self, steps, gap=0.3):
        ok = True
        for step in steps:
            if isinstance(step, str):
                ok = self.press(step) and ok
            elif isinstance(step, (list, tuple)):
                ok = self.combo(step) and ok
            elif isinstance(step, dict):
                action = step.get("action", "press")
                if action == "press":
                    ok = self.press(step["button"], step.get("duration", 0.1)) and ok
                elif action == "hold":
                    ok = self.hold(step["button"], step.get("duration", 1.0)) and ok
                elif action == "wait":
                    time.sleep(step.get("duration", 1.0))
                    continue
            time.sleep(gap)
        return ok

    def run_recovery(self, scenario):
        steps = RECOVERY_SEQUENCES.get(scenario)
        if not steps:
            log.warning(f"Unknown recovery scenario: {scenario}")
            return False
        log.info(f"Running recovery: {scenario}")
        return self.sequence(steps, gap=0)


def get_controller():
    ctrl = ChiakiController()
    ctrl.connect()
    return ctrl

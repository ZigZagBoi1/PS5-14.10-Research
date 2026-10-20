"""
Controller Input — Send button presses to Chiaki window.

Uses a single AppleScript call per recovery sequence to minimize focus stealing.
Focuses Chiaki once, sends all keys, then refocuses previous app.
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
    "loader_crash": [
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
        {"action": "wait", "duration": 2},
        {"action": "press", "button": "cross"},
        {"action": "wait", "duration": 20},
        {"action": "press", "button": "cross"},
        {"action": "wait", "duration": 3},
    ],
}


def _find_chiaki_process_name():
    """Find which process name chiaki uses."""
    try:
        r = subprocess.run(["pgrep", "-il", "chiaki"], capture_output=True, text=True, timeout=3)
        for line in r.stdout.strip().splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2:
                name = parts[1]
                if "chiaki" in name.lower():
                    return name
    except Exception:
        pass
    return "chiaki"


def _build_batch_applescript(steps):
    """Build a single AppleScript that focuses Chiaki once, sends all keys
    with delays between them, then refocuses the previous app. One focus
    steal for an entire recovery sequence instead of one per button."""
    lines = []
    lines.append('tell application "System Events"')
    lines.append('    set prevApp to name of first process whose frontmost is true')
    lines.append('    try')
    lines.append('        set chiakiProc to first process whose name contains "chiaki"')
    lines.append('        set frontmost of chiakiProc to true')
    lines.append('    on error')
    lines.append('        return "no_chiaki"')
    lines.append('    end try')
    lines.append('    delay 0.15')

    for step in steps:
        if isinstance(step, dict):
            action = step.get("action", "press")
            if action == "wait":
                dur = step.get("duration", 1.0)
                lines.append(f'    delay {dur}')
            elif action == "press":
                code = CHIAKI_KEYMAP.get(step["button"].lower())
                if code is not None:
                    lines.append(f'    key code {code}')
                    lines.append(f'    delay 0.05')
            elif action == "hold":
                code = CHIAKI_KEYMAP.get(step["button"].lower())
                dur = step.get("duration", 1.0)
                if code is not None:
                    lines.append(f'    key code {code}')
                    lines.append(f'    delay {dur}')

    lines.append('    try')
    lines.append('        set frontmost of (first process whose name is prevApp) to true')
    lines.append('    end try')
    lines.append('end tell')
    return '\n'.join(lines)


class ChiakiController:
    def __init__(self):
        self.system = platform.system().lower()
        self.connected = False

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

        script = _build_batch_applescript([
            {"action": "press", "button": button},
        ])
        try:
            result = subprocess.run(["osascript", "-e", script], capture_output=True,
                                    text=True, timeout=8)
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
        return self._send_key_win_background(key)

    @staticmethod
    def _send_key_win_background(key):
        """Send a key to Chiaki on Windows WITHOUT stealing focus.
        Uses PostMessage to send WM_KEYDOWN/WM_KEYUP to the window handle."""
        ps_script = f'''
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class WinInput {{
    [DllImport("user32.dll")] public static extern IntPtr FindWindow(string cls, string title);
    [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
    [DllImport("user32.dll")] public static extern IntPtr FindWindowEx(IntPtr parent, IntPtr after, string cls, string title);
    public const uint WM_KEYDOWN = 0x0100;
    public const uint WM_KEYUP   = 0x0101;
}}
"@
$vkMap = @{{
    "ENTER"=0x0D; "BACKSPACE"=0x08; "ESCAPE"=0x1B; "TAB"=0x09; "SPACE"=0x20;
    "UP"=0x26; "DOWN"=0x28; "LEFT"=0x25; "RIGHT"=0x27;
    "HOME"=0x24; "END"=0x23; "DELETE"=0x2E; "INSERT"=0x2D;
    "F1"=0x70; "F2"=0x71; "F3"=0x72; "F4"=0x73; "F5"=0x74;
    "a"=0x41; "b"=0x42; "c"=0x43; "d"=0x44; "e"=0x45; "f"=0x46;
    "g"=0x47; "h"=0x48; "i"=0x49; "j"=0x4A; "k"=0x4B; "l"=0x4C;
    "m"=0x4D; "n"=0x4E; "o"=0x4F; "p"=0x50; "q"=0x51; "r"=0x52;
    "s"=0x53; "t"=0x54; "u"=0x55; "v"=0x56; "w"=0x57; "x"=0x58;
    "y"=0x59; "z"=0x5A;
    "1"=0x31; "2"=0x32; "3"=0x33; "4"=0x34; "5"=0x35;
    "ESC"=0x1B;
}}
$vk = $vkMap["{key}"]
if (-not $vk) {{ Write-Error "Unknown key: {key}"; exit 1 }}

$hwnd = [IntPtr]::Zero
$procs = Get-Process | Where-Object {{ $_.ProcessName -like '*chiaki*' -and $_.MainWindowHandle -ne 0 }}
if ($procs) {{ $hwnd = $procs[0].MainWindowHandle }}
if ($hwnd -eq [IntPtr]::Zero) {{ Write-Error "Chiaki not found"; exit 1 }}

[WinInput]::PostMessage($hwnd, [WinInput]::WM_KEYDOWN, [IntPtr]$vk, [IntPtr]::Zero) | Out-Null
Start-Sleep -Milliseconds 50
[WinInput]::PostMessage($hwnd, [WinInput]::WM_KEYUP, [IntPtr]$vk, [IntPtr]::Zero) | Out-Null
Write-Output "ok"
'''
        try:
            r = subprocess.run(["powershell", "-NoProfile", "-c", ps_script],
                               capture_output=True, text=True, timeout=5)
            if r.returncode != 0:
                log.error("Win key send failed: %s", r.stderr.strip())
                return False
            return True
        except Exception as e:
            log.error(f"Win key send failed: {e}")
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
        """Run a recovery sequence as a single batched call.
        Mac: one AppleScript, one focus steal. Windows: PostMessage, zero focus steal."""
        steps = RECOVERY_SEQUENCES.get(scenario)
        if not steps:
            log.warning(f"Unknown recovery scenario: {scenario}")
            return False
        log.info(f"Running recovery: {scenario} (batched)")

        if self.system == "darwin":
            return self._run_batch_mac(steps)
        elif self.system == "windows":
            return self._run_batch_win(steps)
        else:
            return self.sequence(steps, gap=0)

    def _run_batch_mac(self, steps):
        """Execute all steps in one AppleScript — one focus steal total."""
        script = _build_batch_applescript(steps)

        total_time = sum(
            s.get("duration", 0.05) for s in steps if isinstance(s, dict)
        ) + 5
        timeout = max(int(total_time) + 10, 15)

        try:
            result = subprocess.run(
                ["osascript", "-e", script],
                capture_output=True, text=True, timeout=timeout
            )
            if result.returncode != 0:
                log.error("Batch recovery failed: %s", result.stderr.strip())
                return False
            if "no_chiaki" in (result.stdout or ""):
                log.error("Chiaki process not found")
                return False
            log.info("Recovery sequence completed")
            return True
        except subprocess.TimeoutExpired:
            log.error(f"Recovery timed out after {timeout}s")
            return False
        except Exception as e:
            log.error(f"Recovery failed: {e}")
            return False


    def _run_batch_win(self, steps):
        """Execute all steps via PostMessage — zero focus stealing on Windows."""
        for step in steps:
            if not isinstance(step, dict):
                continue
            action = step.get("action", "press")
            if action == "wait":
                time.sleep(step.get("duration", 1.0))
            elif action in ("press", "hold"):
                key = CHIAKI_KEYMAP_WIN.get(step["button"].lower())
                if key:
                    self._send_key_win_background(key)
                    time.sleep(step.get("duration", 0.05) if action == "hold" else 0.05)
        log.info("Recovery sequence completed (Windows)")
        return True


def get_controller():
    ctrl = ChiakiController()
    ctrl.connect()
    return ctrl

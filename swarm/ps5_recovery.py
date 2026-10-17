"""PS5 crash auto-recovery via Chiaki-ng Remote Play.

When the Lua loader dies (game crash, sandbox kill, etc.), this module:
1. Detects the outage via health check failures
2. Connects to PS5 via Chiaki-ng Remote Play
3. Sends controller inputs to close the crashed game and reopen it
4. Waits for the loader to come back on port 9026

Requires: Chiaki-ng installed and paired with the PS5 (one-time setup).
"""

import subprocess
import time
import logging
import threading
import os

logger = logging.getLogger("swarm")

# Chiaki-ng paths (winget install location)
CHIAKI_PATHS = [
    r"C:\Program Files\chiaki-ng\chiaki.exe",
    r"C:\Program Files (x86)\chiaki-ng\chiaki.exe",
    os.path.expanduser(r"~\AppData\Local\Programs\chiaki-ng\chiaki.exe"),
    "chiaki",  # PATH fallback
]


def find_chiaki() -> str:
    for p in CHIAKI_PATHS:
        if p == "chiaki-ng":
            try:
                subprocess.run(["chiaki-ng", "--version"], capture_output=True, timeout=5)
                return p
            except Exception:
                continue
        elif os.path.isfile(p):
            return p
    return ""


class PS5Recovery:
    """Automated crash recovery for the PS5 loader."""

    def __init__(self, ps5_connection, ps5_ip: str = "10.0.0.96"):
        self.ps5 = ps5_connection
        self.ps5_ip = ps5_ip
        self.chiaki_path = find_chiaki()
        self.recovery_count = 0
        self.last_recovery = None
        self._lock = threading.Lock()

        if self.chiaki_path:
            logger.info(f"[recovery] Chiaki-ng found at: {self.chiaki_path}")
        else:
            logger.warning("[recovery] Chiaki-ng not found — manual recovery required for game crashes")

    def is_available(self) -> bool:
        return bool(self.chiaki_path)

    def attempt_recovery(self) -> bool:
        """Attempt to recover the PS5 loader after a crash.

        Recovery strategy:
        1. First, just wait — many crashes auto-recover (per-connection kills)
        2. If still down after 30s, try sending PS button via Chiaki-ng
        3. Navigate: close game → reopen game → wait for loader
        """
        with self._lock:
            logger.info("[recovery] === PS5 CRASH RECOVERY INITIATED ===")
            logger.info(f"[recovery] Consecutive failures: {self.ps5.consecutive_failures}")

            # Step 1: Wait briefly — per-connection crashes recover on their own
            logger.info("[recovery] Step 1: Waiting 30s for auto-recovery...")
            time.sleep(30)
            if self.ps5.health_check():
                logger.info("[recovery] Loader recovered on its own!")
                return True

            # Step 2: Wait a bit longer — game might be restarting
            logger.info("[recovery] Step 2: Waiting 60s more...")
            time.sleep(60)
            if self.ps5.health_check():
                logger.info("[recovery] Loader recovered after extended wait!")
                return True

            # Step 3: Try Chiaki-ng recovery
            if not self.chiaki_path:
                logger.error("[recovery] Chiaki-ng not available — cannot auto-recover.")
                logger.error("[recovery] Manual intervention required: reopen Hamidashi Creative on PS5")
                return False

            logger.info("[recovery] Step 3: Attempting Chiaki-ng remote recovery...")
            success = self._chiaki_recovery_sequence()

            if success:
                self.recovery_count += 1
                self.last_recovery = time.time()
                logger.info(f"[recovery] === RECOVERY SUCCESSFUL (total: {self.recovery_count}) ===")
            else:
                logger.error("[recovery] === RECOVERY FAILED — manual intervention needed ===")

            return success

    def _chiaki_recovery_sequence(self) -> bool:
        """Send controller inputs via Chiaki-ng to restart the game.

        Sequence:
        1. PS button (go to home screen / dismiss crash dialog)
        2. Wait for home screen
        3. Navigate to Hamidashi Creative
        4. Press X to launch
        5. Wait for loader to come up on port 9026
        """
        try:
            # For now, use a PowerShell script that sends keystrokes
            # Chiaki-ng maps keyboard keys to controller buttons
            recovery_script = self._generate_recovery_script()

            # Write temp script
            script_path = os.path.join(os.path.dirname(__file__), "state", "recovery_keys.ps1")
            os.makedirs(os.path.dirname(script_path), exist_ok=True)
            with open(script_path, "w") as f:
                f.write(recovery_script)

            # Execute the key sequence
            logger.info("[recovery] Launching Chiaki-ng and sending recovery inputs...")
            result = subprocess.run(
                ["powershell", "-ExecutionPolicy", "Bypass", "-File", script_path],
                capture_output=True, text=True, timeout=180
            )

            if result.returncode != 0:
                logger.error(f"[recovery] Recovery script failed: {result.stderr[:200]}")

            # Wait for loader to come back
            logger.info("[recovery] Waiting for loader to come back on port 9026...")
            return self.ps5.wait_for_loader(timeout=300, check_interval=10)

        except subprocess.TimeoutExpired:
            logger.error("[recovery] Recovery script timed out (180s)")
            return False
        except Exception as e:
            logger.error(f"[recovery] Recovery error: {e}")
            return False

    def _generate_recovery_script(self) -> str:
        """Generate PowerShell script that sends keystrokes to Chiaki-ng.

        Default Chiaki-ng key mappings:
        - PS button: Escape
        - X button: Return (Enter)
        - O button: Backspace
        - D-pad: Arrow keys
        - Options: F1
        """
        return f'''
# PS5 Crash Recovery via Chiaki-ng
# Sends controller inputs to close crashed game and reopen it

Add-Type -AssemblyName System.Windows.Forms

# Check if Chiaki-ng is running, start it if not
$chiaki = Get-Process -Name "chiaki-ng" -ErrorAction SilentlyContinue
if (-not $chiaki) {{
    Start-Process "{self.chiaki_path}"
    Start-Sleep -Seconds 5
    # Connect to PS5 (double-click the console entry)
    # This part depends on Chiaki-ng being pre-configured
    Start-Sleep -Seconds 10
}}

# Bring Chiaki-ng to foreground
$chiaki = Get-Process -Name "chiaki-ng" -ErrorAction SilentlyContinue
if ($chiaki) {{
    $sig = '[DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);'
    Add-Type -MemberDefinition $sig -Name WinAPI -Namespace Win32
    [Win32.WinAPI]::SetForegroundWindow($chiaki.MainWindowHandle)
    Start-Sleep -Seconds 1
}}

# Send PS button (Escape) to dismiss crash dialog / go to home
[System.Windows.Forms.SendKeys]::SendWait("{{ESC}}")
Start-Sleep -Seconds 3

# Send PS button again to make sure we're at home
[System.Windows.Forms.SendKeys]::SendWait("{{ESC}}")
Start-Sleep -Seconds 3

# If there's a "Close Application" prompt, press X (Enter)
[System.Windows.Forms.SendKeys]::SendWait("{{ENTER}}")
Start-Sleep -Seconds 5

# Navigate to the game (it should be the most recent on home screen)
# Press Enter (X button) to launch Hamidashi Creative
[System.Windows.Forms.SendKeys]::SendWait("{{ENTER}}")
Start-Sleep -Seconds 3

# Confirm launch if prompted
[System.Windows.Forms.SendKeys]::SendWait("{{ENTER}}")
Start-Sleep -Seconds 10

Write-Output "Recovery inputs sent. Waiting for loader..."
'''

    def get_status(self) -> dict:
        return {
            "chiaki_available": self.is_available(),
            "chiaki_path": self.chiaki_path,
            "recovery_count": self.recovery_count,
            "last_recovery": self.last_recovery,
        }

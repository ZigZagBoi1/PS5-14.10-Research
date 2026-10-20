"""
Chiaki Manager — Launch, monitor, and restart the Chiaki Remote Play client.

Chiaki connects directly to the PS5 over LAN. After one-time pairing,
it doesn't need PSN servers, so it works with the DNS blocker.
"""
import subprocess
import platform
import time
import os
import signal
import logging
import json

log = logging.getLogger("ps5remote.chiaki")

CHIAKI_PATHS = {
    "darwin": [
        "/Applications/Chiaki.app/Contents/MacOS/Chiaki",
        "/Applications/chiaki-ng.app/Contents/MacOS/chiaki",
        os.path.expanduser("~/Applications/Chiaki.app/Contents/MacOS/Chiaki"),
    ],
    "windows": [
        r"C:\Program Files\Chiaki\chiaki.exe",
        r"C:\Program Files\chiaki-ng\chiaki.exe",
        r"C:\Program Files (x86)\Chiaki\chiaki.exe",
    ],
}


def find_chiaki_binary():
    system = platform.system().lower()
    paths = CHIAKI_PATHS.get(system, [])
    for p in paths:
        if os.path.exists(p):
            return p
    for name in ["chiaki", "chiaki-ng"]:
        try:
            result = subprocess.run(["which" if system != "windows" else "where", name],
                                    capture_output=True, text=True, timeout=5)
            path = result.stdout.strip()
            if path and os.path.exists(path):
                return path
        except Exception:
            pass
    return None


def is_chiaki_running():
    system = platform.system().lower()
    try:
        if system == "darwin":
            # Match the main executable, not QtWebEngine helpers whose paths
            # also contain the application bundle name.
            result = subprocess.run(["pgrep", "-ix", "chiaki"], capture_output=True, text=True, timeout=5)
        elif system == "windows":
            result = subprocess.run(["tasklist", "/FI", "IMAGENAME eq chiaki.exe"],
                                    capture_output=True, text=True, timeout=5)
        else:
            result = subprocess.run(["pgrep", "-f", "chiaki"], capture_output=True, text=True, timeout=5)
        return result.returncode == 0 and result.stdout.strip() != ""
    except Exception:
        return False


def kill_chiaki():
    system = platform.system().lower()
    try:
        if system == "windows":
            subprocess.run(["taskkill", "/F", "/IM", "chiaki.exe"], capture_output=True, timeout=5)
        elif system == "darwin":
            subprocess.run(["pkill", "-ix", "chiaki"], capture_output=True, timeout=5)
        else:
            subprocess.run(["pkill", "-f", "chiaki"], capture_output=True, timeout=5)
        time.sleep(1)
        return True
    except Exception:
        return False


class ChiakiSession:
    def __init__(self, ps5_ip, regist_key=None, morning_salt=None, config_dir=None):
        self.ps5_ip = ps5_ip
        self.regist_key = regist_key
        self.morning_salt = morning_salt
        self.process = None
        self.binary = find_chiaki_binary()
        self.config_dir = config_dir or os.path.join(os.path.dirname(__file__), "..", "chiaki_config")

    def is_available(self):
        return self.binary is not None

    def launch(self, fullscreen=True):
        if not self.binary:
            log.error("Chiaki not found. Install chiaki-ng first.")
            return False

        if is_chiaki_running():
            log.info("Chiaki already running")
            return True

        cmd = [self.binary]
        if self.regist_key:
            cmd.extend(["--connect", self.ps5_ip])

        env = os.environ.copy()
        try:
            self.process = subprocess.Popen(
                cmd, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            log.info(f"Chiaki launched (PID={self.process.pid})")
            time.sleep(3)
            return self.process.poll() is None
        except Exception as e:
            log.error(f"Failed to launch Chiaki: {e}")
            return False

    def stop(self):
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.process = None
        else:
            kill_chiaki()

    def restart(self):
        log.info("Restarting Chiaki...")
        self.stop()
        time.sleep(2)
        return self.launch()

    def is_connected(self):
        if self.process and self.process.poll() is not None:
            return False
        return is_chiaki_running()

    def health_check(self):
        if not is_chiaki_running():
            return {"status": "dead", "action": "restart"}
        return {"status": "ok"}

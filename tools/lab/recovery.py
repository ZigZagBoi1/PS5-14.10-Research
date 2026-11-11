"""PS5 recovery via Chiaki keyboard input.

Recovery strategies:
  1. WebProcess crash: page reload via PS5 browser (navigate away and back)
  2. Game freeze: close game + relaunch via Chiaki controller input
  3. Remote Play disconnect: restart Chiaki process
  4. Console panic: STOP — log and require human power cycle
"""
from __future__ import annotations
import os
import socket
import subprocess
import sys
import time
from .classifier import Outcome, Classification
from .config import LabConfig

CHIAKI_BRIDGE_AVAILABLE = False
try:
    if os.name == "nt":
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        from chiaki_mcp.chiaki_bridge import ChiakiBridge, ChiakiError
        CHIAKI_BRIDGE_AVAILABLE = True
except ImportError:
    pass


def is_lua_loader_up(ip: str, port: int = 9026, timeout: float = 3.0) -> bool:
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.close()
        return True
    except OSError:
        return False


def is_console_alive(ip: str, timeout: float = 3.0) -> bool:
    try:
        s = socket.create_connection((ip, 80), timeout=timeout)
        s.close()
        return True
    except OSError:
        pass
    try:
        s = socket.create_connection((ip, 443), timeout=timeout)
        s.close()
        return True
    except OSError:
        pass
    import subprocess as sp
    r = sp.run(["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip],
               capture_output=True, timeout=timeout + 2)
    return r.returncode == 0


def wait_for_loader(ip: str, port: int = 9026, timeout: float = 120.0,
                    poll: float = 3.0, log=None) -> bool:
    log = log or print
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        if is_lua_loader_up(ip, port):
            log(f"[+] Loader answering after {time.monotonic() - start:.0f}s")
            return True
        time.sleep(poll)
    log(f"[!] Loader not back after {timeout:.0f}s")
    return False


class RecoveryEngine:
    def __init__(self, config: LabConfig, log=None):
        self.cfg = config
        self.log = log or print
        self._bridge = None
        self._consecutive_failures = 0

    def _get_bridge(self):
        if not CHIAKI_BRIDGE_AVAILABLE:
            return None
        if self._bridge is None:
            try:
                self._bridge = ChiakiBridge()
            except Exception as e:
                self.log(f"[!] ChiakiBridge init failed: {e}")
        return self._bridge

    def attempt_recovery(self, classification: Classification) -> bool:
        if classification.outcome == Outcome.CONSOLE_PANIC:
            self.log("[!!] SUSPECTED CONSOLE PANIC — stopping. Power cycle required.")
            self._consecutive_failures += 1
            return False

        if classification.outcome == Outcome.SUCCESS:
            self._consecutive_failures = 0
            return True

        self._consecutive_failures += 1
        if self._consecutive_failures >= self.cfg.max_consecutive_crashes:
            self.log(f"[!!] {self._consecutive_failures} consecutive failures — stopping.")
            return False

        if classification.outcome == Outcome.SERVER_FAILURE:
            self.log("[*] Server-side failure — no console recovery needed.")
            return True

        if classification.outcome == Outcome.WEBPROCESS_CRASH:
            self.log("[*] WebProcess crash — waiting for page recovery...")
            time.sleep(5)
            return True

        if classification.outcome in (Outcome.APP_FREEZE, Outcome.RP_DISCONNECT):
            self.log("[*] App freeze/disconnect — attempting Chiaki recovery...")
            return self._chiaki_game_restart()

        return True

    def _chiaki_game_restart(self) -> bool:
        if not self.cfg.chiaki_recovery_enabled:
            self.log("[!] Chiaki recovery disabled in config.")
            return False

        bridge = self._get_bridge()
        if bridge is None:
            self.log("[!] Chiaki bridge unavailable — manual recovery required.")
            return self._wait_for_manual_recovery()

        try:
            self.log("[*] Running Chiaki game-restart sequence...")
            frame = bridge.capture()
            token = frame.token

            for btn in ["cross"] * 5:
                frame = bridge.press(btn, token, hold_ms=100)
                token = frame.token
                time.sleep(0.3)

            for btn in ["circle"] * 3:
                frame = bridge.press(btn, token, hold_ms=100)
                token = frame.token
                time.sleep(0.3)

            frame = bridge.press("ps", token, hold_ms=1500)
            token = frame.token
            time.sleep(3)

            frame = bridge.press("circle", token, hold_ms=100)
            token = frame.token
            time.sleep(1)

            frame = bridge.press("options", token, hold_ms=150)
            token = frame.token
            time.sleep(2)

            for _ in range(6):
                frame = bridge.press("down", token, hold_ms=100)
                token = frame.token
                time.sleep(0.3)

            frame = bridge.press("cross", token, hold_ms=150)
            token = frame.token
            time.sleep(2)

            frame = bridge.press("cross", token, hold_ms=150)
            token = frame.token
            time.sleep(5)

            for _ in range(5):
                frame = bridge.press("cross", token, hold_ms=100)
                token = frame.token
                time.sleep(1)

            self.log("[*] Game restart sequence sent. Waiting for loader...")
            return wait_for_loader(self.cfg.ps5_ip, self.cfg.lua_port,
                                   self.cfg.chiaki_recovery_timeout_seconds,
                                   log=self.log)
        except Exception as e:
            self.log(f"[!] Chiaki recovery failed: {e}")
            return self._wait_for_manual_recovery()

    def _wait_for_manual_recovery(self) -> bool:
        self.log("[*] Waiting for manual game relaunch...")
        return wait_for_loader(self.cfg.ps5_ip, self.cfg.lua_port,
                               self.cfg.chiaki_recovery_timeout_seconds,
                               log=self.log)

    def check_for_panic(self) -> bool:
        if not is_console_alive(self.cfg.ps5_ip):
            self.log("[!!] Console not responding to ping — possible kernel panic.")
            return True
        return False

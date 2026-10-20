"""
PS5 Game Keeper — Keeps the game running and probe port open.

This does NOT send probes. It only:
1. Monitors the probe port (9026)
2. If closed, runs recovery sequences to relaunch the game
3. Keeps Chiaki and PS5 alive

The AI loop (/loop) decides what probes to write and send via send_probe.py.
"""
import os
import sys
import time
import json
import logging
import signal
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from config import load_config
from capture.hdmi import take_screenshot
from capture.chiaki_manager import ChiakiSession, is_chiaki_running
from controller.dualsense import get_controller
from power.wake import is_probe_port_open, is_ps5_reachable, is_chiaki_port_open
from analyzer.screen import ScreenAnalyzer, ScreenState

log = logging.getLogger("ps5remote.keeper")

BASE_DIR = os.path.dirname(os.path.dirname(__file__))


def latest_probe_transport(ip, port, results_dir=None):
    """Read the newest sender sidecar for this console without probing it."""
    root = Path(results_dir or Path(BASE_DIR).parent / "results")
    newest = None
    newest_mtime = -1
    for path in root.rglob("*.json"):
        try:
            mtime = path.stat().st_mtime
            if mtime <= newest_mtime:
                continue
            record = json.loads(path.read_text(encoding="utf-8"))
            if record.get("remote") != f"{ip}:{port}" or "status" not in record:
                continue
            newest, newest_mtime = record, mtime
        except (OSError, ValueError, TypeError):
            continue
    return newest


class GameKeeper:
    def __init__(self, config=None):
        self.config = config or load_config()
        self.running = False
        self.controller = get_controller()
        self.chiaki = ChiakiSession(self.config["ps5_ip"])
        self.analyzer = ScreenAnalyzer(
            ai_provider="anthropic",
            api_key=os.environ.get("ANTHROPIC_API_KEY", ""),
        )
        self.screenshot_dir = os.path.join(BASE_DIR, self.config["screenshot_dir"])
        os.makedirs(self.screenshot_dir, exist_ok=True)
        self.log_file = os.path.join(BASE_DIR, self.config["log_file"])
        self.stats_file = os.path.join(BASE_DIR, "loop_stats.json")
        self.stats = {
            "started_at": datetime.now().isoformat(),
            "recoveries": 0,
            "chiaki_restarts": 0,
            "consecutive_port_closed": 0,
            "last_state": "starting",
            "last_recovery": "",
            "port_open_since": None,
            "last_probe_transport_status": None,
            "last_probe_response_bytes": None,
        }
        self.check_count = 0

    def log_event(self, event, details=""):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{ts}] {event}: {details}"
        with open(self.log_file, "a") as f:
            f.write(entry + "\n")
        log.info(entry)

    def save_stats(self):
        with open(self.stats_file, "w") as f:
            json.dump(self.stats, f, indent=2)

    def take_check_screenshot(self):
        self.check_count += 1
        fname = os.path.join(self.screenshot_dir, f"check_{self.check_count % 10:02d}.png")
        if take_screenshot(fname):
            return fname
        return None

    def recover_game(self, scenario="game_crash"):
        self.log_event("RECOVERY", f"Running {scenario} sequence")
        if self.controller.run_recovery(scenario):
            self.stats["recoveries"] += 1
            self.stats["last_recovery"] = f"{scenario} at {datetime.now().isoformat()}"
        else:
            self.log_event("RECOVERY_FAILED", f"{scenario} input sequence did not complete")

    def run(self):
        self.running = True
        self.log_event("KEEPER_START", json.dumps({
            "ps5_ip": self.config["ps5_ip"],
            "mode": "keep-alive only, no probe sending",
        }))

        use_ai = bool(os.environ.get("ANTHROPIC_API_KEY"))

        while self.running:
            try:
                if not is_ps5_reachable(self.config["ps5_ip"]):
                    self.stats["last_state"] = "ps5_unreachable"
                    self.log_event("PS5_OFFLINE", "PS5 not reachable")
                    time.sleep(30)
                    continue

                if not is_chiaki_running():
                    self.stats["chiaki_restarts"] += 1
                    self.log_event("CHIAKI_RESTART", "Chiaki not running")
                    self.chiaki.restart()
                    time.sleep(5)

                if is_probe_port_open(self.config["ps5_ip"], self.config["probe_port"]):
                    if self.stats["last_state"] != "port_open":
                        self.stats["port_open_since"] = datetime.now().isoformat()
                        self.log_event("PORT_OPEN", "TCP port 9026 is open; loader execution unverified")
                    self.stats["consecutive_port_closed"] = 0
                    self.stats["last_state"] = "port_open"
                    latest = latest_probe_transport(self.config["ps5_ip"], self.config["probe_port"])
                    if latest is not None:
                        status = latest["status"]
                        if status != self.stats["last_probe_transport_status"]:
                            self.log_event("PROBE_TRANSPORT", f"Last probe status: {status}")
                        self.stats["last_probe_transport_status"] = status
                        self.stats["last_probe_response_bytes"] = latest.get("response_bytes")
                    time.sleep(5)
                else:
                    self.stats["consecutive_port_closed"] += 1
                    self.stats["last_state"] = "port_closed"

                    if self.stats["consecutive_port_closed"] == 1:
                        self.log_event("PORT_CLOSED", "Probe port closed, checking screen")
                        screenshot = self.take_check_screenshot()
                        if screenshot:
                            state = self.analyzer.analyze(screenshot, use_ai=use_ai)
                            self.log_event("SCREEN_STATE", str(state))
                            if state == ScreenState.GAME_CRASHED or state == ScreenState.ERROR_DIALOG:
                                self.recover_game("game_crash")
                            elif state == ScreenState.HOME_SCREEN:
                                self.recover_game("relaunch_game")
                            elif state == ScreenState.BLACK_SCREEN:
                                self.recover_game("relaunch_game")
                            elif state == ScreenState.GAME_FROZEN:
                                self.recover_game("freeze_recovery")
                            else:
                                self.recover_game("game_crash")
                        else:
                            self.recover_game("game_crash")

                    elif self.stats["consecutive_port_closed"] >= 3:
                        self.log_event("RECOVERY_RETRY", f"Port still closed after {self.stats['consecutive_port_closed']} checks")
                        self.recover_game("game_crash")
                        self.stats["consecutive_port_closed"] = 0

                    time.sleep(5)

                self.save_stats()

            except KeyboardInterrupt:
                break
            except Exception as e:
                self.log_event("ERROR", str(e))
                time.sleep(10)

        self.running = False
        self.log_event("KEEPER_STOP", "Shutting down")

    def stop(self):
        self.running = False


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(os.path.join(BASE_DIR, "ps5_remote.log")),
        ]
    )

    config = load_config()
    keeper = GameKeeper(config)

    def signal_handler(sig, frame):
        log.info("Shutting down...")
        keeper.stop()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    log.info("=" * 60)
    log.info("PS5 GAME KEEPER — keeps port 9026 open for AI")
    log.info("=" * 60)
    log.info(f"PS5 IP: {config['ps5_ip']}")
    log.info("This does NOT send probes. Use send_probe.py or the API.")
    log.info("=" * 60)

    keeper.run()


if __name__ == "__main__":
    main()

"""
24/7 Autonomous Loop — Keeps PS5 research running unattended.

No continuous streaming. Takes a screenshot only when it needs to check state.
Recovery from crashes/freezes uses saved button sequences (no AI needed).
AI vision is optional — basic pixel analysis handles most cases.

When probe port 9026 is open: sends probes from the queue.
When it's closed: runs recovery sequence to relaunch the game.
"""
import os
import sys
import time
import json
import logging
import signal
import socket
import struct
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from config import load_config
from capture.hdmi import take_screenshot
from capture.chiaki_manager import ChiakiSession, is_chiaki_running
from controller.dualsense import get_controller, RECOVERY_SEQUENCES
from power.wake import wake_ps5, get_ps5_state, is_probe_port_open, is_ps5_reachable
from analyzer.screen import ScreenAnalyzer, ScreenState

log = logging.getLogger("ps5remote.loop")

BASE_DIR = os.path.dirname(os.path.dirname(__file__))


class LoopStats:
    def __init__(self):
        self.started_at = datetime.now().isoformat()
        self.iterations = 0
        self.probes_sent = 0
        self.probes_failed = 0
        self.recoveries = 0
        self.chiaki_restarts = 0
        self.ps5_wakes = 0
        self.errors = 0
        self.last_state = "starting"
        self.last_action = "starting"
        self.last_probe = ""
        self.last_action_time = datetime.now().isoformat()
        self.consecutive_port_closed = 0

    def to_dict(self):
        return self.__dict__

    def save(self, path):
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)


class AutonomousLoop:
    def __init__(self, config=None, probe_dir=None):
        self.config = config or load_config()
        self.running = False
        self.stats = LoopStats()
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
        self.probe_dir = probe_dir
        self.probe_queue = []
        self._load_probe_queue()

    def _load_probe_queue(self):
        if self.probe_dir and os.path.isdir(self.probe_dir):
            for f in sorted(os.listdir(self.probe_dir)):
                if f.endswith(".lua"):
                    self.probe_queue.append(os.path.join(self.probe_dir, f))
            log.info(f"Loaded {len(self.probe_queue)} probes from {self.probe_dir}")

    def log_event(self, event, details=""):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{ts}] {event}: {details}"
        with open(self.log_file, "a") as f:
            f.write(entry + "\n")
        log.info(entry)

    def take_check_screenshot(self):
        self.stats.iterations += 1
        fname = os.path.join(self.screenshot_dir, f"check_{self.stats.iterations % 10:02d}.png")
        if take_screenshot(fname):
            return fname
        return None

    def check_probe_port(self):
        return is_probe_port_open(self.config["ps5_ip"], self.config["probe_port"])

    def send_probe(self, probe_file):
        if not os.path.exists(probe_file):
            self.log_event("PROBE_MISSING", probe_file)
            return False

        try:
            with open(probe_file, "r") as f:
                source = f.read()

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(60)
            sock.connect((self.config["ps5_ip"], self.config["probe_port"]))

            payload = source.encode("utf-8")
            sock.sendall(struct.pack("<Q", len(payload)))
            sock.sendall(payload)

            chunks = []
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
                except socket.timeout:
                    break
            sock.close()

            output = b"".join(chunks).decode("utf-8", errors="replace")
            probe_name = os.path.basename(probe_file).replace(".lua", "")
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            result_dir = os.path.join(BASE_DIR, "..", "results", "autonomous")
            os.makedirs(result_dir, exist_ok=True)
            result_file = os.path.join(result_dir, f"{probe_name}_{ts}.txt")
            with open(result_file, "w") as f:
                f.write(output)

            self.stats.probes_sent += 1
            self.stats.last_probe = probe_name
            self.log_event("PROBE_SENT", f"{probe_name} -> {result_file} ({len(output)} bytes)")
            return True

        except Exception as e:
            self.stats.probes_failed += 1
            self.log_event("PROBE_FAILED", f"{probe_file}: {e}")
            return False

    def recover_game(self, scenario="loader_crash"):
        self.stats.recoveries += 1
        self.log_event("RECOVERY", f"Running {scenario} sequence")
        self.controller.run_recovery(scenario)
        self.stats.last_action = f"recovery:{scenario}"
        self.stats.last_action_time = datetime.now().isoformat()

    def ensure_chiaki(self):
        if not is_chiaki_running():
            self.stats.chiaki_restarts += 1
            self.log_event("CHIAKI_RESTART", "Chiaki not running, restarting")
            self.chiaki.restart()
            time.sleep(5)
            return is_chiaki_running()
        return True

    def ensure_ps5_awake(self):
        if not is_ps5_reachable(self.config["ps5_ip"]):
            self.stats.ps5_wakes += 1
            self.log_event("PS5_WAKE", "PS5 not reachable, sending WOL")
            wake_ps5(self.config["ps5_ip"], self.config["ps5_mac"])
            time.sleep(20)
            return is_ps5_reachable(self.config["ps5_ip"])
        return True

    def run(self):
        self.running = True
        self.log_event("LOOP_START", json.dumps({
            "ps5_ip": self.config["ps5_ip"],
            "probes_queued": len(self.probe_queue),
        }))

        self.ensure_chiaki()
        interval = self.config["screenshot_interval"]
        use_ai = bool(os.environ.get("ANTHROPIC_API_KEY"))

        while self.running:
            try:
                if not self.ensure_ps5_awake():
                    self.log_event("PS5_OFFLINE", "PS5 not reachable after WOL")
                    time.sleep(30)
                    continue

                self.ensure_chiaki()

                if self.check_probe_port():
                    self.stats.consecutive_port_closed = 0
                    self.stats.last_state = "probe_port_open"

                    if self.probe_queue:
                        probe = self.probe_queue.pop(0)
                        self.send_probe(probe)
                        time.sleep(2)
                    else:
                        self.log_event("IDLE", "Probe port open but queue empty")
                        time.sleep(10)
                else:
                    self.stats.consecutive_port_closed += 1
                    self.stats.last_state = "probe_port_closed"

                    if self.stats.consecutive_port_closed == 1:
                        self.log_event("PORT_CLOSED", "Probe port closed, checking screen")
                        screenshot = self.take_check_screenshot()
                        if screenshot:
                            state = self.analyzer.analyze(screenshot, use_ai=use_ai)
                            self.log_event("SCREEN_STATE", state)

                            if state == ScreenState.GAME_CRASHED or state == ScreenState.ERROR_DIALOG:
                                self.recover_game("game_crash")
                            elif state == ScreenState.HOME_SCREEN:
                                self.recover_game("relaunch_game")
                            elif state == ScreenState.BLACK_SCREEN:
                                self.recover_game("relaunch_game")
                            elif state == ScreenState.GAME_FROZEN:
                                self.recover_game("freeze_recovery")
                            else:
                                self.recover_game("loader_crash")

                    elif self.stats.consecutive_port_closed >= 3:
                        self.log_event("RECOVERY_RETRY", f"Port still closed after {self.stats.consecutive_port_closed} checks")
                        self.recover_game("loader_crash")
                        self.stats.consecutive_port_closed = 0

                    time.sleep(interval * 3)

                if self.stats.iterations % 50 == 0:
                    self.stats.save(self.stats_file)
                    self.log_event("STATS", json.dumps(self.stats.to_dict()))

                time.sleep(interval)

            except KeyboardInterrupt:
                break
            except Exception as e:
                self.stats.errors += 1
                self.log_event("ERROR", str(e))
                time.sleep(10)

        self.running = False
        self.stats.save(self.stats_file)
        self.log_event("LOOP_STOP", json.dumps(self.stats.to_dict()))

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

    probe_dir = None
    if len(sys.argv) > 1:
        probe_dir = sys.argv[1]
        if not os.path.isdir(probe_dir):
            probe_dir = os.path.join(BASE_DIR, "..", probe_dir)

    loop = AutonomousLoop(config, probe_dir=probe_dir)

    def signal_handler(sig, frame):
        log.info("Shutting down...")
        loop.stop()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    log.info("=" * 60)
    log.info("PS5 AUTONOMOUS RESEARCH LOOP")
    log.info("=" * 60)
    log.info(f"PS5 IP: {config['ps5_ip']}")
    log.info(f"Check interval: {config['screenshot_interval']}s")
    log.info(f"Probes queued: {len(loop.probe_queue)}")
    log.info(f"AI vision: {'on' if os.environ.get('ANTHROPIC_API_KEY') else 'off'}")
    log.info("=" * 60)

    loop.run()


if __name__ == "__main__":
    main()

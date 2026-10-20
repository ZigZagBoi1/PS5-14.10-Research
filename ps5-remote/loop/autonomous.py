"""
24/7 Autonomous Loop — The main brain that keeps PS5 research running.

This loop:
1. Takes screenshots via Chiaki
2. Analyzes the screen state
3. Detects crashes, freezes, disconnects
4. Relaunches the game automatically
5. Reconnects Chiaki if it dies
6. Wakes the PS5 if it sleeps
7. Sends probes when the game is running
8. Logs everything

The AI agent calls the REST API; this loop is the fallback autopilot
that handles recovery even when no AI agent is actively connected.
"""
import os
import sys
import time
import json
import logging
import threading
import signal
import socket
import struct
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from config import load_config
from capture.hdmi import take_screenshot, get_latest_screenshot
from capture.chiaki_manager import ChiakiSession, is_chiaki_running
from controller.dualsense import get_controller
from power.wake import wake_ps5, get_ps5_state, is_probe_port_open
from analyzer.screen import ScreenAnalyzer, ScreenState

log = logging.getLogger("ps5remote.loop")


class LoopStats:
    def __init__(self):
        self.started_at = datetime.now().isoformat()
        self.iterations = 0
        self.crashes_detected = 0
        self.freezes_detected = 0
        self.relaunches = 0
        self.chiaki_restarts = 0
        self.ps5_wakes = 0
        self.probes_sent = 0
        self.errors = 0
        self.last_state = ScreenState.UNKNOWN
        self.last_action = "starting"
        self.last_action_time = datetime.now().isoformat()

    def to_dict(self):
        return self.__dict__


class AutonomousLoop:
    def __init__(self, config=None, probe_queue=None):
        self.config = config or load_config()
        self.running = False
        self.stats = LoopStats()
        self.controller = get_controller()
        self.chiaki = ChiakiSession(self.config["ps5_ip"])
        self.analyzer = ScreenAnalyzer(
            ai_provider="anthropic",
            api_key=os.environ.get("ANTHROPIC_API_KEY", ""),
        )
        self.screenshot_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), self.config["screenshot_dir"])
        os.makedirs(self.screenshot_dir, exist_ok=True)
        self.probe_queue = probe_queue or []
        self.probe_lock = threading.Lock()
        self.last_good_time = time.time()
        self.consecutive_frozen = 0
        self.consecutive_black = 0
        self.log_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), self.config["log_file"])

    def log_event(self, event, details=""):
        ts = datetime.now().isoformat()
        entry = f"[{ts}] {event}: {details}\n"
        with open(self.log_file, "a") as f:
            f.write(entry)
        log.info(f"{event}: {details}")

    def take_screenshot(self):
        self.stats.iterations += 1
        fname = os.path.join(self.screenshot_dir, f"loop_{self.stats.iterations:08d}.png")
        if take_screenshot(fname):
            return fname
        return None

    def cleanup_old_screenshots(self, keep=50):
        import glob
        files = sorted(glob.glob(os.path.join(self.screenshot_dir, "loop_*.png")))
        if len(files) > keep:
            for f in files[:-keep]:
                try:
                    os.remove(f)
                except Exception:
                    pass

    def handle_state(self, state, screenshot_path):
        self.stats.last_state = state
        now = time.time()

        if state == ScreenState.GAME_RUNNING:
            self.last_good_time = now
            self.consecutive_frozen = 0
            self.consecutive_black = 0
            self._maybe_send_probe()
            return "running"

        elif state == ScreenState.HOME_SCREEN:
            self.last_good_time = now
            self.consecutive_frozen = 0
            self.consecutive_black = 0
            self.log_event("HOME_SCREEN", "Game not running, attempting relaunch")
            return self._relaunch_game()

        elif state == ScreenState.GAME_CRASHED or state == ScreenState.ERROR_DIALOG:
            self.stats.crashes_detected += 1
            self.log_event("CRASH_DETECTED", f"state={state}")
            return self._handle_crash()

        elif state == ScreenState.GAME_FROZEN:
            self.consecutive_frozen += 1
            if self.consecutive_frozen >= 3:
                self.stats.freezes_detected += 1
                self.log_event("FREEZE_DETECTED", f"frozen for {self.consecutive_frozen} checks")
                return self._handle_freeze()
            return "monitoring_freeze"

        elif state == ScreenState.BLACK_SCREEN:
            self.consecutive_black += 1
            if self.consecutive_black >= 5:
                self.log_event("BLACK_SCREEN_EXTENDED", "PS5 may be off or Chiaki disconnected")
                return self._handle_black_screen()
            return "monitoring_black"

        elif state == ScreenState.CHIAKI_DISCONNECTED:
            self.log_event("CHIAKI_DISCONNECTED", "Restarting Chiaki")
            return self._restart_chiaki()

        elif state == ScreenState.LOADING:
            self.last_good_time = now
            return "loading"

        return "unknown"

    def _handle_crash(self):
        ctrl = self.controller
        time.sleep(1)
        ctrl.press("cross")
        time.sleep(2)
        ctrl.press("cross")
        time.sleep(2)
        return self._relaunch_game()

    def _handle_freeze(self):
        ctrl = self.controller
        ctrl.ps_button()
        time.sleep(2)
        ctrl.press("options")
        time.sleep(1)
        for _ in range(3):
            ctrl.press("down")
            time.sleep(0.3)
        ctrl.press("cross")
        time.sleep(2)
        ctrl.press("cross")
        time.sleep(5)
        self.consecutive_frozen = 0
        return self._relaunch_game()

    def _relaunch_game(self):
        self.stats.relaunches += 1
        self.log_event("RELAUNCH", "Attempting game relaunch")
        ctrl = self.controller

        ctrl.ps_button()
        time.sleep(2)

        ctrl.press("cross")
        time.sleep(5)

        ctrl.press("cross")
        time.sleep(3)

        self.stats.last_action = "relaunch"
        self.stats.last_action_time = datetime.now().isoformat()
        return "relaunched"

    def _handle_black_screen(self):
        if not is_chiaki_running():
            return self._restart_chiaki()

        ps5_state = get_ps5_state(self.config["ps5_ip"], self.config["probe_port"])
        if ps5_state == "off" or ps5_state == "rest_mode":
            self.stats.ps5_wakes += 1
            self.log_event("WAKING_PS5", f"PS5 state: {ps5_state}")
            wake_ps5(self.config["ps5_ip"], self.config["ps5_mac"])
            time.sleep(15)
            return self._restart_chiaki()

        self.consecutive_black = 0
        return "black_screen_handled"

    def _restart_chiaki(self):
        self.stats.chiaki_restarts += 1
        self.log_event("CHIAKI_RESTART", "Restarting Chiaki session")
        self.chiaki.restart()
        time.sleep(5)
        self.stats.last_action = "chiaki_restart"
        self.stats.last_action_time = datetime.now().isoformat()
        return "chiaki_restarted"

    def _maybe_send_probe(self):
        with self.probe_lock:
            if not self.probe_queue:
                return
            if not is_probe_port_open(self.config["ps5_ip"], self.config["probe_port"]):
                return
            probe_file = self.probe_queue.pop(0)

        self.log_event("SENDING_PROBE", probe_file)
        try:
            self._send_probe(probe_file)
            self.stats.probes_sent += 1
        except Exception as e:
            self.stats.errors += 1
            self.log_event("PROBE_ERROR", str(e))

    def _send_probe(self, probe_file):
        if not os.path.exists(probe_file):
            raise FileNotFoundError(probe_file)

        with open(probe_file, "r") as f:
            source = f.read()

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)
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
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        result_file = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "results", f"{os.path.basename(probe_file)}_{ts}.txt"
        )
        os.makedirs(os.path.dirname(result_file), exist_ok=True)
        with open(result_file, "w") as f:
            f.write(output)
        self.log_event("PROBE_COMPLETE", f"{probe_file} -> {result_file}")

    def add_probe(self, probe_file):
        with self.probe_lock:
            self.probe_queue.append(probe_file)

    def run(self):
        self.running = True
        self.log_event("LOOP_START", json.dumps({"config": {
            "ps5_ip": self.config["ps5_ip"],
            "interval": self.config["screenshot_interval"],
        }}))

        if not is_chiaki_running():
            self.log_event("STARTING_CHIAKI", "Initial launch")
            self.chiaki.launch()
            time.sleep(5)

        interval = self.config["screenshot_interval"]
        use_ai = bool(os.environ.get("ANTHROPIC_API_KEY"))

        while self.running:
            try:
                screenshot = self.take_screenshot()
                if screenshot:
                    state = self.analyzer.analyze(screenshot, use_ai=use_ai)
                    action = self.handle_state(state, screenshot)
                    if self.stats.iterations % 30 == 0:
                        self.log_event("STATUS", json.dumps(self.stats.to_dict()))
                        self.cleanup_old_screenshots()
                else:
                    if not is_chiaki_running():
                        self._restart_chiaki()

                time.sleep(interval)

            except KeyboardInterrupt:
                break
            except Exception as e:
                self.stats.errors += 1
                self.log_event("ERROR", str(e))
                time.sleep(5)

        self.running = False
        self.log_event("LOOP_STOP", json.dumps(self.stats.to_dict()))

    def stop(self):
        self.running = False


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler("ps5_remote.log"),
        ]
    )

    config = load_config()
    loop = AutonomousLoop(config)

    def signal_handler(sig, frame):
        log.info("Shutting down...")
        loop.stop()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    log.info("Starting autonomous PS5 control loop")
    log.info(f"PS5 IP: {config['ps5_ip']}")
    log.info(f"Screenshot interval: {config['screenshot_interval']}s")
    log.info(f"AI analysis: {'enabled' if os.environ.get('ANTHROPIC_API_KEY') else 'disabled (set ANTHROPIC_API_KEY)'}")

    loop.run()


if __name__ == "__main__":
    main()

"""
REST API Server — HTTP interface for AI agents to control the PS5.

Endpoints:
  GET  /status           — PS5 state + Chiaki state + last screenshot analysis
  GET  /screenshot       — Take and return a screenshot (as PNG)
  GET  /screenshot/latest — Return the most recent screenshot
  POST /button/:name     — Press a button (cross, circle, up, down, etc.)
  POST /hold/:name       — Hold a button (with ?duration=1.0)
  POST /combo            — Press multiple buttons {buttons: ["l1","r1"]}
  POST /sequence         — Run a sequence of actions
  POST /relaunch         — Relaunch the game after crash
  POST /wake             — Wake PS5 from rest mode
  POST /chiaki/start     — Start Chiaki
  POST /chiaki/restart   — Restart Chiaki
  GET  /chiaki/status    — Chiaki health check
  GET  /analyze          — AI-analyze current screenshot
  POST /probe/send       — Send a Lua probe to PS5
"""
import os
import sys
import time
import json
import logging
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from config import load_config
from capture.hdmi import take_screenshot, get_latest_screenshot
from capture.chiaki_manager import ChiakiSession
from controller.dualsense import get_controller
from power.wake import wake_ps5, get_ps5_state
from analyzer.screen import ScreenAnalyzer, ScreenState

log = logging.getLogger("ps5remote.api")


class AppState:
    def __init__(self, config):
        self.config = config
        self.controller = get_controller()
        self.chiaki = ChiakiSession(config["ps5_ip"])
        self.analyzer = ScreenAnalyzer(
            ai_provider="anthropic",
            api_key=os.environ.get("ANTHROPIC_API_KEY", ""),
        )
        self.screenshot_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), config["screenshot_dir"])
        os.makedirs(self.screenshot_dir, exist_ok=True)
        self.last_state = ScreenState.UNKNOWN
        self.screenshot_counter = 0


def make_handler(app):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            log.info(format % args)

        def _json(self, data, status=200):
            body = json.dumps(data).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)

        def _png(self, path):
            with open(path, "rb") as f:
                data = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", len(data))
            self.end_headers()
            self.wfile.write(data)

        def _read_body(self):
            length = int(self.headers.get("Content-Length", 0))
            if length:
                return json.loads(self.rfile.read(length))
            return {}

        def do_GET(self):
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/")
            params = parse_qs(parsed.query)

            if path == "/status":
                ps5_state = get_ps5_state(app.config["ps5_ip"], app.config["probe_port"])
                self._json({
                    "ps5": ps5_state,
                    "chiaki": app.chiaki.health_check(),
                    "screen": app.last_state,
                    "controller": app.controller.connected,
                })

            elif path == "/screenshot":
                app.screenshot_counter += 1
                fname = os.path.join(app.screenshot_dir, f"api_{app.screenshot_counter:06d}.png")
                if take_screenshot(fname):
                    self._png(fname)
                else:
                    self._json({"error": "screenshot failed"}, 500)

            elif path == "/screenshot/latest":
                latest = get_latest_screenshot(app.screenshot_dir)
                if latest:
                    self._png(latest)
                else:
                    self._json({"error": "no screenshots"}, 404)

            elif path == "/chiaki/status":
                self._json(app.chiaki.health_check())

            elif path == "/analyze":
                use_ai = "ai" in params
                app.screenshot_counter += 1
                fname = os.path.join(app.screenshot_dir, f"analyze_{app.screenshot_counter:06d}.png")
                if take_screenshot(fname):
                    state = app.analyzer.analyze(fname, use_ai=use_ai)
                    app.last_state = state
                    self._json({"state": state, "screenshot": fname})
                else:
                    self._json({"error": "screenshot failed"}, 500)

            else:
                self._json({"error": "not found"}, 404)

        def do_POST(self):
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/")
            params = parse_qs(parsed.query)

            if path.startswith("/button/"):
                button = path.split("/button/")[1]
                duration = float(params.get("duration", [0.1])[0])
                ok = app.controller.press(button, duration)
                self._json({"ok": ok, "button": button})

            elif path.startswith("/hold/"):
                button = path.split("/hold/")[1]
                duration = float(params.get("duration", [1.0])[0])
                ok = app.controller.hold(button, duration)
                self._json({"ok": ok, "button": button, "duration": duration})

            elif path == "/combo":
                body = self._read_body()
                buttons = body.get("buttons", [])
                app.controller.combo(buttons)
                self._json({"ok": True, "buttons": buttons})

            elif path == "/sequence":
                body = self._read_body()
                steps = body.get("steps", [])
                gap = body.get("gap", 0.3)
                app.controller.sequence(steps, gap)
                self._json({"ok": True, "steps_count": len(steps)})

            elif path == "/relaunch":
                result = relaunch_game(app)
                self._json(result)

            elif path == "/wake":
                ok = wake_ps5(app.config["ps5_ip"], app.config["ps5_mac"])
                self._json({"ok": ok})

            elif path == "/chiaki/start":
                ok = app.chiaki.launch()
                self._json({"ok": ok})

            elif path == "/chiaki/restart":
                ok = app.chiaki.restart()
                self._json({"ok": ok})

            elif path == "/probe/send":
                body = self._read_body()
                probe_file = body.get("file", "")
                result = send_probe(app, probe_file)
                self._json(result)

            else:
                self._json({"error": "not found"}, 404)

    return Handler


def relaunch_game(app):
    log.info("Relaunching game...")
    ctrl = app.controller
    ctrl.ps_button()
    time.sleep(2)
    ctrl.press("options")
    time.sleep(1)
    ctrl.press("cross")
    time.sleep(1)
    ctrl.press("cross")
    time.sleep(3)
    ctrl.press("cross")
    time.sleep(5)
    return {"ok": True, "action": "relaunch_attempted"}


def send_probe(app, probe_file):
    import socket
    import struct

    if not os.path.exists(probe_file):
        return {"ok": False, "error": f"file not found: {probe_file}"}

    try:
        with open(probe_file, "r") as f:
            source = f.read()

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)
        sock.connect((app.config["ps5_ip"], app.config["probe_port"]))

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
        return {"ok": True, "output": output}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def start_server(config=None):
    if config is None:
        config = load_config()
    app = AppState(config)
    handler = make_handler(app)
    server = HTTPServer((config["api_host"], config["api_port"]), handler)
    log.info(f"API server on http://{config['api_host']}:{config['api_port']}")
    server.serve_forever()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    start_server()

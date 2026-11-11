"""Beacon monitor: polls telemetry API and classifies experiment outcomes.

Talks to the existing /api/events endpoint on 10.0.0.80:8081 (proxied
through nginx at /api/).  Also parses nginx access log lines for
GET /beacon requests from the PS5.
"""

import json
import re
import time
import subprocess
from datetime import datetime, timezone
from enum import Enum


class Outcome(str, Enum):
    SUCCESS = "SUCCESS"
    JS_EXCEPTION = "JS_EXCEPTION"
    WEBPROCESS_CRASH = "WEBPROCESS_CRASH"
    APP_FREEZE = "APP_FREEZE"
    REMOTE_PLAY_DISCONNECT = "REMOTE_PLAY_DISCONNECT"
    SERVER_FAILURE = "SERVER_FAILURE"
    CONSOLE_PANIC = "CONSOLE_PANIC"
    TIMEOUT = "TIMEOUT"
    UNKNOWN = "UNKNOWN"


# Beacon message patterns that signal specific outcomes
SUCCESS_PATTERNS = [
    re.compile(r"COMPLETE", re.I),
    re.compile(r"DONE", re.I),
    re.compile(r"VP=", re.I),
    re.compile(r"WALK-VT=", re.I),
    re.compile(r"BASE=0x", re.I),
]

ERROR_PATTERNS = [
    re.compile(r"ERR", re.I),
    re.compile(r"FAIL", re.I),
    re.compile(r"EXCEPTION", re.I),
    re.compile(r"FORGE-ERR", re.I),
]

CRASH_PATTERNS = [
    re.compile(r"CRASH", re.I),
]


def ssh_cmd(server, cmd, timeout=10):
    """Run a command on the server via SSH."""
    try:
        r = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=no",
             server, cmd],
            capture_output=True, text=True, timeout=timeout
        )
        return r.stdout.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", -1
    except Exception as e:
        return str(e), -2


class BeaconMonitor:
    def __init__(self, server="marwanserver@10.0.0.80", console_ip="10.0.0.96"):
        self.server = server
        self.console_ip = console_ip
        self.api_base = "http://127.0.0.1:8081"
        self._last_event_ts = None

    def fetch_events(self, since_ts=None):
        """Fetch recent beacon events from the telemetry API."""
        cmd = f"curl -s {self.api_base}/api/events"
        out, rc = ssh_cmd(self.server, cmd)
        if rc != 0 or not out:
            return None
        try:
            events = json.loads(out)
            if since_ts and isinstance(events, list):
                events = [e for e in events if e.get("server_ts", "") > since_ts]
            return events
        except json.JSONDecodeError:
            return None

    def fetch_nginx_beacons(self, lines=50):
        """Tail the nginx access log for recent beacon requests from PS5."""
        cmd = (f"tail -n {lines} /var/log/nginx/ps5-guide-entry-access.log "
               f"| grep 'GET /beacon' | grep '{self.console_ip}'")
        out, rc = ssh_cmd(self.server, cmd, timeout=8)
        if not out:
            return []
        entries = []
        for line in out.strip().split("\n"):
            if not line:
                continue
            m_param = re.search(r'GET /beacon\?m=([^ ]+)', line)
            m_ts = re.search(r'\[([^\]]+)\]', line)
            entries.append({
                "msg": m_param.group(1) if m_param else "",
                "ts": m_ts.group(1) if m_ts else "",
                "raw": line,
            })
        return entries

    def check_server_health(self):
        """Verify the telemetry server is responding."""
        cmd = f"curl -s -o /dev/null -w '%{{http_code}}' {self.api_base}/api/status"
        out, rc = ssh_cmd(self.server, cmd, timeout=8)
        return out.strip() == "200"

    def check_console_reachable(self):
        """Ping the PS5 to see if it's alive."""
        cmd = f"ping -c 1 -W 2 {self.console_ip}"
        _, rc = ssh_cmd(self.server, cmd, timeout=8)
        return rc == 0

    def check_lua_port(self):
        """Check if the Lua handler on port 9026 is accepting connections."""
        cmd = (f"timeout 3 bash -c 'echo | nc -w 2 {self.console_ip} 9026' "
               f">/dev/null 2>&1 && echo OK || echo FAIL")
        out, rc = ssh_cmd(self.server, cmd, timeout=8)
        return "OK" in out

    def classify_beacons(self, beacons):
        """Classify a list of beacon messages into an outcome."""
        if not beacons:
            return Outcome.TIMEOUT, "No beacons received"

        msgs = [b.get("msg", "") for b in beacons]
        all_text = " ".join(msgs)

        for p in CRASH_PATTERNS:
            if p.search(all_text):
                return Outcome.WEBPROCESS_CRASH, f"Crash beacon: {p.pattern}"

        has_success = False
        has_error = False
        for p in SUCCESS_PATTERNS:
            if p.search(all_text):
                has_success = True
                break
        for p in ERROR_PATTERNS:
            if p.search(all_text):
                has_error = True
                break

        if has_success and not has_error:
            return Outcome.SUCCESS, f"Success in {len(beacons)} beacons"
        if has_error:
            return Outcome.JS_EXCEPTION, f"Error beacon in {len(beacons)} messages"

        return Outcome.UNKNOWN, f"{len(beacons)} beacons, no clear outcome"

    def wait_for_outcome(self, run_id, timeout_sec=60, poll_interval=3):
        """Poll for beacons matching a run and classify the outcome.

        Returns (outcome, detail, beacons).
        """
        deadline = time.time() + timeout_sec
        collected = []

        while time.time() < deadline:
            beacons = self.fetch_nginx_beacons(lines=100)
            if beacons:
                run_beacons = [b for b in beacons if run_id in b.get("msg", "")]
                if not run_beacons:
                    run_beacons = beacons[-20:]
                if run_beacons:
                    collected.extend(run_beacons)
                    outcome, detail = self.classify_beacons(run_beacons)
                    if outcome in (Outcome.SUCCESS, Outcome.WEBPROCESS_CRASH,
                                   Outcome.JS_EXCEPTION):
                        return outcome, detail, collected

            time.sleep(poll_interval)

        if not collected:
            if not self.check_console_reachable():
                return Outcome.CONSOLE_PANIC, "Console unreachable after timeout", []
            return Outcome.TIMEOUT, "No beacons within timeout", []

        outcome, detail = self.classify_beacons(collected)
        return outcome, detail, collected

    def full_health_check(self):
        """Run all health checks and return a status dict."""
        server_ok = self.check_server_health()
        console_ok = self.check_console_reachable()
        lua_ok = self.check_lua_port() if console_ok else False

        if not server_ok:
            status = "SERVER_DOWN"
        elif not console_ok:
            status = "CONSOLE_UNREACHABLE"
        elif not lua_ok:
            status = "GAME_NOT_RUNNING"
        else:
            status = "READY"

        return {
            "status": status,
            "server": server_ok,
            "console_reachable": console_ok,
            "lua_port": lua_ok,
            "ts": datetime.now(timezone.utc).isoformat(),
        }

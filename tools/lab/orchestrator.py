"""Main experiment orchestrator — bounded retries, restart-safe state, watchdog."""
from __future__ import annotations
import json
import os
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

from .classifier import (Outcome, Classification, classify_lua_result,
                         classify_beacon_result, is_recoverable)
from .config import LabConfig, ROOT
from .hypothesis import list_hypotheses
from .recovery import RecoveryEngine, is_lua_loader_up, is_console_alive
from .safety import check_global_stop, set_global_stop, gate_dangerous, ExecutionLimiter
from .telemetry import run_id, RunLog

STATE_FILE = ROOT / "tools" / "lab" / "orchestrator_state.json"


class Experiment:
    def __init__(self, name: str, probe_path: str, probe_type: str = "lua",
                 crash_class: str = "LOW", description: str = "",
                 max_retries: int | None = None, timeout: int | None = None):
        self.name = name
        self.probe_path = probe_path
        self.probe_type = probe_type  # "lua" or "webkit"
        self.crash_class = crash_class
        self.description = description
        self.max_retries = max_retries
        self.timeout = timeout


def _save_state(state: dict):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    tmp.replace(STATE_FILE)


def _load_state() -> dict:
    if STATE_FILE.exists():
        with open(STATE_FILE, encoding="utf-8") as f:
            return json.load(f)
    return {"status": "idle", "current_experiment": None, "retry_count": 0,
            "completed": [], "failed": [], "last_run_id": None}


class Orchestrator:
    def __init__(self, config: LabConfig | None = None, log=None):
        self.cfg = config or LabConfig.load()
        self.log = log or print
        self.state = _load_state()
        self.run_log = RunLog(str(ROOT / self.cfg.telemetry_dir))
        self.recovery = RecoveryEngine(self.cfg, log=self.log)
        self.limiter = ExecutionLimiter(self.cfg)

    def _persist(self):
        _save_state(self.state)

    def status(self) -> dict:
        return {
            "orchestrator": self.state["status"],
            "current_experiment": self.state.get("current_experiment"),
            "retry_count": self.state.get("retry_count", 0),
            "completed": len(self.state.get("completed", [])),
            "failed": len(self.state.get("failed", [])),
            "console_alive": is_console_alive(self.cfg.ps5_ip, timeout=2),
            "loader_up": is_lua_loader_up(self.cfg.ps5_ip, self.cfg.lua_port, timeout=2),
            "global_stop": check_global_stop(self.cfg),
            "last_run_id": self.state.get("last_run_id"),
        }

    def run_experiment(self, experiment: Experiment) -> Classification:
        if check_global_stop(self.cfg):
            self.log("[!!] Global stop active — refusing to run.")
            return Classification(Outcome.SERVER_FAILURE, "global stop", False)

        allowed, reason = gate_dangerous(self.cfg, experiment.name, experiment.crash_class)
        if not allowed:
            self.log(f"[!!] Blocked: {reason}")
            return Classification(Outcome.SERVER_FAILURE, reason, False)

        max_retries = experiment.max_retries or self.cfg.max_retries_per_experiment
        self.state["current_experiment"] = experiment.name
        self.state["status"] = "running"
        self.state["retry_count"] = 0
        self._persist()

        self.limiter.start()
        last_classification = None

        for attempt in range(max_retries + 1):
            ok, limit_reason = self.limiter.check()
            if not ok:
                self.log(f"[!!] Limiter: {limit_reason}")
                set_global_stop(limit_reason)
                break

            rid = run_id()
            self.state["last_run_id"] = rid
            self.state["retry_count"] = attempt
            self._persist()

            self.log(f"\n[*] === {experiment.name} attempt {attempt + 1}/{max_retries + 1} (run {rid}) ===")

            try:
                classification = self._execute_probe(experiment, rid)
            except Exception as e:
                tb = traceback.format_exc()
                self.log(f"[!] Exception: {e}\n{tb}")
                classification = Classification(Outcome.SERVER_FAILURE, str(e), True,
                                                "orchestrator_exception")

            last_classification = classification
            self.run_log.record(rid, experiment.name, experiment.probe_path,
                                classification,
                                {"attempt": attempt + 1, "crash_class": experiment.crash_class})
            self.limiter.tick()

            self.log(f"[*] Result: {classification.outcome.value} — {classification.detail}")

            if classification.outcome == Outcome.SUCCESS:
                self.state["completed"].append({
                    "name": experiment.name, "run_id": rid,
                    "ts": datetime.now(timezone.utc).isoformat()
                })
                self.state["status"] = "idle"
                self.state["current_experiment"] = None
                self._persist()
                return classification

            if not is_recoverable(classification):
                self.log("[!!] Unrecoverable failure — stopping.")
                self.state["failed"].append({
                    "name": experiment.name, "run_id": rid,
                    "outcome": classification.outcome.value,
                    "ts": datetime.now(timezone.utc).isoformat()
                })
                self.state["status"] = "stopped"
                self._persist()
                return classification

            if self.recovery.check_for_panic():
                classification = Classification(Outcome.CONSOLE_PANIC,
                                                "console unreachable after probe", False,
                                                "panic_detected")
                self.run_log.record(rid + "_panic", experiment.name, experiment.probe_path,
                                    classification)
                self.state["status"] = "panic"
                self._persist()
                return classification

            recovered = self.recovery.attempt_recovery(classification)
            if not recovered:
                self.log("[!!] Recovery failed — stopping.")
                self.state["status"] = "stopped"
                self._persist()
                return classification

            self.log(f"[*] Recovered. Retrying ({attempt + 1}/{max_retries})...")

        self.state["failed"].append({
            "name": experiment.name,
            "outcome": "MAX_RETRIES",
            "ts": datetime.now(timezone.utc).isoformat()
        })
        self.state["status"] = "idle"
        self.state["current_experiment"] = None
        self._persist()
        return last_classification or Classification(Outcome.SERVER_FAILURE, "no attempts", False)

    def _execute_probe(self, experiment: Experiment, rid: str) -> Classification:
        if experiment.probe_type == "lua":
            return self._run_lua_probe(experiment, rid)
        elif experiment.probe_type == "webkit":
            return self._run_webkit_probe(experiment, rid)
        else:
            return Classification(Outcome.SERVER_FAILURE,
                                  f"unknown probe type: {experiment.probe_type}", True)

    def _run_lua_probe(self, experiment: Experiment, rid: str) -> Classification:
        import subprocess
        probe_path = experiment.probe_path
        if not os.path.isabs(probe_path):
            probe_path = str(ROOT / probe_path)

        timeout = experiment.timeout or self.cfg.max_experiment_runtime_seconds
        cmd = [
            sys.executable, str(ROOT / "tools" / "send_probe.py"),
            probe_path,
            "--save", "--metadata",
            "--ip", self.cfg.ps5_ip,
            "--port", str(self.cfg.lua_port),
            "--timeout", str(min(timeout, 60)),
            "--total-timeout", str(timeout),
        ]
        start = time.monotonic()
        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    timeout=timeout, cwd=str(ROOT))
            elapsed = time.monotonic() - start
            output = result.stdout + result.stderr

            if result.returncode == 0 and ("COMPLETE" in output or "saved" in output.lower()):
                return classify_lua_result("COMPLETE", output.encode(), elapsed)
            elif "CONNECTION_REFUSED" in output or "refused" in output.lower():
                return classify_lua_result("CONNECTION_REFUSED", b"", elapsed)
            elif "CONNECTION_RESET" in output or "reset" in output.lower():
                return classify_lua_result("CONNECTION_RESET", b"", elapsed)
            elif "timed out" in output.lower() or "timeout" in output.lower():
                return classify_lua_result("IDLE_TIMEOUT", b"", elapsed)
            else:
                return classify_lua_result("ERROR", output.encode(), elapsed)
        except subprocess.TimeoutExpired:
            return classify_lua_result("TOTAL_TIMEOUT", b"", time.monotonic() - start)
        except Exception as e:
            return Classification(Outcome.SERVER_FAILURE, str(e), True, "subprocess_error")

    def _run_webkit_probe(self, experiment: Experiment, rid: str) -> Classification:
        self.log(f"[*] WebKit probe: {experiment.probe_path}")
        import subprocess as sp
        probe_path = experiment.probe_path
        if not os.path.isabs(probe_path):
            probe_path = str(ROOT / probe_path)

        server = f"{self.cfg.server_user}@{self.cfg.server_ip}"
        webroot = "/var/www/ps5-guide-entry"

        # Deploy probe to server
        self.log("[*] Deploying probe to server...")
        try:
            r = sp.run(["scp", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=no",
                         probe_path, f"{server}:{webroot}/probes/"],
                        capture_output=True, text=True, timeout=30)
            if r.returncode != 0:
                return Classification(Outcome.SERVER_FAILURE,
                                      f"SCP failed: {r.stderr.strip()}", True, "scp_fail")
        except Exception as e:
            return Classification(Outcome.SERVER_FAILURE, str(e), True, "scp_error")

        probe_name = os.path.basename(probe_path)
        self.log(f"[*] Deployed as /probes/{probe_name}")

        # Monitor beacons via server telemetry API
        timeout = experiment.timeout or self.cfg.max_experiment_runtime_seconds
        self.log(f"[*] Waiting for beacons (timeout={timeout}s)...")
        deadline = time.monotonic() + timeout
        beacons = []

        while time.monotonic() < deadline:
            try:
                r = sp.run(
                    ["ssh", "-o", "ConnectTimeout=5", server,
                     f"tail -n 30 /var/log/nginx/ps5-guide-entry-access.log | grep 'GET /beacon' | grep '{self.cfg.ps5_ip}'"],
                    capture_output=True, text=True, timeout=10)
                if r.stdout.strip():
                    lines = r.stdout.strip().split("\n")
                    for line in lines:
                        if line not in beacons:
                            beacons.append(line)
                            self.log(f"  beacon: {line[-80:]}")

                    text = " ".join(beacons)
                    if "DONE" in text or "COMPLETE" in text or "RESULT" in text:
                        from .classifier import classify_beacon_result
                        msgs = [l for l in beacons]
                        return classify_beacon_result(msgs, False, time.monotonic() - (deadline - timeout))
                    if "FATAL" in text or "CRASH" in text:
                        from .classifier import classify_beacon_result
                        return classify_beacon_result(beacons, True, time.monotonic() - (deadline - timeout))
            except Exception:
                pass
            time.sleep(3)

        if beacons:
            from .classifier import classify_beacon_result
            return classify_beacon_result(beacons, False, timeout)
        return Classification(Outcome.APP_FREEZE, f"no beacons in {timeout}s", True, "webkit_no_beacons")

    def run_queue(self, experiments: list[Experiment]) -> list[Classification]:
        results = []
        for i, exp in enumerate(experiments):
            if check_global_stop(self.cfg):
                self.log(f"[!!] Global stop — skipping remaining {len(experiments) - i} experiments.")
                break
            self.log(f"\n{'='*60}")
            self.log(f"[*] Queue item {i + 1}/{len(experiments)}: {exp.name}")
            self.log(f"{'='*60}")
            result = self.run_experiment(exp)
            results.append(result)
            if result.outcome == Outcome.CONSOLE_PANIC:
                self.log("[!!] Console panic detected — aborting queue.")
                break
        return results

"""Safety controls: global stop, execution limits, dangerous experiment gating."""
from __future__ import annotations
import os
import signal
import time
from pathlib import Path
from .config import LabConfig, ROOT

STOP_FILE = ROOT / "tools" / "lab" / "STOP"


def check_global_stop(config: LabConfig) -> bool:
    if config.global_stop:
        return True
    if STOP_FILE.exists():
        return True
    return False


def set_global_stop(reason: str = ""):
    with open(STOP_FILE, "w") as f:
        f.write(f"STOPPED: {reason}\n{time.strftime('%Y-%m-%d %H:%M:%S')}\n")


def clear_global_stop():
    if STOP_FILE.exists():
        STOP_FILE.unlink()


def is_dangerous(experiment_name: str, crash_class: str) -> bool:
    crash_class = crash_class.upper()
    return crash_class in ("HIGH", "RISKY")


def gate_dangerous(config: LabConfig, experiment_name: str, crash_class: str) -> tuple[bool, str]:
    if not is_dangerous(experiment_name, crash_class):
        return True, "safe experiment"
    if not config.dangerous_experiments_opt_in:
        return False, "dangerous experiment requires opt-in (set dangerous_experiments_opt_in=true)"
    return True, "dangerous experiment approved via opt-in"


class ExecutionLimiter:
    def __init__(self, config: LabConfig):
        self.cfg = config
        self._start_time: float | None = None
        self._runs = 0

    def start(self):
        self._start_time = time.monotonic()
        self._runs = 0

    def check(self) -> tuple[bool, str]:
        if check_global_stop(self.cfg):
            return False, "global stop active"
        if self._start_time and (time.monotonic() - self._start_time) > self.cfg.max_experiment_runtime_seconds:
            return False, f"runtime limit exceeded ({self.cfg.max_experiment_runtime_seconds}s)"
        return True, "ok"

    def tick(self):
        self._runs += 1

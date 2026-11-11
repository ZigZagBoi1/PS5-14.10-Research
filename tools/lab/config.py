"""Lab configuration — all tunables in one place."""
from __future__ import annotations
import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
CONFIG_PATH = ROOT / "tools" / "lab" / "lab_config.json"


@dataclass
class LabConfig:
    ps5_ip: str = "10.0.0.96"
    lua_port: int = 9026
    server_ip: str = "10.0.0.80"
    server_user: str = "marwanserver"
    beacon_port: int = 8082
    serve_port: int = 443
    firmware: str = "14.10"

    # Safety
    max_retries_per_experiment: int = 3
    max_consecutive_crashes: int = 5
    global_stop: bool = False
    dangerous_experiments_opt_in: bool = False
    max_experiment_runtime_seconds: int = 300

    # Recovery
    chiaki_recovery_enabled: bool = True
    chiaki_recovery_timeout_seconds: int = 120
    reboot_detection_enabled: bool = True

    # Telemetry
    telemetry_dir: str = "results/lab_runs"
    hypothesis_file: str = "results/hypotheses.json"

    # Experiment queue
    experiment_queue: list = field(default_factory=list)

    def save(self):
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_PATH, "w") as f:
            json.dump(asdict(self), f, indent=2)

    @classmethod
    def load(cls) -> "LabConfig":
        if CONFIG_PATH.exists():
            with open(CONFIG_PATH) as f:
                data = json.load(f)
            return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
        return cls()

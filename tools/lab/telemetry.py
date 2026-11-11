"""Telemetry: unique run IDs, structured evidence, JSONL logging."""
from __future__ import annotations
import hashlib
import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from .classifier import Classification
from .config import ROOT


def run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:8]


def probe_hash(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()[:16]


class RunLog:
    def __init__(self, base_dir: str | None = None):
        self.base = Path(base_dir or str(ROOT / "results" / "lab_runs"))
        self.base.mkdir(parents=True, exist_ok=True)
        self._path = self.base / f"lab_{datetime.now(timezone.utc).strftime('%Y%m%d')}.jsonl"

    def record(self, rid: str, experiment: str, probe_path: str | None,
               classification: Classification, extra: dict | None = None):
        entry = {
            "run_id": rid,
            "ts": datetime.now(timezone.utc).isoformat(),
            "experiment": experiment,
            "probe": probe_path,
            "probe_hash": probe_hash(probe_path) if probe_path and os.path.exists(probe_path) else None,
            "outcome": classification.outcome.value,
            "detail": classification.detail,
            "recoverable": classification.recoverable,
            "crash_signature": classification.crash_signature,
        }
        if extra:
            entry.update(extra)
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        return entry

    def recent(self, n: int = 20) -> list[dict]:
        if not self._path.exists():
            return []
        lines = self._path.read_text(encoding="utf-8").strip().splitlines()
        result = []
        for line in lines[-n:]:
            try:
                result.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return result

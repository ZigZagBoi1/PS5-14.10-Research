"""Hypothesis registry: track claims, evidence, contradictions, next experiments."""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from .config import ROOT


HYPOTHESIS_PATH = ROOT / "results" / "hypotheses.json"


def _load() -> list[dict]:
    if HYPOTHESIS_PATH.exists():
        return json.loads(HYPOTHESIS_PATH.read_text(encoding="utf-8"))
    return []


def _save(hypotheses: list[dict]):
    HYPOTHESIS_PATH.parent.mkdir(parents=True, exist_ok=True)
    HYPOTHESIS_PATH.write_text(json.dumps(hypotheses, indent=2), encoding="utf-8")


def add_hypothesis(name: str, claim: str, evidence: list[str],
                   contradictions: list[str] | None = None,
                   next_experiment: str | None = None,
                   status: str = "open") -> dict:
    hyps = _load()
    h = {
        "id": len(hyps) + 1,
        "name": name,
        "claim": claim,
        "evidence": evidence,
        "contradictions": contradictions or [],
        "next_experiment": next_experiment,
        "status": status,
        "created": datetime.now(timezone.utc).isoformat(),
        "updated": datetime.now(timezone.utc).isoformat(),
    }
    hyps.append(h)
    _save(hyps)
    return h


def update_hypothesis(hypothesis_id: int, **kwargs) -> dict | None:
    hyps = _load()
    for h in hyps:
        if h["id"] == hypothesis_id:
            h.update(kwargs)
            h["updated"] = datetime.now(timezone.utc).isoformat()
            _save(hyps)
            return h
    return None


def list_hypotheses(status: str | None = None) -> list[dict]:
    hyps = _load()
    if status:
        return [h for h in hyps if h.get("status") == status]
    return hyps


def close_hypothesis(hypothesis_id: int, result: str, evidence: list[str]) -> dict | None:
    return update_hypothesis(hypothesis_id, status=result,
                             evidence=evidence)

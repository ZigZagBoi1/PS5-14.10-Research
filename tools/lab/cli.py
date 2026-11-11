"""CLI entry point for the lab system.

Usage:
  python -m tools.lab dashboard            — show dashboard
  python -m tools.lab status               — quick orchestrator status
  python -m tools.lab run <probe>          — run a single experiment (auto-detects lua/webkit)
  python -m tools.lab deploy <probe.html>  — deploy WebKit probe to server
  python -m tools.lab stop                 — set global stop
  python -m tools.lab clear-stop           — clear global stop
  python -m tools.lab hypotheses           — list hypotheses
  python -m tools.lab add-hyp <name> <claim> — add hypothesis
"""
from __future__ import annotations
import sys
import json
from pathlib import Path

from .config import LabConfig
from .dashboard import dashboard
from .hypothesis import add_hypothesis, list_hypotheses
from .orchestrator import Orchestrator, Experiment
from .safety import set_global_stop, clear_global_stop


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m tools.lab <command> [args...]")
        print("Commands: dashboard, status, run, stop, clear-stop, hypotheses, add-hyp")
        return

    cmd = sys.argv[1]
    cfg = LabConfig.load()

    if cmd == "dashboard":
        print(dashboard(cfg))

    elif cmd == "status":
        orch = Orchestrator(cfg)
        s = orch.status()
        for k, v in s.items():
            print(f"  {k}: {v}")

    elif cmd == "run":
        if len(sys.argv) < 3:
            print("Usage: python -m tools.lab run <probe_path> [--crash-class LOW] [--type lua|webkit]")
            return
        probe = sys.argv[2]
        crash_class = "LOW"
        probe_type = None
        if "--crash-class" in sys.argv:
            idx = sys.argv.index("--crash-class")
            if idx + 1 < len(sys.argv):
                crash_class = sys.argv[idx + 1]
        if "--type" in sys.argv:
            idx = sys.argv.index("--type")
            if idx + 1 < len(sys.argv):
                probe_type = sys.argv[idx + 1]
        if probe_type is None:
            probe_type = "webkit" if probe.endswith(".html") else "lua"
        name = Path(probe).stem
        exp = Experiment(name=name, probe_path=probe, probe_type=probe_type,
                         crash_class=crash_class)
        orch = Orchestrator(cfg)
        result = orch.run_experiment(exp)
        print(f"\nFinal: {result.outcome.value} — {result.detail}")

    elif cmd == "deploy":
        if len(sys.argv) < 3:
            print("Usage: python -m tools.lab deploy <probe.html> [--as-index]")
            return
        from .probe_deployer import deploy_probe
        probe = sys.argv[2]
        as_index = "--as-index" in sys.argv
        result = deploy_probe(probe, as_index=as_index)
        if result["success"]:
            print(f"Deployed: {result['url']}")
            print(f"Hash: {result['hash']}")
        else:
            print(f"Failed: {result['message']}")

    elif cmd == "stop":
        reason = " ".join(sys.argv[2:]) if len(sys.argv) > 2 else "manual stop"
        set_global_stop(reason)
        print(f"Global stop set: {reason}")

    elif cmd == "clear-stop":
        clear_global_stop()
        print("Global stop cleared.")

    elif cmd == "hypotheses":
        hyps = list_hypotheses()
        if not hyps:
            print("No hypotheses registered.")
        for h in hyps:
            print(f"  [{h['id']}] {h['status']:<12} {h['name']}")
            if h.get("next_experiment"):
                print(f"       next: {h['next_experiment']}")

    elif cmd == "add-hyp":
        if len(sys.argv) < 4:
            print("Usage: python -m tools.lab add-hyp <name> <claim>")
            return
        name = sys.argv[2]
        claim = " ".join(sys.argv[3:])
        h = add_hypothesis(name, claim, [])
        print(f"Added hypothesis #{h['id']}: {name}")

    else:
        print(f"Unknown command: {cmd}")


if __name__ == "__main__":
    main()

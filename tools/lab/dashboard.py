"""Lab dashboard — console status, experiment state, validated discoveries."""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path

from .config import LabConfig, ROOT
from .hypothesis import list_hypotheses
from .orchestrator import _load_state
from .recovery import is_lua_loader_up, is_console_alive
from .safety import check_global_stop
from .telemetry import RunLog


def dashboard(config: LabConfig | None = None) -> str:
    cfg = config or LabConfig.load()
    orch = _load_state()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    console_alive = is_console_alive(cfg.ps5_ip, timeout=2)
    loader_up = is_lua_loader_up(cfg.ps5_ip, cfg.lua_port, timeout=2)
    stopped = check_global_stop(cfg)

    lines = []
    lines.append(f"╔══════════════════════════════════════════════════════════╗")
    lines.append(f"║  PS5 14.10 RESEARCH LAB DASHBOARD — {now}  ║")
    lines.append(f"╠══════════════════════════════════════════════════════════╣")
    lines.append(f"║")
    lines.append(f"║  CONSOLE STATUS")
    lines.append(f"║    IP:          {cfg.ps5_ip}")
    lines.append(f"║    Ping:        {'ALIVE' if console_alive else 'DOWN'}")
    lines.append(f"║    Lua loader:  {'UP' if loader_up else 'DOWN'}")
    lines.append(f"║    Firmware:    {cfg.firmware}")
    lines.append(f"║")
    lines.append(f"║  ORCHESTRATOR")
    lines.append(f"║    Status:      {orch.get('status', 'unknown')}")
    lines.append(f"║    Current:     {orch.get('current_experiment') or '(none)'}")
    lines.append(f"║    Retries:     {orch.get('retry_count', 0)}")
    lines.append(f"║    Completed:   {len(orch.get('completed', []))}")
    lines.append(f"║    Failed:      {len(orch.get('failed', []))}")
    lines.append(f"║    Global stop: {'YES' if stopped else 'no'}")
    lines.append(f"║    Last run:    {orch.get('last_run_id') or '(none)'}")
    lines.append(f"║")

    # Recent runs
    run_log = RunLog(str(ROOT / cfg.telemetry_dir))
    recent = run_log.recent(10)
    lines.append(f"║  RECENT RUNS (last 10)")
    if recent:
        for r in recent:
            ts = r.get("ts", "?")[:19]
            outcome = r.get("outcome", "?")
            exp = r.get("experiment", "?")[:30]
            lines.append(f"║    {ts}  {outcome:<22} {exp}")
    else:
        lines.append(f"║    (no runs recorded)")
    lines.append(f"║")

    # Hypotheses
    hyps = list_hypotheses()
    open_hyps = [h for h in hyps if h.get("status") == "open"]
    confirmed = [h for h in hyps if h.get("status") == "confirmed"]
    dead = [h for h in hyps if h.get("status") == "dead"]
    lines.append(f"║  HYPOTHESIS REGISTRY")
    lines.append(f"║    Open:        {len(open_hyps)}")
    lines.append(f"║    Confirmed:   {len(confirmed)}")
    lines.append(f"║    Dead:        {len(dead)}")
    if open_hyps:
        lines.append(f"║    Active:")
        for h in open_hyps[:5]:
            lines.append(f"║      [{h['id']}] {h['name'][:45]}")
            if h.get("next_experiment"):
                lines.append(f"║          next: {h['next_experiment'][:45]}")
    lines.append(f"║")

    # Validated discoveries (from STATE.md)
    state_md = ROOT / "results" / "STATE.md"
    if state_md.exists():
        content = state_md.read_text(encoding="utf-8")
        lines.append(f"║  VALIDATED STATE (from STATE.md)")
        for line in content.strip().splitlines()[:12]:
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("---"):
                lines.append(f"║    {line[:60]}")
    lines.append(f"║")

    # Safety
    lines.append(f"║  SAFETY")
    lines.append(f"║    Dangerous opt-in:    {cfg.dangerous_experiments_opt_in}")
    lines.append(f"║    Max retries:         {cfg.max_retries_per_experiment}")
    lines.append(f"║    Max consecutive:     {cfg.max_consecutive_crashes}")
    lines.append(f"║    Max runtime:         {cfg.max_experiment_runtime_seconds}s")
    lines.append(f"║")
    lines.append(f"╚══════════════════════════════════════════════════════════╝")

    return "\n".join(lines)


if __name__ == "__main__":
    print(dashboard())

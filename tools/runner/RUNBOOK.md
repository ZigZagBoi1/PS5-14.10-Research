# Autonomous Research Runner — Operational Runbook

## Architecture

```
supervisor.py  ─── manages task lifecycle
    │
    ├── task_db.py  ─── SQLite task/checkpoint/dead-end database
    ├── scheduler.py ── generates tasks from capability graph + evidence
    └── config.json  ── budgets, safety limits, timeouts
```

Each task runs as a fresh `claude --print -p <prompt>` invocation with its
own context window. No state leaks between tasks. The supervisor checkpoints
after every task.

## Commands

```bash
# Generate tasks from evidence state
python -m tools.runner seed

# Show status (tasks, checkpoint, PID)
python -m tools.runner status

# Start supervisor (runs until budget/stop/no-tasks)
python -m tools.runner start

# Run exactly one task then stop (testing)
python -m tools.runner test-cycle

# Pause after current task completes
python -m tools.runner pause

# Resume paused supervisor
python -m tools.runner resume

# Graceful stop after current task
python -m tools.runner stop

# Emergency: kill process immediately
python -m tools.runner emergency

# Recover from crash (reset stale tasks, clear locks)
python -m tools.runner recover
```

## Configuration (tools/runner/config.json)

| Key | Default | Purpose |
|-----|---------|---------|
| max_tasks_per_run | 20 | Budget: tasks per supervisor invocation |
| max_runtime_minutes | 120 | Budget: wall clock per run |
| session_timeout_minutes | 30 | Per-task timeout |
| max_retries_per_task | 2 | Retry failed tasks |
| max_consecutive_failures | 3 | Stop after N failures in a row |
| pause_between_tasks_seconds | 5 | Cool-down between tasks |
| cooldown_after_rate_limit_seconds | 300 | Rate limit back-off |

## Safety Limits

- `no_console_probes: true` — tasks are analysis-only, never contact PS5
- `no_destructive_git: true` — no force push, no branch delete
- `require_evidence_for_claims: true` — findings must cite file:line
- Tasks that match `completed_topics` or `dead_ends` tables are skipped
- The scheduler never generates probe-execution tasks

## Task Priorities

0. Contradictory evidence requiring reconciliation
1. Unverified claims with existing raw captures
2. External research not compared against evidence
3. Incorrect calculations and source inconsistencies
4. Reproducibility checks
5. Documentation of unresolved blockers

## Recovery

### After SSH disconnect / process kill
```bash
python -m tools.runner recover   # resets stale running tasks
python -m tools.runner start     # resumes from last checkpoint
```

### After server restart
Same as above. The SQLite DB persists. PID/lock files are cleaned on start.

### Stale task detection
Tasks marked "running" for >30 minutes are automatically reset to "pending"
on next `start` or `recover`.

## Monitoring

```bash
# Live status
python -m tools.runner status

# Run log (JSONL)
tail -f tools/runner/runs.jsonl

# Task database
sqlite3 tools/runner/tasks.db "SELECT status, COUNT(*) FROM tasks GROUP BY status"

# Recent events
sqlite3 tools/runner/tasks.db "SELECT * FROM run_log ORDER BY timestamp DESC LIMIT 20"
```

## Fresh-Context Continuation

Each task gets a self-contained prompt with:
1. Task description and evidence references
2. Instructions to load context via `tools/context.py`
3. Rules preventing re-investigation and probe execution
4. Output path for findings

The supervisor never accumulates context across tasks.

## Unattended Operation

```bash
# Start with nohup for SSH resilience
nohup python -m tools.runner start > tools/runner/supervisor.log 2>&1 &

# Or with tmux/screen
tmux new-session -d -s runner 'python -m tools.runner start'

# Monitor
tmux attach -t runner
```

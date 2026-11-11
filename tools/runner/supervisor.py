#!/usr/bin/env python3
"""Persistent autonomous research supervisor.

Manages research sessions: launches tasks, monitors health, checkpoints
progress, and recovers from failures. Each task runs in a fresh Claude Code
CLI session with minimal context loaded via tools/context.py.

Usage:
    python -m tools.runner.supervisor start       # start supervisor
    python -m tools.runner.supervisor status       # show status
    python -m tools.runner.supervisor pause        # pause after current task
    python -m tools.runner.supervisor resume       # resume paused supervisor
    python -m tools.runner.supervisor stop         # graceful stop
    python -m tools.runner.supervisor emergency    # immediate stop
    python -m tools.runner.supervisor seed         # generate initial tasks
    python -m tools.runner.supervisor test-cycle   # run one task then stop (for testing)
    python -m tools.runner.supervisor recover      # recover from crash
"""

import argparse
import datetime
import json
import os
import signal
import subprocess
import sys
import time
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from tools.runner.task_db import TaskDB
from tools.runner.scheduler import generate_tasks

CONFIG_PATH = os.path.join(ROOT, "tools", "runner", "config.json")
PID_FILE = os.path.join(ROOT, "tools", "runner", "supervisor.pid")
LOCK_FILE = os.path.join(ROOT, "tools", "runner", "supervisor.lock")
PAUSE_FILE = os.path.join(ROOT, "tools", "runner", "supervisor.pause")
STOP_FILE = os.path.join(ROOT, "tools", "runner", "supervisor.stop")
RUN_LOG = os.path.join(ROOT, "tools", "runner", "runs.jsonl")


def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


def log_event(run_id, event, task_id=None, details=None):
    entry = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "run_id": run_id,
        "event": event,
        "task_id": task_id,
        "details": details,
    }
    os.makedirs(os.path.dirname(RUN_LOG), exist_ok=True)
    with open(RUN_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")
    print(f"[{entry['timestamp']}] {event}" + (f" ({task_id})" if task_id else ""))


def generate_run_id():
    return datetime.datetime.utcnow().strftime("run-%Y%m%d-%H%M%S")


def write_pid():
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))


def read_pid():
    if os.path.exists(PID_FILE):
        with open(PID_FILE) as f:
            try:
                return int(f.read().strip())
            except ValueError:
                return None
    return None


def is_running(pid):
    if pid is None:
        return False
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def cleanup_files():
    for f in (PID_FILE, LOCK_FILE, STOP_FILE, PAUSE_FILE):
        if os.path.exists(f):
            try:
                os.remove(f)
            except OSError:
                pass


def should_stop():
    return os.path.exists(STOP_FILE)


def should_pause():
    return os.path.exists(PAUSE_FILE)


def build_task_prompt(task):
    """Build a self-contained prompt for a fresh Claude Code session."""
    prompt = f"""You are an autonomous research analyst for the PS5 14.10 kernel research project.

TASK: {task['title']}
TYPE: {task['type']}
DESCRIPTION: {task.get('description', 'No description')}

CONTEXT LOADING:
1. Run: python tools/context.py 1 --estimate  (to see what's available)
2. Read results/STATE.md for current research state
3. Read docs/CAPABILITY_GRAPH.md for evidence chain
4. Use python tools/search_index.py search "<term>" for targeted lookups

RULES:
- This is OFFLINE ANALYSIS ONLY. Do NOT connect to any console or send probes.
- Do NOT generate new Lua probes. Analyze existing evidence only.
- Do NOT claim results without citing specific files and line numbers.
- Do NOT re-investigate topics already in docs/DEAD_ENDS_REFERENCE.md.
- Distinguish VERIFIED [M], SUPPORTED [S], and INFERRED [I] evidence grades.
- If you find a contradiction, document it precisely with both sources.
- If evidence is insufficient, say so rather than speculating.

OUTPUT:
When done, write your findings to a file:
  results/analysis/{task['id']}.md

Include:
- What was investigated
- What was found (with file:line citations)
- Verdict: CONSISTENT / CONTRADICTION / INSUFFICIENT_EVIDENCE / DEAD_END
- Any corrections needed in existing docs

Then update the checkpoint:
  python tools/state.py set last_analysis="{task['id']}"
"""
    return prompt


def execute_task(task, config, run_id, db):
    """Execute a single research task in a fresh session."""
    log_event(run_id, "task_start", task["id"], task["title"])

    prompt = build_task_prompt(task)
    timeout = config["supervisor"]["session_timeout_minutes"] * 60

    # Ensure analysis output directory exists
    os.makedirs(os.path.join(ROOT, "results", "analysis"), exist_ok=True)

    # Write prompt to temp file for claude to read
    prompt_file = os.path.join(ROOT, "tools", "runner", f"_prompt_{task['id']}.txt")
    with open(prompt_file, "w", encoding="utf-8") as f:
        f.write(prompt)

    try:
        # Execute via claude CLI with the prompt piped in
        result = subprocess.run(
            ["claude", "--print", "--dangerously-skip-permissions",
             "-p", prompt],
            capture_output=True, text=True, timeout=timeout,
            cwd=ROOT,
            env={**os.environ, "CLAUDE_CODE_ENTRYPOINT": "cli"},
        )

        output = result.stdout + result.stderr
        success = result.returncode == 0

        # Check if analysis file was created
        analysis_file = os.path.join(ROOT, "results", "analysis", f"{task['id']}.md")
        has_output = os.path.exists(analysis_file)

        if success or has_output:
            db.complete_task(task["id"], result=output[:2000])
            log_event(run_id, "task_complete", task["id"],
                      f"output={has_output}, rc={result.returncode}")
            return True
        else:
            db.fail_task(task["id"], error=output[:1000])
            log_event(run_id, "task_fail", task["id"],
                      f"rc={result.returncode}, err={output[:200]}")
            return False

    except subprocess.TimeoutExpired:
        db.fail_task(task["id"], error="timeout")
        log_event(run_id, "task_timeout", task["id"])
        return False
    except FileNotFoundError:
        db.fail_task(task["id"], error="claude CLI not found")
        log_event(run_id, "task_error", task["id"], "claude CLI not in PATH")
        return False
    except Exception as e:
        db.fail_task(task["id"], error=str(e))
        log_event(run_id, "task_error", task["id"], traceback.format_exc()[:500])
        return False
    finally:
        if os.path.exists(prompt_file):
            os.remove(prompt_file)


def update_file_checkpoint(db, run_id, tasks_done, start_time):
    """Write checkpoint to both DB and the repo checkpoint file."""
    stats = db.get_stats()
    state = {
        "run_id": run_id,
        "tasks_done_this_run": tasks_done,
        "elapsed_minutes": round((time.time() - start_time) / 60, 1),
        "stats": stats,
    }
    db.save_checkpoint(run_id, state)

    # Also update the repo checkpoint
    checkpoint_path = os.path.join(ROOT, "results", "CHECKPOINT.md")
    now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(checkpoint_path, "w", encoding="utf-8") as f:
        f.write(f"""# Research Checkpoint

## Last Updated
{now}

## Runner State
- Run ID: {run_id}
- Tasks completed this run: {tasks_done}
- Elapsed: {state['elapsed_minutes']} minutes
- Pending: {stats['pending']} | Running: {stats['running']} | Completed: {stats['completed']} | Failed: {stats['failed']}

## Continuation
To resume: `python -m tools.runner.supervisor start`
Runner auto-loads minimal context and picks up from last completed task.
""")


def cmd_start(args):
    """Main supervisor loop."""
    pid = read_pid()
    if is_running(pid):
        print(f"Supervisor already running (PID {pid})")
        return

    config = load_config()
    db = TaskDB()
    run_id = generate_run_id()

    # Recovery: reset stale running tasks
    db.reset_stale_running()

    # Generate tasks if none pending
    stats = db.get_stats()
    if stats["pending"] == 0:
        added, _ = generate_tasks(db)
        log_event(run_id, "tasks_generated", details=f"{added} tasks")

    write_pid()
    cleanup_files()  # clear stop/pause signals
    # Re-write pid after cleanup
    write_pid()

    log_event(run_id, "supervisor_start")
    budget = config["budget"]
    sup_cfg = config["supervisor"]

    tasks_done = 0
    consecutive_failures = 0
    start_time = time.time()

    test_mode = args.test_cycle if hasattr(args, "test_cycle") else False

    try:
        while True:
            # Budget checks
            elapsed_min = (time.time() - start_time) / 60
            if elapsed_min > budget["max_runtime_minutes"]:
                log_event(run_id, "budget_time_exceeded")
                break
            if tasks_done >= budget["max_tasks_per_run"]:
                log_event(run_id, "budget_tasks_exceeded")
                break
            if consecutive_failures >= sup_cfg["max_consecutive_failures"]:
                log_event(run_id, "max_failures_reached")
                break
            if should_stop():
                log_event(run_id, "stop_requested")
                break

            # Pause handling
            while should_pause():
                log_event(run_id, "paused")
                time.sleep(10)

            # Get next task
            task = db.get_next_task()
            if not task:
                # Try generating more
                added, _ = generate_tasks(db)
                if added == 0:
                    log_event(run_id, "no_tasks_remaining")
                    break
                continue

            # Execute
            success = execute_task(task, config, run_id, db)
            tasks_done += 1

            if success:
                consecutive_failures = 0
            else:
                consecutive_failures += 1

            # Checkpoint after each task
            update_file_checkpoint(db, run_id, tasks_done, start_time)

            # Test mode: stop after one task
            if test_mode:
                log_event(run_id, "test_cycle_complete")
                break

            # Pause between tasks
            time.sleep(sup_cfg["pause_between_tasks_seconds"])

    except KeyboardInterrupt:
        log_event(run_id, "interrupted")
    except Exception as e:
        log_event(run_id, "supervisor_error", details=traceback.format_exc()[:500])
    finally:
        update_file_checkpoint(db, run_id, tasks_done, start_time)
        log_event(run_id, "supervisor_stop", details=f"tasks={tasks_done}")
        cleanup_files()

    print(f"\nRun {run_id}: {tasks_done} tasks completed")
    stats = db.get_stats()
    print(f"  Pending: {stats['pending']} | Completed: {stats['completed']} | Failed: {stats['failed']}")


def cmd_status(args):
    db = TaskDB()
    stats = db.get_stats()
    pid = read_pid()
    running = is_running(pid)

    print(f"Supervisor: {'RUNNING (PID ' + str(pid) + ')' if running else 'STOPPED'}")
    print(f"Paused: {os.path.exists(PAUSE_FILE)}")
    print(f"\nTasks:")
    for k, v in stats.items():
        print(f"  {k}: {v}")

    cp = db.get_last_checkpoint()
    if cp:
        print(f"\nLast checkpoint: {datetime.datetime.fromtimestamp(cp['timestamp']).isoformat()}")
        print(f"  Run: {cp['run_id']}, Done: {cp['tasks_completed']}, Remaining: {cp['tasks_remaining']}")

    pending = db.get_pending_tasks()
    if pending:
        print(f"\nNext tasks:")
        for t in pending[:5]:
            print(f"  [{t['priority']}] {t['title']}")


def cmd_pause(args):
    open(PAUSE_FILE, "w").close()
    print("Pause signal sent. Supervisor will pause after current task.")


def cmd_resume(args):
    if os.path.exists(PAUSE_FILE):
        os.remove(PAUSE_FILE)
        print("Resume signal sent.")
    else:
        print("Supervisor is not paused.")


def cmd_stop(args):
    open(STOP_FILE, "w").close()
    print("Stop signal sent. Supervisor will stop after current task.")


def cmd_emergency(args):
    pid = read_pid()
    if is_running(pid):
        os.kill(pid, signal.SIGTERM)
        print(f"SIGTERM sent to PID {pid}")
    cleanup_files()
    print("Emergency stop complete. Run 'recover' before restarting.")


def cmd_seed(args):
    db = TaskDB()
    added, total = generate_tasks(db)
    print(f"Generated {added} new tasks from {total} scanned")
    stats = db.get_stats()
    print(f"Total pending: {stats['pending']}")


def cmd_test_cycle(args):
    args.test_cycle = True
    cmd_start(args)


def cmd_recover(args):
    db = TaskDB()
    db.reset_stale_running()
    cleanup_files()
    stats = db.get_stats()
    print(f"Recovery complete. Reset stale tasks.")
    print(f"  Pending: {stats['pending']} | Completed: {stats['completed']} | Failed: {stats['failed']}")


def main():
    parser = argparse.ArgumentParser(description="Autonomous research supervisor")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("start", help="Start supervisor")
    sub.add_parser("status", help="Show status")
    sub.add_parser("pause", help="Pause after current task")
    sub.add_parser("resume", help="Resume paused supervisor")
    sub.add_parser("stop", help="Graceful stop")
    sub.add_parser("emergency", help="Immediate stop")
    sub.add_parser("seed", help="Generate initial tasks")
    sub.add_parser("test-cycle", help="Run one task then stop")
    sub.add_parser("recover", help="Recover from crash")

    args = parser.parse_args()

    cmds = {
        "start": cmd_start, "status": cmd_status, "pause": cmd_pause,
        "resume": cmd_resume, "stop": cmd_stop, "emergency": cmd_emergency,
        "seed": cmd_seed, "test-cycle": cmd_test_cycle, "recover": cmd_recover,
    }

    if args.command in cmds:
        cmds[args.command](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

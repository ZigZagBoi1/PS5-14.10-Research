#!/usr/bin/env python3
"""End-to-end test of the task lifecycle and recovery."""

import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from tools.runner.task_db import TaskDB
from tools.runner.scheduler import generate_tasks

def test_full_cycle():
    print("=== Test 1: Fresh-Context Continuation ===")
    print()

    # Use a test DB
    db_path = os.path.join(ROOT, "tools", "runner", "test_tasks.db")
    if os.path.exists(db_path):
        os.remove(db_path)
    db = TaskDB(db_path)

    # Seed tasks
    added, total = generate_tasks(db)
    print(f"Seeded {added} tasks from {total} scanned")
    stats = db.get_stats()
    print(f"  Pending: {stats['pending']}")
    print()

    # Session 1: Get and complete a task
    print("--- Session 1: Execute first task ---")
    task1 = db.get_next_task()
    print(f"  Got: [{task1['priority']}] {task1['title']}")
    print(f"  Status: {task1['status']}")

    # Simulate analysis work
    db.complete_task(task1["id"],
        result="UMA zone allocator confirmed via FreeBSD source",
        evidence_refs=["docs/FINDINGS.md:42"])
    print(f"  Completed with result")

    # Checkpoint
    db.save_checkpoint("session-1", {"tasks_done": 1})
    print(f"  Checkpoint saved")
    print()

    # Verify deduplication
    dup = db.is_investigated(task1["title"])
    print(f"  Dedup check: {dup}")
    assert dup == "completed", f"Expected 'completed', got {dup}"

    # Session 2: Simulate fresh context (new DB connection)
    print("--- Session 2: Fresh context, resume ---")
    db2 = TaskDB(db_path)

    # Check last checkpoint
    cp = db2.get_last_checkpoint()
    print(f"  Last checkpoint: run={cp['run_id']}, done={cp['tasks_completed']}")

    # Get next task (should not repeat task1)
    task2 = db2.get_next_task()
    print(f"  Got: [{task2['priority']}] {task2['title']}")
    assert task2["id"] != task1["id"], "Got same task — dedup failed!"
    print(f"  Different from session 1: YES")

    db2.complete_task(task2["id"],
        result="No evidence of double-free in captures",
        evidence_refs=["results/phase2_kernel_objects/10_umtx_stress_20261015_190047.txt"])
    db2.save_checkpoint("session-2", {"tasks_done": 2})
    print(f"  Completed and checkpointed")
    print()

    # Test 2: Interruption Recovery
    print("=== Test 2: Simulated Interruption Recovery ===")
    print()

    # Get a task and leave it "running" (simulate crash)
    task3 = db2.get_next_task()
    print(f"  Started: {task3['title']}")
    print(f"  Status: running (simulating crash...)")

    # New DB connection — simulates process restart
    db3 = TaskDB(db_path)
    stats = db3.get_stats()
    print(f"  Before recovery: running={stats['running']}, pending={stats['pending']}")

    # Recovery
    db3.reset_stale_running(max_age_seconds=0)  # instant for test
    stats = db3.get_stats()
    print(f"  After recovery: running={stats['running']}, pending={stats['pending']}")
    assert stats["running"] == 0, "Stale task not reset!"
    print(f"  Stale task reset: YES")

    # Resume: should get the same task back
    task3_retry = db3.get_next_task()
    print(f"  Retried: {task3_retry['title']}")
    assert task3_retry["id"] == task3["id"], "Different task after recovery!"
    print(f"  Same task retried: YES")
    db3.complete_task(task3_retry["id"], result="Recovery test passed")
    print()

    # Test 3: Dead-end prevention
    print("=== Test 3: Dead-End Prevention ===")
    print()

    db3.mark_dead_end("Test dead end topic", "Proven impossible", task3["id"])
    result = db3.add_task("dead-test", "test", "Test dead end topic")
    print(f"  Added dead-end task: {result}")
    assert result is None, "Should have been blocked!"
    print(f"  Blocked: YES")
    print()

    # Final stats
    print("=== Final Stats ===")
    stats = db3.get_stats()
    print(f"  Completed: {stats['completed']}")
    print(f"  Pending: {stats['pending']}")
    print(f"  Failed: {stats['failed']}")
    print(f"  Dead ends: {stats['dead_ends']}")
    print(f"  Completed topics: {stats['completed_topics']}")

    # Cleanup
    os.remove(db_path)
    print()
    print("ALL TESTS PASSED")


if __name__ == "__main__":
    test_full_cycle()

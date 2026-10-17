#!/usr/bin/env python3
"""Live terminal dashboard for the swarm — run in a separate terminal."""

import os
import sys
import time
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import SWARM_QUEUE_DIR, SWARM_LOGS_DIR, PROJECT_ROOT

def get_queue_stats():
    queue_file = os.path.join(SWARM_QUEUE_DIR, "queue.json")
    if not os.path.exists(queue_file):
        return {"total": 0, "pending": 0, "completed": 0, "failed": 0}
    with open(queue_file, "r") as f:
        tasks = json.load(f)
    stats = {"total": len(tasks), "pending": 0, "completed": 0, "failed": 0, "assigned": 0}
    by_type = {}
    for t in tasks:
        stats[t.get("status", "unknown")] = stats.get(t.get("status", "unknown"), 0) + 1
        if t["status"] == "pending":
            by_type[t["type"]] = by_type.get(t["type"], 0) + 1
    return stats, by_type

def get_recent_log_lines(n=20):
    log_files = sorted(
        [f for f in os.listdir(SWARM_LOGS_DIR) if f.endswith(".log")],
        reverse=True
    )
    if not log_files:
        return []
    with open(os.path.join(SWARM_LOGS_DIR, log_files[0]), "r") as f:
        lines = f.readlines()
    return lines[-n:]

def get_probe_count():
    swarm_dir = os.path.join(PROJECT_ROOT, "probes", "swarm_generated")
    if not os.path.exists(swarm_dir):
        return 0
    return len([f for f in os.listdir(swarm_dir) if f.endswith(".lua")])

def main():
    while True:
        os.system("cls" if os.name == "nt" else "clear")

        print("=" * 70)
        print("  PS5 14.10 KERNEL EXPLOIT SWARM — LIVE DASHBOARD")
        print("=" * 70)
        print()

        try:
            stats, by_type = get_queue_stats()
        except Exception:
            stats = {"total": 0, "pending": 0, "completed": 0, "failed": 0, "assigned": 0}
            by_type = {}

        probes = get_probe_count()

        print(f"  QUEUE:     {stats.get('pending', 0)} pending | {stats.get('assigned', 0)} assigned | "
              f"{stats.get('completed', 0)} completed | {stats.get('failed', 0)} failed")
        print(f"  PROBES:    {probes} generated")
        print()

        if by_type:
            print("  PENDING BY TYPE:")
            for t, c in sorted(by_type.items(), key=lambda x: -x[1]):
                print(f"    {t:30s} {c}")
            print()

        print("  RECENT LOG:")
        print("  " + "-" * 66)
        for line in get_recent_log_lines(25):
            print(f"  {line.rstrip()}")

        print()
        print("  [Ctrl+C to exit dashboard — swarm keeps running]")

        time.sleep(5)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nDashboard closed.")

#!/usr/bin/env python3
"""
PS5 14.10 KERNEL EXPLOIT SWARM — 100 Agent Autonomous System
=============================================================
Runs 24/7, fully hands-free. Researches, writes probes, sends them to the PS5,
analyzes results, documents findings, commits to git.

Usage:
    python swarm/swarm.py [--dry-run] [--agents N]

Set ANTHROPIC_API_KEY env var for paid models, or use OpenCode Zen free tier.
"""

import sys
import os
import time
import signal
import logging
import argparse
import threading
from datetime import datetime, timedelta

# Add swarm dir to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import (
    PS5_IP, PS5_PORT, AGENT_COUNTS, MODEL_MAP, ANTHROPIC_API_KEY,
    PROJECT_ROOT, RESULTS_DIR, SWARM_STATE_DIR, SWARM_LOGS_DIR, SWARM_QUEUE_DIR,
    MAX_CONCURRENT_API_CALLS, FAST_MODEL, OPENROUTER_API_KEY,
)
from task_queue import TaskQueue, Priority
from ps5_connection import PS5Connection
from ai_client import AIClient
from agents import AGENT_CLASSES

# ── Logging ──
os.makedirs(SWARM_LOGS_DIR, exist_ok=True)
log_file = os.path.join(SWARM_LOGS_DIR, f"swarm_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(log_file, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("swarm")


class Swarm:
    def __init__(self, agent_scale: float = 1.0, dry_run: bool = False):
        self.project_root = PROJECT_ROOT
        self.dry_run = dry_run
        self.agent_scale = agent_scale  # 1.0 = all 100, 0.1 = 10 agents

        # ── State dirs ──
        os.makedirs(SWARM_STATE_DIR, exist_ok=True)
        os.makedirs(SWARM_QUEUE_DIR, exist_ok=True)
        os.makedirs(os.path.join(PROJECT_ROOT, "probes", "swarm_generated"), exist_ok=True)

        # ── Task queue ──
        self.queue = TaskQueue(SWARM_QUEUE_DIR)

        # ── PS5 connection ──
        self.ps5 = PS5Connection(PS5_IP, PS5_PORT, RESULTS_DIR)

        # ── AI clients (one per model) ──
        self._ai_clients: dict[str, AIClient] = {}

        # ── Agents ──
        self.agents: list = []
        self._shutdown = threading.Event()

    def get_ai_client(self, role: str) -> AIClient:
        model = MODEL_MAP.get(role, FAST_MODEL)
        if model not in self._ai_clients:
            use_opencode = not ANTHROPIC_API_KEY or "deepseek" in model or "pickle" in model or "nemotron" in model
            self._ai_clients[model] = AIClient(
                model=model,
                api_key=ANTHROPIC_API_KEY,
                use_opencode=use_opencode,
            )
        return self._ai_clients[model]

    def spawn_agents(self):
        agent_num = 0
        for role, count in AGENT_COUNTS.items():
            scaled_count = max(1, int(count * self.agent_scale))
            agent_class = AGENT_CLASSES.get(role)
            if not agent_class:
                logger.warning(f"No implementation for role: {role}")
                continue

            for i in range(scaled_count):
                agent_num += 1
                agent_id = f"{role}_{i+1:02d}"
                agent = agent_class(agent_id, self)
                self.agents.append(agent)

        logger.info(f"Spawned {len(self.agents)} agents across {len(AGENT_COUNTS)} roles")

    def seed_initial_tasks(self):
        """Seed the queue with initial high-priority tasks."""
        seeds = [
            ("write_probe", {
                "description": "Complete Sony syscall survey: test syscalls 627-676 (the untested second half). Skip 661-670 (dev group, sandbox-killed). Test one at a time with print fencing before each call."
            }, Priority.HIGH, ["seed", "survey"]),
            ("write_probe", {
                "description": "Syscall 624 timing oracle: call it 1000 times in a tight loop, measure if the counter changes correlate with heap allocations. Also test with different arg values (0-255)."
            }, Priority.HIGH, ["seed", "kaslr"]),
            ("write_probe", {
                "description": "Syscall 563-566 with proper proc structures: these are proc group syscalls. Try passing pid as arg1, buffer as arg2. Try kinfo_proc-sized buffers."
            }, Priority.HIGH, ["seed", "syscall"]),
            ("write_probe", {
                "description": "Syscall 640 structure fuzzing: try every combination of arg count and buffer positions. It takes 6+ args and returns 0 — find what structure it expects."
            }, Priority.MEDIUM, ["seed", "syscall"]),
            ("write_probe", {
                "description": "Syscall timing side channel: measure the time (via syscall 624 counter delta or gettimeofday) that different syscalls take. Compare valid vs invalid addresses as arguments. Timing differences can reveal kernel memory layout."
            }, Priority.HIGH, ["seed", "kaslr", "timing"]),
            ("write_probe", {
                "description": "Heap spray + sysctl: spray thousands of 16KB GPU mmap pages, then use sysctl to query kernel process info. Check if any kernel object addresses appear in adjacent memory."
            }, Priority.MEDIUM, ["seed", "heap"]),
            ("write_probe", {
                "description": "Socket object leak: create 50 sockets of different types (TCP, UDP, RAW, SCTP), then scan GPU mmap adjacent memory for socket kernel objects that might contain kernel pointers."
            }, Priority.MEDIUM, ["seed", "heap", "network"]),
            ("write_probe", {
                "description": "FreeBSD UMA zone cross-reference: allocate objects of known sizes (pipes, sockets, files), measure what zones they land in, scan for kernel pointers in adjacent allocations."
            }, Priority.MEDIUM, ["seed", "heap"]),
        ]

        for task_type, payload, priority, tags in seeds:
            self.queue.add(task_type, payload, priority=priority, tags=tags)

        logger.info(f"Seeded {len(seeds)} initial tasks")

    def start(self):
        logger.info("=" * 60)
        logger.info("  PS5 14.10 KERNEL EXPLOIT SWARM")
        logger.info(f"  Agents: {len(self.agents)}")
        logger.info(f"  Target: {PS5_IP}:{PS5_PORT}")
        logger.info(f"  Dry run: {self.dry_run}")
        logger.info("=" * 60)

        # Check PS5 health
        logger.info("Checking PS5 loader health...")
        if self.ps5.health_check():
            logger.info("PS5 loader is UP and responding")
        else:
            logger.warning("PS5 loader is DOWN — swarm will wait for it to come online")

        # Seed tasks if queue is empty
        if self.queue.get_stats()["pending"] == 0:
            self.seed_initial_tasks()

        # Start all agents
        for agent in self.agents:
            agent.start()
            time.sleep(0.1)  # stagger startup

        logger.info(f"All {len(self.agents)} agents running")

        # ── Status printer ──
        self._status_thread = threading.Thread(target=self._print_status_loop, daemon=True)
        self._status_thread.start()

        # Block until shutdown
        try:
            while not self._shutdown.is_set():
                self._shutdown.wait(10)
        except KeyboardInterrupt:
            logger.info("Ctrl+C received, shutting down...")
            self.stop()

    def stop(self):
        logger.info("Stopping all agents...")
        self._shutdown.set()
        for agent in self.agents:
            agent.stop()
        time.sleep(2)
        logger.info("Swarm stopped.")

    def _print_status_loop(self):
        while not self._shutdown.is_set():
            stats = self.queue.get_stats()
            ps5 = self.ps5.get_status()

            active = sum(1 for a in self.agents if a.stats.get("last_active") and
                         time.time() - a.stats["last_active"] < 300)

            completed = sum(a.stats["tasks_completed"] for a in self.agents)
            failed = sum(a.stats["tasks_failed"] for a in self.agents)

            logger.info(
                f"[STATUS] Agents: {active}/{len(self.agents)} active | "
                f"Queue: {stats['pending']}p/{stats['assigned']}a/{stats['completed']}c/{stats['failed']}f | "
                f"PS5: {'UP' if ps5['alive'] else 'DOWN'} ({ps5['total_probes_sent']} sent) | "
                f"Tasks: {completed} done, {failed} failed"
            )

            self._shutdown.wait(60)


def main():
    parser = argparse.ArgumentParser(description="PS5 14.10 Kernel Exploit Swarm")
    parser.add_argument("--dry-run", action="store_true", help="Don't actually send probes")
    parser.add_argument("--agents", type=int, default=100, help="Number of agents (scales proportionally)")
    args = parser.parse_args()

    scale = args.agents / 100.0

    # Check for API key
    if not ANTHROPIC_API_KEY and not OPENROUTER_API_KEY:
        print("\n" + "=" * 60)
        print("  NO API KEY FOUND")
        print("=" * 60)
        print()
        print("  The swarm needs an LLM backend. Easiest free option:")
        print()
        print("  1. Go to https://openrouter.ai/keys")
        print("  2. Sign up (free, no credit card)")
        print("  3. Create an API key")
        print("  4. Run:  set OPENROUTER_API_KEY=sk-or-your-key-here")
        print("  5. Then re-launch this script")
        print()
        print("  Free models (DeepSeek, Llama, etc.) have no cost.")
        print("=" * 60)
        sys.exit(1)

    # Handle Ctrl+C
    swarm = Swarm(agent_scale=scale, dry_run=args.dry_run)
    signal.signal(signal.SIGINT, lambda s, f: swarm.stop())

    swarm.spawn_agents()
    swarm.start()


if __name__ == "__main__":
    main()

"""Base agent class — all 100 agents inherit from this."""

import time
import threading
import logging
import traceback
from typing import Optional

logger = logging.getLogger("swarm")

class Agent:
    ROLE = "base"
    TASK_TYPES = []       # what task types this agent can claim
    CYCLE_INTERVAL = 60   # seconds between autonomous cycles

    def __init__(self, agent_id: str, swarm):
        self.agent_id = agent_id
        self.swarm = swarm
        self.queue = swarm.queue
        self.ps5 = swarm.ps5
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self.stats = {
            "tasks_completed": 0,
            "tasks_failed": 0,
            "cycles": 0,
            "last_active": None,
            "errors": [],
        }

    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name=self.agent_id)
        self._thread.start()

    def stop(self):
        self.running = False

    def _run_loop(self):
        logger.info(f"[{self.agent_id}] started ({self.ROLE})")
        while self.running:
            try:
                self.stats["cycles"] += 1
                self.stats["last_active"] = time.time()

                # Try to claim a task from the queue
                task = self.queue.claim(self.agent_id, self.TASK_TYPES)
                if task:
                    logger.info(f"[{self.agent_id}] claimed {task.type} task {task.id}")
                    try:
                        result = self.execute_task(task)
                        self.queue.complete(task.id, result)
                        self.stats["tasks_completed"] += 1
                        logger.info(f"[{self.agent_id}] completed {task.id}")
                    except Exception as e:
                        self.queue.fail(task.id, str(e))
                        self.stats["tasks_failed"] += 1
                        self.stats["errors"].append(str(e))
                        if len(self.stats["errors"]) > 20:
                            self.stats["errors"] = self.stats["errors"][-20:]
                        logger.error(f"[{self.agent_id}] failed {task.id}: {e}")
                else:
                    # No queued task — run autonomous cycle
                    self.autonomous_cycle()

            except Exception as e:
                logger.error(f"[{self.agent_id}] loop error: {e}\n{traceback.format_exc()}")

            time.sleep(self.CYCLE_INTERVAL)

        logger.info(f"[{self.agent_id}] stopped")

    def execute_task(self, task) -> dict:
        """Override in subclass — handle a claimed task."""
        raise NotImplementedError

    def autonomous_cycle(self):
        """Override in subclass — what to do when no tasks are queued."""
        pass

    def submit_task(self, task_type, payload, priority=2, tags=None):
        """Convenience: add a task to the shared queue."""
        return self.queue.add(task_type, payload, priority=priority, tags=tags)

    def read_file(self, path: str) -> str:
        try:
            with open(path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception:
            return ""

    def write_file(self, path: str, content: str):
        import os
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

    def list_files(self, directory: str, pattern: str = "*") -> list[str]:
        import glob
        return sorted(glob.glob(f"{directory}/{pattern}"))

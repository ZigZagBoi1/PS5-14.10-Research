"""Thread-safe task queue with priority and deduplication."""

import json
import os
import time
import threading
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Optional
from enum import IntEnum

class Priority(IntEnum):
    CRITICAL = 0    # kernel pointer found, exploit chain step
    HIGH = 1        # promising lead, new attack surface
    MEDIUM = 2      # standard research, probe writing
    LOW = 3         # documentation, cleanup, re-validation
    BACKGROUND = 4  # speculative research, long shots

@dataclass
class Task:
    id: str
    type: str               # "write_probe", "send_probe", "analyze_result", "research", "document", etc.
    priority: int
    payload: dict            # type-specific data
    created_at: float = field(default_factory=time.time)
    assigned_to: Optional[str] = None
    assigned_at: Optional[float] = None
    completed_at: Optional[float] = None
    status: str = "pending"  # pending, assigned, running, completed, failed, cancelled
    result: Optional[dict] = None
    attempts: int = 0
    max_attempts: int = 3
    parent_task: Optional[str] = None
    tags: list = field(default_factory=list)

    def fingerprint(self):
        key = f"{self.type}:{json.dumps(self.payload, sort_keys=True)}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

class TaskQueue:
    def __init__(self, persist_dir: str):
        self.persist_dir = persist_dir
        os.makedirs(persist_dir, exist_ok=True)
        self._lock = threading.Lock()
        self._tasks: dict[str, Task] = {}
        self._fingerprints: set[str] = set()
        self._counter = 0
        self._load()

    def _load(self):
        queue_file = os.path.join(self.persist_dir, "queue.json")
        if os.path.exists(queue_file):
            with open(queue_file, "r") as f:
                data = json.load(f)
            for td in data:
                task = Task(**td)
                self._tasks[task.id] = task
                if task.status in ("pending", "assigned", "running"):
                    self._fingerprints.add(task.fingerprint())
            self._counter = len(self._tasks)

    def _save(self):
        queue_file = os.path.join(self.persist_dir, "queue.json")
        with open(queue_file, "w") as f:
            json.dump([asdict(t) for t in self._tasks.values()], f, indent=2)

    def add(self, task_type: str, payload: dict, priority: int = Priority.MEDIUM,
            parent: str = None, tags: list = None) -> Optional[Task]:
        with self._lock:
            self._counter += 1
            task = Task(
                id=f"task_{self._counter:06d}",
                type=task_type,
                priority=priority,
                payload=payload,
                parent_task=parent,
                tags=tags or [],
            )
            fp = task.fingerprint()
            if fp in self._fingerprints:
                return None  # duplicate
            self._fingerprints.add(fp)
            self._tasks[task.id] = task
            self._save()
            return task

    def claim(self, agent_id: str, task_types: list[str] = None) -> Optional[Task]:
        with self._lock:
            candidates = [
                t for t in self._tasks.values()
                if t.status == "pending"
                and (task_types is None or t.type in task_types)
                and t.attempts < t.max_attempts
            ]
            if not candidates:
                return None
            candidates.sort(key=lambda t: (t.priority, t.created_at))
            task = candidates[0]
            task.status = "assigned"
            task.assigned_to = agent_id
            task.assigned_at = time.time()
            task.attempts += 1
            self._save()
            return task

    def complete(self, task_id: str, result: dict = None):
        with self._lock:
            task = self._tasks.get(task_id)
            if task:
                task.status = "completed"
                task.completed_at = time.time()
                task.result = result
                self._fingerprints.discard(task.fingerprint())
                self._save()

    def fail(self, task_id: str, error: str = None):
        with self._lock:
            task = self._tasks.get(task_id)
            if task:
                task.status = "pending" if task.attempts < task.max_attempts else "failed"
                task.assigned_to = None
                task.result = {"error": error}
                self._save()

    def cancel(self, task_id: str):
        with self._lock:
            task = self._tasks.get(task_id)
            if task:
                task.status = "cancelled"
                self._fingerprints.discard(task.fingerprint())
                self._save()

    def get_stats(self) -> dict:
        with self._lock:
            stats = {"pending": 0, "assigned": 0, "running": 0,
                     "completed": 0, "failed": 0, "cancelled": 0}
            for t in self._tasks.values():
                stats[t.status] = stats.get(t.status, 0) + 1
            return stats

    def get_pending_by_type(self) -> dict:
        with self._lock:
            by_type = {}
            for t in self._tasks.values():
                if t.status == "pending":
                    by_type[t.type] = by_type.get(t.type, 0) + 1
            return by_type

    def get_recent_completed(self, n: int = 20) -> list[Task]:
        with self._lock:
            completed = [t for t in self._tasks.values() if t.status == "completed"]
            completed.sort(key=lambda t: t.completed_at or 0, reverse=True)
            return completed[:n]

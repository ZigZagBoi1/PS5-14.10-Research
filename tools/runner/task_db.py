#!/usr/bin/env python3
"""SQLite-backed task database for the autonomous research runner.

Tracks tasks, their state, evidence references, and prevents re-investigation
of completed or disproven hypotheses.
"""

import json
import os
import sqlite3
import time
from contextlib import contextmanager

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_DB = os.path.join(ROOT, "tools", "runner", "tasks.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    priority INTEGER DEFAULT 2,
    status TEXT DEFAULT 'pending',
    created_at REAL,
    started_at REAL,
    completed_at REAL,
    result TEXT,
    error TEXT,
    attempt INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 2,
    parent_id TEXT,
    tags TEXT DEFAULT '[]',
    evidence_refs TEXT DEFAULT '[]',
    fingerprint TEXT UNIQUE
);

CREATE TABLE IF NOT EXISTS completed_topics (
    topic TEXT PRIMARY KEY,
    task_id TEXT,
    completed_at REAL,
    verdict TEXT
);

CREATE TABLE IF NOT EXISTS dead_ends (
    topic TEXT PRIMARY KEY,
    reason TEXT,
    task_id TEXT,
    recorded_at REAL
);

CREATE TABLE IF NOT EXISTS run_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT,
    timestamp REAL,
    event TEXT,
    task_id TEXT,
    details TEXT
);

CREATE TABLE IF NOT EXISTS checkpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL,
    run_id TEXT,
    tasks_completed INTEGER,
    tasks_remaining INTEGER,
    state_json TEXT
);
"""


class TaskDB:
    def __init__(self, db_path=None):
        self.db_path = db_path or DEFAULT_DB
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _init_db(self):
        with self._conn() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def add_task(self, task_id, type_, title, description="", priority=2,
                 tags=None, evidence_refs=None, parent_id=None, max_attempts=2):
        fingerprint = f"{type_}:{title}"
        tags = json.dumps(tags or [])
        evidence_refs = json.dumps(evidence_refs or [])
        with self._conn() as conn:
            # Check if already completed or dead-ended
            row = conn.execute(
                "SELECT topic FROM completed_topics WHERE topic = ?",
                (title,)
            ).fetchone()
            if row:
                return None  # already done
            row = conn.execute(
                "SELECT topic FROM dead_ends WHERE topic = ?",
                (title,)
            ).fetchone()
            if row:
                return None  # dead end
            try:
                conn.execute(
                    """INSERT INTO tasks (id, type, title, description, priority,
                       status, created_at, tags, evidence_refs, parent_id,
                       max_attempts, fingerprint)
                       VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?)""",
                    (task_id, type_, title, description, priority,
                     time.time(), tags, evidence_refs, parent_id,
                     max_attempts, fingerprint)
                )
                return task_id
            except sqlite3.IntegrityError:
                return None  # duplicate fingerprint

    def get_next_task(self):
        with self._conn() as conn:
            row = conn.execute(
                """SELECT * FROM tasks WHERE status = 'pending'
                   ORDER BY priority ASC, created_at ASC LIMIT 1"""
            ).fetchone()
            if row:
                conn.execute(
                    "UPDATE tasks SET status='running', started_at=?, attempt=attempt+1 WHERE id=?",
                    (time.time(), row["id"])
                )
                return dict(row)
            return None

    def complete_task(self, task_id, result="", evidence_refs=None):
        with self._conn() as conn:
            conn.execute(
                """UPDATE tasks SET status='completed', completed_at=?,
                   result=?, evidence_refs=? WHERE id=?""",
                (time.time(), result, json.dumps(evidence_refs or []), task_id)
            )
            row = conn.execute("SELECT title FROM tasks WHERE id=?", (task_id,)).fetchone()
            if row:
                conn.execute(
                    "INSERT OR REPLACE INTO completed_topics VALUES (?, ?, ?, ?)",
                    (row["title"], task_id, time.time(), "completed")
                )

    def fail_task(self, task_id, error=""):
        with self._conn() as conn:
            row = conn.execute("SELECT attempt, max_attempts FROM tasks WHERE id=?", (task_id,)).fetchone()
            if row and row["attempt"] >= row["max_attempts"]:
                conn.execute(
                    "UPDATE tasks SET status='failed', error=?, completed_at=? WHERE id=?",
                    (error, time.time(), task_id)
                )
            else:
                conn.execute(
                    "UPDATE tasks SET status='pending', error=? WHERE id=?",
                    (error, task_id)
                )

    def mark_dead_end(self, topic, reason, task_id=None):
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO dead_ends VALUES (?, ?, ?, ?)",
                (topic, reason, task_id, time.time())
            )

    def is_investigated(self, topic):
        with self._conn() as conn:
            c = conn.execute("SELECT 1 FROM completed_topics WHERE topic=?", (topic,)).fetchone()
            if c:
                return "completed"
            d = conn.execute("SELECT 1 FROM dead_ends WHERE topic=?", (topic,)).fetchone()
            if d:
                return "dead_end"
            return None

    def get_stats(self):
        with self._conn() as conn:
            stats = {}
            for status in ("pending", "running", "completed", "failed"):
                row = conn.execute("SELECT COUNT(*) as c FROM tasks WHERE status=?", (status,)).fetchone()
                stats[status] = row["c"]
            stats["dead_ends"] = conn.execute("SELECT COUNT(*) as c FROM dead_ends").fetchone()["c"]
            stats["completed_topics"] = conn.execute("SELECT COUNT(*) as c FROM completed_topics").fetchone()["c"]
            return stats

    def log_event(self, run_id, event, task_id=None, details=None):
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO run_log (run_id, timestamp, event, task_id, details) VALUES (?,?,?,?,?)",
                (run_id, time.time(), event, task_id, details)
            )

    def save_checkpoint(self, run_id, state):
        stats = self.get_stats()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO checkpoints (timestamp, run_id, tasks_completed, tasks_remaining, state_json) VALUES (?,?,?,?,?)",
                (time.time(), run_id, stats["completed"], stats["pending"], json.dumps(state))
            )

    def get_last_checkpoint(self):
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM checkpoints ORDER BY timestamp DESC LIMIT 1"
            ).fetchone()
            return dict(row) if row else None

    def get_pending_tasks(self):
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM tasks WHERE status='pending' ORDER BY priority ASC, created_at ASC"
            ).fetchall()
            return [dict(r) for r in rows]

    def reset_stale_running(self, max_age_seconds=1800):
        cutoff = time.time() - max_age_seconds
        with self._conn() as conn:
            conn.execute(
                "UPDATE tasks SET status='pending' WHERE status='running' AND started_at < ?",
                (cutoff,)
            )

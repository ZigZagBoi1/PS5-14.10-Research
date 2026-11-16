#!/usr/bin/env python3
"""Offline lifecycle tests for the research runner task database."""

import tempfile
import unittest
from pathlib import Path

from tools.runner.task_db import TaskDB


class TaskDBTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = TaskDB(str(Path(self.tmp.name) / "tasks.db"))
        self.task_id = self.db.add_task("t1", "analysis", "Inspect a hypothesis")

    def tearDown(self):
        self.tmp.cleanup()

    def test_get_next_task_returns_the_row_after_the_running_update(self):
        task = self.db.get_next_task()
        self.assertEqual(task["id"], self.task_id)
        self.assertEqual(task["status"], "running")
        self.assertEqual(task["attempt"], 1)
        self.assertIsNotNone(task["started_at"])

    def test_second_call_does_not_return_the_running_task(self):
        self.db.get_next_task()
        self.assertIsNone(self.db.get_next_task())


if __name__ == "__main__":
    unittest.main()

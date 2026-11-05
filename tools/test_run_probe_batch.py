"""Offline tests for run_probe_batch manifest publication."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import run_probe_batch


class FixedDateTime:
    @classmethod
    def now(cls):
        return cls()

    def astimezone(self):
        return self

    def isoformat(self, timespec=None):
        return "2026-11-04T12:00:00+00:00"

    def strftime(self, fmt):
        return "20261104_120000"


class ManifestCollisionTests(unittest.TestCase):
    def test_existing_manifest_is_not_replaced(self):
        with tempfile.TemporaryDirectory() as tmp:
            previous = Path.cwd()
            os.chdir(tmp)
            try:
                Path("results").mkdir()
                Path("probe.lua").write_text("return 1\n", encoding="utf-8")
                existing = Path("results/probe_batch_20261104_120000.json")
                existing.write_text("keep\n", encoding="utf-8")

                with mock.patch.object(run_probe_batch, "datetime", FixedDateTime), \
                        mock.patch.object(run_probe_batch, "send_lua",
                                          return_value="COMPLETE"), \
                        mock.patch.object(sys, "argv",
                                          ["run_probe_batch.py", "probe.lua", "--save"]):
                    self.assertEqual(run_probe_batch.main(), 0)

                self.assertEqual(existing.read_text(encoding="utf-8"), "keep\n")
                new = list(Path("results").glob(
                    "probe_batch_20261104_120000_*/*.json"))
                self.assertEqual(len(new), 1)
                manifest = json.loads(new[0].read_text(encoding="utf-8"))
                self.assertEqual(manifest["records"][0]["status"], "COMPLETE")
            finally:
                os.chdir(previous)


if __name__ == "__main__":
    unittest.main()

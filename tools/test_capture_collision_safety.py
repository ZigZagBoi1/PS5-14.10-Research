#!/usr/bin/env python3
"""Offline regressions for collision-safe Python capture persistence.

These tests call the real ``_save_capture`` helper in a temporary checkout
layout.  They do not open a network connection or send a probe.
"""

import contextlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


TOOLS_DIR = Path(__file__).resolve().parent
SENDER_PATH = TOOLS_DIR / "send_probe.py"
FIXED_STAMP = "20240102_030405"


def _load_sender():
    spec = importlib.util.spec_from_file_location("capture_collision_sender", SENDER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load %s" % SENDER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@contextlib.contextmanager
def _in_directory(path):
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


class CaptureCollisionSafetyTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(prefix="capture-collision-")
        self.addCleanup(self.tempdir.cleanup)
        self.checkout = Path(self.tempdir.name) / "checkout"
        self.run_dir = self.checkout / "run"
        self.probe = self.checkout / "probes" / "phase_collision" / "same_probe.lua"
        self.probe.parent.mkdir(parents=True)
        self.run_dir.mkdir(parents=True)
        self.probe.write_text("-- offline fixture\n", encoding="utf-8")
        self.sender = _load_sender()
        # _results_dir derives the checkout's probes root from module __file__.
        self.sender.__file__ = str(self.checkout / "tools" / "send_probe.py")

    def _save(self, response, metadata, write_metadata=True):
        with _in_directory(self.run_dir), mock.patch.object(
            self.sender, "_timestamp", return_value=FIXED_STAMP
        ), contextlib.redirect_stdout(io.StringIO()):
            return self.sender._save_capture(
                self.probe, response, metadata, write_metadata=write_metadata
            )

    @property
    def legacy_dir(self):
        return self.run_dir / "results" / "phase_collision"

    @property
    def legacy_stem(self):
        return "same_probe_%s" % FIXED_STAMP

    def test_same_timestamp_metadata_runs_keep_distinct_matched_pairs(self):
        first_txt, first_json = self._save(b"first response", {"run": 1})
        second_txt, second_json = self._save(b"second response", {"run": 2})

        self.assertEqual(first_txt.name, self.legacy_stem + ".txt")
        self.assertEqual(first_json.name, self.legacy_stem + ".json")
        self.assertEqual(first_txt.parent, Path("results/phase_collision"))
        self.assertNotEqual(first_txt, second_txt)
        self.assertEqual(second_txt.name, first_txt.name)
        self.assertEqual(second_json.name, first_json.name)
        self.assertEqual(second_txt.parent, second_json.parent)

        saved_txt = sorted((self.run_dir / "results").rglob("*.txt"))
        saved_json = sorted((self.run_dir / "results").rglob("*.json"))
        self.assertEqual(len(saved_txt), 2)
        self.assertEqual(len(saved_json), 2)
        self.assertEqual({path.read_bytes() for path in saved_txt},
                         {b"first response", b"second response"})
        records = [json.loads(path.read_text(encoding="utf-8")) for path in saved_json]
        self.assertEqual({record["run"] for record in records}, {1, 2})
        for record, meta_path in zip(records, saved_json):
            output_path = self.run_dir / record["output_path"]
            recorded_meta_path = self.run_dir / record["metadata_path"]
            self.assertTrue(output_path.is_file())
            self.assertEqual(recorded_meta_path, meta_path)
            self.assertEqual(output_path.parent, meta_path.parent)

    def test_same_timestamp_silent_metadata_runs_keep_distinct_empty_pairs(self):
        first_txt, first_json = self._save(b"", {"run": "first"})
        second_txt, second_json = self._save(b"", {"run": "second"})

        self.assertNotEqual(first_txt, second_txt)
        self.assertEqual(second_txt.parent, second_json.parent)
        self.assertEqual((self.run_dir / first_txt).read_bytes(), b"")
        self.assertEqual((self.run_dir / second_txt).read_bytes(), b"")
        records = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in sorted((self.run_dir / "results").rglob("*.json"))
        ]
        self.assertEqual({record["run"] for record in records}, {"first", "second"})

    def test_noncolliding_response_keeps_legacy_root_filename(self):
        out_path, meta_path = self._save(
            b"ordinary", {"unused": True}, write_metadata=False
        )

        self.assertEqual(out_path, Path("results/phase_collision") /
                         (self.legacy_stem + ".txt"))
        self.assertIsNone(meta_path)
        self.assertEqual((self.run_dir / out_path).read_bytes(), b"ordinary")

    def test_unserializable_metadata_does_not_publish_an_unmatched_capture(self):
        with self.assertRaises(TypeError):
            self._save(b"response", {"not_json": object()})

        results = self.run_dir / "results"
        saved_files = list(results.rglob("*")) if results.exists() else []
        self.assertEqual([path for path in saved_files if path.is_file()], [])

    def test_existing_capture_symlink_is_not_followed_or_overwritten(self):
        self.legacy_dir.mkdir(parents=True)
        protected = self.checkout / "protected-by-symlink.txt"
        protected.write_bytes(b"do not overwrite")
        legacy_txt = self.legacy_dir / (self.legacy_stem + ".txt")
        legacy_txt.symlink_to(protected)

        out_path, meta_path = self._save(b"new capture", {"run": "safe"})

        self.assertEqual(protected.read_bytes(), b"do not overwrite")
        self.assertNotEqual(self.run_dir / out_path, legacy_txt)
        self.assertFalse((self.run_dir / out_path).is_symlink())
        self.assertEqual((self.run_dir / out_path).read_bytes(), b"new capture")
        self.assertEqual((self.run_dir / out_path).parent,
                         (self.run_dir / meta_path).parent)

    def test_existing_metadata_sidecar_routes_pair_without_overwriting_it(self):
        self.legacy_dir.mkdir(parents=True)
        legacy_json = self.legacy_dir / (self.legacy_stem + ".json")
        legacy_json.write_text('{"preexisting": true}\n', encoding="utf-8")

        out_path, meta_path = self._save(b"capture", {"run": "new"})

        self.assertEqual(legacy_json.read_text(encoding="utf-8"),
                         '{"preexisting": true}\n')
        self.assertNotEqual((self.run_dir / meta_path), legacy_json)
        self.assertEqual((self.run_dir / out_path).parent,
                         (self.run_dir / meta_path).parent)
        record = json.loads((self.run_dir / meta_path).read_text(encoding="utf-8"))
        self.assertEqual(record["output_path"], str(out_path))
        self.assertEqual(record["metadata_path"], str(meta_path))


if __name__ == "__main__":
    unittest.main()

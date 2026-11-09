#!/usr/bin/env python3
"""Regression tests for the generated 13.60 syscall label table.

``tools/ghidra_label_syscalls.py`` used to carry a hand-maintained
``SYSCALL_NAMES`` dict transcribed from a FreeBSD-9 ordering with unimplemented
slots dropped. Because the transcription kept list positions instead of syscall
numbers, entries drifted by up to sixteen (``429: jail_attach`` where the
capture says ``sigwait``). These tests hold the table to the committed capture
and to the arities in ``sysent_index.json``.

Run with::

    python -m unittest tools.test_syscall_labels -v
"""

import csv
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "tools" / "ghidra_label_syscalls.py"
GEN = ROOT / "tools" / "gen_syscall_labels.py"
NATIVE = ROOT / "docs" / "sysent-names-13.60.csv"
COMPAT = ROOT / "docs" / "sysent-compat-names-13.60.csv"
INDEX = ROOT / "docs" / "dumps_13.60" / "sysent_index.json"
PROBE_57E = ROOT / "probes" / "phase15_native_sysent" / "57e_jail_reachability.lua"
NOSYS_RVA = 0x265760


def script_labels():
    text = SCRIPT.read_text(encoding="utf-8")
    body = text.split("# BEGIN GENERATED SYSCALL_NAMES", 1)[1]
    body = body.split("# END GENERATED SYSCALL_NAMES", 1)[0]
    return {int(m.group(1)): m.group(2)
            for m in re.finditer(r'^\s*(\d+):\s*"([a-z0-9_.]+)",', body, re.M)}


def csv_names(path):
    with open(path, newline="", encoding="utf-8") as fh:
        return {int(r["number"]): r["name"] for r in csv.DictReader(fh)}


class GeneratedTableTests(unittest.TestCase):
    def test_table_matches_the_capture(self):
        names = csv_names(NATIVE)
        expected = {n: v.replace(".", "_") for n, v in names.items()
                    if n < 532 and v and v != "obs_{" and not v.startswith("#")}
        self.assertEqual(script_labels(), expected)

    def test_generator_check_passes(self):
        import subprocess, sys
        proc = subprocess.run([sys.executable, str(GEN), "--check"],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_identities_that_were_wrong(self):
        labels = script_labels()
        self.assertEqual(labels[429], "sigwait")
        self.assertEqual(labels[430], "thr_create")
        self.assertEqual(labels[431], "thr_exit")
        self.assertEqual(labels[432], "thr_self")
        self.assertEqual(labels[433], "thr_kill")
        self.assertEqual(labels[442], "thr_suspend")
        self.assertEqual(labels[443], "thr_wake")
        self.assertEqual(labels[444], "kldunloadf")
        self.assertEqual(labels[454], "_umtx_op")
        self.assertEqual(labels[455], "thr_new")
        self.assertEqual(labels[456], "sigqueue")

    def test_no_slot_is_named_jail(self):
        for path in (NATIVE, COMPAT):
            names = csv_names(path)
            hits = [n for n, v in names.items() if "jail" in v.lower()]
            self.assertEqual(hits, [], path.name)


class ArityTests(unittest.TestCase):
    """The capture's narg must fit the name the capture gives that slot."""

    EXPECTED = {
        430: 3,   # thr_create(ucontext_t *, long *, int)
        431: 1,   # thr_exit(long *)
        432: 1,   # thr_self(long *)
        433: 2,   # thr_kill(long, int)
        442: 1,   # thr_suspend(const struct timespec *)
        443: 1,   # thr_wake(long)
        444: 2,   # kldunloadf(int, int)
        455: 2,   # thr_new(struct thr_param *, int)
        456: 3,   # sigqueue(pid_t, int, void *)
    }

    def test_narg_matches_the_named_prototype(self):
        entries = {e["num"]: e for e in
                   json.loads(INDEX.read_text())["entries"]}
        for num, narg in self.EXPECTED.items():
            self.assertEqual(entries[num]["narg"], narg, num)

    def test_jail_slots_are_nosys(self):
        entries = {e["num"]: e for e in
                   json.loads(INDEX.read_text())["entries"]}
        for num in (338, 436, 506, 507):
            entry = entries[num]
            self.assertEqual(int(entry["sy_call_off"], 16), NOSYS_RVA, num)
            self.assertEqual(entry["narg"], 0, num)


class Probe57eTests(unittest.TestCase):
    def test_probe_calls_the_jail_slots_and_a_control(self):
        text = PROBE_57E.read_text(encoding="utf-8")
        called = [int(m.group(1)) for m in
                  re.finditer(r'tag_call\("[^"]*",\s*(\d+),', text)]
        self.assertEqual(sorted(set(called)), [338, 429, 436, 506, 507])
        # 496/497 are mkdirat/mkfifoat and must not appear as calls.
        self.assertNotIn(", 496,", text)
        self.assertNotIn(", 497,", text)

    def test_probe_records_the_correction(self):
        text = PROBE_57E.read_text(encoding="utf-8")
        self.assertIn("CORRECTION (2026-10-19)", text)
        self.assertIn("429 is sigwait", text)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Offline regressions for the data-gather FontFace walk validity gate."""

from pathlib import Path
import json
import re
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parent.parent
PROBE = ROOT / "probes" / "phase13_webkit" / "data-gather" / "probe-modules.html"


def extract_function(text, name):
    """Return one function declaration by brace-matching its body."""
    match = re.search(r"\bfunction\s+" + re.escape(name) + r"\s*\(", text)
    if not match:
        raise AssertionError(f"{name} helper missing")
    start = text.find("{", match.end())
    if start < 0:
        raise AssertionError(f"{name} body missing")
    depth = 0
    for index in range(start, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[match.start():index + 1]
    raise AssertionError(f"{name} body is not closed")


@unittest.skipUnless(shutil.which("node"), "node not installed")
class DataGatherWalkTests(unittest.TestCase):
    def run_validator(self, cases):
        helper = extract_function(PROBE.read_text(encoding="utf-8"),
                                  "validWalkSlots")
        script = helper + "\n" + """
const cases = JSON.parse(process.argv[1]);
for (const [name, values, expected] of cases) {
    const args = values.map((v) => BigInt(v));
    const actual = validWalkSlots(...args);
    if (actual !== expected) {
        throw new Error(`${name}: expected ${expected}, got ${actual}`);
    }
}
"""
        result = subprocess.run(
            ["node", "-e", script, json.dumps(cases)],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_slot_validator_accepts_both_known_layout_families(self):
        deltas = [0x1710B78, 0x1710B48, 0x324C3D8, 0x1710478,
                  0x324C3D8, 0x324C3D8, 0x1ABA728, 0x1710318]
        cases = []
        for name, vp in (("reference-family", 0x80C6A1B28),
                         ("issue-295-family", 0x8158EDB28)):
            values = [hex(vp)] + [hex(vp - delta) for delta in deltas]
            cases.append([name, values, True])
        self.run_validator(cases)

    def test_slot_validator_rejects_zero_or_corrupt_slots(self):
        vp = 0x8158EDB28
        deltas = [0x1710B78, 0x1710B48, 0x324C3D8, 0x1710478,
                  0x324C3D8, 0x324C3D8, 0x1ABA728, 0x1710318]
        values = [hex(vp)] + [hex(vp - delta) for delta in deltas]
        zero_s2 = list(values)
        zero_s2[3] = "0x0"
        broken_icf = list(values)
        broken_icf[5] = hex(int(broken_icf[5], 16) + 0x10)
        wrong_delta = list(values)
        wrong_delta[1] = hex(int(wrong_delta[1], 16) + 0x1000)
        low_pointer = list(values)
        low_pointer[8] = "0x100000000"
        cases = [
            ["zero-slot", zero_s2, False],
            ["broken-icf", broken_icf, False],
            ["wrong-slot-delta", wrong_delta, False],
            ["low-pointer", low_pointer, False],
        ]
        self.run_validator(cases)
    def test_production_call_site_uses_validator(self):
        text = PROBE.read_text(encoding="utf-8")
        self.assertIn("walkOK=validWalkSlots(VP,S0,S1,S2,S3,S4,S5,S6,S7);", text)
        self.assertIsNone(re.search(r"walkOK\s*=\s*true\s*;", text))
    def test_success_message_does_not_claim_assumed_base(self):
        text = PROBE.read_text(encoding="utf-8")
        self.assertIn("SUCCESS — VP='+hex(VP)+'; base RVA unresolved", text)
        self.assertNotIn("SUCCESS — VP='+hex(VP)+' BASE='+hex(BASE)", text)


if __name__ == "__main__":
    unittest.main()

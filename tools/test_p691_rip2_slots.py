#!/usr/bin/env python3
"""Regression tests for p691's portable RIP2 vtable-slot selection."""

import json
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROBE = ROOT / "probes" / "phase13_webkit" / "p691-walk-forge-fixed.html"


def extract_function(source: str, name: str) -> str:
    """Return one top-level JS function, brace-matched rather than line-based."""
    marker = f"function {name}("
    start = source.find(marker)
    if start < 0:
        raise AssertionError(f"missing function {name}")
    opening = source.find("{", start)
    if opening < 0:
        raise AssertionError(f"missing body for {name}")
    depth = 0
    for index in range(opening, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    raise AssertionError(f"unterminated function {name}")


@unittest.skipUnless(shutil.which("node"), "node not installed")
class P691Rip2SlotTests(unittest.TestCase):
    def helper(self, name: str) -> str:
        return extract_function(PROBE.read_text(encoding="utf-8"), name)

    def run_js(self, helpers: str, body: str) -> str:
        result = subprocess.run(
            ["node", "-e", helpers + "\n" + body],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_default_slot_fill_uses_measured_safe_slot(self):
        output = self.run_js(
            self.helper("rip2SlotFill"),
            "process.stdout.write(rip2SlotFill(0x800010000n,0x800020000n,-1).toString(16));",
        )
        self.assertEqual(output, "800020000")

    def test_probe_defaults_disable_poison_and_byte_probe(self):
        source = PROBE.read_text(encoding="utf-8")
        self.assertIn("PK=qint('pk',-1)", source)
        self.assertIn("var gOff=qint('goff',-1);", source)

    def test_slot_loop_uses_poison_helper_and_has_no_hardcoded_ret(self):
        source = PROBE.read_text(encoding="utf-8")
        self.assertIn("put64(sk,8+jv*8,rip2SlotValue(jv,SLOT_FILL,PK))", source)
        self.assertNotIn("G_RET=S0>1n?S0-1n:0n", source)
        self.assertNotIn("G_TRY=S0-BigInt(gOff)", source)

    def test_poison_arm_changes_only_the_requested_slot(self):
        output = self.run_js(
            self.helper("rip2SlotValue"),
            "const a=[];for(let i=0;i<16;i++)a.push(rip2SlotValue(i,0x800020000n,4).toString(16));"
            "process.stdout.write(JSON.stringify(a));",
        )
        values = json.loads(output)
        self.assertEqual(values[4], "4141414141414141")
        self.assertTrue(all(value == "800020000" for index, value in enumerate(values)
                            if index != 4))

    def test_all_poison_mode_marks_every_slot(self):
        output = self.run_js(
            self.helper("rip2SlotValue"),
            "const a=[];for(let i=0;i<16;i++)a.push(rip2SlotValue(i,0x800020000n,16).toString(16));"
            "process.stdout.write(JSON.stringify(a));",
        )
        self.assertEqual(json.loads(output), ["4141414141414141"] * 16)

    def test_explicit_goff_probes_s0_minus_requested_offset(self):
        output = self.run_js(
            self.helper("rip2SlotFill"),
            "process.stdout.write(rip2SlotFill(0x800010000n,0x800020000n,7).toString(16));",
        )
        self.assertEqual(output, "80000fff9")


if __name__ == "__main__":
    unittest.main()

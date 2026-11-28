#!/usr/bin/env python3
"""Exercise FontFace oracle boundary readers with calibrated range semantics."""

from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parent.parent
PROBE_ROOT = Path("probes/phase13_webkit")
MAIN_PROBES = (
    "p672-iterateclients-callback-dispatch.html",
    "p690-walk-forge-oracle.html",
    "p691-walk-forge-fixed.html",
    "p804-vtable-verify.html",
    "p807-base-discovery.html",
    "p809-elf-got-reader.html",
    "p809v24b.html",
    "p809v25d.html",
    "p809v25e.html",
    "p809v25e10.html",
    "p809v25e37.html",
    "p811-addrof-read.html",
    "p812-heap-scan.html",
    "p813-arw-read.html",
    "p813v2-feng-shui.html",
    "p814-ur-fengshui.html",
    "p815-wide-rs.html",
    "p816-diag.html",
    "p817-magic-base-discovery.html",
)
ADAPTED_P691C = PROBE_ROOT / "adapted-guide-entry/p691c-oracle-fix.html"
ADAPTED_P811 = PROBE_ROOT / "adapted-guide-entry/p811-oracle-status3.html"
CASES = (
    (0x1000, 0x2000),
    (0, 0x5000),
    (1, 0x2000),
    (0x40, 0x100),
    (0x3000, 0x1000),
)


def extract_function(text: str, name: str) -> str:
    """Return one named JavaScript function, including its body."""
    match = re.search(rf"\bfunction\s+{re.escape(name)}\s*\(", text)
    if not match:
        raise AssertionError(f"missing function {name}()")
    start = match.start()
    opening = text.find("{", match.end())
    if opening < 0:
        raise AssertionError(f"missing body for {name}()")

    depth = 0
    quote = None
    escaped = False
    line_comment = False
    block_comment = False
    for index in range(opening, len(text)):
        char = text[index]
        nxt = text[index:index + 2]
        if line_comment:
            if char == "\n":
                line_comment = False
            continue
        if block_comment:
            if nxt == "*/":
                block_comment = False
            continue
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if nxt == "//":
            line_comment = True
            continue
        if nxt == "/*":
            block_comment = True
            continue
        if char in ("'", '"', "`"):
            quote = char
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start:index + 1]
    raise AssertionError(f"unterminated function {name}()")


def evaluate_reader(path: Path, mode: str) -> list[int | None]:
    text = path.read_text(encoding="utf-8")
    chk = extract_function(text, "chk")
    boundary = extract_function(text, "boundary")
    chk = re.sub(r"\bfunction\s+chk\s*\(", "function chk_x(", chk)
    boundary = re.sub(r"\bfunction\s+boundary\s*\(", "function boundary_x(", boundary)
    boundary = re.sub(r"\bchk\b", "chk_x", boundary)

    if mode == "status3":
        invoke = "boundary_x(chk_x(0), chk_x(0x41), chk_x(0x1000))"
    else:
        invoke = "boundary_x(0)"
    normalize = "value && typeof value === 'object' ? value.b : value"

    script = f"""
let pair = [0, 0];
const document = {{ fonts: {{ check(_font, ch) {{
  const cp = ch.codePointAt(0);
  return cp >= pair[0] && cp <= pair[1];
}} }} }};
const fam = 'zz0';
function setR(_target) {{}}
{chk}
{boundary}
const cases = {json.dumps(CASES)};
const out = [];
for (const [from, to] of cases) {{
  pair = [from, to];
  const value = {invoke};
  out.push({normalize});
}}
console.log(JSON.stringify(out));
"""
    proc = subprocess.run(
        ["node", "-e", script],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(f"{path}: Node harness failed:\n{proc.stderr}")
    return json.loads(proc.stdout)


@unittest.skipUnless(shutil.which("node"), "node not installed")
class FontsOraclePolarityTests(unittest.TestCase):
    def assert_cases(self, path: Path, mode: str = "number") -> None:
        actual = evaluate_reader(path, mode)
        expected = [to if frm <= to else -1 for frm, to in CASES]
        self.assertEqual(expected, actual, str(path))

    def test_negated_main_helpers_read_the_to_word(self) -> None:
        for name in MAIN_PROBES:
            with self.subTest(probe=name):
                self.assert_cases(PROBE_ROOT / name)

    def test_adapted_raw_helper_reads_the_to_word(self) -> None:
        self.assert_cases(ADAPTED_P691C, "object")

    def test_adapted_status3_accepts_zero_based_ranges(self) -> None:
        self.assert_cases(ADAPTED_P811, "status3")


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Parse-check the classic scripts in probes that previously failed to load."""

import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# These probes shipped with parser errors, so their beacons never started.
# The browser treats a classic <script> as a Script, not a Module: top-level
# await is rejected and `typeof import` is not a valid expression.
CLASSIC_PROBES = (
    "probes/phase13_webkit/p731-formdata-construction-timing.html",
    "probes/phase13_webkit/p734-history-navigation-timing.html",
    "probes/phase13_webkit/p771-webaudio-buffer-residue.html",
    "probes/phase13_webkit/adapted-guide-entry/p802-deep-api-scan.html",
    "probes/phase14_rop/tester-hub.html",
    "probes/phase13_webkit/data-gather/probe-modules.html",
)

SCRIPT_RE = re.compile(
    r"<script(?![^>]*\bsrc=)(?![^>]*\btype\s*=\s*['\"]?module)[^>]*>"
    r"(.*?)</script>",
    re.IGNORECASE | re.DOTALL,
)


@unittest.skipUnless(shutil.which("node"), "node not installed")
class ClassicProbeScriptTests(unittest.TestCase):
    def test_known_probes_parse_as_classic_scripts(self):
        with tempfile.TemporaryDirectory() as tmp:
            for relative in CLASSIC_PROBES:
                text = (ROOT / relative).read_text(encoding="utf-8")
                scripts = [m.group(1) for m in SCRIPT_RE.finditer(text)
                           if m.group(1).strip()]
                self.assertTrue(scripts, relative)
                for index, code in enumerate(scripts):
                    script = Path(tmp) / f"probe-{index}.js"
                    script.write_text(code, encoding="utf-8", newline="\n")
                    result = subprocess.run(
                        ["node", "--check", str(script)],
                        capture_output=True, text=True,
                    )
                    self.assertEqual(
                        result.returncode, 0,
                        f"{relative} inline script {index}:\n{result.stderr}",
                    )


if __name__ == "__main__":
    unittest.main()

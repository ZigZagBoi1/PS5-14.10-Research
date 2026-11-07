"""Pin the 55c correction across prose.

Probe 55c passed `0x100` in sys 622's size field, which the entry check rejects with
`0x800E0001` before dispatch, so the capture records the reject path and nothing else.
`1335a` is the successor that dispatches at `0x40`. The ledger grades 55c `V`, but a grade
guards a row, not a sentence: any paragraph that cites 55c next to 622 or 0x800E0001 must
say that it is void, or the library can contradict the ledger.
"""

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Verbatim archives, agent scratch notes and local scratch trees are history, not
# claims under maintenance.
SKIP_PREFIXES = ("results", "docs/agent-work", ".local", "tmp")
SKIP_FILES = {"docs/ALL_PROBES.md", "docs/ALL_RESULTS.md"}

MARKERS = ("void", "withdrawn", "entry check", "gate reject", "reject", "regraded")


def _documents():
    for path in sorted(ROOT.rglob("*.md")):
        rel = path.relative_to(ROOT).as_posix()
        if rel in SKIP_FILES or rel.startswith(SKIP_PREFIXES):
            continue
        yield rel, path.read_text(encoding="utf-8", errors="replace")


def _paragraphs(text):
    return [block for block in re.split(r"\n\s*\n", text) if block.strip()]


PROBE_55C = re.compile(r"(?<![0-9a-fA-Fx])55c(?![0-9a-fA-F])")


def _flags_55c(paragraph):
    """Match the probe id, not the hex substring: `0x55c` is a register offset."""
    if not PROBE_55C.search(paragraph):
        return False
    return "622" in paragraph or "0x800e0001" in paragraph.lower()


class Sys622ProseTests(unittest.TestCase):
    def test_every_55c_paragraph_carries_the_correction(self):
        offenders = []
        for rel, text in _documents():
            for paragraph in _paragraphs(text):
                if not _flags_55c(paragraph):
                    continue
                lowered = paragraph.lower()
                if not any(marker in lowered for marker in MARKERS):
                    first = paragraph.strip().splitlines()[0][:90]
                    offenders.append("%s: %s" % (rel, first))
        self.assertEqual([], offenders, "paragraph cites 55c without the correction")

    def test_the_retracted_reading_is_not_asserted(self):
        retracted = "worked on a real request"
        for rel, text in _documents():
            for paragraph in _paragraphs(text):
                if retracted not in paragraph:
                    continue
                lowered = paragraph.lower()
                self.assertTrue(
                    any(marker in lowered for marker in MARKERS),
                    "%s asserts the retracted reading" % rel)

    def test_probe_index_grades_55c_void(self):
        text = (ROOT / "docs" / "PROBE_INDEX.md").read_text(encoding="utf-8")
        row = [line for line in text.splitlines() if line.startswith("| 55c |")]
        self.assertEqual(1, len(row), "expected exactly one 55c row")
        self.assertIn("| VOID |", row[0])


if __name__ == "__main__":
    unittest.main()

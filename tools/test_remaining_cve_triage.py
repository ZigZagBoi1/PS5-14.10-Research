#!/usr/bin/env python3
"""Pins for docs/REMAINING_CVE_TRIAGE.md.

The triage note's value is that every "blocked" or "untested" verdict points at
a committed line. These tests hold those lines: the 54a capture, the FINDINGS
console-device line, the scene-research CVE headings, the 13.60 sendfile entry,
and the absence of KTLS strings in the captured data range.

Offline and read-only.
"""

import json
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DUMPS = ROOT / "docs" / "dumps_13.60"
NOTE = ROOT / "docs" / "REMAINING_CVE_TRIAGE.md"
SCENE = ROOT / "docs" / "research" / "scene_research_oct2026.md"
FINDINGS = ROOT / "docs" / "FINDINGS.md"
ATTACK = ROOT / "docs" / "ATTACK_SURFACE.md"
INDEX = ROOT / "docs" / "PROBE_INDEX.md"
RESULT_54A = ROOT / "results" / "54a_dsp_access_check_20261018_032254.txt"
PROBE_54A = ROOT / "probes" / "phase10_untested_theories" / "54a_dsp_access_check.lua"


class ResultCitationTests(unittest.TestCase):
    def test_54a_capture_records_the_control_and_the_three_failures(self):
        lines = RESULT_54A.read_text(encoding="utf-8").splitlines()
        self.assertEqual(lines[2], "/dev/null: OPEN_OK fd=22 (closing immediately)")
        for i, path in ((4, "/dev/dsp"), (5, "/dev/dsp0.0"), (6, "/dev/sndstat")):
            self.assertEqual(
                lines[i],
                f"{path}: OPEN_DENIED_OR_ABSENT ret=0xffffffffffffffffffffffff")
        self.assertIn("RESULT_LIMIT: accessibility only", "\n".join(lines))

    def test_54a_source_states_its_own_scope(self):
        source = PROBE_54A.read_text(encoding="utf-8")
        self.assertIn("open/close only; no mmap or ioctl", source)
        self.assertIn("CRASH_CLASS: LOW", source)

    def test_findings_blocks_console_and_tty(self):
        text = FINDINGS.read_text(encoding="utf-8")
        self.assertIn(
            "`/dev/console`, `/dev/tty`, `/dev/bpf`, `/dev/crypto`, `/dev/pf` all blocked",
            text)

    def test_attack_surface_lists_ioctl_as_blocked(self):
        text = ATTACK.read_text(encoding="utf-8")
        self.assertIn("| `ioctl` | 54 | Blocked |", text)

    def test_probe_index_records_sys622_device_context_failure(self):
        text = INDEX.read_text(encoding="utf-8")
        self.assertIn("0x800E0001", text)


class SceneResearchTests(unittest.TestCase):
    def test_the_four_cves_are_named_where_the_note_says(self):
        # Locate by content, not line index: the scene document gains sections
        # over time and a line pin silently rots.
        text = SCENE.read_text(encoding="utf-8")
        for heading in (
            "**CVE-2026-49417 - /dev/dsp close-while-mapped UAF**",
            "**CVE-2026-45257 - KTLS receive page cache overwrite**",
            "**CVE-2026-49416 - vt(4) CONS_HISTORY ioctl overflow**",
            "**CVE-2026-49414 - ELF ASLR disable for setuid PIE**",
        ):
            self.assertIn(heading, text, heading)


class SendfileArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = (DUMPS / "kernel_text.bin").read_bytes()
        cls.index = {e["num"]: e for e in
                     json.loads((DUMPS / "sysent_index.json").read_text())["entries"]}

    def test_sendfile_slot_and_body(self):
        entry = self.index[393]
        self.assertEqual(entry["narg"], 7)
        slot = int(entry["sy_call_off"], 16)
        self.assertEqual(slot, 0x265B88)
        rel = struct.unpack_from("<i", self.text, slot + 1)[0]
        self.assertEqual((slot + 5 + rel) & 0xFFFFFFFFFFFFFFFF, 0x8340E0)

    def test_sendfile_copies_in_a_0x20_byte_hdtr(self):
        # mov edx,0x20 at 0x834150 then call 0x259280 (copyin) at 0x834158.
        self.assertEqual(self.text[0x834150:0x834155], bytes.fromhex("ba20000000"))
        self.assertEqual(self.text[0x834158], 0xE8)
        rel = struct.unpack_from("<i", self.text, 0x834159)[0]
        self.assertEqual((0x834158 + 5 + rel) & 0xFFFFFFFFFFFFFFFF, 0x259280)

    def test_data_range_has_no_ktls_string(self):
        data = (DUMPS / "kernel_data.bin").read_bytes()
        for needle in (b"ktls", b"KTLS", b"SO_TXTLS"):
            self.assertEqual(data.count(needle), 0, needle)


class CorpusAbsenceTests(unittest.TestCase):
    """The note says these paths were never issued; prove it from the tree.

    Probes can exist without ever having run — the tree ships PREPARED probes
    (for example 58d, which is named after sendfile but has no result capture).
    "Never issued" is therefore a claim about executed captures, so this scans
    ``results/**/*.txt``, not probe sources.
    """

    def _corpus_text(self) -> str:
        chunks = []
        for path in ROOT.glob("results/**/*.txt"):
            chunks.append(path.read_text(encoding="utf-8", errors="replace"))
        return "\n".join(chunks)

    def test_no_sendfile_in_the_corpus(self):
        self.assertNotIn("sendfile", self._corpus_text().lower())

    def test_no_execve_call_in_the_corpus(self):
        corpus = self._corpus_text().lower()
        for needle in ("make_syscall(59)", "sc_execve", "execve("):
            self.assertNotIn(needle, corpus, needle)

    def test_no_setuid_mention_in_the_corpus(self):
        self.assertNotIn("setuid", self._corpus_text().lower())


class NoteTests(unittest.TestCase):
    def test_note_has_a_row_for_every_cve(self):
        text = NOTE.read_text(encoding="utf-8")
        for cve in ("49417", "45257", "49416", "49414"):
            self.assertIn(f"| {cve} |", text)

    def test_note_states_the_limits(self):
        text = NOTE.read_text(encoding="utf-8")
        self.assertIn("not evidence of absence", text)
        self.assertIn("Blocked at the tested open path", text)
        self.assertIn("No CVE is assessed here", text)

    def test_note_links_only_files_that_exist_on_master(self):
        text = NOTE.read_text(encoding="utf-8")
        import re
        for target in re.findall(r"\]\(([A-Za-z0-9_.-]+\.md)\)", text):
            candidates = [ROOT / "docs" / target, ROOT / target]
            self.assertTrue(any(p.exists() for p in candidates), target)


if __name__ == "__main__":
    unittest.main()

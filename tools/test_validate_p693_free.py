#!/usr/bin/env python3
"""Pin the offline validator for the p693 rcw=0 free signature."""

import unittest
from pathlib import Path

from tools import validate_p693_free as v

ROOT = Path(__file__).resolve().parent.parent
CAPTURE = (ROOT / "tools/browser_runner/beacon_logs"
           / "capture-9369f267-c0cc-4133-8f78-7cdaa6ffc3f5.jsonl")


class CommittedCaptureTests(unittest.TestCase):
    def test_the_committed_v35_capture_grades_consistent(self):
        verdict, r = v.analyze(v.tags_from(str(CAPTURE)))
        self.assertEqual(verdict, "FREE_SIGNATURE_CONSISTENT")
        checks = r["checks"]
        for key in ("rc_word_zeroed_c68_eq_0",
                    "icf_collapse_vt_q2_eq_q4_eq_q5",
                    "freelist_link_c70_eq_vt_q2",
                    "freelist_link_c78_eq_vt_q2",
                    "vptr_untouched_c88_eq_vp",
                    "probe_vt_s2_matches_dump_q2",
                    "header_h60_in_module_band",
                    "c80_small_nonzero",
                    "freed_addr_in_spray_band"):
            self.assertIs(checks.get(key), True, key)

    def test_no_tautological_geometry_key_remains(self):
        verdict, r = v.analyze(v.tags_from(str(CAPTURE)))
        self.assertEqual(verdict, "FREE_SIGNATURE_CONSISTENT")
        self.assertNotIn("c88_is_freed_plus_0x20", r["checks"])

    def test_the_dump_decodes_the_documented_icf_collapse(self):
        verdict, r = v.analyze(v.tags_from(str(CAPTURE)))
        q = r["walkvt_qwords"]
        self.assertEqual(hex(q[2]), "0x83f4f9750")
        self.assertEqual(q[2], q[4])
        self.assertEqual(q[2], q[5])


class AdversarialInputTests(unittest.TestCase):
    def _tags(self):
        return list(v.tags_from(str(CAPTURE)))

    def test_missing_walk_vt_is_incomplete_not_a_silent_pass(self):
        tags = [t for t in self._tags() if "WALK-VT=" not in t]
        verdict, r = v.analyze(tags)
        self.assertEqual(verdict, "INCOMPLETE")
        self.assertIn("WALK-VT", r["missing"])

    def test_missing_vp_is_incomplete_not_a_silent_pass(self):
        tags = [t for t in self._tags() if not v.VP_RE.search(t)]
        verdict, r = v.analyze(tags)
        self.assertEqual(verdict, "INCOMPLETE")
        self.assertIn("VP", r["missing"])

    def test_missing_scanpin_is_incomplete_not_a_silent_pass(self):
        tags = [t for t in self._tags() if not v.SCANPIN_RE.search(t)]
        verdict, r = v.analyze(tags)
        self.assertEqual(verdict, "INCOMPLETE")
        self.assertIn("SCANPIN", r["missing"])

    def test_missing_spmap_is_incomplete_not_a_silent_pass(self):
        tags = [t for t in self._tags() if not v.SPMAP_RE.search(t)]
        verdict, r = v.analyze(tags)
        self.assertEqual(verdict, "INCOMPLETE")
        self.assertIn("SPMAP", r["missing"])

    def test_a_corrupted_freelist_link_is_inconsistent(self):
        tags = [t.replace("c70-0x83f4f9750", "c70-0xdeadbeef")
                for t in self._tags()]
        verdict, r = v.analyze(tags)
        self.assertEqual(verdict, "INCONSISTENT")
        self.assertIn("freelist_link_c70_eq_vt_q2", r["failed"])

    def test_a_large_c80_fails_the_verdict(self):
        # c80_small_nonzero was excluded by the old endswith gate; it must
        # now be able to fail the run.
        tags = [t.replace("c80-0x2,", "c80-0x20000,") for t in self._tags()]
        verdict, r = v.analyze(tags)
        self.assertEqual(verdict, "INCONSISTENT")
        self.assertIn("c80_small_nonzero", r["failed"])

    def test_a_broken_icf_collapse_in_the_dump_fails_the_verdict(self):
        # The old gate excluded the icf key by name; a collapse that is
        # false in the raw dump must now block FREE_SIGNATURE_CONSISTENT.
        tags = self._tags()
        for i, t in enumerate(tags):
            m = v.WALKVT_RE.search(t)
            if not m:
                continue
            dump = m.group(1)
            qwords = [dump[j:j + 16] for j in range(0, len(dump), 16)]
            qwords[4] = "60974f3f08000000"
            tags[i] = t[:m.start(1)] + "".join(qwords) + t[m.end(1):]
            break
        verdict, r = v.analyze(tags)
        self.assertEqual(verdict, "INCONSISTENT")
        self.assertIn("icf_collapse_vt_q2_eq_q4_eq_q5", r["failed"])

    def test_non_rcw0_run_is_not_graded(self):
        tags = [t.replace("rcw=0", "rcw=1") for t in self._tags()]
        self.assertEqual(v.analyze(tags)[0], "NOT_RCW0")


if __name__ == "__main__":
    unittest.main()

"""Exercise the offline CLI against small, independently specified repositories."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "audit_research.py"


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.write("docs/PROBE_INDEX.md", "| # | Name | Status | Key Finding |\n"
                   "|---|---|---|---|\n| 43i | `fn_redirect` | OK | Write persists |\n")
        self.write("probes/phase10/43i_fn_redirect.lua",
                   '-- PROBE 43i: REDIRECT\nerror("must never run")\n')
        self.write("results/43i_fn_redirect_20261016_180730.txt",
                   "pid: 100\nwrite persists\n=== PROBE 43i COMPLETE ===\n")
        self.ledger = {"version": 1, "findings": []}

    def write(self, path, content):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return target

    def run_audit(self, *args):
        self.write("docs/RESEARCH_EVIDENCE.json", json.dumps(self.ledger))
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(self.root), *args],
            capture_output=True, text=True, encoding="utf-8", timeout=15,
        )

    def symlink(self, path, target):
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            path.symlink_to(target)
        except (NotImplementedError, OSError) as error:
            if (sys.platform == "win32" and
                    (isinstance(error, NotImplementedError) or
                     getattr(error, "winerror", None) in (50, 1314))):
                self.skipTest(f"symlinks unavailable: {error}")
            raise

    def finding(self, **overrides):
        path = "results/43i_fn_redirect_20261016_180730.txt"
        item = {
            "id": "redirect", "experiment": "43i_fn_redirect",
            "status": "superseded", "summary": "Persistence is not execution.",
            "superseded_by": ["controls"],
            "evidence": [{"path": path,
                          "sha256": hashlib.sha256((self.root / path).read_bytes()).hexdigest(),
                          "anchors": ["write persists"]}],
            "references": [{"path": "docs/PROBE_INDEX.md", "anchor": "| 43i |"}],
            "notes": ["No hardware reproduction."],
        }
        item.update(overrides)
        return item

    def test_read_only_deterministic_inventory(self):
        before = {p.relative_to(self.root): p.read_bytes()
                  for p in self.root.rglob("*") if p.is_file()}
        first = self.run_audit()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertIn("43i_fn_redirect", first.stdout)
        self.assertIn("completion marker present", first.stdout)
        self.assertEqual(first.stdout, self.run_audit().stdout)
        for name, content in before.items():
            self.assertEqual((self.root / name).read_bytes(), content)

    def test_no_log_is_missing_support_not_a_failed_experiment(self):
        (self.root / "results/43i_fn_redirect_20261016_180730.txt").unlink()
        result = self.run_audit()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("NO_LOG", result.stdout)
        self.assertNotIn("experiment failed", result.stdout)

    def test_reused_id_does_not_merge_distinct_experiments(self):
        self.write("probes/other/43i_other.lua", "-- PROBE 43i: OTHER\n")
        result = self.run_audit()
        self.assertIn("ID_REUSED", result.stdout)
        self.assertIn("43i_other", result.stdout)
        self.assertIn("NO_LOG", result.stdout)

    def test_same_stem_in_two_phases_makes_log_provenance_ambiguous(self):
        self.write("probes/other/43i_fn_redirect.lua", "-- PROBE 43i: OTHER VERSION\n")
        result = self.run_audit()
        self.assertIn("AMBIGUOUS_LOG", result.stdout)
        self.assertIn("INDEX_AMBIGUOUS", result.stdout)

    def test_index_missing_source_and_header_mismatch(self):
        self.write("docs/PROBE_INDEX.md", "| 44a | `missing` | OK | Claim |\n")
        self.write("probes/phase10/43i_fn_redirect.lua", "-- PROBE 43h: WRONG\n")
        result = self.run_audit()
        self.assertIn("INDEX_NO_SOURCE", result.stdout)
        self.assertIn("HEADER_MISMATCH", result.stdout)
        self.assertIn("UNINDEXED", result.stdout)

    def test_grouped_rows_do_not_create_spurious_missing_files(self):
        self.write("docs/PROBE_INDEX.md", "| 43h–i | `group_*` | VARIOUS | Historical group |\n")
        (self.root / "probes/phase10/43i_fn_redirect.lua").unlink()
        self.write("probes/phase10/43h_group_one.lua", "-- PROBE 43h: GROUP\n")
        self.write("probes/phase10/43i_group_two.lua", "-- PROBE 43i: GROUP\n")
        result = self.run_audit()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("INDEX_NO_SOURCE", result.stdout)
        self.assertNotIn("UNINDEXED", result.stdout)

    def test_grouped_range_reports_each_missing_id(self):
        self.write("docs/PROBE_INDEX.md", "| 43g–i | `group_*` | OK | Group |\n")
        self.write("probes/phase10/43i_group_one.lua", "-- PROBE 43i: GROUP\n")
        result = self.run_audit()
        self.assertEqual(result.returncode, 0, result.stderr)
        missing = [s for s in result.stdout.splitlines() if "**INDEX_NO_SOURCE**" in s]
        self.assertEqual(len(missing), 2)
        self.assertIn("43g", missing[0])
        self.assertIn("43h", missing[1])

    def test_grouped_range_does_not_cover_unrelated_same_id(self):
        self.write("docs/PROBE_INDEX.md", "| 43h–i | `group_*` | OK | Group |\n")
        self.write("probes/phase10/43h_group_one.lua", "-- PROBE 43h: GROUP\n")
        self.write("probes/phase10/43i_group_two.lua", "-- PROBE 43i: GROUP\n")
        result = self.run_audit()
        self.assertEqual(result.returncode, 0, result.stderr)
        unindexed = [s for s in result.stdout.splitlines() if "**UNINDEXED**" in s]
        self.assertEqual(len(unindexed), 1)
        self.assertIn("43i_fn_redirect.lua", unindexed[0])
        self.assertNotIn("INDEX_NO_SOURCE", result.stdout)

    def test_grouped_name_mismatch_reports_missing_member(self):
        self.write("docs/PROBE_INDEX.md", "| 43h–i | `group_*` | OK | Group |\n")
        self.write("probes/phase10/43h_group_one.lua", "-- PROBE 43h: GROUP\n")
        result = self.run_audit()
        missing = [s for s in result.stdout.splitlines() if "**INDEX_NO_SOURCE**" in s]
        self.assertEqual(len(missing), 1)
        self.assertIn("43i", missing[0])
        self.assertIn("**UNINDEXED**", result.stdout)

    def test_grouped_multiple_matches_are_ambiguous_and_uncovered(self):
        self.write("docs/PROBE_INDEX.md", "| 43h–i | `group_*` | OK | Group |\n")
        self.write("probes/phase10/43h_group_one.lua", "-- PROBE 43h: GROUP\n")
        self.write("probes/phase10/43i_group_one.lua", "-- PROBE 43i: GROUP\n")
        self.write("probes/other/43i_group_one.lua", "-- PROBE 43i: GROUP\n")
        result = self.run_audit()
        self.assertIn("**INDEX_AMBIGUOUS**", result.stdout)
        unindexed = [s for s in result.stdout.splitlines() if "**UNINDEXED**" in s]
        self.assertEqual(len(unindexed), 3)
        self.assertFalse(any("43h_group_one.lua" in s for s in unindexed))

    def test_unsupported_group_name_does_not_cover_by_id(self):
        for name in ("`*`", "descriptive group", "`group_*` and others", "`group_?`"):
            with self.subTest(name=name):
                self.write("docs/PROBE_INDEX.md", f"| 43h–i | {name} | OK | Group |\n")
                result = self.run_audit()
                self.assertIn("**INDEX_AMBIGUOUS**", result.stdout)
                self.assertIn("**UNINDEXED**", result.stdout)

    def test_grouped_exact_alternatives_match_per_id(self):
        self.write("docs/PROBE_INDEX.md", "| 43h–43i | `group_one`/`fn_redirect` | OK | Group |\n")
        self.write("probes/phase10/43h_group_one.lua", "-- PROBE 43h: GROUP\n")
        result = self.run_audit()
        self.assertNotIn("INDEX_NO_SOURCE", result.stdout)
        self.assertNotIn("UNINDEXED", result.stdout)
        self.assertNotIn("INDEX_AMBIGUOUS", result.stdout)

    def test_single_id_prefix_does_not_cover_unrelated_source(self):
        self.write("docs/PROBE_INDEX.md", "| 43i | `group_*` | OK | Group |\n")
        self.write("probes/phase10/43i_group_one.lua", "-- PROBE 43i: GROUP\n")
        result = self.run_audit()
        unindexed = [s for s in result.stdout.splitlines() if "**UNINDEXED**" in s]
        self.assertEqual(len(unindexed), 1)
        self.assertIn("43i_fn_redirect.lua", unindexed[0])

    def test_binary_partial_log_is_not_treated_as_success(self):
        target = self.root / "results/43i_fn_redirect_20261016_180730.txt"
        target.write_bytes(b"=== PROBE 43i: TEST ===\n\xff\x00crash record")
        result = self.run_audit()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("no completion marker", result.stdout)
        self.assertNotIn("completion marker present", result.stdout)

    def test_embedded_truncated_dump_does_not_hide_completion(self):
        self.write("results/43i_fn_redirect_20261016_180730.txt",
                   "[truncated]\n=== PROBE 43i COMPLETE ===\n")
        self.assertIn("completion marker present", self.run_audit().stdout)

    def test_explicit_supersession_renders_anchored_evidence(self):
        self.ledger["findings"] = [self.finding(), self.finding(
            id="controls", status="observed", superseded_by=[])]
        result = self.run_audit()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Superseded by: controls", result.stdout)
        self.assertIn("#L2", result.stdout)
        self.assertIn("No hardware reproduction.", result.stdout)

    def test_hash_drift_is_an_error_even_with_anchor_still_present(self):
        item = self.finding(status="observed", superseded_by=[])
        self.ledger["findings"] = [item]
        with (self.root / item["evidence"][0]["path"]).open("ab") as stream:
            stream.write(b"new bytes\n")
        result = self.run_audit()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("HASH_MISMATCH", result.stdout)

    def test_finding_requires_evidence_for_its_named_experiment(self):
        unrelated = self.write(
            "results/45b_shellcode_write_diag_20261016_191357.txt",
            "unrelated but hash-pinned observation\n",
        )
        item = self.finding(status="observed", superseded_by=[])
        item["evidence"] = [{
            "path": unrelated.relative_to(self.root).as_posix(),
            "sha256": hashlib.sha256(unrelated.read_bytes()).hexdigest(),
            "anchors": ["hash-pinned observation"],
        }]
        self.ledger["findings"] = [item]
        result = self.run_audit()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("must include evidence for experiment 43i_fn_redirect", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_dotdot_alias_to_docs_is_not_direct_experiment_evidence(self):
        document = self.write("docs/43i_fn_redirect.lua", "document, not a probe\n")
        item = self.finding(status="observed", superseded_by=[])
        item["evidence"] = [{
            "path": "probes/../docs/43i_fn_redirect.lua",
            "sha256": hashlib.sha256(document.read_bytes()).hexdigest(),
            "anchors": ["document, not a probe"],
        }]
        self.ledger["findings"] = [item]
        result = self.run_audit()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("must include evidence for experiment 43i_fn_redirect", result.stderr)

    def test_probes_symlink_to_docs_is_not_direct_experiment_evidence(self):
        document = self.write("docs/43i_fn_redirect.lua", "document, not a probe\n")
        self.symlink(self.root / "probes/43i_fn_redirect.lua",
                     Path("../docs/43i_fn_redirect.lua"))
        item = self.finding(status="observed", superseded_by=[])
        item["evidence"] = [{
            "path": "probes/43i_fn_redirect.lua",
            "sha256": hashlib.sha256(document.read_bytes()).hexdigest(),
            "anchors": ["document, not a probe"],
        }]
        self.ledger["findings"] = [item]
        result = self.run_audit()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("must include evidence for experiment 43i_fn_redirect", result.stderr)

    def test_probes_symlink_to_matching_probe_is_direct_experiment_evidence(self):
        source = self.root / "probes/phase10/43i_fn_redirect.lua"
        self.symlink(self.root / "probes/aliases/43i_fn_redirect.lua",
                     Path("../phase10/43i_fn_redirect.lua"))
        item = self.finding(status="observed", superseded_by=[])
        item["evidence"] = [{
            "path": "probes/aliases/43i_fn_redirect.lua",
            "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "anchors": ["-- PROBE 43i: REDIRECT"],
        }]
        self.ledger["findings"] = [item]
        result = self.run_audit()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_evidence_and_stale_document_anchor_are_errors(self):
        item = self.finding(status="observed", superseded_by=[])
        item["references"][0]["anchor"] = "absent claim"
        (self.root / item["evidence"][0]["path"]).unlink()
        self.ledger["findings"] = [item]
        result = self.run_audit()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("MISSING_EVIDENCE", result.stdout)
        self.assertIn("MISSING_ANCHOR", result.stdout)

    def test_evidence_anchor_drift_is_an_error(self):
        item = self.finding(status="observed", superseded_by=[])
        item["evidence"][0]["anchors"] = ["absent observation"]
        self.ledger["findings"] = [item]
        result = self.run_audit()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("MISSING_ANCHOR", result.stdout)

    def test_explicit_lf_hash_mode_survives_windows_checkout_conversion(self):
        item = self.finding(status="observed", superseded_by=[])
        item["evidence"][0]["hash_mode"] = "lf"
        self.ledger["findings"] = [item]
        path = self.root / item["evidence"][0]["path"]
        path.write_bytes(path.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
        # The initial fixture uses write_text, so pin an independent LF digest.
        item["evidence"][0]["sha256"] = hashlib.sha256(
            b"pid: 100\nwrite persists\n=== PROBE 43i COMPLETE ===\n").hexdigest()
        result = self.run_audit()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("LF-normalized", result.stdout)

    def test_invalid_hash_mode_and_duplicate_ids_are_rejected(self):
        invalid = []
        for mode in ("ignore-all-whitespace", [], {}):
            item = self.finding(status="observed", superseded_by=[])
            item["evidence"][0]["hash_mode"] = mode
            invalid.append([item])
        for findings in (*invalid, [self.finding(), self.finding()]):
            with self.subTest(findings=findings):
                self.ledger["findings"] = findings
                result = self.run_audit()
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_unknown_supersession_target_and_cycle_are_rejected(self):
        for findings in ([self.finding()], [self.finding(), self.finding(
                id="controls", superseded_by=["redirect"])]):
            with self.subTest(findings=findings):
                self.ledger["findings"] = findings
                result = self.run_audit()
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_invalid_schema_and_escaping_paths_are_rejected(self):
        for changes in ({"status": "proven exploit"}, {"evidence": []},
                        {"id": ""}, {"superseded_by": "controls"},
                        {"references": [{"path": "../outside", "anchor": "x"}]}):
            with self.subTest(changes=changes):
                self.ledger["findings"] = [self.finding(**changes)]
                result = self.run_audit()
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_report_can_be_written_but_cannot_overwrite_inputs(self):
        result = self.run_audit("--output", str(self.root / "report.md"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / "report.md").read_text(encoding="utf-8").startswith(
            "# Offline research audit"))
        for path in ("docs/PROBE_INDEX.md", "probes/phase10/43i_fn_redirect.lua",
                     "results/43i_fn_redirect_20261016_180730.txt",
                     "docs/RESEARCH_EVIDENCE.json"):
            with self.subTest(path=path):
                result = self.run_audit("--output", str(self.root / path))
                self.assertEqual(result.returncode, 2, result.stderr)

    def test_output_cannot_overwrite_git_metadata(self):
        path = self.write(".git/config", "[core]\nrepositoryformatversion = 0\n")
        before = path.read_bytes()
        result = self.run_audit("--output", str(path))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(path.read_bytes(), before)

    def test_output_cannot_overwrite_unrelated_existing_files(self):
        path = self.write("other/config", "valuable unrelated settings")
        result = self.run_audit("--output", str(path))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(path.read_text(encoding="utf-8"), "valuable unrelated settings")

    def test_generated_report_can_be_refreshed(self):
        args = ("--output", str(self.root / "report.md"))
        first = self.run_audit(*args)
        second = self.run_audit(*args)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)

    def test_ledger_text_cannot_embed_active_html_or_markdown_images(self):
        item = self.finding(status="observed", superseded_by=[],
                            summary='<img src="https://example.invalid/tracker">',
                            notes=["![remote](https://example.invalid/image)"])
        self.ledger["findings"] = [item]
        result = self.run_audit()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("<img ", result.stdout)
        self.assertNotIn("![remote]", result.stdout)

    def test_missing_repository_is_a_clear_usage_error(self):
        result = self.run_audit("--root", str(self.root / "absent"))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()

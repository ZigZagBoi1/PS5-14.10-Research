#!/usr/bin/env python3
"""Gate: every beacon log / capture cited in the session docs must be in the tree.

Born from the PR #303 audit (2026-11-19): the squashed bench-harness sync cited
16 evidence IDs in docs/SESSION_2026-11-18.md but shipped 11 — the negative
controls that carry the attribution (the v31/v32 yield deaths, the first
RIP2-CALL-OK bisection logs) stayed on bench-harness while the headline claims
went up for merge. The docs cite IDs precisely so the evidence stays auditable;
this gate makes that audit mechanical instead of a manual diff review.

Verdicts (read-only; no console contact, no writes):

  FAIL  cited ID whose artifact exists on disk but is ABSENT from the git tree
        of the checked ref (default HEAD; pass --ref for a PR branch pre-flight).
        This is the exact #303 failure mode: evidence exists, wasn't committed.
  WARN  cited ID with no artifact on disk and not a commit short-hash — an
        evidence gap in its own right, or a stale doc citation.
  SKIP  unknown token that resolves as a commit short-hash (docs also cite
        commits); no beacon expectation.

Run with::

    python -m unittest discover -s tools -p "test_cited_evidence.py" -v
    python tools/test_cited_evidence.py --ref feat/fontface-chain-295
    python tools/test_cited_evidence.py --docs docs/SESSION_2026-11-18.md --ref pr-303
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import unittest
from pathlib import Path
from typing import List, NamedTuple, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
BEACON_DIR = ROOT / "tools" / "browser_runner" / "beacon_logs"

# Artifact families an evidence ID can materialize as, matching the committed
# naming: beacons_<id>-<uuid>.log and capture-<id>-<uuid>.jsonl
FAMILIES = (("beacons_", "*.log"), ("capture-", "*.jsonl"))

# `beacons_534e0534` — the explicit citation form.
EXPLICIT_RE = re.compile(r"beacons[_-]?([0-9a-fA-F]{8})")
# `42c334f4` — the backticked shorthand used in session tables and logs lines.
# Guards keep address literals (0x1000e062) and sub-windows of longer hex runs
# (0x102680000001) out of the citation set.
SHORTHAND_RE = re.compile(r"(?<![0-9a-fA-Fx_])`([0-9a-f]{8})`(?![0-9a-fA-F])")

DEFAULT_DOC_GLOB = "SESSION_*.md"


class Citation(NamedTuple):
    ident: str
    doc: str
    line_no: int


def read_doc(path: Path) -> str:
    """Decode a doc robustly. SESSION_2026-11-17.md is UTF-16LE; a cp1252
    fallback would happily produce garbage, so sniff the BOM first."""
    raw = path.read_bytes()
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16")
    for codec in ("utf-8", "utf-8-sig", "cp1252", "latin-1"):
        try:
            return raw.decode(codec)
        except UnicodeDecodeError:
            continue
    raise ValueError(f"undecodable doc: {path}")


def citations_in(docs: List[Path]) -> List[Citation]:
    """All evidence IDs cited across the docs, first-occurrence per (id, doc)."""
    out: List[Citation] = []
    seen = set()
    for doc in docs:
        for line_no, line in enumerate(read_doc(doc).splitlines(), 1):
            for regex in (EXPLICIT_RE, SHORTHAND_RE):
                for m in regex.finditer(line):
                    ident = m.group(1).lower()
                    if (ident, doc.name) not in seen:
                        seen.add((ident, doc.name))
                        out.append(Citation(ident, doc.name, line_no))
    return out


def disk_files_for(ident: str) -> List[str]:
    """Artifact filenames on the working disk for one evidence ID."""
    hits: List[str] = []
    if BEACON_DIR.is_dir():
        for prefix, pattern in FAMILIES:
            hits.extend(p.name for p in BEACON_DIR.glob(prefix + ident + pattern))
    return hits


def tree_files(ref: str) -> List[str]:
    """Paths under beacon_logs/ in the git tree of `ref`."""
    proc = subprocess.run(
        ["git", "-C", str(ROOT), "ls-tree", "-r", "--name-only", ref,
         "--", "tools/browser_runner/beacon_logs"],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git ls-tree {ref} failed: {proc.stderr.strip()}")
    return proc.stdout.splitlines()


def is_commit_short_hash(ident: str) -> bool:
    proc = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "--verify", "--quiet",
         f"{ident}^{{commit}}"],
        capture_output=True, text=True,
    )
    return proc.returncode == 0


def in_tree(tree: List[str], ident: str) -> bool:
    """ls-tree returns full paths; match on the basename."""
    return any(Path(name).name.startswith(prefix + ident)
               for prefix, _ in FAMILIES for name in tree)


def audit(ref: str = "HEAD",
          docs: Optional[List[Path]] = None
          ) -> Tuple[List[Citation], List[Citation], List[Citation],
                     List[Citation], List[Citation]]:
    """Classify every citation against `ref`.

    Returns (fail, warn, skip, ok, citations).
    """
    if docs is None:
        docs = sorted((ROOT / "docs").glob(DEFAULT_DOC_GLOB))
    cites = citations_in(docs)
    tree = tree_files(ref)

    fail: List[Citation] = []
    warn: List[Citation] = []
    skip: List[Citation] = []
    ok: List[Citation] = []
    for c in cites:
        on_disk = bool(disk_files_for(c.ident))
        there = in_tree(tree, c.ident)
        if on_disk and not there:
            fail.append(c)
        elif not on_disk and not there:
            if is_commit_short_hash(c.ident):
                skip.append(c)
            else:
                warn.append(c)
        else:
            ok.append(c)
    return fail, warn, skip, ok, cites


class CitedEvidenceGate(unittest.TestCase):
    """The gate as run by the offline suite: citations vs HEAD."""

    def test_session_docs_exist(self):
        docs = sorted((ROOT / "docs").glob(DEFAULT_DOC_GLOB))
        self.assertGreater(len(docs), 0,
                           f"no docs matched docs/{DEFAULT_DOC_GLOB} — glob broke?")

    def test_beacon_dir_exists(self):
        self.assertTrue(BEACON_DIR.is_dir(),
                        f"missing evidence dir: {BEACON_DIR}")

    def test_every_cited_evidence_id_is_in_head_tree(self):
        fail, warn, skip, ok, cites = audit("HEAD")
        self.assertGreater(len(cites), 0,
                           "no citations extracted — regexes broke?")
        if fail:
            lines = [f"  {c.ident}  cited at {c.doc}:{c.line_no} — on disk, "
                     f"absent from HEAD tree" for c in fail]
            self.fail("cited evidence missing from the committed tree:\n"
                      + "\n".join(lines))


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Check that cited beacon evidence exists in the git tree.")
    ap.add_argument("--ref", default="HEAD",
                    help="git ref to audit (default HEAD; pass a PR branch "
                         "for pre-flight)")
    ap.add_argument("--docs", nargs="*", default=None,
                    help="docs to scan (default: docs/SESSION_*.md)")
    args = ap.parse_args(argv)
    docs = [Path(d) for d in args.docs] if args.docs else None
    try:
        fail, warn, skip, ok, cites = audit(args.ref, docs)
    except (RuntimeError, ValueError) as exc:
        print(f"ERROR: {exc}")
        return 2
    print(f"ref={args.ref}  citations={len(cites)}  ok={len(ok)}  "
          f"FAIL={len(fail)}  warn={len(warn)}  skipped-commits={len(skip)}")
    for c in fail:
        print(f"  FAIL  {c.ident}  cited {c.doc}:{c.line_no}  "
              f"on disk, ABSENT from tree")
    for c in warn:
        print(f"  WARN  {c.ident}  cited {c.doc}:{c.line_no}  "
              f"no artifact on disk, not a commit")
    for c in skip:
        print(f"  skip  {c.ident}  (commit short-hash)")
    if fail:
        print("\ngate: FAIL — commit the missing artifacts into the ref "
              "before shipping the claim.")
        return 1
    print("\ngate: PASS")
    return 0


if __name__ == "__main__":
    # unittest discovery imports this module without executing __main__; only
    # an argv-driven run takes the CLI path.
    if any(a.startswith("--") for a in sys.argv[1:]):
        raise SystemExit(main())
    unittest.main()

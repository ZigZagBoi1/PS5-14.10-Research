#!/usr/bin/env python3
"""Run the repository's bounded, hardware-free verification suite.

This entry point uses an explicit, sorted list rather than discovery.  It does
not import or invoke senders, sweep drivers, watchdogs, swarm code, Lua probes,
or network transports.  Selected tests read committed artifacts or use
throwaway local files only.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import TextIO
import unittest


ROOT = Path(__file__).resolve().parents[1]
SAFE_TEST_MODULES = (
    "tests.test_audit_research",
    "tools.test_analyze_result",
    "tools.test_deep_result_scanner",
    "tools.test_evidence_pins",
    "tools.test_handler_claim_audit",
    "tools.test_remaining_cve_triage",
    "tools.test_sys622_bitmap",
    "tools.test_syscall_labels",
    "tools.test_umtx454_correction",
    "tools.test_webkit_false_positive",
)


def build_suite(loader: unittest.TestLoader = unittest.defaultTestLoader) -> unittest.TestSuite:
    """Load every explicitly selected module and reject an empty selection."""
    for path in (ROOT, ROOT / "tools"):
        rendered = str(path)
        if rendered not in sys.path:
            sys.path.insert(0, rendered)

    suite = unittest.TestSuite()
    for module_name in SAFE_TEST_MODULES:
        selected = loader.loadTestsFromName(module_name)
        if selected.countTestCases() == 0:
            raise RuntimeError(f"selected module has no tests: {module_name}")
        suite.addTests(selected)
    if suite.countTestCases() == 0:
        raise RuntimeError("selected test suite has no tests")
    return suite


def run_suite(suite: unittest.TestSuite, stream: TextIO | None = None) -> int:
    """Run an already-selected suite and return a process-compatible status."""
    result = unittest.TextTestRunner(verbosity=2, stream=stream).run(suite)
    return 0 if result.wasSuccessful() else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="list selected test modules and exit")
    args = parser.parse_args(argv)
    if args.list:
        print("\n".join(SAFE_TEST_MODULES))
        return 0
    try:
        suite = build_suite()
    except RuntimeError as exc:
        print(f"offline verification setup error: {exc}", file=sys.stderr)
        return 2
    return run_suite(suite)


if __name__ == "__main__":
    raise SystemExit(main())

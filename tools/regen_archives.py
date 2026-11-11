"""Regenerate docs/ALL_PROBES.md and docs/ALL_RESULTS.md.

Concatenates the full probe corpus and result captures into the two
large-context-ingestion archives, with a per-file index. Deterministic:
files are walked in sorted order, so a clean tree always regenerates the
same archives byte-for-byte.

Usage:
    python3 tools/regen_archives.py            # write both archives
    python3 tools/regen_archives.py --check    # report staleness, write nothing
"""

import argparse
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

PROBE_GLOBS = ("*.lua", "*.js", "*.html")
RESULT_GLOB = "*.txt"

# Binary-ish or pathological captures that do not belong in an LLM-ingestion
# archive (e.g. results with embedded NULs from memory dumps). They stay on
# disk; the archive index marks them as skipped.
def is_text(path: Path) -> bool:
    try:
        chunk = path.read_bytes()[:4096]
    except OSError:
        return False
    return b"\x00" not in chunk


def gather(base: Path, globs) -> list[Path]:
    files: list[Path] = []
    for pattern in globs:
        files.extend(base.rglob(pattern))
    return sorted(files, key=lambda p: p.relative_to(base).as_posix())


def rel(path: Path, base: Path) -> str:
    return path.relative_to(base).as_posix()


def render_archive(title: str, intro: str, base: Path, files: list[Path],
                   base_label: str) -> str:
    lines: list[str] = []
    lines.append(f"# {title}")
    lines.append("")
    lines.append(intro)
    lines.append(f"Regenerated {date.today().isoformat()} by "
                 f"`tools/regen_archives.py` — deterministic, do not hand-edit.")
    lines.append("")
    skipped = [f for f in files if not is_text(f)]
    kept = [f for f in files if is_text(f)]
    lines.append(f"**Files in this archive: {len(kept)}**"
                 + (f" ({len(skipped)} skipped: binary content)" if skipped else ""))
    lines.append("")
    lines.append("## Index")
    lines.append("")
    for f in kept:
        lines.append(f"- `{rel(f, base)}` ({f.stat().st_size} bytes)")
    for f in skipped:
        lines.append(f"- `{rel(f, base)}` ({f.stat().st_size} bytes) — SKIPPED (binary)")
    lines.append("")
    lines.append("---")
    lines.append("")
    for f in kept:
        lines.append(f"## FILE: {base_label}/{rel(f, base)}")
        lines.append("")
        text = f.read_text(encoding="utf-8", errors="replace")
        lines.append("```")
        lines.append(text.rstrip("\n"))
        lines.append("```")
        lines.append("")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="report staleness without writing")
    args = parser.parse_args(argv)

    probe_files = gather(ROOT / "probes", PROBE_GLOBS)
    result_files = gather(ROOT / "results", (RESULT_GLOB,))

    all_probes = DOCS / "ALL_PROBES.md"
    all_results = DOCS / "ALL_RESULTS.md"

    probes_out = render_archive(
        "All Probes — PS5 14.10 Research",
        "Snapshot of the full probe corpus (Lua + JS + HTML) concatenated for "
        "large-context ingestion.",
        ROOT / "probes", probe_files, "probes")
    results_out = render_archive(
        "All Probe Results — PS5 14.10 Research",
        "Archive of all probe result captures, concatenated for large-context "
        "ingestion.",
        ROOT / "results", result_files, "results")

    if args.check:
        stale = False
        for path, content in ((all_probes, probes_out), (all_results, results_out)):
            current = path.read_text(encoding="utf-8") if path.exists() else ""
            state = "current" if current == content else "STALE"
            stale = stale or state == "STALE"
            print(f"{path.relative_to(ROOT)}: {state}")
        return 1 if stale else 0

    all_probes.write_text(probes_out, encoding="utf-8")
    all_results.write_text(results_out, encoding="utf-8")
    print(f"{all_probes.relative_to(ROOT)}: {len(probe_files)} probe files, "
          f"{all_probes.stat().st_size} bytes")
    print(f"{all_results.relative_to(ROOT)}: {len(result_files)} result files, "
          f"{all_results.stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())

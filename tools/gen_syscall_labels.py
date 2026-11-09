#!/usr/bin/env python3
"""Regenerate the syscall label table in tools/ghidra_label_syscalls.py.

The label table must come from the committed 13.60 sysent capture
(``docs/sysent-names-13.60.csv``), not from a hand-maintained list. The previous
hand list was a compacted FreeBSD-9 sequence: it dropped unimplemented slots
without renumbering, so its entries drifted by up to sixteen numbers
(``429: jail_attach`` where the table says ``sigwait``, ``430:
extattr_list_fd`` where the table says ``thr_create``).

Usage::

    python tools/gen_syscall_labels.py           # rewrite the block
    python tools/gen_syscall_labels.py --check   # exit 1 on drift

The generated block covers every named entry up to the first Sony-specific
number (532); the Ghidra script labels 532-676 as ``sony_syscall_N`` itself.
"""

import argparse
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CSV_PATH = ROOT / "docs" / "sysent-names-13.60.csv"
SCRIPT_PATH = ROOT / "tools" / "ghidra_label_syscalls.py"

BEGIN = "# BEGIN GENERATED SYSCALL_NAMES"
END = "# END GENERATED SYSCALL_NAMES"
FIRST_SONY = 532

# Names the capture uses for slots that exist but carry no symbol.
UNNAMED = {"obs_{", "nosys"}


def load_names(csv_path=CSV_PATH, limit=FIRST_SONY):
    """Return {number: name} for named standard entries below ``limit``."""
    names = {}
    with open(csv_path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            num = int(row["number"])
            name = row["name"].strip()
            if num >= limit:
                continue
            if not name or name in UNNAMED or name.startswith("#"):
                continue
            # Ghidra labels cannot carry the capture's ABI prefix separator.
            names[num] = name.replace(".", "_")
    return names


def render(names):
    """Render the SYSCALL_NAMES block body (markers included)."""
    lines = [BEGIN]
    for num in sorted(names):
        lines.append('    %d: "%s",' % (num, names[num]))
    lines.append(END)
    return lines


def replace_block(text, block):
    """Return ``text`` with the generated block swapped in."""
    lines = text.splitlines()
    try:
        start = next(i for i, ln in enumerate(lines) if ln.startswith(BEGIN))
        end = next(i for i, ln in enumerate(lines) if ln.startswith(END))
    except StopIteration:
        raise SystemExit(f"markers not found in {SCRIPT_PATH}")
    return "\n".join(lines[:start] + block + lines[end + 1:]) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if the file is out of date")
    args = ap.parse_args(argv)

    names = load_names()
    current = SCRIPT_PATH.read_text(encoding="utf-8")
    updated = replace_block(current, render(names))

    if args.check:
        if current != updated:
            print("ghidra_label_syscalls.py label table is stale; "
                  "run tools/gen_syscall_labels.py", file=sys.stderr)
            return 1
        print(f"{len(names)} labels match {CSV_PATH.name}")
        return 0

    SCRIPT_PATH.write_text(updated, encoding="utf-8", newline="\n")
    print(f"wrote {len(names)} labels from {CSV_PATH.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

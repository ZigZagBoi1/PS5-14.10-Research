#!/usr/bin/env python3
"""Inventory printed 64-bit high-half address candidates in saved text captures.

This is lexical triage only: printed inputs, signed offsets, and return sentinels
can match. A match is never proof of kernel-pointer provenance.
"""

from collections import defaultdict
from pathlib import Path
import re
import struct


ROOT = Path(__file__).resolve().parent.parent
PATTERN = re.compile(
    r"(?i)(?<![0-9a-f])(?:0x)?(ffffffff[_]?[89abcdef][0-9a-f]{7})(?![0-9a-f])"
)


def main() -> None:
    found = defaultdict(list)
    raw_found = defaultdict(list)
    for path in (ROOT / "results").rglob("*.txt"):
        binary = path.read_bytes()
        for offset in range(len(binary) - 7):
            value = struct.unpack_from("<Q", binary, offset)[0]
            if 0xFFFFFFFF80000000 <= value <= 0xFFFFFFFFEFFFFFFF:
                raw_found[f"{value:016x}"].append((path.relative_to(ROOT), offset))
        raw = binary.decode("utf-8", errors="replace")
        for lineno, line in enumerate(raw.splitlines(), 1):
            for match in PATTERN.finditer(line):
                value = match.group(1).replace("_", "").lower()
                if value == "ffffffffffffffff":
                    continue
                found[value].append((path.relative_to(ROOT), lineno, line.strip()))
    print(f"unique={len(found)} occurrences={sum(map(len, found.values()))}")
    for value, hits in sorted(found.items(), key=lambda item: (-len(item[1]), item[0])):
        path, lineno, line = hits[0]
        context = line[:180].encode("ascii", errors="backslashreplace").decode("ascii")
        print(f"{value} count={len(hits)} first={path}:{lineno}: {context}")
    print(f"raw_binary_unique={len(raw_found)} raw_binary_occurrences={sum(map(len, raw_found.values()))}")
    for value, hits in sorted(raw_found.items(), key=lambda item: (-len(item[1]), item[0])):
        path, offset = hits[0]
        print(f"raw {value} count={len(hits)} first={path}+0x{offset:x}")


if __name__ == "__main__":
    main()

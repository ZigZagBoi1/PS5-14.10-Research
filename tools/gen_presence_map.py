#!/usr/bin/env python3
"""Regenerate the measured sysent presence table from saved sweep records.

Usage::

    python tools/gen_presence_map.py            # print the table
    python tools/gen_presence_map.py --write    # update docs/SYSENT_PRESENCE_14_10.md

Every sweep writes one JSON record per run (`--save`), so the map is a derived
artifact and this keeps it in step with the captures instead of with memory of
them. For each syscall the newest record wins: `RETURNED` means the call completed
and reports the return value, `KILLED_IN_CALL` means it took the process down, which
is *not* proof of an absent slot - a handler that faults or refuses the arguments
does the same (docs/SYSCALL_ABSENT_VS_LETHAL.md). Names come from the 13.60 sysent capture and
label the slot, not the handler body.
"""

import argparse
import csv
import glob
import json
import os
import re

DOC = os.path.join("docs", "SYSENT_PRESENCE_14_10.md")
NAMES = os.path.join("docs", "sysent-names-13.60.csv")
START = "<!-- presence-table:start -->"
END = "<!-- presence-table:end -->"

STATUS_ABSENT = "KILLED_IN_CALL"
STATUS_RETURNED = "RETURNED"
RET_RE = re.compile(r"ret=(0x[0-9a-fA-F]+)")


def load_names(path=NAMES):
    names = {}
    with open(path, "r", encoding="utf-8", newline="") as f:
        for row in csv.reader(f):
            if row and row[0].strip().isdigit():
                names[int(row[0])] = row[1].strip() if len(row) > 1 else "?"
    return names


def load_measurements(pattern="results/**/syscall_isolation_sweep_*.json"):
    """Return {number: (started_at, status, ret)} keeping the newest per number."""
    best = {}
    for path in glob.glob(pattern, recursive=True):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            continue
        started = data.get("started_at") or ""
        for rec in data.get("records", []):
            num = rec.get("num")
            status = rec.get("status")
            if num is None or status is None:
                continue
            attempts = rec.get("attempts") or []
            detail = attempts[-1].get("detail") if attempts else None
            match = RET_RE.search(detail or "")
            ret = match.group(1) if match else None
            previous = best.get(num)
            if previous is None or started >= previous[0]:
                best[num] = (started, status, ret)
    return best


def format_ret(ret):
    """Render a 64-bit return as a signed decimal when it is small, else hex."""
    if not ret:
        return "?"
    value = int(ret, 16) & 0xFFFFFFFFFFFFFFFF
    signed = value - (1 << 64) if value >= (1 << 63) else value
    if -0x10000 <= signed <= 0x10000:
        return str(signed)
    return "0x%X" % value


def render(names, measurements):
    lines = [START, "| syscall | 13.60 name | return | status |", "|---|---|---|---|"]
    for num in sorted(measurements):
        started, status, ret = measurements[num]
        name = names.get(num, "?")
        if status == STATUS_ABSENT:
            lines.append("| %d | `%s` | - | kills |" % (num, name))
        elif status == STATUS_RETURNED:
            lines.append("| %d | `%s` | `%s` | present |" % (num, name, format_ret(ret)))
        else:
            lines.append("| %d | `%s` | ? | %s |" % (num, name, status))
    lines.append(END)
    return "\n".join(lines)


def write_doc(table, path=DOC):
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    if START not in text or END not in text:
        raise SystemExit("%s has no %s/%s markers" % (path, START, END))
    head = text.split(START)[0]
    tail = text.split(END, 1)[1]
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(head + table + tail)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--write", action="store_true",
                        help="replace the table inside %s" % DOC)
    parser.add_argument("--pattern", default="results/**/syscall_isolation_sweep_*.json")
    args = parser.parse_args(argv)

    names = load_names()
    measurements = load_measurements(args.pattern)
    if not measurements:
        raise SystemExit("no sweep records matched %s" % args.pattern)
    table = render(names, measurements)
    if args.write:
        write_doc(table)
        print("updated %s (%d slots)" % (DOC, len(measurements)))
    else:
        print(table)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

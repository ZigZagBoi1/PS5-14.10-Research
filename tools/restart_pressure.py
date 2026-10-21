#!/usr/bin/env python3
"""Measure what a killed loader leaves behind, and how long the game needs.

Every kill costs one loader process. After roughly fifteen to twenty kills
since boot the game takes longer and longer to bring it back - nine seconds at
first, then 37, 54, 66 and over 90 - and eventually the port stops accepting
until the console is power cycled. Something accumulates outside the process
that dies.

This driver samples the counters a *fresh* loader starts with (probe 217a),
kills it with an unimplemented syscall number, times the recovery, and samples
again. A counter that climbs across restarts is system-wide and gives a readout
of the console's state that does not depend on the game; a counter that resets
means the accumulation is invisible from userland and only the clock sees it.

Usage::

    python tools/restart_pressure.py --ps5-ip 192.168.1.121 --rounds 6 --save

Each round costs one kill, so the default is small on purpose.
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from send_probe import run_source, wait_for_loader  # noqa: E402

SAMPLE_PROBE = Path(__file__).resolve().parent.parent / "probes" / \
    "phase17_new_vectors" / "217a_restart_pressure.lua"

KILL_SOURCE = """
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
print("KILL NOW")
local sc = make_syscall(4095)
sc()
print("STILL ALIVE")
"""

SAMPLE_FIELDS = ("pid", "ops624", "mods593", "vm674", "c1", "c2")


def parse_sample(text):
    """Pull the SAMPLE line out of a probe transcript, or None."""
    match = re.search(r"^SAMPLE (.*)$", text, re.MULTILINE)
    if not match:
        return None
    sample = {}
    for part in match.group(1).split():
        key, _, value = part.partition("=")
        if not key or not value:
            continue
        try:
            numbers = [int(piece, 0) for piece in value.split("/")]
        except ValueError:
            continue
        sample[key] = numbers[0] if len(numbers) == 1 else tuple(numbers)
    return sample


def measure(rounds, take_sample, kill, wait_ready, clock=time.monotonic,
            log=lambda _message: None):
    """Sample, kill, time the recovery, sample again - for each round."""
    rows = []
    first = take_sample()
    rows.append({"round": 0, "sample": first, "recovery": None})
    if first is None:
        log("[!] The loader did not answer the sample probe - is it running?")
        return rows
    for index in range(1, rounds + 1):
        kill()
        started = clock()
        ready = wait_ready()
        elapsed = round(clock() - started, 1)
        if not ready:
            rows.append({"round": index, "sample": None,
                         "recovery": elapsed, "failed": True})
            log("[!] The loader never answered again after round %d (%.1fs)"
                % (index, elapsed))
            break
        rows.append({"round": index, "sample": take_sample(),
                     "recovery": elapsed})
        log("[+] Round %d: back after %.1fs" % (index, elapsed))
    return rows


def format_report(rows, remote):
    """Render the measurements as a table and a verdict per counter."""
    lines = ["restart pressure on %s" % remote, ""]
    header = "round  recovery  " + "  ".join(SAMPLE_FIELDS)
    lines.append(header)
    lines.append("-" * len(header))
    for row in rows:
        sample = row["sample"] or {}
        cells = []
        for field in SAMPLE_FIELDS:
            value = sample.get(field)
            if isinstance(value, tuple):
                cells.append("/".join(str(v) for v in value))
            else:
                cells.append("-" if value is None else str(value))
        recovery = "-" if row["recovery"] is None else "%.1fs" % row["recovery"]
        if row.get("failed"):
            recovery += " (lost)"
        lines.append("%-5d  %-8s  %s" % (row["round"], recovery,
                                         "  ".join(cells)))
    lines.append("")
    lines.append(verdict(rows))
    return "\n".join(lines)


def verdict(rows):
    """Say which counters held their value and which moved across restarts."""
    samples = [row["sample"] for row in rows if row["sample"]]
    if len(samples) < 2:
        return "not enough samples to compare"
    notes = []
    for field in SAMPLE_FIELDS:
        values = [sample.get(field) for sample in samples]
        if any(value is None for value in values):
            continue
        if field == "pid":
            if len(set(values)) == 1:
                notes.append("pid never changed: the loader was not restarted")
            continue
        if len(set(values)) == 1:
            notes.append("%s held at %s" % (field, values[0]))
        else:
            notes.append("%s moved: %s" % (field, " -> ".join(str(v) for v in values)))
    recoveries = [row["recovery"] for row in rows if row["recovery"]]
    if recoveries:
        notes.append("recovery %.1fs to %.1fs"
                     % (min(recoveries), max(recoveries)))
    return "; ".join(notes)


def main():
    parser = argparse.ArgumentParser(
        description="Measure what a killed loader leaves behind")
    parser.add_argument("--ps5-ip", default="192.168.1.121")
    parser.add_argument("--port", type=int, default=9026)
    parser.add_argument("--rounds", type=int, default=6,
                        help="kills to spend (default 6; each one kills the loader)")
    parser.add_argument("--sample", default=str(SAMPLE_PROBE),
                        help="probe whose SAMPLE line is read after each restart")
    parser.add_argument("--wait", type=float, default=180.0,
                        help="give up on a recovery after this many seconds")
    parser.add_argument("--save", action="store_true",
                        help="write the table and a JSON record under results/")
    args = parser.parse_args()

    sample_source = Path(args.sample).read_text(encoding="utf-8")
    remote = "%s:%d" % (args.ps5_ip, args.port)

    def take_sample():
        status, text = run_source(args.ps5_ip, args.port, sample_source,
                                  timeout=15.0)
        sample = parse_sample(text)
        if sample is None:
            print("[!] Sample returned %s and no SAMPLE line" % status)
        return sample

    def kill():
        run_source(args.ps5_ip, args.port, KILL_SOURCE, timeout=8.0)

    def wait_ready():
        return wait_for_loader(args.ps5_ip, args.port, timeout=args.wait,
                               poll=2.0, answers=True, log=lambda m: print(m))

    rows = measure(args.rounds, take_sample, kill, wait_ready,
                   log=lambda message: print(message))
    report = format_report(rows, remote)
    print("")
    print(report)

    if args.save:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_dir = Path("results") / "phase17_new_vectors"
        out_dir.mkdir(parents=True, exist_ok=True)
        text_path = out_dir / ("restart_pressure_%s.txt" % stamp)
        text_path.write_text(report + "\n", encoding="utf-8")
        json_path = out_dir / ("restart_pressure_%s.json" % stamp)
        json_path.write_text(json.dumps({"remote": remote, "rounds": rows},
                                        indent=2), encoding="utf-8")
        print("[*] wrote %s and %s" % (text_path, json_path))

    return 0 if all(not row.get("failed") for row in rows) else 1


if __name__ == "__main__":
    sys.exit(main())

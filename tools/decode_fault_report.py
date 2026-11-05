#!/usr/bin/env python3
"""Decode the loader's fault report out of a saved probe capture.

The loader installs a SIGILL/SIGBUS/SIGSEGV handler whose ROP chain writes to the
client socket, so any capture where the probe faulted already contains the report:

    +0x00  u64  magic 0x13371337
    +0x08  u64  signal number (11 = SIGSEGV, 10 = SIGBUS, 4 = SIGILL)
    +0x10  u64  the "crashing address" slot, usually zero
    +0x18  ...  0x100 bytes of the saved thread context

This tool finds every report in a capture (there can be one per connection) and prints
the three header words plus the qwords of the context block. It does not interpret the
context layout beyond printing it, because that layout is the kernel's sigcontext and
was not verified here.

Usage:
    python tools/decode_fault_report.py results/phase17_new_vectors/988a_fault_channel_*.txt
    python tools/decode_fault_report.py --scan results      # every capture with a report
"""

import argparse
import glob
import os
import struct
import sys

MAGIC = struct.pack("<I", 0x13371337)
HEAD = 0x18
CONTEXT = 0x100
SIGNALS = {4: "SIGILL", 10: "SIGBUS", 11: "SIGSEGV"}


def reports(blob):
    """Yield (offset, signal, crash_addr, context) for every report in blob."""
    start = 0
    while True:
        i = blob.find(MAGIC, start)
        if i < 0:
            return
        end = i + HEAD + CONTEXT
        if end > len(blob):
            return
        _, signal, crash = struct.unpack("<3Q", blob[i:i + HEAD])
        yield i, signal, crash, blob[i + HEAD:end]
        start = i + HEAD


def show(path, verbose=False):
    with open(path, "rb") as f:
        blob = f.read()
    found = list(reports(blob))
    if not found:
        return 0
    print("%s: %d report(s)" % (path, len(found)))
    for off, signal, crash, ctx in found:
        name = SIGNALS.get(signal, "signal %d" % signal)
        print("  at 0x%X  %s  crash_slot=0x%X" % (off, name, crash))
        if verbose:
            for o in range(0, CONTEXT, 8):
                v = struct.unpack("<Q", ctx[o:o + 8])[0]
                if v:
                    print("    ctx+0x%02X = 0x%X" % (o, v))
    return len(found)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("paths", nargs="*", help="capture files")
    ap.add_argument("--scan", metavar="DIR", help="walk DIR for captures containing a report")
    ap.add_argument("--verbose", action="store_true", help="print every non-zero context qword")
    args = ap.parse_args(argv)

    targets = list(args.paths)
    if args.scan:
        targets += sorted(glob.glob(os.path.join(args.scan, "**", "*.txt"), recursive=True))

    total = 0
    files = 0
    for p in targets:
        if not os.path.isfile(p):
            continue
        n = show(p, args.verbose)
        if n:
            files += 1
            total += n
    if args.scan:
        print("-- %d report(s) across %d capture(s)" % (total, files))
    return 0 if total or not args.scan else 1


if __name__ == "__main__":
    sys.exit(main())

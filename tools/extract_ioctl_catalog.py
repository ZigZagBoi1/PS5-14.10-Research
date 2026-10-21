#!/usr/bin/env python3
"""Extract candidate ioctl command codes from the 13.60 kernel text capture.

Reads docs/dumps_13.60/kernel_text.bin (KASLR base 0xffffffff8a9c0000), scans
cmp/mov imm32 instruction bytes for ioctl-shaped constants, and clusters them
by code proximity to locate driver ioctl dispatchers.

Usage:
    PYTHONIOENCODING=utf-8 python tools/extract_ioctl_catalog.py [--text PATH] [--out PATH]

Output: JSON list of {cluster_rva, va, code, dir, size, group, ordinal} plus a
human-readable table on stdout. 13.60-labeled capture; codes may differ on
other firmwares. See docs/IOCTL_CATALOG_13_60.md.
"""
import argparse
import json
import re
import struct
from pathlib import Path

DEFAULT_TEXT = Path(__file__).resolve().parent.parent / "docs/dumps_13.60/kernel_text.bin"
KERNEL_BASE = 0xFFFFFFFF8A9C0000

CMP_R32_IMM = re.compile(rb"\x81[\xF8-\xFF]")
CMP_EAX_IMM = re.compile(rb"(?<!\x81)\x3D")


def imm32_hits(text):
    hits = []
    for m in CMP_R32_IMM.finditer(text):
        o = m.end()
        if o + 4 <= len(text):
            hits.append((m.start(), struct.unpack("<I", text[o:o + 4])[0]))
    for m in CMP_EAX_IMM.finditer(text):
        o = m.end()
        if o + 4 <= len(text):
            hits.append((m.start(), struct.unpack("<I", text[o:o + 4])[0]))
    return hits


def ioctl_like(imm):
    size = (imm >> 16) & 0x3FFF
    group = (imm >> 8) & 0xFF
    ordinal = imm & 0xFF
    direction = (imm >> 30) & 0x3
    if not (0x20 <= group <= 0x7E and ordinal <= 0x50):
        return False
    if size > 0x400 or (size & 3):
        return False
    return direction in (1, 2, 3) or size == 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--text", type=Path, default=DEFAULT_TEXT)
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()

    text = args.text.read_bytes()
    cand = [(o, i) for (o, i) in imm32_hits(text) if ioctl_like(i)]
    cand.sort()

    clusters = []
    cur = [cand[0]]
    for (o, i) in cand[1:]:
        if o - cur[-1][0] <= 0x600:
            cur.append((o, i))
        else:
            clusters.append(cur)
            cur = [(o, i)]
    clusters.append(cur)

    rows = []
    for c in clusters:
        for o, i in c:
            rows.append({
                "cluster_rva": hex(c[0][0]),
                "code": f"0x{i:08X}",
                "dir": (i >> 30) & 0x3,
                "size": (i >> 16) & 0x3FFF,
                "group": chr((i >> 8) & 0xFF),
                "ordinal": i & 0xFF,
                "rva": hex(o),
                "va": hex(KERNEL_BASE + o),
            })
    real = [r for r in rows if r["dir"] in (1, 2, 3)]
    print(f"{len(rows)} ioctl-like constants, {len(real)} with direction bits, "
          f"{len(clusters)} clusters")
    for r in real:
        print(f"  {r['code']}  dir={r['dir']} size={r['size']:4} group={r['group']!r} "
              f"ord={r['ordinal']:3}  cluster_rva={r['cluster_rva']}")
    if args.out:
        args.out.write_text(json.dumps(rows, indent=1), encoding="utf-8")
        print(f"wrote {args.out}")


if __name__ == "__main__":
    main()

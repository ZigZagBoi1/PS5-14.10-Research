#!/usr/bin/env python3
"""Tests for tools/parse_beacons.py — synthetic nginx beacon logs."""

import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "parse_beacons.py")

# 13.60 reference (p691-run3): VP=0x80C6A1B28, slots as in REF.
REF_VP = 0x80C6A1B28
REF_SLOTS = [0x80AF90FB0, 0x80AF90FE0, 0x809455750, 0x80AF916B0,
             0x809455750, 0x809455750, 0x80ABE7400, 0x80AF91810, 0x0]


def make_log(lines):
    fd, path = tempfile.mkstemp(suffix=".log")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")
    return path


def beacon(uid, msg):
    return (f'1.2.3.4 - - [17/Nov/2026:00:00:00 +0000] '
            f'"GET /beacon/MOD-{msg}?t=1&u={uid} HTTP/1.1" 200 2')


def full_run(uid, vp, slots, base):
    lines = [beacon(uid, "VER-DATA-1"), beacon(uid, "WALK-ok%3Dtrue")]
    lines.append(beacon(uid, f"VP-{hex(vp)}"))
    lines.append(beacon(uid, f"BASE-{hex(base)}"))
    for i, s in enumerate(slots):
        lines.append(beacon(uid, f"S{i}-{hex(s)}"))
    lines.append(beacon(uid, "COMPLETE"))
    return lines


def run_tool(path, *extra):
    return subprocess.run([sys.executable, TOOL, path, *extra],
                          capture_output=True, text=True)


def test_match_1360_layout():
    """14.10 run with identical deltas at a different slide -> MATCH."""
    slide = 0x120000  # different ASLR slide from 13.60
    vp = REF_VP + slide
    slots = [s + slide if s else 0 for s in REF_SLOTS]
    path = make_log(full_run("AAAAAA", vp, slots, vp - 0xC6A1B28))
    try:
        r = run_tool(path)
        assert r.returncode == 0, r.stderr
        assert "MATCH_1360_LAYOUT" in r.stdout
        assert "VP_RVA CONFIRMED = 0xc6a1b28" in r.stdout
    finally:
        os.unlink(path)


def test_uniform_shift_recompute():
    """Vtable moved vs .text: every VP-slot delta shifts by one constant."""
    # Text slots keep their 13.60 RVAs (same slide as VP), but the vtable
    # itself sits 0x8000 higher against .text (different link), so each
    # VP-si delta grows by exactly 0x8000 while inter-slot gaps are unchanged.
    shift = 0x8000
    vp = REF_VP + 0x120000
    slots = [s + 0x120000 if s else 0 for s in REF_SLOTS]  # pure slide
    vp += shift  # vtable sits higher against .text
    path = make_log(full_run("BBBBBB", vp, slots, vp - 0xC6A1B28))
    try:
        r = run_tool(path)
        assert r.returncode == 0, r.stderr
        assert "UNIFORM_SHIFT_RVA_RECOMPUTED" in r.stdout
        assert "VP_RVA RECOMPUTED = 0xc6a9b28" in r.stdout  # 0xC6A1B28 + 0x8000
        assert f"base={hex(vp - (0xC6A1B28 + shift))}" in r.stdout
    finally:
        os.unlink(path)


def test_mismatch_garbage_slots():
    """Random slot values -> MISMATCH, not a false RVA."""
    vp = 0x812345678
    slots = [0x811111110, 0x822222220, 0x833333330, 0x844444440,
             0x855555550, 0x866666660, 0x877777770, 0x888888880, 0x0]
    path = make_log(full_run("CCCCCC", vp, slots, vp - 0xC6A1B28))
    try:
        r = run_tool(path)
        assert r.returncode == 1
        assert "MISMATCH_MANUAL_REVIEW" in r.stdout
    finally:
        os.unlink(path)


def test_incomplete_run():
    """Only a UA beacon, no VP -> INCOMPLETE, exit 1."""
    path = make_log([beacon("DDDDDD", "UA-Mozilla%2F5.0")])
    try:
        r = run_tool(path)
        assert r.returncode == 1
        assert "INCOMPLETE" in r.stdout
    finally:
        os.unlink(path)


def test_base_claim_disagreement_flagged():
    """Probe BASE claim inconsistent with its own VP -> agree=False."""
    slide = 0x120000
    vp = REF_VP + slide
    slots = [s + slide if s else 0 for s in REF_SLOTS]
    wrong_base = vp - 0xC6A1B28 - 0x4000  # corrupted beacon
    path = make_log(full_run("EEEEEE", vp, slots, wrong_base))
    try:
        r = run_tool(path)
        assert r.returncode == 0
        assert "agree=False" in r.stdout
        assert "MATCH_1360_LAYOUT" in r.stdout  # slots still decide
    finally:
        os.unlink(path)


def test_uid_filter_and_json():
    import json
    slide = 0x120000
    vp = REF_VP + slide
    slots = [s + slide if s else 0 for s in REF_SLOTS]
    lines = full_run("AAAAAA", vp, slots, vp - 0xC6A1B28)
    lines += full_run("BBBBBB", 0x0, [0] * 9, 0x0)
    path = make_log(lines)
    try:
        r = run_tool(path, "--uid", "AAAAAA", "--json")
        assert r.returncode == 0
        data = json.loads(r.stdout)
        assert len(data) == 1
        assert data[0]["uid"] == "AAAAAA"
        assert data[0]["verdict"] == "MATCH_1360_LAYOUT"
    finally:
        os.unlink(path)


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL {fn.__name__}: {e}")
    sys.exit(1 if failed else 0)

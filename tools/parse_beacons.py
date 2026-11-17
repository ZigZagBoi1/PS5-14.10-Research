#!/usr/bin/env python3
"""Parse data-gather tester beacons (probe-modules.html) and recompute VP_RVA.

The upstream data-gather rig (probes/phase13_webkit/data-gather/) emits beacon
lines into the VPS nginx log (/var/log/nginx/ps5_beacons.log), one HTTP GET per
beacon:

    GET /beacon/MOD-<MESSAGE>?t=<ms>&u=<UID> ...

This tool groups beacons by UID into runs, validates each run, and -- crucially
-- does NOT trust the probe's hardcoded BASE = VP - 0xC6A1B28 (13.60 value).
It recomputes the slide from the absolute S-slots: inter-slot deltas are
ASLR-invariant within one firmware build, so if the 14.10 slot deltas match the
13.60 p691-run3 boot-stable set, the same build is running and VP_RVA =
0xC6A1B28 is confirmed; if deltas match but VP-si deltas all shift by the same
amount, the build differs and the true RVA falls out of the shift.

Usage:
    python tools/parse_beacons.py /var/log/nginx/ps5_beacons.log
    python tools/parse_beacons.py beacons.log --uid AB12CD --json

Exit code: 0 if at least one run validates, 1 otherwise.
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, field

# --- 13.60 reference: p691-run3 (2026-11-14, grade M, INDEX.md:3489) ---------
# Boot-stable across 5 boots; deltas confirmed by VP_SLOT_DELTAS_CORRECTED.md.
REF = {
    "VP": 0x80C6A1B28,
    "S0": 0x80AF90FB0,
    "S1": 0x80AF90FE0,
    "S2": 0x809455750,
    "S3": 0x80AF916B0,
    "S4": 0x809455750,
    "S5": 0x809455750,
    "S6": 0x80ABE7400,
    "S7": 0x80AF91810,
    "S8": 0x0,
}
ASSUMED_VP_RVA = 0xC6A1B28  # the value probe-modules.html hardcodes

SLOT_KEYS = ["S0", "S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8"]

BEACON_RE = re.compile(r"/beacon/MOD-([^?\s]+)\?[^?\s]*\bu=([A-Z0-9]{6})")
HEX_RE = re.compile(r"^0x[0-9a-fA-F]+$")


@dataclass
class Run:
    uid: str
    vp: int = 0
    base_claimed: int = 0
    slots: dict = field(default_factory=dict)
    walk_ok: bool = False
    complete: bool = False
    messages: list = field(default_factory=list)


def parse_kv(msg):
    """Split a beacon message like 'VP-0x80c6a1b28' into ('VP', 0x80c6a1b28)."""
    if "-" not in msg:
        return msg, None
    key, _, val = msg.partition("-")
    if HEX_RE.match(val):
        return key, int(val, 16)
    return key, val


def parse_log(path):
    runs = {}
    with open(path, "r", errors="replace") as f:
        for line in f:
            m = BEACON_RE.search(line)
            if not m:
                continue
            msg, uid = m.group(1), m.group(2)
            from urllib.parse import unquote
            msg = unquote(msg)
            run = runs.setdefault(uid, Run(uid=uid))
            run.messages.append(msg)
            key, val = parse_kv(msg)
            if key == "VP" and isinstance(val, int):
                run.vp = val
            elif key == "BASE" and isinstance(val, int):
                run.base_claimed = val
            elif key in SLOT_KEYS and isinstance(val, int):
                run.slots[key] = val
            elif key == "WALK":
                run.walk_ok = val == "ok=true"
            elif key == "COMPLETE":
                run.complete = True
    return runs


def analyze(run):
    """Return (verdict, details) for one run."""
    d = {"uid": run.uid, "vp": hex(run.vp), "walk_ok": run.walk_ok,
         "complete": run.complete}
    if not run.vp or len(run.slots) < 4:
        return "INCOMPLETE", d

    # 1. Probe's own claim: does BASE = VP - 0xC6A1B28 hold?
    base_implied = run.vp - ASSUMED_VP_RVA
    d["base_probe_claim"] = hex(run.base_claimed)
    d["base_implied_by_assumed_rva"] = hex(base_implied)
    d["probe_base_matches_assumption"] = (run.base_claimed == base_implied)

    # 2. Inter-slot deltas. Under pure ASLR the whole image slides as one
    #    mapping, so VP-si is slide-invariant and must equal the 13.60 values
    #    exactly. If every slot instead shifted by the SAME amount relative to
    #    the reference, the vtable moved as a unit against .text (different
    #    link) and the true RVA is assumed_rva + shift.
    #    S8 is 0 in both (past-end), skip it for matching.
    ref_deltas = {k: REF["VP"] - REF[k] for k in SLOT_KEYS[:8]}
    run_deltas = {}
    shifts = {}  # run_delta - ref_delta per slot
    for k in SLOT_KEYS[:8]:
        if k not in run.slots:
            continue
        run_deltas[k] = run.vp - run.slots[k]
        shifts[k] = run_deltas[k] - ref_deltas[k]

    # Sanity: the probe's claimed BASE should reproduce VP at VP+RVA. If the
    # probe's arithmetic contradicts itself, distrust the beacon before
    # trusting any delta math derived from it.
    if run.base_claimed and run.base_claimed + ASSUMED_VP_RVA != run.vp:
        d["warning"] = "probe BASE claim inconsistent with VP; beacon suspect"
    d["slot_deltas"] = {k: hex(v) for k, v in run_deltas.items()}
    d["delta_shift_vs_1360"] = {k: hex(v) for k, v in shifts.items()}

    nonzero_shifts = [v for v in shifts.values() if v != 0]
    if not shifts:
        return "INCOMPLETE", d

    # Slide-invariance test first: are the inter-slot gaps identical to the
    # reference? If gaps moved too, the build is genuinely different and only
    # the structural fingerprint (below) is meaningful.
    gap_consistent = all(
        run.slots[a] - run.slots[b] == REF[a] - REF[b]
        for a, b in zip(SLOT_KEYS[:8], SLOT_KEYS[1:8])
        if a in run.slots and b in run.slots and REF[a] and REF[b]
    )
    d["inter_slot_gaps_match_1360"] = gap_consistent

    if not nonzero_shifts and gap_consistent:
        # Every VP-slot delta identical to 13.60 -> same build, pure slide.
        d["vp_rva_confirmed"] = hex(ASSUMED_VP_RVA)
        d["base_true"] = hex(base_implied)
        return "MATCH_1360_LAYOUT", d

    unique_shifts = set(nonzero_shifts)
    if (len(unique_shifts) == 1 and len(nonzero_shifts) == len(shifts)
            and gap_consistent):
        # Gaps identical but every slot offset from VP by the same constant:
        # vtable (.rodata) moved as a unit relative to .text — different link
        # of the same code. True RVA = assumed + shift.
        shift = nonzero_shifts[0]
        true_rva = ASSUMED_VP_RVA + shift
        d["uniform_shift"] = hex(shift)
        d["vp_rva_recomputed"] = hex(true_rva)
        d["base_true"] = hex(run.vp - true_rva)
        return "UNIFORM_SHIFT_RVA_RECOMPUTED", d

    # 3. Structural fingerprint that survives ANY slide: slot-vs-slot deltas.
    structural = {}
    present = [k for k in SLOT_KEYS[:8] if k in run.slots]
    for a, b in zip(present, present[1:]):
        key = f"{a}-{b}"
        structural[key] = run.slots[a] - run.slots[b]
        structural[key + "_ref"] = REF[a] - REF[b]
        structural[key + "_match"] = structural[key] == structural[key + "_ref"]
    d["structural_slot_pairs"] = structural
    return "MISMATCH_MANUAL_REVIEW", d


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log", help="nginx beacon log (or captured beacon lines)")
    ap.add_argument("--uid", help="only analyze this UID")
    ap.add_argument("--json", action="store_true", help="JSON output")
    args = ap.parse_args()

    runs = parse_log(args.log)
    if args.uid:
        runs = {args.uid: runs[args.uid]} if args.uid in runs else {}
    if not runs:
        print("no beacon runs found", file=sys.stderr)
        return 1

    results = []
    ok = False
    for uid in sorted(runs):
        verdict, details = analyze(runs[uid])
        details["verdict"] = verdict
        results.append(details)
        if verdict in ("MATCH_1360_LAYOUT", "UNIFORM_SHIFT_RVA_RECOMPUTED"):
            ok = True

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print(f"UID {r['uid']}: {r['verdict']}")
            print(f"  VP={r['vp']} walk_ok={r['walk_ok']} complete={r['complete']}")
            if "base_probe_claim" in r:
                print(f"  BASE probe-claimed={r['base_probe_claim']} "
                      f"implied(0xC6A1B28)={r['base_implied_by_assumed_rva']} "
                      f"agree={r['probe_base_matches_assumption']}")
            if "vp_rva_confirmed" in r:
                print(f"  VP_RVA CONFIRMED = {r['vp_rva_confirmed']}  base={r['base_true']}")
            if "vp_rva_recomputed" in r:
                print(f"  uniform shift={r['uniform_shift']} -> "
                      f"VP_RVA RECOMPUTED = {r['vp_rva_recomputed']}  base={r['base_true']}")
            if r["verdict"] == "MISMATCH_MANUAL_REVIEW":
                for k in ("slot_deltas", "delta_shift_vs_1360"):
                    print(f"  {k}: {r[k]}")
            print()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Parse data-gather tester beacons (probe-modules.html) and validate walks.

Relative slot deltas can identify a layout fingerprint, but this tool does not
infer an absolute VP_RVA or module base without an independent anchor.

The upstream data-gather rig (probes/phase13_webkit/data-gather/) emits beacon
lines into the VPS nginx log (/var/log/nginx/ps5_beacons.log), one HTTP GET per
beacon:

    GET /beacon/MOD-<MESSAGE>?t=<ms>&u=<UID> ...

This tool groups beacons by UID into runs, validates each run, and -- crucially
-- does NOT trust the probe's hardcoded BASE = VP - 0xC6A1B28. Relative deltas
provide a layout fingerprint, not an absolute module base. Issue #295 measured
the same slot deltas with VP_RVA 0x724DB28, so a fingerprint match cannot select
between absolute layout families. Run validity is checked separately from
address inference; incomplete, failed, malformed, or contradictory records
cannot produce a successful exit.

Usage:
    python tools/parse_beacons.py /var/log/nginx/ps5_beacons.log
    python tools/parse_beacons.py beacons.log --uid AB12CD --json

Exit code: 0 if at least one valid run has a recognized reference-relative
fingerprint, 1 otherwise. A valid but unknown fingerprint remains manual review.
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, field

# --- Reference fingerprint: p691-run3 (2026-11-14, grade M, INDEX.md:3482) --
# Boot-stable across 5 boots; deltas confirmed by VP_SLOT_DELTAS_CORRECTED.md.
# Issue #295 later measured the same deltas at VP_RVA 0x724DB28, so these
# absolute addresses are one observed layout family, not a universal RVA.
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


def analyze_layout(run):
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
    #    mapping, so VP-si is slide-invariant. A uniform shift means the
    #    vtable moved relative to the reference code slots; it remains a
    #    relative observation, not an absolute RVA.
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
    d["delta_shift_vs_reference"] = {k: hex(v) for k, v in shifts.items()}

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
    d["inter_slot_gaps_match_reference"] = gap_consistent

    if not nonzero_shifts and gap_consistent:
        # Matching relative deltas validate the walk shape only. They do not
        # independently anchor an absolute RVA: issue #295 has identical
        # deltas at VP_RVA 0x724DB28 rather than this family's 0xC6A1B28.
        d["reference_fingerprint"] = "p691-run3"
        d["absolute_rva"] = "unresolved"
        return "MATCH_REFERENCE_DELTAS", d

    unique_shifts = set(nonzero_shifts)
    if (len(unique_shifts) == 1 and len(nonzero_shifts) == len(shifts)
            and gap_consistent):
        # Gaps identical but every slot offset from VP by the same constant.
        # This is a relative shift against the reference family, not proof of
        # an absolute RVA or base without an independent anchor.
        shift = nonzero_shifts[0]
        d["uniform_shift"] = hex(shift)
        d["absolute_rva"] = "unresolved"
        return "UNIFORM_SHIFT_REFERENCE_DELTAS", d

    # 3. Structural fingerprint that survives ANY slide: slot-vs-slot deltas.
    structural = {}
    present = [k for k in SLOT_KEYS[:8] if k in run.slots]
    for a, b in zip(present, present[1:]):
        key = f"{a}-{b}"
        structural[key] = run.slots[a] - run.slots[b]
        structural[key + "_ref"] = REF[a] - REF[b]
        structural[key + "_match"] = structural[key] == structural[key + "_ref"]
    d["structural_slot_pairs"] = structural
    d["absolute_rva"] = "unresolved"
    return "MISMATCH_MANUAL_REVIEW", d


def analyze(run):
    """Keep diagnostic layout matching separate from evidence validity."""
    layout_verdict, details = analyze_layout(run)
    errors = []
    seen = {}
    numeric_keys = {"VP", "BASE", *SLOT_KEYS}
    for message in run.messages:
        key, value = parse_kv(message)
        if key not in numeric_keys and key not in {"WALK", "COMPLETE"}:
            continue
        if (key in numeric_keys and not isinstance(value, int)
                or key == "WALK" and value not in {"ok=true", "ok=false"}
                or key == "COMPLETE" and value is not None):
            errors.append(f"malformed {key}")
        if key in seen and seen[key] != value:
            errors.append(f"contradictory {key}")
        seen[key] = value
    if not run.walk_ok:
        errors.append("walk not successful")
    if not run.complete:
        errors.append("completion missing")
    if not run.vp:
        errors.append("VP missing or zero")
    if any(not run.slots.get(key) for key in SLOT_KEYS[:8]):
        errors.append("required slots S0-S7 missing or zero")
    if "BASE" not in seen or run.base_claimed != run.vp - ASSUMED_VP_RVA:
        errors.append("BASE missing or inconsistent with probe assumption")
    details["layout_verdict"] = layout_verdict
    details["run_valid"] = not errors
    details["validation_errors"] = sorted(set(errors))
    if errors:
        return "INVALID_RUN", details
    details["address_inference"] = (
        "unresolved: relative slot deltas cannot determine absolute module base")
    return layout_verdict, details


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
        if (details["run_valid"] and verdict in
                ("MATCH_REFERENCE_DELTAS", "UNIFORM_SHIFT_REFERENCE_DELTAS")):
            ok = True

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print(f"UID {r['uid']}: {r['verdict']}")
            print(f"  VP={r['vp']} walk_ok={r['walk_ok']} complete={r['complete']}")
            print(f"  run_valid={r['run_valid']} layout={r['layout_verdict']}")
            if r["validation_errors"]:
                print(f"  validation_errors={r['validation_errors']}")
            if "base_probe_claim" in r:
                print(f"  BASE probe-claimed={r['base_probe_claim']} "
                      f"implied(0xC6A1B28)={r['base_implied_by_assumed_rva']} "
                      f"agree={r['probe_base_matches_assumption']}")
            if "reference_fingerprint" in r:
                print(f"  reference deltas={r['reference_fingerprint']} "
                      "absolute VP_RVA=unresolved")
            if "uniform_shift" in r:
                print(f"  relative shift={r['uniform_shift']} "
                      "absolute VP_RVA=unresolved")
            if "address_inference" in r:
                print(f"  {r['address_inference']}")
            if r["verdict"] == "MISMATCH_MANUAL_REVIEW":
                for k in ("slot_deltas", "delta_shift_vs_reference"):
                    print(f"  {k}: {r[k]}")
            print()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

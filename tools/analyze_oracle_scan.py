#!/usr/bin/env python3
"""Grade FontFace ``document.fonts.check()`` +2 offset-scan captures offline.

Issue #305 reports a text-family pointer found by reading u32 pairs at bsearch
offset +2 (bytes 2-5 of each 64-bit word) instead of the old +3 offset.  This
tool grades a captured log WITHOUT a console and WITHOUT trusting the probe's
own interpretation:

  * a +2 read of a heap pointer (0x10XX...) lands in [0x100000, 0x10FFFF];
  * a +2 read of a text pointer (0x01XX...) lands in [0x10000, 0x1FFFF];
  * a read above the Unicode ceiling (0x10FFFF) is the all-false ceiling and
    is NOT pointer evidence;
  * each bsearch costs 21 check() calls, SELF discovery costs 3, and a page
    load has a ~120-call budget (so at most five reads per probe).

A full text-pointer claim is only accepted when the family read, the +2
confirmation read on the same object, and an in-band VTAB claim all agree.
Absent any of those, the verdict is downgraded rather than guessed.

The +2 regime alone can produce false positives: cobrajet302gt's T14K/T14F
law found a dword flip class (0x80000004 <-> 0x7FFFFFF4, 7/7 boots) at the
same stale-alias slot.  A `FULLWIDTH_CONFIRMED` tier therefore sits above
`TEXT_PTR_CONFIRMED`: it requires full-width (never truncated) reads of the
same slot in two generations with a byte-echo signature agreeing, and no
flip-class value.  Full-width readQ tokens (`FW_...`) are a separate
primitive and are NOT charged to the 21-calls-per-bsearch +2 budget.

All inputs are treated as untrusted text; no console, network, or probe
execution is involved.

Usage:
    python tools/analyze_oracle_scan.py walk.log
    python tools/analyze_oracle_scan.py walk.log --json
    python tools/analyze_oracle_scan.py beacons.log --uid AB12CD --json

Exit code: 0 if at least one selected run is internally consistent, 1 if all
selected runs are INVALID_RUN (or no run matched --uid).
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from urllib.parse import unquote

# Oracle semantics from issue #305 (grades are about the capture, not the bug).
UNICODE_CEILING = 0x10FFFF
HEAP_LO, HEAP_HI = 0x100000, 0x10FFFF
TEXT_LO, TEXT_HI = 0x10000, 0x1FFFF
TEXT_ADDR_LO, TEXT_ADDR_HI = 0x100000000, 0x1FFFFFFFF
BSEARCH_CALLS = 21
SELF_CALLS = 3
PAGE_CALL_BUDGET = 120
MAX_WORD = 0xFFFFFFFFFFFFFFFF
DEFAULT_ECHO_MASK = 0xFFFFFFFFFFFF  # full 48-bit comparison, never truncated
FLIP_DWORDS = (0x80000004, 0x7FFFFFF4)  # cobrajet302gt T14K/T14F stale-alias flip class

BEACON_RE = re.compile(r"\bBEACON\s+\S+:\s*(.*)")
UID_RE = re.compile(r"(?:\bu=([A-Z0-9]{6})\b|\bUID=([A-Z0-9]{6})\b)")
TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?P<key>[A-Za-z][A-Za-z0-9_]*(?:\+[0-9]+)?)=(?P<val>[^\s,;?&]+)"
)
READ_KEY_RE = re.compile(r"^(?P<region>[A-Za-z][A-Za-z0-9]*)\+(?P<offset>[0-9]+)$")
FW_PREFIX, MARK_PREFIX = "FW_", "MARK_"


@dataclass
class Read:
    label: str
    raw: str
    value: int | None = None
    cls: str = "MALFORMED"
    error: str | None = None


@dataclass
class FullRead:
    slot: str
    gen: int
    raw: str
    value: int | None = None
    error: str | None = None


@dataclass
class Run:
    uid: str = "default"
    reads: list[Read] = field(default_factory=list)
    full_reads: list[FullRead] = field(default_factory=list)
    marks: dict[str, int] = field(default_factory=dict)
    echo_mask: int = DEFAULT_ECHO_MASK
    gen: int = 1
    self_found: bool = False
    calls_reported: int | None = None
    vtab_claim: int | None = None
    errors: list[str] = field(default_factory=list)


def parse_value(raw: str) -> int | None:
    """Parse a decimal or 0x-prefixed value; reject anything else."""
    try:
        if raw.lower().startswith("0x"):
            return int(raw, 16)
        if raw.isdigit():
            return int(raw, 10)
    except ValueError:
        return None
    return None


def classify(value: int) -> str:
    """Classify a +2-scan u32 result by the address family it reveals."""
    if value > UNICODE_CEILING:
        return "CEILING"
    if HEAP_LO <= value <= HEAP_HI:
        return "HEAP"
    if TEXT_LO <= value <= TEXT_HI:
        return "TEXT"
    return "SMALL"


def parse_log(path: str) -> dict[str, Run]:
    """Group beacon/console tokens into runs by UID."""
    runs: dict[str, Run] = {}
    current = "default"
    with open(path, "r", errors="replace") as handle:
        for line in handle:
            beacon = BEACON_RE.search(line)
            text = unquote(beacon.group(1) if beacon else line)
            uid_match = UID_RE.search(text)
            if uid_match:
                current = uid_match.group(1) or uid_match.group(2)
            run = runs.setdefault(current, Run(uid=current))
            for match in TOKEN_RE.finditer(text):
                key, raw = match.group("key"), match.group("val")
                if key == "UID":
                    continue
                if key == "SELF":
                    value = parse_value(raw)
                    if value is None or value != 0:
                        run.self_found = True
                    continue
                if key == "CALLS":
                    value = parse_value(raw)
                    if value is None:
                        run.errors.append(f"malformed CALLS={raw}")
                    else:
                        run.calls_reported = value
                    continue
                if key == "VTAB":
                    value = parse_value(raw)
                    if value is None:
                        run.errors.append(f"malformed VTAB={raw}")
                    else:
                        run.vtab_claim = value
                    continue
                if key == "GEN":
                    value = parse_value(raw)
                    if value is None or value < 1:
                        run.errors.append(f"malformed GEN={raw}")
                    else:
                        run.gen = value
                    continue
                if key == "ECHO_MASK":
                    value = parse_value(raw)
                    if value is None or value < 0 or value > MAX_WORD:
                        run.errors.append(f"malformed ECHO_MASK={raw}")
                    else:
                        run.echo_mask = value
                    continue
                if key.startswith(FW_PREFIX):
                    slot = key[len(FW_PREFIX):]
                    if not READ_KEY_RE.match(slot):
                        run.errors.append(f"malformed FW slot {key}")
                    else:
                        run.full_reads.append(FullRead(slot=slot, gen=run.gen, raw=raw))
                    continue
                if key.startswith(MARK_PREFIX):
                    slot = key[len(MARK_PREFIX):]
                    value = parse_value(raw)
                    if not READ_KEY_RE.match(slot) or value is None or value > MAX_WORD:
                        run.errors.append(f"malformed MARK {key}={raw}")
                    else:
                        run.marks[slot] = value
                    continue
                if READ_KEY_RE.match(key):
                    run.reads.append(Read(label=key, raw=raw))
    return runs


def has_confirm(run: Run, read: Read) -> bool:
    """A confirmation is the same region at offset+2, also in the text band."""
    parsed = READ_KEY_RE.match(read.label)
    if not parsed:
        return False
    confirm_key = f"{parsed.group('region')}+{int(parsed.group('offset')) + 2}"
    return any(
        other.label == confirm_key and other.cls == "TEXT" and other.value is not None
        for other in run.reads
    )


def fullwidth_echo(run: Run, slot: str) -> tuple[bool, str]:
    """Check byte-echo agreement for a slot across at least two generations.

    Comparison is always on the full ECHO_MASK (48 bits by default), never on
    a truncated 32-bit slice.  If a planted MARK token exists, every observed
    generation must echo it; otherwise the generations must agree with each
    other under the same mask.
    """
    reads = [r for r in run.full_reads if r.slot == slot and r.value is not None]
    if len({r.gen for r in reads}) < 2:
        return False, "NEED_TWO_GENERATIONS"
    mask = run.echo_mask
    mark = run.marks.get(slot)
    if mark is not None:
        if any((r.value & mask) != (mark & mask) for r in reads):
            return False, "MARKER_MISMATCH"
        return True, "MARKER_ECHO_OK"
    values = {r.value & mask for r in reads}
    if len(values) != 1:
        return False, "ECHO_MISMATCH"
    return True, "ECHO_OK"


def analyze(run: Run) -> dict:
    """Validate the budget and grade the pointer claim for a single run."""
    errors = list(run.errors)
    notes: list[str] = []
    for full in run.full_reads:
        value = parse_value(full.raw)
        if value is None or value > MAX_WORD:
            full.error = f"malformed full-width value {full.raw!r}"
            errors.append(f"{full.slot} gen{full.gen}: {full.error}")
        else:
            full.value = value
    for read in run.reads:
        value = parse_value(read.raw)
        if value is None:
            read.error = f"malformed value {read.raw!r}"
            errors.append(f"{read.label}: {read.error}")
            continue
        read.value = value
        read.cls = classify(value)

    calls = len([r for r in run.reads if r.value is not None]) * BSEARCH_CALLS
    if run.self_found:
        calls += SELF_CALLS
    budget_ok = calls <= PAGE_CALL_BUDGET
    if not budget_ok:
        errors.append(
            f"PAGE_CALL_BUDGET_EXCEEDED: {calls} calls > {PAGE_CALL_BUDGET} "
            f"(max {PAGE_CALL_BUDGET // BSEARCH_CALLS} reads)"
        )
    if run.calls_reported is not None and run.calls_reported != calls:
        errors.append(
            f"CALL_COUNT_MISMATCH: reported {run.calls_reported}, recomputed {calls}"
        )
    if run.vtab_claim is not None and not (
        TEXT_ADDR_LO <= run.vtab_claim <= TEXT_ADDR_HI
    ):
        errors.append(f"VTAB_OUT_OF_TEXT_BAND: {run.vtab_claim:#x}")

    text_reads = [r for r in run.reads if r.cls == "TEXT"]
    confirmed_family = [r for r in text_reads if has_confirm(run, r)]
    flip_suspect = any(
        (f.value & 0xFFFFFFFF) in FLIP_DWORDS
        for f in run.full_reads
        if f.value is not None
    )
    echo_slot = None
    echo_ok = False
    if confirmed_family:
        echo_slot = confirmed_family[0].label
        echo_ok, echo_note = fullwidth_echo(run, echo_slot)
        if run.full_reads or run.marks:
            prefix = "FULLWIDTH_ECHO_OK" if echo_ok else "FULLWIDTH_ECHO_FAILED"
            notes.append(f"{prefix}:{echo_slot}:{echo_note}")

    if errors:
        verdict = "INVALID_RUN"
    elif not text_reads:
        verdict = "NO_TEXT_POINTER"
    elif flip_suspect:
        verdict = "FLIP_CLASS_SUSPECT"
    elif confirmed_family and run.vtab_claim is not None and echo_ok:
        verdict = "FULLWIDTH_CONFIRMED"
    elif confirmed_family and run.vtab_claim is not None:
        verdict = "TEXT_PTR_CONFIRMED"
    elif confirmed_family:
        verdict = "TEXT_FAMILY_CONFIRMED"
    else:
        verdict = "TEXT_FAMILY_ONLY"

    return {
        "uid": run.uid,
        "reads": [
            {
                "label": r.label,
                "raw": r.raw,
                "value": r.value,
                "class": r.cls,
                "error": r.error,
            }
            for r in run.reads
        ],
        "fullwidth_reads": [
            {
                "slot": f.slot,
                "gen": f.gen,
                "raw": f.raw,
                "value": f.value,
                "error": f.error,
            }
            for f in run.full_reads
        ],
        "marks": {slot: hex(value) for slot, value in run.marks.items()},
        "echo_mask": hex(run.echo_mask),
        "flip_class_suspect": flip_suspect,
        "self_found": run.self_found,
        "calls_reported": run.calls_reported,
        "calls_recomputed": calls,
        "budget_ok": budget_ok,
        "vtab_claim": run.vtab_claim,
        "verdict": verdict,
        "notes": notes,
        "validation_errors": errors,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", help="beacon/console capture to grade")
    parser.add_argument("--uid", help="only grade this run UID")
    parser.add_argument("--json", action="store_true", help="emit one JSON record per run")
    args = parser.parse_args(argv)

    runs = parse_log(args.log)
    if args.uid:
        runs = {uid: run for uid, run in runs.items() if uid == args.uid}
    records = [analyze(run) for run in runs.values()]

    if args.json:
        print(json.dumps(records, indent=2, sort_keys=True))
    else:
        for record in records:
            errors = "; ".join(record["validation_errors"]) or "none"
            notes = "; ".join(record["notes"]) or "none"
            print(
                f"{record['uid']}: {record['verdict']} "
                f"reads={len(record['reads'])} fw_reads={len(record['fullwidth_reads'])} "
                f"calls={record['calls_recomputed']} "
                f"budget_ok={record['budget_ok']} notes={notes} errors={errors}"
            )
    return 0 if records and all(r["verdict"] != "INVALID_RUN" for r in records) else 1


if __name__ == "__main__":
    raise SystemExit(main())

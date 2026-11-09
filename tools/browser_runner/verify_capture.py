"""Offline framing/integrity checks. Delivery completeness is always UNKNOWN in v1."""
from __future__ import annotations

import argparse
import base64
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import re
import uuid

try:
    from .capture import (SCHEMA, VERSION, MAX_BODY_BYTES, MAX_TARGET_BYTES,
                          MAX_RECORD_BYTES, decode_request, valid_timestamp)
except ImportError:  # direct CLI execution
    from capture import (SCHEMA, VERSION, MAX_BODY_BYTES, MAX_TARGET_BYTES,
                         MAX_RECORD_BYTES, decode_request, valid_timestamp)


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _constant(value):
    raise ValueError("nonfinite JSON constant")


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("overflowed JSON number")
    return number


def _keys(record, expected):
    if type(record) is not dict or set(record) != set(expected.split()):
        raise ValueError("unexpected record fields")


def _integer(value):
    return type(value) is int and value >= 0


def _client_diagnostics(events):
    sessions = {}
    warnings = []
    for client in events:
        if not client:
            continue
        session = client.get("session", [])
        numbers = client.get("n", [])
        if len(session) != 1 or not session[0] or len(numbers) != 1:
            warnings.append("unscoped or ambiguous client metadata; not used for gap analysis")
            continue
        number = numbers[0]
        if not isinstance(number, str) or not re.fullmatch(r"[0-9]{1,20}", number):
            warnings.append("invalid client sequence; not used for gap analysis")
            continue
        sessions.setdefault(session[0], []).append(int(number))
    reports = {}
    for session, numbers in sessions.items():
        counts = Counter(numbers)
        ordered = sorted(counts)
        reports[session] = {
            "observed_count": len(numbers),
            "duplicates": {str(n): count for n, count in counts.items() if count > 1},
            # No assumption about the initial client sequence, or its final value.
            "gaps_between_observed": [[a + 1, b - 1] for a, b in zip(ordered, ordered[1:])
                                      if b > a + 1],
            "out_of_order": any(b < a for a, b in zip(numbers, numbers[1:])),
        }
    return reports, warnings


def verify_capture(path: Path) -> dict:
    """Read one bounded line at a time; malformed captures never count as complete."""
    errors = []
    incomplete = []
    capture_id = None
    opened = False
    closed = False
    count = 0
    clients = []
    line_number = 0
    try:
        with Path(path).open("rb") as source:
            while True:
                raw = source.readline(MAX_RECORD_BYTES + 1)
                if not raw:
                    break
                line_number += 1
                if len(raw) > MAX_RECORD_BYTES:
                    errors.append(f"line {line_number}: record exceeds size bound")
                    break
                if not raw.endswith(b"\n"):
                    incomplete.append(f"line {line_number}: truncated/unframed final record")
                    break
                try:
                    record = json.loads(raw.decode("utf-8"), object_pairs_hook=_object,
                                        parse_constant=_constant, parse_float=_finite_float)
                    if type(record) is not dict:
                        raise ValueError("record is not an object")
                    kind = record.get("record_type")
                    if line_number == 1:
                        _keys(record, "record_type schema version capture_id started_at "
                              "limits durability provenance")
                        if kind != "open" or record["schema"] != SCHEMA:
                            raise ValueError("missing opening record or wrong schema")
                        if type(record["version"]) is not int or record["version"] != VERSION:
                            raise ValueError("unsupported schema version")
                        if str(uuid.UUID(record["capture_id"])) != record["capture_id"]:
                            raise ValueError("invalid capture UUID")
                        if not valid_timestamp(record["started_at"]):
                            raise ValueError("invalid opening timestamp")
                        _keys(record["limits"], "body_bytes target_bytes")
                        if any(type(v) is not int for v in record["limits"].values()):
                            raise ValueError("capture limits must be integers")
                        if record["limits"] != {"body_bytes": MAX_BODY_BYTES,
                                                "target_bytes": MAX_TARGET_BYTES}:
                            raise ValueError("unsupported capture limits")
                        if record["durability"] != "flush-only":
                            raise ValueError("unsupported durability declaration")
                        provenance = record["provenance"]
                        _keys(provenance, "local_files_sha256 caller_reported")
                        if type(provenance["caller_reported"]) is not dict:
                            raise ValueError("caller provenance is not an object")
                        hashes = provenance["local_files_sha256"]
                        if type(hashes) is not dict or any(
                            not isinstance(v, str) or not re.fullmatch("[0-9a-f]{64}", v)
                            for v in hashes.values()
                        ):
                            raise ValueError("invalid provenance digest")
                        capture_id = record["capture_id"]
                        opened = True
                        continue
                    if not opened:
                        raise ValueError("no valid opening record")
                    if closed:
                        raise ValueError("record after closing record")
                    if record.get("capture_id") != capture_id:
                        raise ValueError("capture identity mismatch")
                    if kind == "event":
                        _keys(record, "record_type capture_id sequence received_at request")
                        if not _integer(record["sequence"]) or record["sequence"] != count + 1:
                            raise ValueError("server sequence is not contiguous acceptance order")
                        if not valid_timestamp(record["received_at"]):
                            raise ValueError("invalid arrival timestamp")
                        request = record["request"]
                        _keys(request, "method raw_target query format tag measurement "
                              "measurement_utf8_length body_base64 body_length body_sha256 "
                              "declared_length client_reported")
                        if not _integer(request["body_length"]) or request["body_length"] > MAX_BODY_BYTES:
                            raise ValueError("invalid body length")
                        if not isinstance(request["body_base64"], str):
                            raise ValueError("body representation is not base64 text")
                        body = base64.b64decode(request["body_base64"], validate=True)
                        if base64.b64encode(body).decode("ascii") != request["body_base64"]:
                            raise ValueError("noncanonical base64")
                        if len(body) != request["body_length"]:
                            raise ValueError("body length mismatch")
                        if hashlib.sha256(body).hexdigest() != request["body_sha256"]:
                            raise ValueError("body hash mismatch")
                        decoded = decode_request(request["method"], request["raw_target"], body,
                                                 declared_length=request["declared_length"])
                        if decoded.status != "accepted" or decoded.record() != request:
                            raise ValueError("raw request and interpreted fields disagree")
                        # dict equality treats bool and int alike; explicitly type numeric fields.
                        length = request["measurement_utf8_length"]
                        if length is not None and not _integer(length):
                            raise ValueError("invalid measurement byte length")
                        count += 1
                        if request["client_reported"]:
                            clients.append(request["client_reported"])
                    elif kind == "close":
                        _keys(record, "record_type capture_id accepted_count closed_at")
                        if not _integer(record["accepted_count"]) or record["accepted_count"] != count:
                            raise ValueError("closing count mismatch")
                        if not valid_timestamp(record["closed_at"]):
                            raise ValueError("invalid closing timestamp")
                        closed = True
                    else:
                        raise ValueError("unknown record type")
                except (ValueError, TypeError, KeyError, AttributeError, UnicodeError,
                        RecursionError, OverflowError):
                    errors.append(f"line {line_number}: invalid schema, encoding, or record consistency")
    except OSError as exc:
        errors.append("capture read failed: " + str(exc))
    if not opened:
        incomplete.append("no valid opening record")
    if not closed:
        incomplete.append("missing valid closing record")
    clients, warnings = _client_diagnostics(clients)
    return {
        "capture_integrity": "INVALID" if errors else "INCOMPLETE" if incomplete else "VALID",
        "delivery_completeness": "UNKNOWN",
        "capture_id": capture_id,
        "accepted_records_verified": count,
        "closed": closed,
        "errors": errors,
        "incomplete": incomplete,
        "client_reported": clients,
        "warnings": warnings,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    args = parser.parse_args(argv)
    report = verify_capture(args.capture)
    print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))
    return {"VALID": 0, "INVALID": 1, "INCOMPLETE": 2}[report["capture_integrity"]]


if __name__ == "__main__":
    raise SystemExit(main())

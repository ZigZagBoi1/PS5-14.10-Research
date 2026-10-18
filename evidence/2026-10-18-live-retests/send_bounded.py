#!/usr/bin/env python3
"""One-shot Lua-loader sender with a self-contained evidence receipt.

The sender performs one TCP connection, transmits the documented uint64 length
prefix plus UTF-8 Lua bytes, and records the raw response without decoding it.
It does not retry or alter the supplied script.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import socket
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("script", type=Path)
    ap.add_argument("--label", required=True)
    ap.add_argument("--ip", default="10.0.0.96")
    ap.add_argument("--port", type=int, default=9026)
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--max-response", type=int, default=1 << 20)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()

    script_bytes = args.script.read_bytes()
    if b"\x00" in script_bytes:
        raise SystemExit("refusing NUL-containing script")
    frame = struct.pack("<Q", len(script_bytes)) + script_bytes
    out = args.output
    out.mkdir(parents=True, exist_ok=True)
    (out / "script.lua").write_bytes(script_bytes)
    (out / "frame.bin").write_bytes(frame)

    receipt = {
        "label": args.label,
        "script_original_path": str(args.script),
        "sender_script_path": str(Path(__file__).resolve()),
        "ip": args.ip,
        "port": args.port,
        "protocol": "little-endian uint64 byte length followed by raw UTF-8 Lua",
        "script_bytes": len(script_bytes),
        "script_sha256": sha256(script_bytes),
        "frame_bytes": len(frame),
        "frame_sha256": sha256(frame),
        "started_utc": utc_now(),
        "connected": False,
        "submitted": False,
        "response_bytes": None,
        "response_sha256": None,
        "eof": False,
        "timeout": False,
        "error": None,
        "finished_utc": None,
    }
    response = bytearray()
    try:
        with socket.create_connection((args.ip, args.port), timeout=args.timeout) as sock:
            receipt["connected"] = True
            sock.settimeout(args.timeout)
            sock.sendall(frame)
            receipt["submitted"] = True
            while len(response) < args.max_response:
                try:
                    chunk = sock.recv(min(65536, args.max_response - len(response)))
                except socket.timeout:
                    receipt["timeout"] = True
                    break
                if not chunk:
                    receipt["eof"] = True
                    break
                response.extend(chunk)
    except Exception as exc:  # record the exception without hiding the receipt
        receipt["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        raw = bytes(response)
        (out / "response.raw").write_bytes(raw)
        receipt["response_bytes"] = len(raw)
        receipt["response_sha256"] = sha256(raw)
        receipt["finished_utc"] = utc_now()
        (out / "SESSION.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")

    print(json.dumps(receipt, indent=2))
    if receipt["error"] or not receipt["connected"] or not receipt["submitted"]:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

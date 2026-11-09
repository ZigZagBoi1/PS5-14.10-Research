"""Server-only bridge smoke test. Does not contact a PS5 or decrypt a PUP."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time
import uuid


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bridge", type=Path, required=True)
    ap.add_argument("--source", type=Path, required=True)
    ap.add_argument("--out-parent", type=Path, required=True)
    ap.add_argument("--bind", default="10.0.0.80")
    ap.add_argument("--port", type=int, default=19028)
    args = ap.parse_args()
    out = args.out_parent / ("offline-smoke-" + str(uuid.uuid4()))
    process = subprocess.Popen(
        [sys.executable, str(args.bridge), "--source", str(args.source),
         "--out", str(out), "--bind", args.bind, "--expect-ip", args.bind,
         "--port", str(args.port)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        for _ in range(120):
            if process.poll() is not None:
                raise RuntimeError(process.communicate())
            path = out / "status.json"
            if path.exists() and json.loads(path.read_text())["stage"] == "listening":
                break
            time.sleep(0.1)
        else:
            raise TimeoutError("Bridge did not listen")
        with socket.create_connection((args.bind, args.port), timeout=5) as conn:
            def exact(size: int) -> bytes:
                data = bytearray()
                while len(data) < size:
                    part = conn.recv(size - len(data))
                    if not part:
                        raise EOFError("Bridge closed during smoke test")
                    data.extend(part)
                return bytes(data)
            def frame(op: str, entry: int = 0, offset: int = 0,
                      payload: bytes = b"", length: int | None = None) -> None:
                conn.sendall(struct.pack("<4sBBHQI", b"P14R", ord(op), entry, 0,
                                         offset, len(payload) if length is None else length) + payload)
                if exact(4) != b"OKAY":
                    raise AssertionError(f"No acknowledgement for {op}")
            frame("R", length=16)
            head = exact(16)
            if head != b"SLB2" + args.source.open("rb").read(16)[4:]:
                raise AssertionError("PUP read mismatch")
            frame("B", entry=1)
            frame("W", entry=1, payload=b"offline-smoke")
            frame("L", payload=b"offline receiver check\n")
            frame("F", offset=0)  # Intentionally report payload failure; skip unpacking.
        if process.wait(timeout=10) != 1:
            raise AssertionError("Expected synthetic failure marker")
        if (out / "PS5_1410_PS5UPDATE1.PUP.dec").read_bytes() != b"offline-smoke":
            raise AssertionError("Output mismatch")
        print("server-only bridge smoke test passed", out)
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)


if __name__ == "__main__":
    main()

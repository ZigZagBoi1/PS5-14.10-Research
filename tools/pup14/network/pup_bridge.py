"""One-session LAN PUP range server and decrypted-output receiver.

This binds only to the requested private IPv4 and accepts only one expected
console IP. It never writes a firmware-update path or contacts a console.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import socket
import struct
import subprocess
import time

PUP_SHA256 = "9f3a0b8811c00ab52b092d2e9f0f13dd4515f018361ff38e4be43fd8c18b21de"
PUP_SIZE = 1_418_890_240
HEADER = struct.Struct("<4sBBHQI")
MAX_FRAME = 2 * 1024 * 1024
MAX_OUTPUT = 2 * 1024 * 1024 * 1024


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(4 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def status(out: Path, stage: str, **extra: object) -> None:
    record = {"stage": stage, "updated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **extra}
    temp = out / "status.json.tmp"
    temp.write_text(json.dumps(record, indent=2), encoding="utf-8")
    os.replace(temp, out / "status.json")


def recv_exact(conn: socket.socket, count: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < count:
        part = conn.recv(min(count - len(chunks), MAX_FRAME))
        if not part:
            raise EOFError("Console connection closed during a frame")
        chunks.extend(part)
    return bytes(chunks)


def serve(conn: socket.socket, source: Path, out: Path, resume: bool = False) -> bool:
    files: dict[int, object] = {}
    written = {1: 0, 2: 0}
    last_reported = 0
    last_progress_time = time.monotonic()
    log_bytes = 0
    requests = 0
    success = False
    receipts_path = out / "block_receipts.jsonl"
    receipts = {}
    if resume and receipts_path.exists():
        for line in receipts_path.read_text(encoding="ascii").splitlines():
            item = json.loads(line)
            receipts[(item["entry"], item["offset"], item["length"])] = item["sha256"]
    with source.open("rb") as pup, (out / "PS5_1410_RESEARCH.log").open("ab") as log, receipts_path.open("a", encoding="ascii") as journal:
        try:
            while True:
                frame = recv_exact(conn, HEADER.size)
                magic, op, entry, reserved, offset, length = HEADER.unpack(frame)
                if magic != b"P14R" or reserved != 0 or length > MAX_FRAME:
                    raise ValueError("Invalid protocol header")
                requests += 1
                if op == ord("R"):
                    if entry != 0 or offset + length > PUP_SIZE:
                        conn.sendall(b"FAIL")
                        raise ValueError("PUP read outside verified source")
                    pup.seek(offset)
                    data = pup.read(length)
                    if len(data) != length:
                        conn.sendall(b"FAIL")
                        raise IOError("Short PUP source read")
                    conn.sendall(b"OKAY" + data)
                elif op == ord("B"):
                    if entry not in (1, 2) or offset or length or entry in files:
                        conn.sendall(b"FAIL")
                        raise ValueError("Unexpected output entry")
                    name = f"PS5_1410_PS5UPDATE{entry}.PUP.dec"
                    target = out / name
                    files[entry] = target.open("r+b" if resume and target.exists() else "x+b")
                    conn.sendall(b"OLD!" if resume else b"OKAY")
                    status(out, "decrypting", current_entry=entry, output_high_water=written)
                elif op == ord("Q"):
                    if entry not in files or offset + length > MAX_OUTPUT:
                        conn.sendall(b"FAIL")
                        raise ValueError("Invalid output range query")
                    key = (entry, offset, length)
                    expected_hash = receipts.get(key)
                    found = False
                    if expected_hash:
                        output = files[entry]
                        output.flush()
                        output.seek(offset)
                        found = hashlib.sha256(output.read(length)).hexdigest() == expected_hash
                    conn.sendall(b"HAVE" if found else b"MISS")
                elif op == ord("W"):
                    if entry not in files or offset + length > MAX_OUTPUT:
                        conn.sendall(b"FAIL")
                        raise ValueError("Output write outside allowed entry")
                    data = recv_exact(conn, length)
                    output = files[entry]
                    output.seek(offset)
                    output.write(data)
                    output.flush()
                    os.fsync(output.fileno())
                    record = {"entry": entry, "offset": offset, "length": length,
                              "sha256": hashlib.sha256(data).hexdigest()}
                    journal.write(json.dumps(record, separators=(",", ":")) + "\n")
                    journal.flush()
                    os.fsync(journal.fileno())
                    receipts[(entry, offset, length)] = record["sha256"]
                    written[entry] = max(written[entry], offset + length)
                    conn.sendall(b"OKAY")
                    total_written = sum(written.values())
                    now = time.monotonic()
                    if (total_written - last_reported >= 8 * 1024 * 1024 or
                            now - last_progress_time >= 10):
                        last_reported = total_written
                        last_progress_time = now
                        status(out, "decrypting", current_entry=entry,
                               output_high_water=written, requests=requests)
                elif op == ord("L"):
                    if entry or offset or log_bytes + length > 8 * 1024 * 1024:
                        conn.sendall(b"FAIL")
                        raise ValueError("Research log limit reached")
                    log.write(recv_exact(conn, length))
                    log.flush()
                    log_bytes += length
                    conn.sendall(b"OKAY")
                elif op == ord("F"):
                    if entry or length or offset not in (0, 1):
                        conn.sendall(b"FAIL")
                        raise ValueError("Invalid finish marker")
                    success = offset == 1
                    conn.sendall(b"OKAY")
                    break
                else:
                    conn.sendall(b"FAIL")
                    raise ValueError("Unknown protocol operation")
        finally:
            for output in files.values():
                output.flush()
                os.fsync(output.fileno())
                output.close()
            log.flush()
            os.fsync(log.fileno())
    status(out, "received" if success else "payload_failed", payload_success=success,
           requests=requests, output_high_water=written, log_bytes=log_bytes)
    return success


def entropy(sample: bytes) -> float:
    if not sample:
        return 0.0
    counts = [0] * 256
    for byte in sample:
        counts[byte] += 1
    return -sum((n / len(sample)) * math.log2(n / len(sample)) for n in counts if n)


def inventory(out: Path, unpacker: Path) -> bool:
    dec_files = sorted(out.glob("PS5_1410_PS5UPDATE*.PUP.dec"))
    if not dec_files or not unpacker.is_file():
        status(out, "unpack_failed", error="Missing decrypted PUP or unpacker")
        return False
    extracted = out / "extracted"
    extracted.mkdir(exist_ok=False)
    runs = []
    for dec in dec_files:
        target = extracted / dec.name.removesuffix(".PUP.dec")
        target.mkdir()
        proc = subprocess.run([str(unpacker), str(dec), str(target)],
                              capture_output=True, text=True, timeout=3600)
        runs.append({"source": dec.name, "size": dec.stat().st_size,
                     "sha256": digest(dec), "returncode": proc.returncode,
                     "stdout_tail": proc.stdout[-2000:], "stderr_tail": proc.stderr[-2000:],
                     "valid_pup": "Invalid PUP image provided." not in proc.stdout})
    files = []
    for path in sorted(extracted.rglob("*")):
        if not path.is_file():
            continue
        with path.open("rb") as f:
            head = f.read(65536)
        files.append({"path": str(path.relative_to(extracted)), "size": path.stat().st_size,
                      "sha256": digest(path), "head_hex": head[:32].hex(),
                      "head_entropy_bits_per_byte": round(entropy(head), 4),
                      "format_hint": "ELF" if head.startswith(b"\x7fELF") else
                      "possible SELF/container" if head.startswith((b"SCE\0", b"\x4f\x15\x3d\x1d")) else
                      "opaque/unknown"})
    report = {"source_pup_sha256": PUP_SHA256, "decrypted_pups": runs,
              "component_count": len(files),
              "kernel_candidates": [item for item in files if "kernel.bin" in item["path"].lower()],
              "files": files,
              "note": "A kernel.bin name does not prove plaintext kernel code or a verified 14.10 RVA."}
    (out / "extraction_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    okay = bool(files) and all(r["returncode"] == 0 and r["valid_pup"] for r in runs)
    status(out, "complete" if okay else "unpack_failed", component_count=len(files),
           kernel_candidates=len(report["kernel_candidates"]), report="extraction_report.json")
    return okay


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--source", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--bind", required=True)
    ap.add_argument("--expect-ip", required=True)
    ap.add_argument("--port", type=int, default=9028)
    ap.add_argument("--unpacker", type=Path)
    ap.add_argument("--resume", action="store_true", help="reuse a prior incomplete output directory")
    args = ap.parse_args()
    bind = ipaddress.ip_address(args.bind)
    expected = ipaddress.ip_address(args.expect_ip)
    if bind.version != 4 or expected.version != 4 or not bind.is_private or not expected.is_private:
        ap.error("Private IPv4 addresses required")
    if not 1024 <= args.port <= 65535:
        ap.error("Port out of range")
    if args.source.stat().st_size != PUP_SIZE or digest(args.source) != PUP_SHA256:
        ap.error("Official 14.10 recovery PUP hash or size mismatch")
    if args.resume:
        if not args.out.is_dir() or not (args.out / "block_receipts.jsonl").is_file():
            ap.error("Resume requires a prior output directory with block receipts")
        marker = json.loads((args.out / "receipt_source.json").read_text(encoding="ascii"))
        if marker != {"source_sha256": PUP_SHA256, "expected_console_ip": str(expected)}:
            ap.error("Resume source or console does not match the saved receipts")
    else:
        args.out.mkdir(parents=True, exist_ok=False)
        (args.out / "receipt_source.json").write_text(json.dumps({
            "source_sha256": PUP_SHA256, "expected_console_ip": str(expected)}), encoding="ascii")
    status(args.out, "starting", source_sha256=PUP_SHA256, expected_console_ip=str(expected))
    try:
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((str(bind), args.port))
            listener.listen(2)
            listener.settimeout(600)
            status(args.out, "listening", source_sha256=PUP_SHA256, expected_console_ip=str(expected))
            while True:
                conn, peer = listener.accept()
                if peer[0] != str(expected):
                    conn.close()
                    continue
                with conn:
                    conn.settimeout(300)
                    status(args.out, "connected", console_ip=peer[0])
                    success = serve(conn, args.source, args.out, args.resume)
                if not success:
                    return 1
                if args.unpacker:
                    status(args.out, "unpacking")
                    return 0 if inventory(args.out, args.unpacker) else 1
                return 0
    except Exception as exc:
        status(args.out, "failed", error=f"{type(exc).__name__}: {exc}")
        raise


if __name__ == "__main__":
    raise SystemExit(main())

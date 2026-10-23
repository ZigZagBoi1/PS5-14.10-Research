#!/usr/bin/env python3
"""Send a Lua probe to the PS5 loader and capture output.

Usage:
    python3 tools/run_probe.py <probe.lua> [--section B] [--ip 192.168.1.35] [--port 9026]
    python3 tools/run_probe.py --batch 93a:A 96a:A 89a:B 92a:D

Output is printed to stdout AND saved to results/<probe>_<section>_<timestamp>.txt
"""
import argparse
import os
import select
import socket
import struct
import sys
import time
from datetime import datetime
from pathlib import Path

MAGIC_VALUE = struct.pack('<Q', 0x13371337)
MAGIC_VALUE_LEN = len(MAGIC_VALUE)
SIGNAL_LEN = 16
MCONTEXT_LEN = 0x100

SIGNALS = {4: "SIGILL", 10: "SIGBUS", 11: "SIGSEGV"}

PROBE_DIR = Path(__file__).resolve().parent.parent / "probes" / "phase17_new_vectors"
RESULT_DIR = Path(__file__).resolve().parent.parent / "results"


def find_probe(name: str) -> Path:
    candidates = sorted(PROBE_DIR.glob(f"{name}*.lua"))
    if not candidates:
        sys.exit(f"No probe matching '{name}' in {PROBE_DIR}")
    return candidates[0]


def build_payload(probe_path: Path, section: str | None) -> bytes:
    source = probe_path.read_bytes()
    if section:
        override = f'TEST_SECTION = "{section}"\n'.encode()
        source = override + source
    return source


def send_and_capture(ip: str, port: int, payload: bytes, timeout: float = 30.0) -> str:
    output_parts: list[str] = []

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(10.0)
        sock.connect((ip, port))
        sock.sendall(struct.pack("<Q", len(payload)) + payload)

        buf = b""
        deadline = time.monotonic() + timeout
        idle_count = 0
        while time.monotonic() < deadline:
            remaining = max(0.1, deadline - time.monotonic())
            readable, _, _ = select.select([sock], [], [], min(1.0, remaining))
            if not readable:
                idle_count += 1
                if idle_count >= 3:
                    break
                continue
            idle_count = 0
            try:
                chunk = sock.recv(8192)
            except Exception:
                break
            if not chunk:
                break
            buf += chunk

        text, crashes = process_buffer(buf)
        output_parts.append(text)
        for c in crashes:
            output_parts.append(c)

    return "\n".join(output_parts)


def process_buffer(buf: bytes) -> tuple[str, list[str]]:
    text_parts: list[str] = []
    crashes: list[str] = []

    while True:
        idx = buf.find(MAGIC_VALUE)
        if idx == -1:
            text_parts.append(buf.decode("latin-1"))
            break
        needed = idx + MAGIC_VALUE_LEN + SIGNAL_LEN + MCONTEXT_LEN
        if len(buf) < needed:
            text_parts.append(buf.decode("latin-1"))
            break
        text_parts.append(buf[:idx].decode("latin-1"))
        start = idx + MAGIC_VALUE_LEN
        sig_data = buf[start:start + SIGNAL_LEN]
        mc_data = buf[start + SIGNAL_LEN:start + SIGNAL_LEN + MCONTEXT_LEN]
        crashes.append(format_crash(sig_data, mc_data))
        buf = buf[start + SIGNAL_LEN + MCONTEXT_LEN:]

    return "".join(text_parts), crashes


def format_crash(sig_data: bytes, mc_data: bytes) -> str:
    code, addr = struct.unpack("<QQ", sig_data)
    sig_name = SIGNALS.get(code, f"Signal {code}")
    lines = [f"\n*** {sig_name} at 0x{addr:016x} ***"]
    fmt = "<QQQQQQQQQQQQQQQQIHHQIHHQQQQQQ"
    names = [
        "onstack", "rdi", "rsi", "rdx", "rcx",
        "r8", "r9", "rax", "rbx", "rbp", "r10",
        "r11", "r12", "r13", "r14", "r15", "trapno",
        "fs", "gs", "addr", "flags", "es", "ds", "err",
        "rip", "cs", "rflags", "rsp", "ss",
    ]
    vals = struct.unpack(fmt, mc_data[:struct.calcsize(fmt)])
    for i in range(1, len(names), 2):
        if i + 1 < len(names):
            lines.append(f"  {names[i]:>5}: {vals[i]:016x}  {names[i+1]:>7}: {vals[i+1]:016x}")
    return "\n".join(lines)


def save_result(probe_name: str, section: str, output: str) -> Path:
    RESULT_DIR.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"{probe_name}_{section}_{ts}.txt"
    p = RESULT_DIR / fname
    p.write_text(output, encoding="utf-8")
    return p


def health_check(ip: str, port: int) -> bool:
    payload = b'print("HEALTH_OK")\n'
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5.0)
            s.connect((ip, port))
            s.sendall(struct.pack("<Q", len(payload)) + payload)
            buf = b""
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                r, _, _ = select.select([s], [], [], 1.0)
                if not r:
                    break
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
            return b"HEALTH_OK" in buf
    except Exception:
        return False


def run_one(ip: str, port: int, probe_spec: str) -> bool:
    if ":" in probe_spec:
        name, section = probe_spec.split(":", 1)
    else:
        name, section = probe_spec, "A"

    probe_path = find_probe(name)
    print(f"\n{'='*60}")
    print(f"PROBE: {probe_path.name}  SECTION: {section}")
    print(f"{'='*60}")

    payload = build_payload(probe_path, section if section != "A" else None)
    output = send_and_capture(ip, port, payload)
    print(output)

    result_path = save_result(name, section, output)
    print(f"\n[saved] {result_path}")

    crashed = "SIGBUS" in output or "SIGSEGV" in output or "SIGILL" in output
    if crashed:
        print("[!] CRASH detected — pausing 5s for loader recovery")
        time.sleep(5)
        if not health_check(ip, port):
            print("[!!] Loader NOT responding after crash — stopping batch")
            return False
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("probes", nargs="*", help="probe:section (e.g. 93a:A 96a:B)")
    ap.add_argument("--ip", default="192.168.1.35")
    ap.add_argument("--port", type=int, default=9026)
    ap.add_argument("--section", default=None, help="Override section for single probe")
    args = ap.parse_args()

    if not args.probes:
        ap.print_help()
        sys.exit(1)

    print(f"[batch] {len(args.probes)} probe(s) -> {args.ip}:{args.port}")
    print(f"[health] checking loader...")
    if not health_check(args.ip, args.port):
        sys.exit("[!!] Loader not responding — is Hamidashi Creative running?")
    print("[health] OK\n")

    for spec in args.probes:
        if args.section and ":" not in spec:
            spec = f"{spec}:{args.section}"
        ok = run_one(args.ip, args.port, spec)
        if not ok:
            print(f"\n[batch] STOPPED — loader down after {spec}")
            sys.exit(1)
        time.sleep(2)

    print(f"\n[batch] ALL {len(args.probes)} probes completed successfully")


if __name__ == "__main__":
    main()

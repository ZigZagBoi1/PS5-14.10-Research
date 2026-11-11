#!/usr/bin/env python3
"""Chunked kernel-page readability sweep.

One connection can execute only about 64 faulting children before the process stops
answering, so a whole-image sweep is split into short connections. The kernel base is a
per-boot property, so it stays valid across connections and only a reboot invalidates it.

Each chunk sends the probe with its START/STOP patched, waits for the verdict line, and
records any page that returned a value instead of the sentinel.

Usage::

    python kernel_read_sweep_chunks.py --ip 192.168.1.121 --base 0xFFFFFFFF95000000 \
        --step 0x4000 --span 0x6200000 --chunk 60
"""

import argparse
import re
import socket
import struct
import sys
import time
from pathlib import Path

PROBE = Path("probes/phase17_new_vectors/1058a_image_4k_read_sweep.lua")
VERDICT = re.compile(rb"\[R\] readable=(\d+) of (\d+)")
HIT = re.compile(rb"\[HIT\] ([0-9A-F]+) = ([0-9A-F]+)")


def run_chunk(ip, port, source, timeout):
    sock = socket.create_connection((ip, port), timeout=10)
    sock.settimeout(timeout)
    sock.sendall(struct.pack("<Q", len(source)) + source)
    buf = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            if b"=== COMPLETE ===" in buf or b"[!]" in buf:
                break
    except socket.timeout:
        pass
    finally:
        sock.close()
    return buf


def wait_ready(ip, port, tries=12, gap=5.0):
    """Wait until the loader answers a trivial script.

    A connection attempt made while the game is replacing the previous process can land on a
    process that dies during setup, which wedges the loader. Only start a chunk once a
    witness script has answered.
    """
    witness = b'print("WITNESS-OK")\n'
    for _ in range(tries):
        try:
            sock = socket.create_connection((ip, port), timeout=5)
            sock.settimeout(10)
            sock.sendall(struct.pack("<Q", len(witness)) + witness)
            if b"WITNESS-OK" in sock.recv(256):
                sock.close()
                return True
            sock.close()
        except OSError:
            pass
        time.sleep(gap)
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", required=True)
    ap.add_argument("--port", type=int, default=9026)
    ap.add_argument("--base", default="0xFFFFFFFF95000000")
    ap.add_argument("--step", default="0x4000")
    ap.add_argument("--span", default="0x6200000")
    ap.add_argument("--chunk", type=int, default=60)
    ap.add_argument("--timeout", type=float, default=60.0)
    args = ap.parse_args()

    template = PROBE.read_text(encoding="utf-8")
    span, step = int(args.span, 16), int(args.step, 16)
    total = span // step
    hits, rows, failed = [], [], 0
    i = 0
    while i < total:
        count = min(args.chunk, total - i)
        start, stop = i * step, (i + count) * step
        src = re.sub(r"local BASE  = 0x[0-9A-Fa-f]+", "local BASE  = %s" % args.base, template)
        src = re.sub(r"local START = 0x[0-9A-Fa-f]+", "local START = 0x%X" % start, src)
        src = re.sub(r"local STOP  = 0x[0-9A-Fa-f]+", "local STOP  = 0x%X" % stop, src)
        src = re.sub(r"local STEP  = 0x[0-9A-Fa-f]+", "local STEP  = 0x%X" % step, src)
        if not wait_ready(args.ip, args.port):
            print("chunk %5X..%X loader never became ready; stopping" % (start, stop), flush=True)
            break
        out = b""
        for attempt in range(3):
            try:
                out = run_chunk(args.ip, args.port, src.encode("utf-8"), args.timeout)
            except OSError as exc:
                out = b"connect failed: %s" % str(exc).encode()
            if VERDICT.search(out):
                break
            time.sleep(6)
        m = VERDICT.search(out)
        done = int(m.group(1)) if m else -1
        hits += [(int(a, 16), int(v, 16)) for a, v in HIT.findall(out)]
        rows.append((start, done, out))
        print("chunk %5X..%X readable=%d" % (start, stop, done), flush=True)
        if done < 0:
            print("  no verdict; stopping so the failure is visible", flush=True)
            tail = out[-300:].decode("utf-8", "replace")
            print("  unmeasured after 3 tries: %r" % tail.replace("\n", " | "), flush=True)
            failed += count
            m = VERDICT.search(b"")
            time.sleep(6)
            i += count
            continue
        i += count

    print("\nreadable pages: %d  unmeasured: %d" % (len(hits), failed), flush=True)
    for addr, val in hits:
        print("  %X = %X" % (addr, val), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

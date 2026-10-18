#!/usr/bin/env python3
"""
PS5 Kernel Dump Receiver

Listens on TCP port 8888, receives labeled kernel regions from the
PS5 dumper payload, and saves them to docs/dumps_13.60/.

Usage:
    python3 receiver.py [--port 8888] [--output-dir docs/dumps_13.60]
"""

import argparse
import json
import os
import socket
import struct
import sys
import time

# Region IDs (must match main.c)
REGION_DATA_GAP      = 1
REGION_DATA_EXTENDED = 2
REGION_HANDLER_FULL  = 3
REGION_PROC_SCAN     = 4
REGION_CRED_FULL     = 5
REGION_PRISON        = 6
REGION_DONE          = 0xFF

REGION_NAMES = {
    REGION_DATA_GAP:      "data_gap",
    REGION_DATA_EXTENDED: "data_extended",
    REGION_HANDLER_FULL:  "handler_full",
    REGION_PROC_SCAN:     "proc_match",
    REGION_CRED_FULL:     "ucred_full",
    REGION_PRISON:        "prison",
}

HEADER_FMT = "<IIQiI"  # region_id, sub_id, kva_start, total_size, num_chunks
HEADER_SIZE = struct.calcsize(HEADER_FMT)
CHUNK_SIZE = 0x4000


def recv_exact(sock, n):
    """Receive exactly n bytes from socket."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"Connection closed (got {len(buf)}/{n} bytes)")
        buf += chunk
    return buf


def receive_region(sock):
    """Receive one region header + data + failmap. Returns (header, data, failmap) or None if done."""
    raw_hdr = recv_exact(sock, HEADER_SIZE)
    region_id, sub_id, kva_start, total_size, num_chunks = struct.unpack(HEADER_FMT, raw_hdr)

    if region_id == REGION_DONE:
        return None

    name = REGION_NAMES.get(region_id, f"unknown_{region_id}")
    print(f"\n[RECV] Region: {name} (sub={sub_id}) @ 0x{kva_start:016x}")
    print(f"       Size: {total_size:,} bytes ({num_chunks} chunks)")

    # Receive data
    data = recv_exact(sock, total_size)
    print(f"       Data received: {len(data):,} bytes")

    # Receive failmap
    failmap = recv_exact(sock, num_chunks)
    failed = sum(failmap)
    print(f"       Failed chunks: {failed}/{num_chunks}")

    return {
        "region_id": region_id,
        "sub_id": sub_id,
        "kva_start": kva_start,
        "total_size": total_size,
        "num_chunks": num_chunks,
        "data": data,
        "failmap": failmap,
        "name": name,
    }


def save_region(region, output_dir):
    """Save a region's data and failmap to disk."""
    name = region["name"]
    sub_id = region["sub_id"]

    if region["region_id"] == REGION_HANDLER_FULL:
        filename = f"handler_full_{sub_id}"
    elif region["region_id"] == REGION_PROC_SCAN:
        filename = f"proc_match_{sub_id}"
    else:
        filename = name

    bin_path = os.path.join(output_dir, f"{filename}.bin")
    failmap_path = os.path.join(output_dir, f"{filename}.bin.failmap")

    with open(bin_path, "wb") as f:
        f.write(region["data"])

    with open(failmap_path, "wb") as f:
        f.write(region["failmap"])

    print(f"       Saved: {bin_path} ({len(region['data']):,} bytes)")
    return {
        "file": f"{filename}.bin",
        "kva_start": f"0x{region['kva_start']:016x}",
        "size": region["total_size"],
        "failed_chunks": sum(region["failmap"]),
        "total_chunks": region["num_chunks"],
    }


def main():
    parser = argparse.ArgumentParser(description="PS5 Kernel Dump Receiver")
    parser.add_argument("--port", type=int, default=8888)
    parser.add_argument("--output-dir", default="docs/dumps_13.60")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    print(f"Listening on 0.0.0.0:{args.port}")
    print(f"Output dir: {args.output_dir}")
    print("Waiting for PS5 connection...")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", args.port))
    srv.listen(1)

    conn, addr = srv.accept()
    print(f"\nConnected from {addr[0]}:{addr[1]}")
    start_time = time.time()

    manifest = {
        "firmware": "13.60",
        "kernel_base": "0xffffffff8a9c0000",
        "chunk_size": CHUNK_SIZE,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "regions": [],
    }

    total_bytes = 0
    region_count = 0

    try:
        while True:
            region = receive_region(conn)
            if region is None:
                print("\n[DONE] All regions received.")
                break

            entry = save_region(region, args.output_dir)
            manifest["regions"].append(entry)
            total_bytes += region["total_size"]
            region_count += 1

    except ConnectionError as e:
        print(f"\n[ERROR] {e}")
    except KeyboardInterrupt:
        print("\n[INTERRUPTED]")
    finally:
        elapsed = time.time() - start_time
        print(f"\nSummary:")
        print(f"  Regions:    {region_count}")
        print(f"  Total data: {total_bytes:,} bytes ({total_bytes/1024/1024:.1f} MB)")
        print(f"  Time:       {elapsed:.1f}s")

        manifest_path = os.path.join(args.output_dir, "final_dump_manifest.json")
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)
        print(f"  Manifest:   {manifest_path}")

        conn.close()
        srv.close()


if __name__ == "__main__":
    main()

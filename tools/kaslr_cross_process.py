#!/usr/bin/env python3
"""KASLR cross-process test.

Sends the 400e fingerprint probe twice — once before and once after a game
relaunch — and compares kernel-derived values to determine if KASLR exists.

Usage:
    python3 tools/kaslr_cross_process.py --ip 192.168.1.35

The script:
  1. Sends 400e, parses fingerprint values
  2. Waits for the loader to go away (game kill)
  3. Polls until the loader comes back (game relaunch)
  4. Sends 400e again, parses again
  5. Compares and prints verdict
"""

import argparse
import re
import socket
import struct
import sys
import time
from pathlib import Path

PROBE_PATH = Path(__file__).resolve().parent.parent / "probes" / "phase21_next_vectors" / "400e_kaslr_stability.lua"
RESULT_DIR = Path(__file__).resolve().parent.parent / "results" / "phase21_next_vectors"

PORT = 9026
IDLE_TIMEOUT = 30.0


def send_probe(ip: str) -> str:
    src = PROBE_PATH.read_text(encoding="utf-8")
    payload = src.encode("utf-8")
    header = struct.pack("<Q", len(payload))

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10.0)
    sock.connect((ip, PORT))
    sock.sendall(header + payload)
    sock.shutdown(socket.SHUT_WR)

    chunks = []
    sock.settimeout(IDLE_TIMEOUT)
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
        except socket.timeout:
            break
    sock.close()
    return b"".join(chunks).decode("utf-8", errors="replace")


def parse_fingerprint(output: str) -> dict:
    fp = {}
    m = re.search(r"pid=(\d+)", output)
    fp["pid"] = int(m.group(1)) if m else -1

    m = re.search(r"EBOOT_BASE=([0-9A-Fa-f_]+)", output)
    fp["eboot_base"] = m.group(1) if m else "?"

    m = re.search(r"SYS624_VMCOUNT=(-?\d+)", output)
    fp["sys624"] = int(m.group(1)) if m else -1

    m = re.search(r"SUB36=([0-9A-Fa-f_]+)", output)
    fp["sub36"] = m.group(1) if m else "?"

    m = re.search(r"SUB43=([0-9A-Fa-f_]+)", output)
    fp["sub43"] = m.group(1) if m else "?"

    m = re.search(r"FN_ADDR=(0x[0-9a-fA-F]+)", output)
    fp["fn_addr"] = m.group(1) if m else "?"

    m = re.search(r"ROP_CHAIN=(0x[0-9a-fA-F]+)", output)
    fp["rop_chain"] = m.group(1) if m else "?"

    m = re.search(r"LIBKERNEL_BASE=([0-9A-Fa-f_]+)", output)
    fp["libkernel_base"] = m.group(1) if m else "?"

    modules = re.findall(r"h=(\d+) base=([0-9A-Fa-f_]+)", output)
    fp["modules"] = {int(h): base for h, base in modules}

    kinfo = re.findall(r"\+([0-9A-Fa-f]+)\s+(\w+)\s+=\s+([0-9A-Fa-f]+)", output)
    fp["kinfo"] = {name: val for _, name, val in kinfo}

    return fp


def check_loader(ip: str) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect((ip, PORT))
        s.close()
        return True
    except (socket.error, OSError):
        return False


def wait_loader_down(ip: str, timeout: float = 120.0):
    print("\n⏳ Waiting for loader to go down (kill the game)...")
    print("   (or press Ctrl+C and relaunch manually, then re-run this script)")
    start = time.time()
    while time.time() - start < timeout:
        if not check_loader(ip):
            print("   ✓ Loader is down.")
            return True
        time.sleep(2.0)
    print("   ⚠ Timeout — loader never went down. Kill the game manually.")
    return False


def wait_loader_up(ip: str, timeout: float = 300.0):
    print("\n⏳ Waiting for loader to come back (relaunch the game)...")
    start = time.time()
    while time.time() - start < timeout:
        if check_loader(ip):
            print("   ✓ Loader is back!")
            time.sleep(2.0)  # let it stabilize
            return True
        time.sleep(3.0)
    print("   ✗ Timeout — loader never came back.")
    return False


def save_result(output: str, run_label: str):
    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    path = RESULT_DIR / f"400e_kaslr_cross_{run_label}_{ts}.txt"
    path.write_text(output, encoding="utf-8")
    print(f"   Saved: {path}")


def compare(fp1: dict, fp2: dict):
    print("\n" + "=" * 60)
    print("  KASLR CROSS-PROCESS COMPARISON")
    print("=" * 60)

    print(f"\n  PID:       run1={fp1['pid']}  run2={fp2['pid']}")
    same_pid = fp1["pid"] == fp2["pid"]
    if same_pid:
        print("  ⚠ SAME PID — this is the SAME process, test is INVALID")
        print("  The game was not relaunched between runs.")
        return

    print(f"  ✓ Different PIDs — valid cross-process comparison\n")

    fields = [
        ("EBOOT_BASE", "eboot_base", "userland", True),
        ("FN_ADDR", "fn_addr", "userland", True),
        ("ROP_CHAIN", "rop_chain", "userland", True),
        ("SUB36", "sub36", "kernel-derived?", False),
        ("SUB43", "sub43", "kernel-derived?", False),
        ("SYS624_VMCOUNT", "sys624", "kernel VM counter", None),
        ("LIBKERNEL_BASE", "libkernel_base", "userland", True),
    ]

    kernel_same = []
    userland_differ = []

    for label, key, category, expect_differ in fields:
        v1 = fp1.get(key, "?")
        v2 = fp2.get(key, "?")
        same = (v1 == v2)
        mark = "=" if same else "≠"

        print(f"  {label:20s}  {str(v1):>20s} {mark} {str(v2):<20s}  ({category})")

        if expect_differ is True:
            if same:
                print(f"    ⚠ Expected DIFFERENT (userland ASLR)")
            else:
                userland_differ.append(label)
        elif expect_differ is False:
            if same:
                kernel_same.append(label)

    # Module comparison
    print("\n  -- Module bases --")
    all_handles = sorted(set(list(fp1.get("modules", {}).keys()) + list(fp2.get("modules", {}).keys())))
    for h in all_handles:
        v1 = fp1.get("modules", {}).get(h, "—")
        v2 = fp2.get("modules", {}).get(h, "—")
        same = (v1 == v2)
        mark = "=" if same else "≠"
        print(f"    h={h}: {v1} {mark} {v2}")

    # kinfo_proc comparison
    print("\n  -- kinfo_proc --")
    all_keys = sorted(set(list(fp1.get("kinfo", {}).keys()) + list(fp2.get("kinfo", {}).keys())))
    for k in all_keys:
        v1 = fp1.get("kinfo", {}).get(k, "—")
        v2 = fp2.get("kinfo", {}).get(k, "—")
        same = (v1 == v2)
        mark = "=" if same else "≠"
        note = ""
        if k == "pid":
            note = " (expected ≠)"
        elif k == "runtime_lo" or k == "runtime_hi":
            note = " (may vary)"
        print(f"    {k:16s}: {v1} {mark} {v2}{note}")

    # Verdict
    print("\n" + "=" * 60)
    if userland_differ and kernel_same:
        print("  ★ VERDICT: NO KERNEL KASLR")
        print(f"    Userland changed ({', '.join(userland_differ)})")
        print(f"    Kernel-derived SAME ({', '.join(kernel_same)})")
        print("    → Kernel base is FIXED per firmware build")
    elif not userland_differ:
        print("  ⚠ VERDICT: INCONCLUSIVE")
        print("    Userland addresses didn't change — something is wrong")
        print("    (same game instance? loader reuse?)")
    elif not kernel_same:
        print("  ★ VERDICT: KERNEL KASLR LIKELY PRESENT")
        print("    Both userland AND kernel-derived values changed")
        print("    → Need side channel for kernel base")
    else:
        print("  ⚠ VERDICT: MIXED — needs manual review")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="KASLR cross-process test")
    parser.add_argument("--ip", default="192.168.1.35", help="PS5 IP")
    parser.add_argument("--port", type=int, default=9026)
    parser.add_argument("--skip-wait", action="store_true",
                        help="Don't wait for kill/relaunch — just run twice with a pause")
    args = parser.parse_args()
    global PORT
    PORT = args.port

    print("=" * 60)
    print("  KASLR CROSS-PROCESS TEST")
    print("  PS5: %s:%d" % (args.ip, PORT))
    print("=" * 60)

    # Run 1
    print("\n[RUN 1] Sending 400e fingerprint probe...")
    try:
        out1 = send_probe(args.ip)
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        sys.exit(1)

    fp1 = parse_fingerprint(out1)
    save_result(out1, "run1")
    print(f"  PID={fp1['pid']}  EBOOT={fp1['eboot_base']}  SUB36={fp1['sub36']}")

    if args.skip_wait:
        print("\n--- Pausing 5s (--skip-wait mode) ---")
        time.sleep(5.0)
    else:
        # Wait for game to die and come back
        print("\n" + "-" * 60)
        print("  NOW: kill the game on the PS5, then relaunch it.")
        print("  The script will detect when the loader comes back.")
        print("-" * 60)

        wait_loader_down(args.ip)
        if not wait_loader_up(args.ip):
            print("Aborting — relaunch the game and re-run this script.")
            sys.exit(1)

    # Run 2
    print("\n[RUN 2] Sending 400e fingerprint probe...")
    try:
        out2 = send_probe(args.ip)
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        sys.exit(1)

    fp2 = parse_fingerprint(out2)
    save_result(out2, "run2")
    print(f"  PID={fp2['pid']}  EBOOT={fp2['eboot_base']}  SUB36={fp2['sub36']}")

    # Compare
    compare(fp1, fp2)


if __name__ == "__main__":
    main()

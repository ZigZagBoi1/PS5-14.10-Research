#!/usr/bin/env python3
"""Minimal UDP DNS responder that redirects ps5.np.playstation.net and
manuals.playstation.net to a chosen IP, forwarding everything else to
a real upstream (default 8.8.8.8).

Usage:
    python dns_hijack.py --ip 10.0.0.231 [--port 53] [--upstream 8.8.8.8]
"""

import argparse
import socket
import struct
import threading

HIJACK_DOMAINS = {
    b"ps5.np.playstation.net",
    b"manuals.playstation.net",
}


def parse_name(data, offset):
    labels = []
    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            ptr = struct.unpack("!H", data[offset:offset+2])[0] & 0x3FFF
            labels.extend(parse_name(data, ptr)[0])
            offset += 2
            return labels, offset
        offset += 1
        labels.append(data[offset:offset+length])
        offset += length
    return labels, offset


def build_response(query, hijack_ip_bytes):
    if len(query) < 12:
        return None

    txid = query[:2]
    flags = struct.unpack("!H", query[2:4])[0]
    qdcount = struct.unpack("!H", query[4:6])[0]

    labels, qend = parse_name(query, 12)
    if qend + 4 > len(query):
        return None

    qtype = struct.unpack("!H", query[qend:qend+2])[0]
    qclass = struct.unpack("!H", query[qend+2:qend+4])[0]

    domain = b".".join(labels).lower()

    if domain in HIJACK_DOMAINS and qtype == 1 and qclass == 1:
        resp = bytearray()
        resp += txid
        resp += struct.pack("!H", 0x8180)  # QR=1, AA=1, RD=1, RA=1
        resp += struct.pack("!H", 1)       # QDCOUNT
        resp += struct.pack("!H", 1)       # ANCOUNT
        resp += struct.pack("!H", 0)       # NSCOUNT
        resp += struct.pack("!H", 0)       # ARCOUNT
        resp += query[12:qend+4]           # question section
        # answer: pointer to question name
        resp += struct.pack("!H", 0xC00C)  # name pointer
        resp += struct.pack("!H", 1)       # TYPE A
        resp += struct.pack("!H", 1)       # CLASS IN
        resp += struct.pack("!I", 60)      # TTL
        resp += struct.pack("!H", 4)       # RDLENGTH
        resp += hijack_ip_bytes
        return bytes(resp)

    return None


def forward_query(query, upstream, timeout=2.0):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(query, (upstream, 53))
        resp, _ = sock.recvfrom(4096)
        sock.close()
        return resp
    except Exception:
        return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", required=True, help="IP to return for hijacked domains")
    parser.add_argument("--port", type=int, default=53)
    parser.add_argument("--upstream", default="8.8.8.8")
    args = parser.parse_args()

    ip_bytes = socket.inet_aton(args.ip)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", args.port))
    print(f"DNS hijack running on :{args.port}")
    print(f"Hijacking: {', '.join(d.decode() for d in HIJACK_DOMAINS)} -> {args.ip}")
    print(f"Upstream: {args.upstream}")

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            resp = build_response(data, ip_bytes)
            if resp:
                labels, _ = parse_name(data, 12)
                domain = b".".join(labels).decode()
                print(f"[HIJACK] {addr[0]} -> {domain} -> {args.ip}")
                sock.sendto(resp, addr)
            else:
                # Forward to upstream
                upstream_resp = forward_query(data, args.upstream)
                if upstream_resp:
                    sock.sendto(upstream_resp, addr)
        except Exception as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    main()

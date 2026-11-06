#!/usr/bin/env python3
"""Minimal DNS spoofer for PS5 WebKit probe delivery.

Spoofs manuals.playstation.net (and optionally other PlayStation domains)
to point to this PC's IP. Forwards all other queries to a real upstream DNS.

Usage (run as admin for port 53):
    python dns_spoof.py
    python dns_spoof.py --ip 192.168.1.100
    python dns_spoof.py --ip 192.168.1.100 --upstream 1.1.1.1
"""

import argparse
import datetime
import socket
import socketserver
import struct
import sys
import threading

SPOOF_DOMAINS = {
    b'manuals.playstation.net',
    b'ps5.np.playstation.net',
}


class DNSHandler(socketserver.BaseRequestHandler):
    spoof_ip = '127.0.0.1'
    upstream = '8.8.8.8'
    query_count = 0
    lock = threading.Lock()

    def handle(self):
        data, sock = self.request
        try:
            resp = self._process(data)
            if resp:
                sock.sendto(resp, self.client_address)
        except Exception as e:
            ts = datetime.datetime.now().strftime('%H:%M:%S')
            print(f'[{ts}] DNS error: {e}')

    def _process(self, data):
        if len(data) < 12:
            return None

        txid = data[:2]
        qdcount = struct.unpack('!H', data[4:6])[0]
        if qdcount < 1:
            return None

        # Parse question section
        offset = 12
        labels = []
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            offset += 1
            labels.append(data[offset:offset + length])
            offset += length

        if offset + 4 > len(data):
            return None

        qtype = struct.unpack('!H', data[offset:offset + 2])[0]
        qclass = struct.unpack('!H', data[offset + 2:offset + 4])[0]
        qname = b'.'.join(labels).lower()
        question = data[12:offset + 4]

        with self.lock:
            self.__class__.query_count += 1
            count = self.__class__.query_count

        ts = datetime.datetime.now().strftime('%H:%M:%S')

        if qtype == 1 and qclass == 1 and qname in SPOOF_DOMAINS:
            # Spoof A record
            ip_bytes = socket.inet_aton(self.spoof_ip)
            print(f'[{ts}] #{count} SPOOF {self.client_address[0]}: '
                  f'{qname.decode()} -> {self.spoof_ip}')
            resp_flags = 0x8580  # QR=1, AA=1, RA=1
            header = txid + struct.pack('!HHHHH', resp_flags, 1, 1, 0, 0)
            answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + ip_bytes
            return header + question + answer
        else:
            # Forward to upstream
            print(f'[{ts}] #{count} FWD   {self.client_address[0]}: '
                  f'{qname.decode()} (type={qtype})')
            try:
                fwd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                fwd.settimeout(3)
                fwd.sendto(data, (self.upstream, 53))
                resp, _ = fwd.recvfrom(4096)
                fwd.close()
                return resp
            except Exception:
                # NXDOMAIN
                resp_flags = 0x8583
                header = txid + struct.pack('!HHHHH', resp_flags, 1, 0, 0, 0)
                return header + question


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'


def main():
    parser = argparse.ArgumentParser(description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--ip', help='IP to spoof to (default: auto-detect)')
    parser.add_argument('--host', default='0.0.0.0', help='Listen address')
    parser.add_argument('--port', type=int, default=53, help='Listen port')
    parser.add_argument('--upstream', default='8.8.8.8', help='Upstream DNS')
    args = parser.parse_args()

    spoof_ip = args.ip or get_local_ip()
    DNSHandler.spoof_ip = spoof_ip
    DNSHandler.upstream = args.upstream

    try:
        server = socketserver.UDPServer((args.host, args.port), DNSHandler)
    except PermissionError:
        print('ERROR: Port 53 requires admin/root privileges.', file=sys.stderr)
        print('Run as: sudo python dns_spoof.py', file=sys.stderr)
        print('Or on Windows: Run terminal as Administrator', file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        if 'already in use' in str(e).lower() or e.errno == 10048:
            print(f'ERROR: Port {args.port} already in use.', file=sys.stderr)
            print('Stop any other DNS server first.', file=sys.stderr)
        else:
            print(f'ERROR: {e}', file=sys.stderr)
        sys.exit(1)

    server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    print('=' * 50)
    print('  PS5 DNS Spoofer')
    print('=' * 50)
    print(f'  Listening: {args.host}:{args.port}')
    print(f'  Spoofing:  manuals.playstation.net -> {spoof_ip}')
    print(f'  Upstream:  {args.upstream}')
    print()
    print(f'  Set PS5 DNS to: {spoof_ip}')
    print(f'  Then open User Guide from any game')
    print('=' * 50)
    print('Ctrl+C to stop\n')

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f'\nStopped. {DNSHandler.query_count} queries handled.')


if __name__ == '__main__':
    main()

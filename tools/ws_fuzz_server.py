#!/usr/bin/env python3
"""Adversarial WebSocket server for the 14.10 guide.

Purpose: exercise WebCore's WebSocket frame parser and its permessage-deflate
path with malformed input. One connection = one case; cases cycle so a page that
reconnects in a loop walks the whole matrix without any coordination.

Handshake deliberately negotiates permessage-deflate so the deflate cases are
reachable. Every case is logged with its index so a crash can be attributed.

  python tools/ws_fuzz_server.py --port 8443 --cert ug_cert.pem --key ug_key.pem

Page side: new WebSocket('wss://manuals.playstation.net:8443/ws')
"""
import argparse
import base64
import hashlib
import logging
import socket
import ssl
import struct
import sys
import threading
import time

from ws_cases import GUID, case_list, deflate_raw, frame  # noqa: E402  (same directory)

def recv_until(sock, marker, limit=65536):
    buf = b""
    while marker not in buf and len(buf) < limit:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf


def handle(conn, addr, case_index, cases, log):
    name, payload, note = cases[case_index]
    try:
        conn.settimeout(10.0)
        req = recv_until(conn, b"\r\n\r\n")
        headers = {}
        for line in req.split(b"\r\n")[1:]:
            if b":" in line:
                k, v = line.split(b":", 1)
                headers[k.strip().lower()] = v.strip()
        key = headers.get(b"sec-websocket-key", b"")
        accept = base64.b64encode(hashlib.sha1(key + GUID.encode()).digest())
        ext = headers.get(b"sec-websocket-extensions", b"")
        negotiate = b"permessage-deflate" in ext
        resp = [
            b"HTTP/1.1 101 Switching Protocols",
            b"Upgrade: websocket",
            b"Connection: Upgrade",
            b"Sec-WebSocket-Accept: " + accept,
        ]
        if negotiate:
            resp.append(b"Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover")
        msg = b"\r\n".join(resp) + b"\r\n\r\n"
        conn.sendall(msg)
        log(f"WS-CASE {case_index} {name} deflate={int(negotiate)} {note}")
        # let the client finish its handshake bookkeeping before the payload
        time.sleep(0.05)
        conn.sendall(payload)
        time.sleep(0.25)
        try:
            conn.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        time.sleep(0.05)
    except Exception as exc:  # noqa: BLE001
        log(f"WS-ERR {case_index} {name} {type(exc).__name__} {exc}")
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--cert", default="ug_cert.pem")
    ap.add_argument("--key", default="ug_key.pem")
    ap.add_argument("--log", default="results/webkit/ws_fuzz.log")
    ap.add_argument("--once", action="store_true", help="stop after one full pass over the cases")
    args = ap.parse_args()

    lock = threading.Lock()
    counter = {"case": 0, "conns": 0}
    cases = case_list()

    def log(line):
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
        with lock:
            with open(args.log, "a", encoding="utf-8") as fh:
                fh.write(f"{stamp} {line}\n")
        print(line, flush=True)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(args.cert, args.key)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", args.port))
    srv.listen(16)
    log(f"WS-FUZZ listening on {args.port} with {len(cases)} cases")
    while True:
        raw, addr = srv.accept()
        with lock:
            idx = counter["case"] % len(cases)
            counter["case"] += 1
            counter["conns"] += 1
            done = counter["case"]
        try:
            conn = ctx.wrap_socket(raw, server_side=True)
        except ssl.SSLError as exc:
            log(f"WS-TLS-FAIL {type(exc).__name__} {exc}")
            raw.close()
            continue
        threading.Thread(target=handle, args=(conn, addr, idx, cases, log), daemon=True).start()
        if args.once and done >= len(cases):
            log("WS-FUZZ full pass done")
            time.sleep(1)
            break


if __name__ == "__main__":
    sys.exit(main())

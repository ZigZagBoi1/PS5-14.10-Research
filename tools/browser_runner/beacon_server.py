#!/usr/bin/env python3
"""Tiny beacon logger for PS5 WebKit probes.

Runs on the server (10.0.0.80) behind nginx. Captures beacon GET/POST
requests and writes them to a JSONL log file. Nginx proxies /beacon to
this on port 8082.

Usage:
    python3 beacon_server.py [--port 8082] [--log beacon_live.jsonl]
"""

import argparse
import json
import os
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs


class BeaconHandler(BaseHTTPRequestHandler):
    log_path = "beacon_live.jsonl"
    _lock = threading.Lock()

    def do_GET(self):
        parts = urlsplit(self.path)
        qs = parse_qs(parts.query)
        msg = qs.get("m", [""])[0]
        ts = datetime.now(timezone.utc).isoformat()
        ip = self.client_address[0]

        entry = {"ts": ts, "ip": ip, "msg": msg, "path": parts.path}

        with self._lock:
            with open(self.log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
                f.flush()

        # Print to stdout for live monitoring
        print(f"[{ts}] {ip}: {msg}", flush=True)

        # Return 1x1 transparent GIF
        self.send_response(200)
        self.send_header("Content-Type", "image/gif")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", "43")
        self.end_headers()
        self.wfile.write(
            b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff"
            b"\x00\x00\x00!\xf9\x04\x00\x00\x00\x00\x00,"
            b"\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
        )

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress default access log


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8082)
    ap.add_argument("--log", default="beacon_live.jsonl")
    args = ap.parse_args()

    BeaconHandler.log_path = args.log
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), BeaconHandler)
    print(f"Beacon logger on :{args.port}, writing to {args.log}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()

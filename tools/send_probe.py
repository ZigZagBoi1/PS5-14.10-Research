#!/usr/bin/env python3
"""Send one Lua recon probe to the PS5 Lua loader.

The sender deliberately performs one connection per invocation. It never
retries a probe automatically: a reset or timeout must be correlated with the
console/watchdog before another run is attempted.
"""

import argparse
import hashlib
import json
import os
import socket
import struct
import sys
import time
from datetime import datetime


STATUS_COMPLETE = "COMPLETE"
STATUS_IDLE_TIMEOUT = "IDLE_TIMEOUT"
STATUS_TOTAL_TIMEOUT = "TOTAL_TIMEOUT"
STATUS_CONNECTION_RESET = "CONNECTION_RESET"
STATUS_CONNECTION_CLOSED = "CONNECTION_CLOSED"
STATUS_CONNECTION_REFUSED = "CONNECTION_REFUSED"
STATUS_CONNECT_TIMEOUT = "CONNECT_TIMEOUT"
STATUS_ERROR = "ERROR"

STRICT_FAILURES = {
    STATUS_IDLE_TIMEOUT,
    STATUS_TOTAL_TIMEOUT,
    STATUS_CONNECTION_RESET,
    STATUS_CONNECTION_CLOSED,
    STATUS_CONNECTION_REFUSED,
    STATUS_CONNECT_TIMEOUT,
    STATUS_ERROR,
}


def _timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _iso_timestamp():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _save_capture(lua_file, response, metadata):
    """Save both the raw response and a machine-readable run record."""
    os.makedirs("results", exist_ok=True)
    probe_name = os.path.splitext(os.path.basename(lua_file))[0]
    stamp = _timestamp()
    out_path = os.path.join("results", "%s_%s.txt" % (probe_name, stamp))
    meta_path = os.path.join("results", "%s_%s.json" % (probe_name, stamp))

    # Keep zero-byte captures: a reset with no output is still evidence.
    with open(out_path, "wb") as f:
        f.write(response)
    metadata["output_path"] = out_path
    metadata["metadata_path"] = meta_path
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, sort_keys=True)
        f.write("\n")
    return out_path, meta_path


def send_lua(ip, port, lua_file, save=False, timeout=30.0, total_timeout=0.0):
    """Send a probe and return a status string.

    ``timeout`` is an idle read timeout, matching the old sender behavior.
    ``total_timeout`` is optional and bounds the whole response phase. No
    retry is performed because a fresh process/ASLR state is created per
    connection and retrying a failed redirect can hide the failure mode.
    """
    with open(lua_file, "r", encoding="utf-8") as f:
        payload = f.read()
    encoded = payload.encode("utf-8")
    started = time.monotonic()
    metadata = {
        "probe": os.path.abspath(lua_file),
        "probe_bytes": len(encoded),
        "probe_sha256": hashlib.sha256(encoded).hexdigest(),
        "remote": "%s:%d" % (ip, port),
        "started_at": _iso_timestamp(),
        "idle_timeout_seconds": timeout,
        "total_timeout_seconds": total_timeout if total_timeout > 0 else None,
    }
    response_parts = []
    status = STATUS_ERROR
    error = None

    print("[*] Connecting to %s:%d..." % (ip, port))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((ip, port))
        print("[*] Connected, sending %d bytes..." % len(encoded))
        # Protocol: 8-byte LE uint64 length prefix, then raw Lua source.
        sock.sendall(struct.pack("<Q", len(encoded)) + encoded)
        print("[*] Waiting for response...")

        deadline = started + total_timeout if total_timeout > 0 else None
        while True:
            try:
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        status = STATUS_TOTAL_TIMEOUT
                        break
                    sock.settimeout(min(timeout, remaining))
                chunk = sock.recv(4096)
                if not chunk:
                    # A clean close with no probe output is different from a
                    # normal completed probe; it commonly means the target
                    # process exited before printing anything.
                    status = (STATUS_COMPLETE if response_parts else
                              STATUS_CONNECTION_CLOSED)
                    break
                response_parts.append(chunk)
                sys.stdout.write(chunk.decode("utf-8", errors="replace"))
                sys.stdout.flush()
            except socket.timeout:
                status = (STATUS_TOTAL_TIMEOUT if deadline is not None and
                          time.monotonic() >= deadline else STATUS_IDLE_TIMEOUT)
                print("\n[*] %s waiting for more data" % status)
                break
    except ConnectionRefusedError as exc:
        status = STATUS_CONNECTION_REFUSED
        error = repr(exc)
        print("[!] Connection refused — is the game running with the Lua loader?")
    except socket.timeout as exc:
        status = STATUS_CONNECT_TIMEOUT
        error = repr(exc)
        print("[!] Connection timed out")
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as exc:
        status = STATUS_CONNECTION_RESET
        error = repr(exc)
        print("[!] Connection reset/aborted by the loader")
    except OSError as exc:
        status = STATUS_ERROR
        error = repr(exc)
        print("[!] Socket error: %s" % exc)
    finally:
        sock.close()

    response = b"".join(response_parts)
    elapsed = time.monotonic() - started
    metadata.update({
        "ended_at": _iso_timestamp(),
        "elapsed_seconds": round(elapsed, 3),
        "status": status,
        "response_bytes": len(response),
    })
    if error:
        metadata["error"] = error

    print("\n[*] Received %d bytes total" % len(response))
    if save:
        out_path, meta_path = _save_capture(lua_file, response, metadata)
        print("[*] Saved to %s" % out_path)
        print("[*] Run record: %s" % meta_path)
    print("[*] Status: %s (%.3fs)" % (status, elapsed))
    return status


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send one Lua probe to PS5")
    parser.add_argument("probe", help="Probe file to send")
    parser.add_argument("--ip", default="10.0.0.96", help="PS5 IP (default: 10.0.0.96)")
    parser.add_argument("--port", type=int, default=9026, help="Lua loader port (default: 9026)")
    parser.add_argument("--save", action="store_true", help="Save response and JSON run record")
    parser.add_argument("--timeout", type=float, default=30.0,
                        help="Idle read timeout in seconds (default: 30)")
    parser.add_argument("--total-timeout", type=float, default=0.0,
                        help="Optional wall-clock limit; 0 disables it")
    parser.add_argument("--strict", action="store_true",
                        help="Exit nonzero unless the loader closes cleanly")
    args = parser.parse_args()

    result = send_lua(args.ip, args.port, args.probe, args.save,
                      args.timeout, args.total_timeout)
    if args.strict and result in STRICT_FAILURES:
        sys.exit(1)

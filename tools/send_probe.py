#!/usr/bin/env python3
"""Send one Lua recon probe to the PS5 Lua loader.

Usage::

    python send_probe.py <probe_file.lua> [--ip 10.0.0.96] [--port 9026] [--save]

The sender performs one connection per invocation and never retries a probe.
When saving a probe below this checkout's ``probes/`` directory, its phase
subdirectories are mirrored below ``results/``. ``--metadata`` adds a JSON
sidecar with the transport status and probe hash.
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
from pathlib import Path


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


def _results_dir(lua_file):
    """Return results/ with the probe's in-tree phase path mirrored."""
    out_dir = Path("results")
    probes_root = Path(__file__).resolve().parent.parent / "probes"
    try:
        rel_dir = Path(lua_file).resolve().relative_to(probes_root).parent
    except ValueError:
        rel_dir = Path(".")
    if rel_dir != Path("."):
        out_dir = out_dir / rel_dir
    return out_dir


def _save_capture(lua_file, response, metadata, write_metadata=False):
    """Save raw response and, optionally, its JSON run record."""
    out_dir = _results_dir(lua_file)
    out_dir.mkdir(parents=True, exist_ok=True)
    probe_name = Path(lua_file).stem
    stamp = _timestamp()
    out_path = out_dir / ("%s_%s.txt" % (probe_name, stamp))
    meta_path = out_dir / ("%s_%s.json" % (probe_name, stamp))

    # Preserve the established behavior: --save alone writes only non-empty
    # response captures. --metadata also records silent/reset runs.
    if response or write_metadata:
        with open(out_path, "wb") as f:
            f.write(response)
        metadata["output_path"] = str(out_path)
        print("[*] Saved to %s" % out_path)
    if write_metadata:
        metadata["metadata_path"] = str(meta_path)
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2, sort_keys=True)
            f.write("\n")
        print("[*] Run record: %s" % meta_path)
    return out_path, meta_path


def _send_raw(ip, port, payload_bytes, timeout=30.0, total_timeout=0.0,
              label="probe"):
    """Send raw Lua bytes over one TCP connection.  Returns (status, response_bytes)."""
    started = time.monotonic()
    response_parts = []
    status = STATUS_ERROR

    print("[*] [%s] Connecting to %s:%d..." % (label, ip, port))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        print("[*] [%s] Connected, sending %d bytes..." % (label, len(payload_bytes)))
        sock.sendall(struct.pack("<Q", len(payload_bytes)) + payload_bytes)
        print("[*] [%s] Waiting for response..." % label)

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
                    status = (STATUS_COMPLETE if response_parts else
                              STATUS_CONNECTION_CLOSED)
                    break
                response_parts.append(chunk)
                sys.stdout.write(chunk.decode("utf-8", errors="replace"))
                sys.stdout.flush()
            except socket.timeout:
                status = (STATUS_TOTAL_TIMEOUT if deadline is not None and
                          time.monotonic() >= deadline else STATUS_IDLE_TIMEOUT)
                print("\n[*] [%s] %s waiting for more data" % (label, status))
                break
    except ConnectionRefusedError:
        status = STATUS_CONNECTION_REFUSED
        print("[!] [%s] Connection refused" % label)
    except socket.timeout:
        status = STATUS_CONNECT_TIMEOUT
        print("[!] [%s] Connection timed out" % label)
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
        status = STATUS_CONNECTION_RESET
        print("[!] [%s] Connection reset/aborted" % label)
    except OSError as exc:
        status = STATUS_ERROR
        print("[!] [%s] Socket error: %s" % (label, exc))
    finally:
        sock.close()

    response = b"".join(response_parts)
    elapsed = time.monotonic() - started
    print("[*] [%s] %d bytes in %.3fs — %s" % (label, len(response), elapsed, status))
    return status, response


_BOOTSTRAP_DEFAULT = os.path.join(
    os.path.dirname(__file__), os.pardir,
    "probes", "phase15_jailbreak", "bootstrap_hardened_loader.lua")


def send_bootstrap(ip, port, bootstrap_file=None, timeout=15.0):
    """Send the hardened-loader bootstrap and return True on success."""
    path = bootstrap_file or _BOOTSTRAP_DEFAULT
    path = os.path.normpath(path)
    if not os.path.isfile(path):
        print("[!] Bootstrap file not found: %s" % path)
        return False
    with open(path, "r", encoding="utf-8") as f:
        payload = f.read().encode("utf-8")
    status, response = _send_raw(ip, port, payload, timeout=timeout,
                                 total_timeout=30.0, label="bootstrap")
    text = response.decode("utf-8", errors="replace")
    if "BOOTSTRAP COMPLETE" in text:
        print("[+] Bootstrap applied — loader hardened for this session")
        return True
    if status in (STATUS_CONNECTION_REFUSED, STATUS_CONNECT_TIMEOUT):
        return False
    print("[*] Bootstrap sent (status: %s) — proceeding with probe" % status)
    return True


def send_lua(ip, port, lua_file, save=False, timeout=30.0, total_timeout=0.0,
             write_metadata=False):
    """Send a probe once and return a transport status string."""
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
                    # A silent close is different from a completed response.
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
        _save_capture(lua_file, response, metadata, write_metadata)
    print("[*] Status: %s (%.3fs)" % (status, elapsed))
    return status


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send one Lua probe to PS5")
    parser.add_argument("probe", help="Probe file to send")
    parser.add_argument("--ip", default="10.0.0.96", help="PS5 IP (default: 10.0.0.96)")
    parser.add_argument("--port", type=int, default=9026, help="Lua loader port (default: 9026)")
    parser.add_argument("--save", action="store_true",
                        help="Save non-empty output under results/")
    parser.add_argument("--metadata", action="store_true",
                        help="With --save, write a JSON run record and save empty captures")
    parser.add_argument("--timeout", type=float, default=30.0,
                        help="Idle read timeout in seconds (default: 30)")
    parser.add_argument("--total-timeout", type=float, default=0.0,
                        help="Optional wall-clock limit; 0 disables it")
    parser.add_argument("--strict", action="store_true",
                        help="Exit nonzero unless the loader returns a response and closes")
    parser.add_argument("--bootstrap", action="store_true",
                        help="Auto-send the hardened loader bootstrap before the probe")
    parser.add_argument("--bootstrap-file", default=None,
                        help="Custom bootstrap Lua file (default: bootstrap_hardened_loader.lua)")
    args = parser.parse_args()

    if args.bootstrap:
        if not send_bootstrap(args.ip, args.port, args.bootstrap_file):
            print("[!] Bootstrap failed — aborting probe")
            sys.exit(1)
        time.sleep(0.5)

    result = send_lua(args.ip, args.port, args.probe, args.save,
                      args.timeout, args.total_timeout, args.metadata)
    if args.strict and result in STRICT_FAILURES:
        sys.exit(1)

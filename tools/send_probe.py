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
import re
import socket
import stat
import struct
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path


STATUS_COMPLETE = "COMPLETE"
STATUS_INCOMPLETE = "INCOMPLETE"
STATUS_IDLE_TIMEOUT = "IDLE_TIMEOUT"
STATUS_TOTAL_TIMEOUT = "TOTAL_TIMEOUT"
STATUS_CONNECTION_RESET = "CONNECTION_RESET"
STATUS_CONNECTION_CLOSED = "CONNECTION_CLOSED"
STATUS_CONNECTION_REFUSED = "CONNECTION_REFUSED"
STATUS_CONNECT_TIMEOUT = "CONNECT_TIMEOUT"
STATUS_ERROR = "ERROR"

STRICT_FAILURES = {
    STATUS_INCOMPLETE,
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


def _ensure_capture_dir(out_dir):
    """Create an output directory without accepting symlinked components."""
    current = Path(".")
    for part in out_dir.parts:
        current /= part
        try:
            mode = os.lstat(current).st_mode
        except FileNotFoundError:
            # The parent was already checked above, so creating one component
            # at a time cannot descend through an existing symlink.
            current.mkdir()
            mode = os.lstat(current).st_mode
        if stat.S_ISLNK(mode):
            raise OSError("refusing symlinked capture directory: %s" % current)
        if not stat.S_ISDIR(mode):
            raise NotADirectoryError("capture path is not a directory: %s" % current)


def _write_new_file(path, content):
    """Publish complete bytes at a new path without replacing an existing file."""
    fd, temporary_path = tempfile.mkstemp(prefix=".capture-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        # link() is an atomic no-replace publication.  In particular, an
        # existing file or symlink raises FileExistsError instead of following
        # or replacing it.
        os.link(temporary_path, path)
    finally:
        try:
            os.unlink(temporary_path)
        except FileNotFoundError:
            pass


def _record_cleanup_note(primary_exc, note):
    """Retain a secondary cleanup failure without replacing its primary error."""
    add_note = getattr(primary_exc, "add_note", None)
    if callable(add_note):
        try:
            add_note(note)
            return
        except Exception:
            pass
    try:
        notes = getattr(primary_exc, "__notes__", None)
        if notes is None:
            notes = []
            setattr(primary_exc, "__notes__", notes)
        notes.append(note)
        return
    except Exception:
        pass
    try:
        notes = getattr(primary_exc, "_capture_cleanup_notes", None)
        if notes is None:
            notes = []
            setattr(primary_exc, "_capture_cleanup_notes", notes)
        notes.append(note)
        return
    except Exception:
        # Do not let a diagnostic failure replace the original persistence
        # error; make the lost cleanup detail observable on old runtimes.
        print("[!] %s" % note, file=sys.stderr)


def _capture_paths(out_dir, probe_name, stamp, write_metadata):
    """Pick legacy root names unless either member of a pair already exists."""
    basename = "%s_%s" % (probe_name, stamp)
    legacy_txt = out_dir / (basename + ".txt")
    legacy_json = out_dir / (basename + ".json")
    has_collision = os.path.lexists(legacy_txt) or os.path.lexists(legacy_json)
    if has_collision:
        out_dir = Path(tempfile.mkdtemp(prefix=basename + "_", dir=str(out_dir)))
    return out_dir / legacy_txt.name, (out_dir / legacy_json.name if write_metadata else None)


def _save_capture(lua_file, response, metadata, write_metadata=False):
    """Save a raw response and, optionally, its matching JSON run record.

    A timestamp collision is kept in an exclusive child run directory so the
    leaf filenames remain recognizable to existing recursive evidence tools.
    """
    # Preserve the established behavior: --save alone writes only non-empty
    # response captures. --metadata also records silent/reset runs.
    if not response and not write_metadata:
        return None, None

    out_dir = _results_dir(lua_file)
    _ensure_capture_dir(out_dir)
    probe_name = Path(lua_file).stem
    stamp = _timestamp()
    out_path, meta_path = _capture_paths(out_dir, probe_name, stamp, write_metadata)
    collision_dir = out_path.parent if out_path.parent != out_dir else None

    record = None
    metadata_bytes = None
    if write_metadata:
        record = dict(metadata)
        record["output_path"] = str(out_path)
        record["metadata_path"] = str(meta_path)
        try:
            metadata_bytes = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode("utf-8")
        except Exception as exc:
            if collision_dir is not None:
                try:
                    collision_dir.rmdir()
                except OSError as cleanup_exc:
                    _record_cleanup_note(
                        exc, "collision directory cleanup failed: %r" % cleanup_exc
                    )
            raise

    # Both leaves are derived from the same selected directory.  Prepare JSON
    # before publishing either file so malformed metadata cannot leave a lone
    # response capture behind.
    _write_new_file(out_path, response)
    raw_stat = os.lstat(out_path)
    if write_metadata:
        try:
            _write_new_file(meta_path, metadata_bytes)
        except OSError as exc:
            cleanup_notes = []
            try:
                current_stat = os.lstat(out_path)
                if (current_stat.st_dev, current_stat.st_ino) == (
                        raw_stat.st_dev, raw_stat.st_ino):
                    os.unlink(out_path)
            except FileNotFoundError:
                pass
            except OSError as cleanup_exc:
                cleanup_notes.append("raw capture cleanup failed: %r" % cleanup_exc)
            if collision_dir is not None:
                try:
                    collision_dir.rmdir()
                except OSError as cleanup_exc:
                    cleanup_notes.append("collision directory cleanup failed: %r" % cleanup_exc)
            for note in cleanup_notes:
                _record_cleanup_note(exc, note)
            raise
        metadata.update(record)

    print("[*] Saved to %s" % out_path)
    if write_metadata:
        print("[*] Run record: %s" % meta_path)
    return out_path, meta_path


def send_lua(ip, port, lua_file, save=False, timeout=30.0, total_timeout=0.0,
             write_metadata=False):
    """Send a probe once and return a transport status string."""
    with open(lua_file, "r", encoding="utf-8") as f:
        payload = f.read()
    markers = re.findall(r"=== PROBE [^\n\"']+ COMPLETE ===", payload)
    expected_marker = markers[-1].encode("utf-8") if markers else None
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
                display = chunk.decode("utf-8", errors="replace")
                # Keep receiving and saving raw bytes if the Windows console
                # cannot represent a character in its active code page.
                encoding = sys.stdout.encoding or "utf-8"
                sys.stdout.write(display.encode(encoding, errors="replace").decode(encoding))
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
    if status == STATUS_COMPLETE and expected_marker and expected_marker not in response:
        status = STATUS_INCOMPLETE
    elapsed = time.monotonic() - started
    metadata.update({
        "ended_at": _iso_timestamp(),
        "elapsed_seconds": round(elapsed, 3),
        "status": status,
        "response_bytes": len(response),
    })
    if expected_marker:
        metadata["expected_completion_marker"] = expected_marker.decode("utf-8")
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
    args = parser.parse_args()

    result = send_lua(args.ip, args.port, args.probe, args.save,
                      args.timeout, args.total_timeout, args.metadata)
    if args.strict and result in STRICT_FAILURES:
        sys.exit(1)

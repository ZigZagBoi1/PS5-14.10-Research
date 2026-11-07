"""Hardware-free beacon decoding and flush-before-success JSONL storage.

This module opens no network connection and never writes to stdout.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import threading
from typing import BinaryIO
from urllib.parse import unquote_to_bytes, urlsplit
import uuid

SCHEMA = "browser-beacon-capture"
VERSION = 1
MAX_BODY_BYTES = 64 * 1024
MAX_TARGET_BYTES = 16 * 1024
MAX_QUERY_FIELDS = 128
MAX_RECORD_BYTES = 1024 * 1024


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def valid_timestamp(value) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.utcoffset() is not None and parsed.utcoffset().total_seconds() == 0
    except ValueError:
        return False


@dataclass(frozen=True)
class DecodedRequest:
    status: str
    reason: str | None
    method: str
    raw_target: str
    body: bytes
    declared_length: int | None
    query: tuple[tuple[str, str | None], ...] = ()
    format: str | None = None
    tag: str | None = None
    measurement: str | None = None

    def record(self) -> dict:
        """JSON-compatible accepted request, retaining the original bytes."""
        if self.status != "accepted":
            raise ValueError("only accepted requests have event records")
        return {
            "method": self.method,
            "raw_target": self.raw_target,
            "query": [list(pair) for pair in self.query],
            "format": self.format,
            "tag": self.tag,
            "measurement": self.measurement,
            "measurement_utf8_length": (
                len(self.measurement.encode("utf-8")) if self.measurement is not None else None
            ),
            "body_base64": base64.b64encode(self.body).decode("ascii"),
            "body_length": len(self.body),
            "body_sha256": hashlib.sha256(self.body).hexdigest(),
            "declared_length": self.declared_length,
            "client_reported": {
                key: [value for name, value in self.query if name == key]
                for key in ("session", "n") if any(name == key for name, _ in self.query)
            },
        }


def _decode(value: str, *, query=False) -> str:
    if re.search(r"%(?![0-9a-fA-F]{2})", value):
        raise ValueError("invalid percent encoding")
    if query:
        value = value.replace("+", " ")
    return unquote_to_bytes(value).decode("utf-8", errors="strict")


def decode_request(method: str, raw_target: str, body: bytes = b"",
                   *, declared_length: int | None = None) -> DecodedRequest:
    """Decode an origin-form target and fully supplied body, without reading I/O.

    POST requires the caller's declared length. Header parsing, duplicate header
    detection, transfer encoding, stream timeouts and reads belong to the adapter.
    """
    if not isinstance(method, str) or not isinstance(raw_target, str) or type(body) is not bytes:
        raise TypeError("method/target must be strings and body must be bytes")
    query: tuple[tuple[str, str | None], ...] = ()

    def result(status, reason=None, format=None, tag=None, measurement=None):
        return DecodedRequest(status, reason, method, raw_target, body, declared_length,
                              query, format, tag, measurement)

    if method not in ("GET", "POST"):
        return result("rejected", "unsupported method")
    if len(body) > MAX_BODY_BYTES:
        return result("rejected", "body too large")
    if declared_length is not None:
        if type(declared_length) is not int or declared_length < 0:
            return result("rejected", "invalid declared length")
        if declared_length > MAX_BODY_BYTES:
            return result("rejected", "declared body too large")
        if declared_length != len(body):
            return result("rejected", "body length mismatch")
    if method == "POST" and declared_length is None:
        return result("rejected", "POST requires declared length")
    if method == "GET" and body:
        return result("rejected", "GET body unsupported")
    if (not raw_target.startswith("/") or raw_target.startswith("//")
            or "#" in raw_target or len(raw_target) > MAX_TARGET_BYTES
            or any(ord(c) <= 32 or ord(c) >= 127 for c in raw_target)):
        return result("rejected", "invalid or oversized ASCII origin-form target")
    parsed = urlsplit(raw_target)
    path = parsed.path
    if path not in ("/beacon", "/beacon.php") and not path.startswith("/beacon/"):
        return result("rejected", "unknown capture route")
    try:
        fields = parsed.query.split("&") if parsed.query else []
        if len(fields) > MAX_QUERY_FIELDS:
            return result("rejected", "too many query fields")
        pairs = []
        for field in fields:
            name, separator, value = field.partition("=")
            pairs.append((_decode(name, query=True),
                          _decode(value, query=True) if separator else None))
        query = tuple(pairs)
        tag = _decode(path[len("/beacon/"):]) if path.startswith("/beacon/") else None
    except (ValueError, UnicodeError):
        return result("rejected", "invalid URL encoding")

    values = {key: [value for name, value in query if name == key]
              for key in ("m", "d", "tag")}
    if any(len(v) > 1 for v in values.values()):
        return result("ambiguous", "duplicate measurement parameter")
    if any(v and v[0] is None for v in values.values()):
        return result("rejected", "measurement parameter has no equals/value")

    if path == "/beacon.php":
        if not values["tag"] or not values["tag"][0]:
            return result("rejected", "PHP alias requires a nonempty query tag")
        tag = values["tag"][0]
    elif values["tag"]:
        return result("ambiguous", "query tag conflicts with route")
    if tag == "":
        return result("rejected", "empty path message/tag")

    if values["m"]:
        if tag is not None or values["d"] or body:
            return result("ambiguous", "multiple measurement sources")
        return result("accepted", format="legacy_m", measurement=values["m"][0])
    if values["d"]:
        if tag is None:
            return result("rejected", "d requires a tag")
        if body:
            return result("ambiguous", "query data and POST body")
        return result("accepted", format="tagged_d", tag=tag, measurement=values["d"][0])
    if method == "POST" and body:
        try:
            message = body.decode("utf-8", errors="strict")
        except UnicodeError:
            message = None  # accepted binary body, never replacement-decoded
        return result("accepted", format="post_body", tag=tag, measurement=message)
    if tag is not None:
        return result("accepted", format="path_message", tag=tag, measurement=tag)
    if method == "POST":
        return result("accepted", format="post_body", measurement="")
    return result("rejected", "missing message")


class CaptureError(OSError):
    """The writer cannot report successful persistence; file may contain a prefix."""


def local_provenance() -> dict:
    """Hash local file bytes at capture creation; not proof of executed code."""
    directory = Path(__file__).resolve().parent
    return {
        name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
        for name in ("capture.py", "verify_capture.py", "serve.py") if (directory / name).is_file()
    }


class CaptureWriter:
    """One writer per sink; serializes acceptance order, fails closed on any I/O error."""

    @classmethod
    def create(cls, directory: Path, *, started_at: str | None = None,
               provenance: dict | None = None) -> "CaptureWriter":
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        capture_id = str(uuid.uuid4())
        path = directory / ("capture-" + capture_id + ".jsonl")
        sink = path.open("xb")  # never append to or overwrite another capture
        try:
            writer = cls(sink, capture_id=capture_id, started_at=started_at,
                         provenance=provenance, owns_sink=True)
        except BaseException:
            try:
                sink.close()  # leave partial evidence; never remove it
            except BaseException:
                pass  # preserve the opening/serialization error
            raise
        writer.path = path
        return writer

    def __init__(self, sink: BinaryIO, *, capture_id: str | None = None,
                 started_at: str | None = None, provenance: dict | None = None,
                 owns_sink: bool = False):
        if sink is None:
            raise CaptureError("missing capture sink")
        if provenance is not None and type(provenance) is not dict:
            raise TypeError("caller provenance must be a JSON object")
        self.capture_id = capture_id or str(uuid.uuid4())
        if str(uuid.UUID(self.capture_id)) != self.capture_id:
            raise ValueError("capture id must be a canonical UUID")
        started_at = started_at or timestamp()
        if not valid_timestamp(started_at):
            raise ValueError("started_at must be an ISO UTC timestamp")
        self._sink = sink
        self._owns_sink = owns_sink
        self._lock = threading.Lock()
        self._failed = False
        self._closed = False
        self._count = 0
        self.path: Path | None = None
        self._emit({
            "record_type": "open", "schema": SCHEMA, "version": VERSION,
            "capture_id": self.capture_id, "started_at": started_at,
            "limits": {"body_bytes": MAX_BODY_BYTES, "target_bytes": MAX_TARGET_BYTES},
            "durability": "flush-only",
            "provenance": {"local_files_sha256": local_provenance(),
                           "caller_reported": provenance or {}},
        })

    def _emit(self, record: dict):
        data = (json.dumps(record, ensure_ascii=True, allow_nan=False,
                           sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        if len(data) > MAX_RECORD_BYTES:
            raise CaptureError("serialized record too large")
        try:
            if self._sink.write(data) != len(data):
                raise CaptureError("short capture write")
            self._sink.flush()
        except Exception as exc:
            self._failed = True  # no further records may hide the failed boundary
            raise CaptureError("capture persistence failed") from exc

    def _ready(self):
        if self._failed or self._closed:
            raise CaptureError("capture is failed or closed")

    def append(self, request: DecodedRequest) -> int:
        # Do not trust caller-mutated/hand-built interpretations.
        if (not isinstance(request, DecodedRequest) or request.status != "accepted"
                or request != decode_request(request.method, request.raw_target, request.body,
                                             declared_length=request.declared_length)):
            raise ValueError("append requires a canonical accepted request")
        record = request.record()
        with self._lock:
            self._ready()
            sequence = self._count + 1
            self._emit({"record_type": "event", "capture_id": self.capture_id,
                        "sequence": sequence, "received_at": timestamp(), "request": record})
            self._count = sequence
            return sequence  # returned only after full write and successful flush

    def close(self):
        with self._lock:
            error = None
            try:
                self._ready()
                self._emit({"record_type": "close", "capture_id": self.capture_id,
                            "accepted_count": self._count, "closed_at": timestamp()})
                self._closed = True
            except BaseException as exc:
                error = exc
                raise
            finally:
                if self._owns_sink:
                    try:
                        self._sink.close()
                    except BaseException as exc:
                        self._failed = True
                        if error is None:
                            if isinstance(exc, Exception):
                                raise CaptureError("capture sink close failed") from exc
                            raise

    def abort(self):
        """Release an owned sink without pretending that a run closed cleanly."""
        with self._lock:
            self._failed = True
            if self._owns_sink:
                self._sink.close()

    def __enter__(self):
        return self

    def __exit__(self, kind, value, traceback):
        if kind is None:
            self.close()
        else:
            try:
                self.abort()
            except BaseException:
                pass  # preserve the caller's original exception

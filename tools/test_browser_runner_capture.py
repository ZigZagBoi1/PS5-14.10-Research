"""Deterministic capture tests: no listener, network, probe or HTTP handler."""
import base64
import concurrent.futures
import contextlib
from dataclasses import replace
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

from tools.browser_runner.capture import (
    CaptureError, CaptureWriter, MAX_BODY_BYTES, decode_request,
)
from tools.browser_runner.verify_capture import verify_capture, main as verify_main


class DecodeTests(unittest.TestCase):
    def test_exact_tagged_d(self):
        r = decode_request("GET", "/beacon/P560-B-POST?d=1%2C2%2C3%2C4")
        self.assertEqual((r.status, r.tag, r.measurement),
                         ("accepted", "P560-B-POST", "1,2,3,4"))
        self.assertEqual(r.query, (("d", "1,2,3,4"),))
        self.assertEqual(r.record()["measurement_utf8_length"], 7)

    def test_legacy_m(self):
        r = decode_request("GET", "/beacon?m=hello+world")
        self.assertEqual((r.status, r.measurement), ("accepted", "hello world"))

    def test_path_message(self):
        r = decode_request("GET", "/beacon/hello%20world%2Fdone?t=123")
        self.assertEqual(r.measurement, "hello world/done")
        self.assertEqual(r.query, (("t", "123"),))

    def test_post_raw_bytes(self):
        body = b"\x00\xff\r\n\\n"
        r = decode_request("POST", "/beacon/TAG", body, declared_length=6)
        self.assertEqual(r.status, "accepted")
        self.assertIsNone(r.measurement)
        self.assertEqual(r.body, b"\x00\xff\r\n\\n")
        self.assertEqual(r.record()["body_base64"], "AP8NClxu")

    def test_post_utf8(self):
        r = decode_request("POST", "/beacon/TAG", b"caf\xc3\xa9", declared_length=5)
        self.assertEqual(r.measurement, "caf\u00e9")
        self.assertEqual(r.record()["measurement_utf8_length"], 5)

    def test_unicode_and_separators(self):
        r = decode_request("GET", "/beacon/TAG?d=caf%C3%A9%0A%5Cn%2B%2F")
        self.assertEqual(r.measurement, "caf\u00e9\n\\n+/")

    def test_ordered_unknown_empty_bare_repeated(self):
        r = decode_request("GET", "/beacon?m=&flag&flag=&x=1&x=2&session=s&n=7")
        self.assertEqual(r.status, "accepted")
        self.assertEqual(r.measurement, "")
        self.assertEqual(r.query, (("m", ""), ("flag", None), ("flag", ""),
                                   ("x", "1"), ("x", "2"), ("session", "s"), ("n", "7")))
        self.assertEqual(r.record()["client_reported"], {"session": ["s"], "n": ["7"]})

    def test_missing_versus_empty(self):
        for target, expected in [("/beacon", "rejected"), ("/beacon?m", "rejected"),
                                 ("/beacon?m=", "accepted"), ("/beacon/T?d=", "accepted")]:
            with self.subTest(target=target):
                self.assertEqual(decode_request("GET", target).status, expected)

    def test_duplicates_are_ambiguous(self):
        for target in ["/beacon?m=a&m=b", "/beacon/T?d=&d=b",
                       "/beacon?m=a&%6d=b", "/beacon.php?tag=a&tag=b"]:
            with self.subTest(target=target):
                r = decode_request("GET", target)
                self.assertEqual(r.status, "ambiguous")
                self.assertIsNone(r.measurement)
                self.assertEqual(len(r.query), 2)

    def test_competing_sources(self):
        for target, method, body in [
            ("/beacon/T?m=x", "GET", b""),
            ("/beacon/T?d=x", "POST", b"body"),
            ("/beacon?m=x", "POST", b"body"),
            ("/beacon/T?tag=x", "GET", b""),
        ]:
            with self.subTest(target=target):
                self.assertEqual(decode_request(method, target, body,
                                                declared_length=len(body)).status, "ambiguous")

    def test_invalid_url_encoding_is_rejected_without_replacement(self):
        for target in ["/beacon/%FF", "/beacon/T?d=%FF", "/beacon?m=%", "/beacon?m=%ZZ"]:
            with self.subTest(target=target):
                r = decode_request("GET", target)
                self.assertEqual(r.status, "rejected")
                self.assertEqual(r.raw_target, target)
                self.assertIsNone(r.measurement)

    def test_decode_exactly_once_and_path_plus(self):
        r = decode_request("GET", "/beacon/a+b%252F?d=%252F+%2B")
        self.assertEqual((r.tag, r.measurement), ("a+b%2F", "%2F +"))

    def test_invalid_routes_targets_methods(self):
        for target in ["/beaconish", "/beacon/", "//beacon/T", "/beacon/T#fragment",
                       "/beacon/T\n", "/beacon/\u00e9", "https://host/beacon"]:
            with self.subTest(target=target):
                self.assertEqual(decode_request("GET", target).status, "rejected")
        self.assertEqual(decode_request("PUT", "/beacon").status, "rejected")

    def test_php_alias_policy(self):
        for method in ["GET", "POST"]:
            r = decode_request(method, "/beacon.php?tag=P573-BOOT",
                               declared_length=0 if method == "POST" else None)
            self.assertEqual((r.status, r.measurement), ("accepted", "P573-BOOT"))
        r = decode_request("POST", "/beacon.php?tag=TAG", b"body", declared_length=4)
        self.assertEqual((r.tag, r.measurement), ("TAG", "body"))
        self.assertEqual(decode_request("GET", "/beacon.php?m=x").status, "rejected")

    def test_post_query_compatibility_explicit(self):
        r = decode_request("POST", "/beacon?m=query", declared_length=0)
        self.assertEqual(r.measurement, "query")

    def test_exact_limit_and_over_limit(self):
        body = b"\xff" * MAX_BODY_BYTES
        self.assertEqual(decode_request("POST", "/beacon/T", body,
                                       declared_length=MAX_BODY_BYTES).body, body)
        self.assertEqual(decode_request("POST", "/beacon/T", body + b"x",
                                       declared_length=MAX_BODY_BYTES + 1).status, "rejected")

    def test_incomplete_and_extra_input(self):
        for length in [2, 4]:
            self.assertEqual(decode_request("POST", "/beacon/T", b"abc",
                                           declared_length=length).reason, "body length mismatch")

    def test_invalid_missing_length_and_get_body(self):
        for length in [None, -1, "3", True]:
            with self.subTest(length=length):
                self.assertEqual(decode_request("POST", "/beacon/T", b"abc",
                                               declared_length=length).status, "rejected")
        self.assertEqual(decode_request("GET", "/beacon/T", b"x").status, "rejected")

    def test_target_and_query_bounds(self):
        self.assertEqual(decode_request("GET", "/beacon/" + "x"*16384).status, "rejected")
        self.assertEqual(decode_request("GET", "/beacon/T?" + "&".join(["x=1"]*129)).status,
                         "rejected")


class FaultSink(io.BytesIO):
    def __init__(self, fault, at=2):
        super().__init__()
        self.fault, self.at, self.writes, self.flushes = fault, at, 0, 0

    def write(self, data):
        self.writes += 1
        if self.writes == self.at:
            if self.fault == "short":
                super().write(data[:5])
                return 5
            if self.fault == "write":
                raise OSError("injected write error")
        return super().write(data)

    def flush(self):
        self.flushes += 1
        if self.fault == "flush" and self.flushes == self.at:
            raise OSError("injected flush error")
        return super().flush()


class WriterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="beacon-capture-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_records_independently_parse_and_payload_round_trip(self):
        body = b"\x00\xff\r\n\\n"
        with CaptureWriter.create(self.root) as writer:
            self.assertEqual(writer.append(decode_request(
                "POST", "/beacon/T", body, declared_length=6)), 1)
        # json/base64 are independent oracles, not the capture decoder/verifier.
        records = [json.loads(line) for line in writer.path.read_bytes().splitlines()]
        self.assertEqual([r["record_type"] for r in records], ["open", "event", "close"])
        event = records[1]["request"]
        self.assertEqual(base64.b64decode(event["body_base64"], validate=True), b"\x00\xff\r\n\\n")
        self.assertEqual(event["body_length"], 6)
        self.assertEqual(event["body_sha256"], hashlib.sha256(b"\x00\xff\r\n\\n").hexdigest())
        self.assertEqual(event["raw_target"], "/beacon/T")
        self.assertEqual(records[2]["accepted_count"], 1)
        self.assertIn("capture.py", records[0]["provenance"]["local_files_sha256"])

    def test_tagged_d_serialization_literal_values(self):
        sink = io.BytesIO()
        writer = CaptureWriter(sink)
        writer.append(decode_request("GET", "/beacon/P560-B-POST?d=1%2C2%2C3%2C4"))
        writer.close()
        event = json.loads(sink.getvalue().splitlines()[1])["request"]
        self.assertEqual(event["tag"], "P560-B-POST")
        self.assertEqual(event["measurement"], "1,2,3,4")
        self.assertEqual(event["query"], [["d", "1,2,3,4"]])

    def test_format_matrix_survives_independent_json_and_byte_readback(self):
        fixtures = [
            ("GET", "/beacon?m=hello+world", b"", "hello world"),
            ("GET", "/beacon/a%2Fb", b"", "a/b"),
            ("GET", "/beacon/T?d=", b"", ""),
            ("GET", "/beacon.php?tag=P573-BOOT", b"", "P573-BOOT"),
            ("POST", "/beacon/T", b"a\x00\xff", None),
            ("POST", "/beacon/T", b"caf\xc3\xa9", "caf\u00e9"),
        ]
        with CaptureWriter.create(self.root) as writer:
            for method, target, body, expected in fixtures:
                writer.append(decode_request(method, target, body,
                              declared_length=len(body) if method == "POST" else None))
        events = [json.loads(l)["request"] for l in writer.path.read_bytes().splitlines()[1:-1]]
        for event, (method, target, body, expected) in zip(events, fixtures):
            self.assertEqual((event["method"], event["raw_target"]), (method, target))
            self.assertEqual(event["measurement"], expected)
            self.assertEqual(base64.b64decode(event["body_base64"], validate=True), body)
            self.assertEqual(event["body_length"], len(body))

    def test_unicode_separators_and_literal_backslashes_are_reversible(self):
        sink = io.BytesIO()
        writer = CaptureWriter(sink)
        writer.append(decode_request("GET", "/beacon/T?d=%0D%0A%0B%0C%C2%85%E2%80%A8%E2%80%A9%5Cn"))
        writer.close()
        lines = sink.getvalue().splitlines()
        self.assertEqual(len(lines), 3)
        self.assertEqual(json.loads(lines[1])["request"]["measurement"], "\r\n\v\f\x85\u2028\u2029\\n")

    def test_at_limit_all_byte_values_round_trip(self):
        body = bytes(range(256))*256
        with CaptureWriter.create(self.root) as writer:
            writer.append(decode_request("POST", "/beacon/T", body, declared_length=65536))
        event = json.loads(writer.path.read_bytes().splitlines()[1])["request"]
        self.assertEqual(base64.b64decode(event["body_base64"]), bytes(range(256))*256)
        self.assertEqual(verify_capture(writer.path)["capture_integrity"], "VALID")

    def test_short_write_is_failure_and_poisoned(self):
        self._failure("short")

    def test_write_exception_is_failure_and_poisoned(self):
        self._failure("write")

    def test_flush_exception_is_failure_and_poisoned(self):
        self._failure("flush")

    def _failure(self, kind):
        sink = FaultSink(kind)
        writer = CaptureWriter(sink)
        request = decode_request("GET", "/beacon?m=literal")
        with self.assertRaises(CaptureError):
            writer.append(request)
        with self.assertRaises(CaptureError):
            writer.append(request)
        with self.assertRaises(CaptureError):
            writer.close()
        self.assertNotIn(b'"record_type":"close"', sink.getvalue())

    def test_opening_write_failure(self):
        with self.assertRaises(CaptureError):
            CaptureWriter(FaultSink("write", at=1))

    def test_close_flush_failure_reported(self):
        writer = CaptureWriter(FaultSink("flush", at=2))
        with self.assertRaises(CaptureError):
            writer.close()

    def test_missing_sink(self):
        with self.assertRaises(CaptureError):
            CaptureWriter(None)

    def test_non_object_provenance_is_rejected_before_success(self):
        with self.assertRaises(TypeError):
            CaptureWriter(io.BytesIO(), provenance=["not an object"])

    def test_first_close_write_error_survives_sink_close_failure(self):
        class BrokenClose(FaultSink):
            def close(self):
                raise OSError("later close error")
        sink = BrokenClose("write", at=2)
        writer = CaptureWriter(sink, owns_sink=True)
        with self.assertRaises(CaptureError) as caught:
            writer.close()
        self.assertEqual(str(caught.exception), "capture persistence failed")

    def test_open_error_survives_sink_close_failure(self):
        class BrokenClose(FaultSink):
            def close(self):
                raise OSError("later close error")
        sink = BrokenClose("write", at=1)
        with mock.patch.object(Path, "open", return_value=sink), mock.patch(
            "tools.browser_runner.capture.local_provenance", return_value={}
        ):
            with self.assertRaises(CaptureError) as caught:
                CaptureWriter.create(self.root)
        self.assertEqual(str(caught.exception), "capture persistence failed")

    def test_caller_error_survives_abort_close_failure(self):
        class BrokenClose(io.BytesIO):
            def close(self):
                raise OSError("later close error")
        first = RuntimeError("caller error")
        with self.assertRaises(RuntimeError) as caught:
            with CaptureWriter(BrokenClose(), owns_sink=True):
                raise first
        self.assertIs(caught.exception, first)

    def test_no_stdout_dependency(self):
        class Broken:
            def write(self, value):
                raise BrokenPipeError("closed stdout")
            def flush(self):
                pass
        with contextlib.redirect_stdout(Broken()):
            with CaptureWriter.create(self.root) as writer:
                writer.append(decode_request("GET", "/beacon?m=ok"))
        self.assertEqual(verify_capture(writer.path)["capture_integrity"], "VALID")

    def test_rejected_ambiguous_and_forged_requests_not_recorded(self):
        sink = io.BytesIO()
        writer = CaptureWriter(sink)
        for request in [decode_request("GET", "/beacon"), decode_request("GET", "/beacon?m=a&m=b"),
                        replace(decode_request("GET", "/beacon?m=real"), measurement="fake")]:
            with self.assertRaises(ValueError):
                writer.append(request)
        writer.close()
        self.assertEqual(json.loads(sink.getvalue().splitlines()[-1])["accepted_count"], 0)

    def test_duplicate_arrivals_not_removed(self):
        with CaptureWriter.create(self.root) as writer:
            request = decode_request("GET", "/beacon?m=same&session=s&n=1")
            writer.append(request)
            writer.append(request)
        report = verify_capture(writer.path)
        self.assertEqual(report["accepted_records_verified"], 2)
        self.assertEqual(report["client_reported"]["s"]["duplicates"], {"1": 2})

    def test_two_simultaneous_captures_same_timestamp_and_threads(self):
        start = threading.Barrier(2)
        def run(label):
            start.wait(timeout=5)
            with CaptureWriter.create(self.root, started_at="2026-11-07T00:00:00Z") as writer:
                for i in range(8):
                    writer.append(decode_request("GET", "/beacon?m="+label+str(i)))
            return writer.path
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            paths = list(pool.map(run, ["a", "b"]))
        self.assertNotEqual(paths[0], paths[1])
        for path, label in zip(paths, ["a", "b"]):
            self.assertEqual(verify_capture(path)["accepted_records_verified"], 8)
            events = [json.loads(l) for l in path.read_bytes().splitlines()][1:-1]
            self.assertEqual([e["request"]["measurement"] for e in events],
                             [label+str(i) for i in range(8)])

    def test_exclusive_creation_collision_never_overwrites(self):
        fixed = "12345678-1234-4234-8234-123456789abc"
        with mock.patch("tools.browser_runner.capture.uuid.uuid4", return_value=fixed):
            writer = CaptureWriter.create(self.root)
            before = writer.path.read_bytes()
            with self.assertRaises(FileExistsError):
                CaptureWriter.create(self.root)
            self.assertEqual(writer.path.read_bytes(), before)
            writer.close()

    def test_multiple_threads_single_writer(self):
        with CaptureWriter.create(self.root) as writer:
            start = threading.Barrier(4)
            def append(i):
                if i < 4:
                    start.wait(timeout=5)
                return writer.append(decode_request("GET", "/beacon?m="+str(i)))
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                sequences = list(pool.map(append, range(48)))
        records = [json.loads(l) for l in writer.path.read_bytes().splitlines()]
        self.assertEqual(sorted(sequences), list(range(1,49)))
        self.assertEqual([r["sequence"] for r in records[1:-1]], list(range(1,49)))
        self.assertEqual({r["request"]["measurement"] for r in records[1:-1]},
                         {str(i) for i in range(48)})
        self.assertEqual(verify_capture(writer.path)["capture_integrity"], "VALID")

    def test_context_exception_leaves_unclosed_capture(self):
        with self.assertRaises(RuntimeError):
            with CaptureWriter.create(self.root) as writer:
                writer.append(decode_request("GET", "/beacon?m=retained"))
                raise RuntimeError("interrupted caller")
        report = verify_capture(writer.path)
        self.assertEqual(report["capture_integrity"], "INCOMPLETE")
        self.assertEqual(report["accepted_records_verified"], 1)


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="beacon-verify-test-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)/"literal.jsonl"
        # Hand-written schema fixture: not generated by CaptureWriter or decode_request.
        cid = "12345678-1234-4234-8234-123456789abc"
        self.records = [
            {"record_type":"open", "schema":"browser-beacon-capture", "version":1,
             "capture_id":cid, "started_at":"2026-11-07T00:00:00Z",
             "limits":{"body_bytes":65536,"target_bytes":16384}, "durability":"flush-only",
             "provenance":{"local_files_sha256":{},"caller_reported":{}}},
            {"record_type":"event","capture_id":cid,"sequence":1,
             "received_at":"2026-11-07T00:00:01Z",
             "request":{"method":"GET","raw_target":"/beacon/T?d=1%2C2",
                        "query":[["d","1,2"]],"format":"tagged_d","tag":"T",
                        "measurement":"1,2","measurement_utf8_length":3,
                        "body_base64":"","body_length":0,
                        "body_sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                        "declared_length":None,"client_reported":{}}},
            {"record_type":"close","capture_id":cid,"accepted_count":1,
             "closed_at":"2026-11-07T00:00:02Z"},
        ]

    def report(self):
        self.path.write_bytes(b"".join(json.dumps(r).encode()+b"\n" for r in self.records))
        return verify_capture(self.path)

    def test_literal_schema_and_unknown_delivery_even_when_closed(self):
        result = self.report()
        self.assertEqual(result["capture_integrity"], "VALID")
        self.assertEqual(result["delivery_completeness"], "UNKNOWN")

    def test_missing_close(self):
        self.records.pop()
        self.assertEqual(self.report()["capture_integrity"], "INCOMPLETE")

    def test_truncated_final_line(self):
        self.report()
        self.path.write_bytes(self.path.read_bytes()[:-7])
        self.assertEqual(verify_capture(self.path)["capture_integrity"], "INCOMPLETE")

    def test_missing_newline_even_on_complete_json(self):
        self.report()
        self.path.write_bytes(self.path.read_bytes()[:-1])
        self.assertEqual(verify_capture(self.path)["capture_integrity"], "INCOMPLETE")

    def test_wrong_schema_and_version(self):
        for key, value in [("schema","wrong"),("version",2),("version",True)]:
            with self.subTest(key=key,value=value):
                original = self.records[0][key]
                self.records[0][key] = value
                self.assertEqual(self.report()["capture_integrity"], "INVALID")
                self.records[0][key] = original

    def test_limits_require_integer_types(self):
        self.records[0]["limits"]["body_bytes"] = 65536.0
        self.assertEqual(self.report()["capture_integrity"], "INVALID")

    def test_literal_provenance_numeric_overflow_is_rejected(self):
        self.records[0]["provenance"]["caller_reported"] = {"number": 1}
        for literal in (b"1e999", b"-1e999"):
            self.report()
            raw = self.path.read_bytes().replace(b'"number": 1', b'"number": ' + literal)
            self.assertIn(literal, raw)
            self.path.write_bytes(raw)
            self.assertEqual(verify_capture(self.path)["capture_integrity"], "INVALID")

    def test_empty_client_metadata_is_not_accumulated(self):
        self.report()
        from tools.browser_runner import verify_capture as verifier
        with mock.patch.object(verifier, "_client_diagnostics", return_value=({}, [])) as analyze:
            self.assertEqual(verify_capture(self.path)["capture_integrity"], "VALID")
        analyze.assert_called_once_with([])

    def test_server_sequence_and_count_tampering(self):
        self.records[1]["sequence"] = 2
        self.assertEqual(self.report()["capture_integrity"], "INVALID")
        self.records[1]["sequence"] = 1
        self.records[2]["accepted_count"] = 2
        self.assertEqual(self.report()["capture_integrity"], "INVALID")

    def test_body_hash_length_and_base64_tampering(self):
        request = self.records[1]["request"]
        for key, value in [("body_length",1),("body_length",False),
                           ("body_sha256","0"*64),("body_base64","not base64")]:
            with self.subTest(key=key):
                original = request[key]; request[key] = value
                self.assertEqual(self.report()["capture_integrity"], "INVALID")
                request[key] = original

    def test_interpretation_and_ordered_query_tampering(self):
        request = self.records[1]["request"]
        request["measurement"] = "forged"
        self.assertEqual(self.report()["capture_integrity"], "INVALID")
        request["measurement"] = "1,2"
        request["query"] = [["d","changed"]]
        self.assertEqual(self.report()["capture_integrity"], "INVALID")

    def test_records_after_close(self):
        self.records.append(self.records[1])
        self.assertEqual(self.report()["capture_integrity"], "INVALID")

    def test_missing_open_and_non_object(self):
        self.records.pop(0)
        self.assertEqual(self.report()["capture_integrity"], "INVALID")
        self.records = [None]
        self.assertEqual(self.report()["capture_integrity"], "INVALID")

    def test_duplicate_json_keys_nonfinite_and_malformed_record(self):
        for raw in [b'{"record_type":"open","record_type":"event"}\n', b'{"x":NaN}\n', b'not json\n']:
            with self.subTest(raw=raw):
                self.path.write_bytes(raw)
                self.assertEqual(verify_capture(self.path)["capture_integrity"], "INVALID")

    def test_empty_capture(self):
        self.path.write_bytes(b"")
        self.assertEqual(verify_capture(self.path)["capture_integrity"], "INCOMPLETE")

    def test_missing_file_is_invalid(self):
        self.assertEqual(verify_capture(self.path)["capture_integrity"], "INVALID")

    def test_client_gaps_duplicates_and_order(self):
        with CaptureWriter.create(Path(self.temp.name)) as writer:
            for n in [1,3,3,2,5]:
                writer.append(decode_request("GET", "/beacon?m=x&session=s&n="+str(n)))
        report = verify_capture(writer.path)
        self.assertEqual(report["client_reported"]["s"]["duplicates"], {"3":2})
        self.assertEqual(report["client_reported"]["s"]["gaps_between_observed"], [[4,4]])
        self.assertTrue(report["client_reported"]["s"]["out_of_order"])
        self.assertEqual(report["delivery_completeness"], "UNKNOWN")

    def test_unscoped_or_duplicate_client_metadata_is_not_combined(self):
        with CaptureWriter.create(Path(self.temp.name)) as writer:
            for q in ["n=1","n=3","session=s&n=2&n=4","session=s&n=bad"]:
                writer.append(decode_request("GET", "/beacon?m=x&"+q))
        report = verify_capture(writer.path)
        self.assertEqual(report["client_reported"], {})
        self.assertEqual(len(report["warnings"]), 4)

    def test_cli_exit_codes(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.report()
            self.assertEqual(verify_main([str(self.path)]), 0)
            self.path.write_bytes(b"")
            self.assertEqual(verify_main([str(self.path)]), 2)
            self.path.write_bytes(b"bad\n")
            self.assertEqual(verify_main([str(self.path)]), 1)

    def test_direct_cli_script(self):
        self.report()
        script = Path(__file__).resolve().parent / "browser_runner/verify_capture.py"
        result = subprocess.run([sys.executable, "-B", str(script), str(self.path)],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["delivery_completeness"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()

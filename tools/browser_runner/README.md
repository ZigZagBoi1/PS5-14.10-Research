# Browser beacon capture (schema version 1)

The capture module is hardware-free and opens no socket. The Python serve.py
adapter now uses it for authoritative JSONL acquisition. Compatibility BEACON
text and stdout are best effort. Old logs are not rewritten. PHP/Apache are
unchanged; the Python alias below does not execute PHP. The display policy is
PR #231's exact ten-separator policy (head cccff399); reconcile that overlapping
handler work when #231 merges, without replacing its PHP changes or tests.

## API and request contract

    from pathlib import Path
    from tools.browser_runner.capture import CaptureWriter, decode_request

    request = decode_request("GET", "/beacon/P560-B-POST?d=1%2C2%2C3%2C4")
    assert request.status == "accepted"
    with CaptureWriter.create(Path("/tmp/my-local-captures")) as capture:
        sequence = capture.append(request)  # success only after complete write + flush
        path = capture.path

The decoder returns an immutable DecodedRequest, with status accepted, rejected,
or ambiguous and a reason for non-acceptance. Only canonical accepted requests
can be appended. Ambiguous requests have **no chosen measurement**. No error
response is sent by this module; serve.py maps its outcomes to non-success
statuses as specified below.

| Format | Interpretation |
| --- | --- |
| GET /beacon?m=text | Legacy query message; m= is an explicit empty message, bare m is rejected. |
| GET /beacon/encoded-message | Decode the entire suffix once, retaining slashes in the message. |
| GET /beacon/tag?d=measurement | Separate decoded tag and data; d= is accepted empty data. |
| POST /beacon/tag + raw bytes | Exact body; UTF-8 measurement when valid, null measurement for binary data. |
| POST /beacon + raw bytes | Untagged body, including explicit zero-length body. |
| POST /beacon/encoded-message + zero-length body | Path-carried sendBeacon message, not a discarded empty measurement. |
| POST /beacon?m=text + zero-length body | Explicit legacy query-message compatibility. |
| /beacon.php?tag=message | Explicit alias for the two inspected PHP-style clients; GET or empty-body POST takes the tag as message. Nonempty POST takes tag + exact body. |

The PHP alias also supports tag + d with an empty body. This is an explicit
Python-foundation contract, **not full PHP emulation**: a nonempty query tag is
required; m-only PHP requests are rejected. No PHP code or rewrite rule changes.

Duplicate decoded m/d/tag parameters are ambiguous, including duplicates with
equal or empty values. Competing measurement sources (for example d and a
nonempty POST body, or a path message plus m) are ambiguous. Unknown query
parameters and repeated metadata are preserved, not silently selected. Duplicate
or invalid client metadata does not invalidate an otherwise unambiguous message,
but cannot be used for client gap analysis.

Raw target is retained literally as ASCII origin-form (not an absolute URL),
without fragments, spaces, or control characters. Percent encoding and UTF-8
are strict; invalid URL encoding is rejected, never replacement-decoded. Plus
becomes space only in query parameters, not in the path. Query pairs retain
order, repeats, and the distinction between a bare key (null value) and key=
(empty string). No second decoding pass is made.

All bodies are immutable bytes. POST requires declared_length as a nonnegative
integer equal to the supplied byte count; absent, invalid, incomplete, extra, and
over-limit bodies are rejected. GET bodies are rejected. Limits are fixed in v1:
64 KiB body, 16 KiB ASCII target, 128 query fields, 1 MiB serialized record.
The observed tagged-d emitters send at most 500 JavaScript code units (roughly
up to 6,000 percent-encoded ASCII characters for UTF-8 scalars); the 16 KiB target
allows this with room for tags/metadata. The 64 KiB body accepts the previously
silently truncated 5,000-byte example without unbounded allocation. These are
application limits, not claims about every browser/server deployment.

The decoder does not read streams or parse HTTP headers. The HTTP adapter must
bound reads before allocating a body, validate original/duplicate Content-Length
headers and unsupported transfer encoding, enforce read deadlines, and pass the
actual declared length. It must not pass the observed prefix length as though
that were the sender's length. serve.py implements these tasks; the decoder remains independently testable.

## JSONL layout

Files are exclusively created as capture-<uuid>.jsonl; timestamps do not determine
uniqueness. Existing files are never appended to or overwritten by create().
One writer owns one sink. Direct BinaryIO injection is for adapters/tests; callers
must not share a sink between distinct writers or write to it outside the writer.

Every record is one UTF-8 JSON object terminated by LF. JSON escaping distinguishes
literal backslashes from control characters. Record shapes:

- open: schema=browser-beacon-capture, version=1, capture_id, started_at, limits,
  durability=flush-only, provenance.
- event: capture_id, sequence (starting at 1), received_at, request.
- close: capture_id, accepted_count, closed_at.

Record type is in record_type. Events are serialized in lock acquisition /
writer acceptance order, **not guaranteed network, sender, or thread start order**.
The lock covers sequence assignment, full write and flush. Duplicate arrivals
are recorded independently; nothing automatically deduplicates them.

request contains method, raw_target, ordered query pairs, format, tag,
measurement, measurement_utf8_length, body_base64, body_length, body_sha256,
declared_length and client_reported. Binary POST measurement is null; its exact
payload is body_base64/body_length, not a lossy display string. For text, the
measurement length counts UTF-8 bytes, not Unicode code points or JS code units.
All original supplied body bytes round-trip independently through standard base64.

Opening provenance contains hashes of locally available capture.py,
verify_capture.py and serve.py file bytes at creation, and a JSON-object caller_reported field.
These are local associations, **not authentication** of executed instructions,
source revisions, consoles, firmware, boots, client sessions, or measurements.
No credential files or environment variables are read. A source hash can be
checked against separately retained source; the verifier validates digest shape,
not historical source identity. UTC timestamps are local clock reports.

## Persistence semantics

append() returns the assigned sequence only after one checked complete binary
write and flush. Short writes and write/flush exceptions raise CaptureError and
poison the writer: further append/close cannot conceal the failed boundary.
An opening failure yields no usable writer. A close failure is also reported.
No stdout operation exists in the writer. Records are bounded before writes.

A failed operation can leave partial **or complete** bytes in the file, especially
on flush failure. Do not delete them, claim absence of receipt, or treat retries
as duplicates to discard. If a fully written close line survives a failed flush,
the offline verifier cannot infer that the caller received a successful close.
Its result describes the retained file, not a history of acknowledgements.

The context manager writes close on a normal exit; on a caller exception it
releases an owned sink without a close record. abort() likewise leaves the file
unclosed. Injected sinks remain caller-owned. Owned files are closed on close
or abort. flush is **not fsync or power-loss durability**; no such option or
guarantee is implemented here. There is no exactly-once delivery guarantee.
An append API return precedes an attempted HTTP response; it is not browser receipt.

## Offline verification

    python3 -B tools/browser_runner/verify_capture.py /path/to/capture.jsonl
    python3 -B -m unittest -v tools.test_browser_runner_capture

CLI exit codes: 0 VALID, 1 INVALID, 2 INCOMPLETE. Integrity VALID means the retained
file has supported framing/schema, opening/event/close records, matching capture
identity/count, monotonic acceptance sequence and consistent raw-body lengths,
hashes and decoded fields. Nonfinite constants and overflowing floating-point
numbers such as literal 1e999, duplicate object keys, unknown schema
fields and inconsistent interpretations are rejected. A missing final LF is
unframed even if the JSON text happens to parse. An empty/unclosed/truncated file
is reported explicitly; a malformed newline-terminated record is INVALID.

The verifier independently checks framing/base64/hash lengths, then uses the
same versioned decoder to check interpretation consistency. Tests additionally
use literal byte/string expectations, standard json/base64 readers, and a
hand-written schema fixture rather than relying only on that shared decoder.

client_reported preserves every query session and n value. Gap diagnostics use
only exactly one nonempty session and one bounded decimal n. No session is
guessed from IP, a capture UUID, filenames, or embedded corpus path tags. Bare,
duplicate, invalid or unscoped metadata produces warnings and is not combined
across clients. Repeats and out-of-order observations are reported; gaps mean
only holes **between observed** client sequence values, not proven lost requests.
Different explicitly reported sessions are separate; session identity is untrusted.

**delivery_completeness is always UNKNOWN in version 1**, even for a valid closed
capture with contiguous server sequence numbers. There is no sender completion
protocol, authenticated start/final count, or proof that unsent/unreceived requests
exist. An unknown query flag such as done does not upgrade that assessment.

## Python HTTP contract

serve.py keeps the existing CLI, serial HTTPServer and static-file containment.
One exclusively created capture-<uuid>.jsonl is required before server creation.
The secondary beacons_<uuid>.log is opened exclusively as UTF-8; its unavailability
is reported but does not prevent required JSONL acquisition. Both are under
beacon_logs/. New files never append to old text logs.

All request connections close after one request. Capture replies explicitly send
Connection: close, Content-Length: 0 and Cache-Control: no-store. Existing static
responses retain HTTP/1.0 implicit close. There is no keep-alive or pipelining;
unread rejected bodies cannot become subsequent requests. The raw target token
is retained from the original request line before BaseHTTPRequestHandler's
leading-double-slash normalization or the static /document/... rewrite.

| Capture request result | HTTP status |
| --- | --- |
| Canonical accepted event fully written and flushed | 204 |
| Malformed URL, missing/ambiguous message, invalid/duplicate Content-Length, unsupported Transfer-Encoding or Expect, GET body, EOF-short POST | 400 |
| Declared POST length absent | 411 |
| Declared body exceeds 65,536 bytes | 413 |
| Idle or total body-read deadline reached | 408 |
| Required sink unavailable or already failed | 503 |
| Required append/write/flush failure | 500 |
| Unknown endpoint | 404 |

Only ASCII decimal Content-Length with optional surrounding space/tab is
accepted; even equal duplicate headers and comma lists are rejected. Leading
zeros are allowed. Length is validated before allocating or reading. GET accepts
absent or zero length. POST requires a length, including explicit zero for
sendBeacon-style path messages. Transfer-Encoding and Expect negotiation are
unsupported, even when a Content-Length is also supplied. The existing base
HTTP parser handles request-line/header limits and unsupported methods (501).
Bodies are read as exact bytes in bounded chunks using BufferedReader.read1.
There is a 5-second socket/read idle timeout and a 10-second overall body deadline
using a monotonic clock. A trickle cannot reset the overall body deadline.
These limits start after headers; there is no overall header or TLS-handshake
deadline. The server remains serial and is not a general hostile-network service.

The HTTP body is exactly the Content-Length-framed bytes. Trailing connection
bytes beyond that length are discarded on close, not guessed to be body bytes
or admitted as another request. Rejected requests and incomplete prefixes do not
become accepted JSONL events. A clean close may therefore follow explicit HTTP
rejections; it does not certify the sender's attempts or measurements complete.

The handler attempts 204 only after append returns from full write plus flush.
A later response-write error leaves the event intact and is retained as the
server's first response_error, separately from acquisition failure. A client retry
can create another event. This neither proves response transmission nor browser
receipt; flush still does not promise fsync or power-loss durability.

### Secondary display policy

JSONL is authoritative. Text-file open/write/short-write/flush/close errors are
best effort and cannot suppress a completed primary event or change its 204
policy. The server retains the first secondary request-log error and emits a
best-effort diagnostic. Closed stdout is ignored for BEACON display, startup
messages and default HTTP access logging, including send_response's log call.
Blocking filesystem/display operations do not have write deadlines; there is no
atomic transaction or simultaneous-persistence promise across JSONL and text.

Legacy m and path messages display normally. Tagged d and nonempty POST bodies
display tag: measurement, with untagged bodies displaying their measurement.
Binary bodies display <binary N bytes; see JSONL>, not replacement-decoded text.
The existing [timestamp] BEACON IP: prefix is retained. Display escapes exactly
CR, LF, VT, FF, FS, GS, RS, NEL, LS and PS as PR #231 does, leaving ordinary UTF-8
text intact. Display escaping is not reversible; JSON/base64 is the byte oracle.

### Lifecycle and failures

run(args) owns capture, optional text file and server. Normal serve_forever return
(e.g. external shutdown()) stops serial admission, closes the listener, then
attempts exactly one capture.close. An exception reaching run(), Ctrl+C, startup
failure, primary persistence failure or handler error reaching the fatal policy
preserves the first acquisition error and aborts without a close record. Cleanup
errors do not mask that error.
A failed close is reported without a second close/abort attempt. A complete close
line can survive a reported close failure, so offline VALID still means file
consistency, not success history. CLI Ctrl+C conservatively leaves the capture
unclosed and exits 130, even if no request was active. Sender completeness stays
UNKNOWN. Primary failure poisons further beacon admission (503) until shutdown;
static service need not stop immediately. Known client disconnects during static
or inherited error-response writes, beacon response transport errors and secondary
output errors do not poison healthy primary capture. Static/error-reply output
scopes delegate the original wfile and classify only BrokenPipeError,
ConnectionResetError and ConnectionAbortedError from its write operation. A
private signal aborts the reply, retains the first response_error and prevents
further sends for that reply. The original stream is restored on every exit.
Base send_error still owns status codes, logging, HTML formatting/encoding and
header construction. Within these guarded replies, preparation failures (even
with a disconnect exception class), file-read errors and generic output OSError
propagate to the handler error policy. The inherited BaseHTTPRequestHandler
TimeoutError catch can instead close a request without setting fatal capture
state for some non-primary operations. Primary writer TimeoutError is wrapped
in CaptureError and remains fatal to acquisition.

The empty beacon/status _reply uses a broader OSError catch covering header
preparation and output: those errors become response_error diagnostics without
poisoning a healthy capture. Thus not every non-output OSError is fatal. This
catch does not cover primary persistence or clear an existing fatal error.
Disconnect recovery is verified for the default unbuffered SocketWriter
(wbufsize=0). Non-default buffering and deferred flush failures are not covered
equivalently by the write-only guard. HEAD remains unsupported (501); an
unsupported HTTP version still receives 505 when transmission succeeds.

The local hashes and metadata do not authenticate executed source, consoles,
firmware or boot identity. No STATE.md/INDEX.md management or automatic newest-file
association is added; PR #233 owns that ledger. PHP/Apache parity, real browser
behavior, TLS runtime, cross-version Python behavior and power-loss durability
remain unverified.

## Tests and resource limits

    python3 -B -m unittest -v tools.test_browser_runner_capture tools.test_browser_runner_http tools.test_browser_runner_paths
    python3 -B tools/verify_offline.py

The explicit offline list registers the foundation and in-memory HTTP tests.
Loopback tests in the same module are skipped unless explicitly enabled:

    BROWSER_RUNNER_LOOPBACK_TESTS=1 python3 -B -m unittest -v tools.test_browser_runner_http.LoopbackTests tools.test_browser_runner_http.RunLoopbackTests

These opt-in tests bind only 127.0.0.1 on an ephemeral port, use dummy payloads and
never contact a console. Socket permission is required; a skipped or denied run
is not evidence of measured transport correctness. The default verifier never
starts them. Preserve independent literal byte/value oracles alongside the shared
interpretation checker.

Verification reads one bounded line at a time and no longer retains empty client
metadata per event. Whole-file memory is not constant: nonempty client metadata,
per-session sequences, diagnostics and errors can still grow with capture length.
No large-file streaming analytics service or independent tamper-proof signature
is provided. Delivery completeness remains UNKNOWN for every schema-v1 file.

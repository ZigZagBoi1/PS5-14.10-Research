# Bounded live retest results

2026-10-18. These sessions used the documented loader framing (little-endian
uint64 source length followed by raw UTF-8 Lua) and a one-shot sender. The
sender was `send_bounded.py` (SHA-256
`82bd08941c27b4f7efa5edf4eee10713283db67a657c25efddb671ceeb38cef6`).
Each raw response and framed request is preserved in its own directory. No
firmware banner or build attestation was obtained.

## Results

| Session | Script SHA-256 | Connection/submission | Last observed output | Completion |
|---|---|---|---|---|
| `aio-661-670-zeroarg` | `365299face4dcd7a05e1dfffff066a61c4f009c9069c8635c16bb1a756006bc6` | Connected and submitted at `2026-10-18T07:33:25.377747Z` | Selector 663 returned `table h=-1 l=4294967295`; selector 661 emitted `BEFORE` with no return. | Raw response EOF; Lua `COMPLETE` was not observed. |
| `retest-53a-aio` | `45b2c85f773c6d1c777d388a7d8d47d65f85a160ef457d95d96d76ca674778cf` | Connected and submitted at `2026-10-18T07:33:37.033770Z` | First `aio_error` `BEFORE` marker. | Raw response EOF; no return or completion marker. |
| `retest-53b-afroute` | `250a5776247a2ff09ffbd19e10e4a850214e7444af406da6369aaacb7b6fd4e0` | Connected and submitted at `2026-10-18T07:33:44.684848Z` | Route socket returned fd 22. Header variants 120 and 92 had write `-1`; variant 152 had write `168`, then `recvmsg` returned `136`. The response was classified as a non-echo candidate with `msglen=136`, `version=5`, `type=4`, `pid=100`, `seq=1`, `errno=0`, and zero pointer-shaped qwords under the script's test. | `PROBE 53b COMPLETE` observed; peer EOF. |
| `retest-53c-kldstat` | `0409275b4ae8edb255cbf871d022a733eb60dde113df5f17b0cfd967755ab6dd` | Connected and submitted at `2026-10-18T07:33:49.414415Z` | First kldstat candidate (`syscall=308`, `fileid=1`, `version=0x70`) `BEFORE` marker. | Raw response EOF; no return or completion marker. |

The sender and source hashes above are copied from the per-session JSON. The
raw response hashes are:

- `aio-661-670-zeroarg/response.raw`: `c618453f09459b473ce299c2578b7320e1bb47e4b230b25711641a5c8dff1104`
- `retest-53a-aio/response.raw`: `8bdce42a4f52aa03171a8df53c4dcec7659e15b5059d33d7c22e15fbe906462b`
- `retest-53b-afroute/response.raw`: `98e260c75f73b2759f269522b3cafe9eea4a8a3811e44cf28f630573c84a6bbe`
- `retest-53c-kldstat/response.raw`: `d5dc1981441495cb2322d116c71722e0c47337f9bfc3f8634a220323f4c9c064`

## Interpretation limits

The selector-663 line is a wrapper-level return representation. Its exact
Sony ABI, signed interpretation, errno, and side effects are not established;
it is not evidence of a vulnerability or kernel access. The selector-661
missing tail and the 53a/53c missing returns do not establish a panic, kill,
sandbox decision, or particular failure cause. The 53b message is an observed
route response candidate, not a kernel-pointer leak or KASLR result.

The prepared 53d script was **not sent**. The retained runtime evidence says
the current `syscall.pipe.__call` value is a Lua function, while 53d derives an
address from that function and writes sentinels into guessed qword offsets.
That premise is not established, so the write was left unexecuted. The current
53d source hash is `d9bdb225b4645f636c2ede62a20462b8999906cea3bd2f96e7c53a2983cf9938`.

The hashes in this report are the actual current source hashes at submission
time. They differ from the older hash table in `docs/RETEST_PLAN_53.md`; that
table must not be used to identify these submitted bytes.

All four sessions are present-day loader observations. They do not authenticate
the firmware, historical dumps, 14.10 sysent layout, patch state, handler
identity, or applicability of the retained 13.60 AIO disassembly.

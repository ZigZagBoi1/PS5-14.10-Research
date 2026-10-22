# WebKit length-window audit: the `.length = 81400` OOB claim

**Superseded 2026-10-19:** The premise below is false. The p156 worker string was
814 characters repeated 100 times, so its real length was 81,400 before any
sweep. The 798-character bait was also smaller than claimed. The corrected
[V480 probe](https://github.com/pastawithpesto/PS5-14.10-Jailbreak-Research/blob/ea1beed081/analysis/false-positive-81400.md)
reported 0/14 length changes after compilation. No header corruption was
established. This file remains only as the historical audit that first rejected
the out-of-bounds-read inference; see [current findings](WEBKIT_FINDINGS.md).

Historical status (invalid premise): **claim refuted as written; header corruption was assumed.** Offline audit, 2026-10-19.
Scope: `docs/WEBKIT_FINDINGS.md` Findings 2 and 3, probes `p146`/`p156`, and the unrun `54g`.

## Verdict

The recorded on-device result is a corrupted JSString length of **81,400** on strings
that were built with **100,000** characters. The findings doc then states that reads
through that string reach "past the original 100,000-byte string". They do not:
81,400 < 100,000, so every index the JSString permits is still inside the character
buffer. What p146 proves is that the overflow overwrites four header bytes with a
value of 81,400. It does not prove an out-of-bounds read, and p156's all-`0x41` scan
cannot distinguish "backing store intact" from "never left the backing store".

## 1. The numbers

| Quantity | Value | Source |
|---|---|---|
| Target string length | 100,000 chars | `probes/phase13_webkit/p146-string-primary.js:45`, `:176` |
| Buffer capacity | exactly 100,000 (built then `substring(0, 100000)`) | `p146-string-primary.js:69`, `:185` |
| Corrupted `.length` | 81,400 | `docs/WEBKIT_FINDINGS.md:44`, `:58` |
| Readable window after corruption | 0 … 81,399 | derived |
| Bytes still inside the buffer past the window | 81,400 … 99,999 | derived |
| `81,400 < 100,000` | true | — |

Language-level reads are bounded by the JSString length, not by the buffer:

```c
// Source/JavaScriptCore/runtime/JSString.h:256
bool canGetIndex(unsigned i) { return i < length(); }
// :976
inline JSString* JSString::getIndex(JSGlobalObject* globalObject, unsigned i)
{
    ...
    ASSERT(canGetIndex(i));
    auto view = this->view(globalObject);
    ...
    return jsSingleCharacterString(vm, view[i]);
}
```

`charCodeAt` reaches `getIndex` after the same `i < length()` test. A *smaller*
length therefore narrows the reachable range. Out-of-bounds requires
`length() > StringImpl length`, which the recorded value contradicts.

The check is version-independent enough to carry here: the JSString length field
has gated character access in every JSC release that stores a separate `m_length`.
This audit does not depend on the exact snapshot offsets, only on the rule that the
length field bounds the read.

## 2. What p146 and p156 actually establish

- **p146**: the metadata-table sweep reaches a JSString header and writes a dword
  that `.length` returns as 81,400. All 14 targets in the worker heap show it, so the
  write is systematic rather than a one-off spill.
- **p156**: every read stays inside the buffer. Header-corrupt strings are only read
  for 32 bytes (`p156-bait-switch.js:120`); the 112-byte metadata scan runs on
  intact-header strings with `b < STR_LEN` (`:147`). Nothing in the probe indexes
  past 99,999, so the all-`0x41` result is what an in-bounds read returns and says
  nothing about bytes ≥ 100,000.

`54g` then scans `100000 … 181399` only if it first finds a string with
`len > STR_LEN` (`probes/phase14_final_push/54g_webkit_kaslr.js:111`). Under the
recorded result that branch never fires, so 54g documents an experiment that the
existing evidence cannot reach.

## 3. Where 81,400 could come from

The sweep is not a single store; it is a long sequence of 112-byte metadata entries
written past a wrapped allocation:

```
38,348,816 * 112 = 4,295,067,392 = 2^32 + 100,096   (0x1_0001_8700)
```

so the table is allocated as one 102,400-byte slot and roughly 4.29 GB of writes
follow it (`p146-string-primary.js:241`, `docs/WEBKIT_FINDINGS.md:40-44`). 81,400 is
not a byte offset reached during that run — offsets there are in the millions — so it
is either a field inside one of the entries (an identifier-table offset, structure
ID, or similar) or a value the entry carries verbatim.

If it is an entry field, it is attacker-influenced by the shape of the generated
function and could plausibly be steered. If it is fixed, the current write gives a
constant length and nothing else.

## 4. Experiment that distinguishes those cases

`probes/phase13_webkit/p161-length-window.js` re-runs the p146 groom twice with the
same generated source size but different metadata content:

| Mode | Body | Calls | Distinct identifiers |
|---|---|---|---|
| `single` | `a();` × 38,348,816 | 38,348,816 | 1 |
| `pair` | `a();b();` × 19,174,408 | 38,348,816 | 2 |

Same total call count and same source size, so any change in the written length
comes from the entry content rather than from the wrap arithmetic.

The probe also measures the window directly, which no previous probe did:

| Beacon | Meaning | Expected if the claim were right | Expected if the audit is right |
|---|---|---|---|
| `HDR-i-len=N` | corrupted length | > 100000 | 81400 |
| `LAST-i` at `len-1` | last readable byte | canary | canary |
| `TAIL-i` at index 99999 | byte that exists in the buffer | canary | **NaN** |
| `PAST-i` at index `len` | first byte outside the window | canary | NaN |
| `SUB-i` | `substring(0,10)` still reads the original data | OK | OK |

`TAIL-i = NaN` while `SUB-i = OK` is the decisive pair: the character buffer still
holds the original 100,000 bytes, and the JSString still refuses to reach them. That
is a length-window shrink, not an OOB primitive.

`?calls=` lowers the call count for harness smoke tests only; the wrap needs the full
38,348,816.

## 5. What would actually be an OOB primitive

1. **Length control.** A written length greater than the real capacity. Needs the
   value from §3 to be content-dependent — that is what p161 tests.
2. **Data-pointer control.** Corrupt `m_fiber`/`m_data8` to a forged StringImpl.
   p156's `charCodeAt` still returning `0x41` argues the pointer was not corrupted by
   this sequence, but it does not exclude a different groom.
3. **A different victim object.** The sweep runs within one 102,400-byte marge slot,
   so the neighbour is a big string. Small strings live in other size classes and
   are not adjacent to the metadata buffer; targeting them needs a separate groom.

Until one of those lands, the WebKit chain has heap-header corruption without a
read primitive, and the "Data extraction (ASLR leak)" stage is blocked rather than
"in progress".

## 6. Changes made with this audit

- `docs/WEBKIT_FINDINGS.md`: Findings 2/3 impact text now states the in-bounds
  reading and links this document; the status table marks the leak stage blocked on
  length control.
- `probes/phase13_webkit/p161-length-window.js`: the experiment above.
- `probes/phase14_final_push/54g_webkit_kaslr.js`: header comment records that its
  OOB branch needs `len > STR_LEN` and is unreachable under the p146 result.

## Sources

- `docs/WEBKIT_FINDINGS.md:40-71`
- `probes/phase13_webkit/p146-string-primary.js:45,69,176,185,241`
- `probes/phase13_webkit/p156-bait-switch.js:120,147`
- `probes/phase14_final_push/54g_webkit_kaslr.js:111`
- WebKit `main`: `Source/JavaScriptCore/runtime/JSString.h:256,976`

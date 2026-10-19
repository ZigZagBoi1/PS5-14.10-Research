# WebKit length-window audit: the `.length = 81400` OOB claim

> **Status revision (2026-10-20): the audited value was a FALSE POSITIVE.** The `.length = 81400` reports were the real string length — the p146/p156 worker chunk literal is 814 characters, so the strings are 81,400 chars from birth and nothing was corrupted. See [pastawithpesto's definitive V480 test](https://github.com/pastawithpesto/PS5-14.10-Jailbreak-Research/blob/master/analysis/false-positive-81400.md) (0 of 14 corrupted with loop-built 1000-char chunks) and WEBKIT_FINDINGS.md Finding 2. The audit below is preserved as the historical analysis that first noticed the capacity inconsistency; its open question — where a value of 81,400 could come from — is now answered: the literal.

Status (historical, 2026-10-19): **claim refuted as written; header corruption stands.** Offline audit.
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

## 7. The site sweep cannot reach the wrap on a 14.10 console

Measured on the same console that produced the earlier WebKit work, through the
User's Guide redirect, with beacons for every phase:

| call sites in one function | source size | blob built | compiled | outcome |
|---|---|---|---|---|
| 2,348,816 | 9 MB | 0.0 s | ok | executed, `SURVIVED` |
| 12,000,000 | 46 MB | 0.7 s | +2.0 s | died at first call, system toast "not enough free system memory" |
| 38,348,816 | 146 MB | 0.7 s | +6.2 s | died at first call, same toast |

In both failing runs the last beacon is `CALLING`; no post-call beacon, no worker
length report. The toast is the WebProcess losing its memory, not a JavaScript
exception.

The 12,000,000-site run bounds the cost at ≥112 bytes per statement: the process
died before it could hold 12,000,000 × 112 = 1.34 GB, so 38,348,816 × 112 =
4,295,067,392 B is out of reach by the same factor the overflow is supposed to
save. That ordering is the problem: `UnlinkedMetadataTable::finalize()` computes
its `unsigned` sum only after the function body has been parsed and its bytecode
generated, so the 38.3M `op_call` sites must already exist as parse structures
before the wrap can happen. The overflow would spare the 4.29 GB allocation at the
moment it is computed — it cannot spare the memory needed to arrive there.

This is structural, not a tuning problem: source bytes per statement are already
at the minimum (`a();` is four characters), and the per-statement cost is the
parser's, not the sweep's.

**Consequence:** the p142/p146 sweep is not executable on a 14.10 console as
written. Any future attempt needs a construct that produces 38.3M metadata entries
without 38.3M statements, or a different 32-bit accumulator reached at a smaller
multiplier.

## 8. Provenance of `.length = 81400`

No artifact in this repository records that value. `results/` contains no p146 or
v146 output, and p146 emits its beacons to the page rather than to a saved log. The
figure appears only as prose in `docs/WEBKIT_FINDINGS.md:44`, added in 097500e. It
should be read as unverified until a run is captured with the beacon server.

The same applies to `docs/WEBKIT_FINDINGS.md:70`, the p141 row recording `SIGSEGV - confirms OOB write
occurs`. That row is inherited from the upstream research repository along with the rest of the table,
and no capture backs it here either. It is also in tension with section 7: a SIGSEGV at the metadata
overflow means the process survived long enough to parse 4.29 GB of bytecode, while both of our runs
were killed by the system for memory at 2.35 M and 12 M sites, roughly a third of the way. Treat that
row as an unverified claim about a different environment, not as evidence that this console reaches
the wrap.

## 9. The accumulator is checked upstream, and the overflow needs 4.29 GB anyway

The `unsigned` accumulator at `probes/phase13_webkit/p142-heap-survive.js:26,117` was real, and it was fixed:

- `UnlinkedMetadataTable::finalize()` returned `void` and accumulated `offset` as a plain `unsigned` until
  commit `97df94ead0` (canonical `commits.webkit.org/319678@main`, 2026-08-24, bug 317632, rdar://172794625),
  which converted it to `CheckedUint32` and made the function return `bool` so
  `UnlinkedCodeBlockGenerator` can report the failure as an OOM during parsing. It was also
  back-ported to `safari-7624.5-branch` as `305413.1022`.
- The regression test the patch added, `JSTests/stress/unlinked-metadata-table-finalize-overflow.js`, is
  marked `//@ slow!` and skipped when `$memoryLimited` is set. It uses `n = 44739242` repetitions of
  `'a();'` — 44.7 M call sites, i.e. 44,739,242 x 96 = 4,294,967,232 = 2^32 exactly. The 96-byte stride
  supersedes the 112-byte figure quoted in `docs/WEBKIT_FINDINGS.md:27`; the conclusion is unchanged
  because the test's own count is higher than the 38.3 M used in the console runs.

Two independent reasons this vector is not live on a 14.10 console:

1. Structural: the overflow happens in `finalize()`, which runs after the body is parsed, so the parse
   structures for >= 4.29 GB of bytecode must already exist. The measured ceiling in §7 is 12 M sites
   before the WebProcess is killed, one third of the count the upstream test needs.
2. Patch state: 14.10 shipped 2026-10-02, five weeks after the fix landed. Whether Sony's fork carries
   `319678@main` is unknown and undetectable from JavaScript, because a fixed engine and an unfixed
   engine behave identically below the overflow point. The measured API surface (p162) is the
   Safari 17.0–17.3 band, so the default base predates the fix; that says nothing about back-ports.

`probes/phase13_webkit/p162-engine-fingerprint.js` dates the engine instead: it beacons a bitmap of
Safari API availability, each API tagged with the release that shipped it (15.4 through 18.x). If the
bitmap comes back at a 2026 level, the fork is recent enough that upstream hardening is likely present
and any future WebKit work should assume checked arithmetic.

## Sources

- `docs/WEBKIT_FINDINGS.md:40-71`
- `probes/phase13_webkit/p146-string-primary.js:45,69,176,185,241`
- `probes/phase13_webkit/p156-bait-switch.js:120,147`
- `probes/phase14_final_push/54g_webkit_kaslr.js:111`
- WebKit `main`: `Source/JavaScriptCore/runtime/JSString.h:256,976`
- WebKit commit `97df94ead0` / `319678@main`: `Source/JavaScriptCore/bytecode/UnlinkedMetadataTable.cpp`, `JSTests/stress/unlinked-metadata-table-finalize-overflow.js`

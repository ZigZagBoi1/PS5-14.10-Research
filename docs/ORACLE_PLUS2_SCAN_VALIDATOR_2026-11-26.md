# Offline grader for the FontFace oracle +2 offset scan (2026-11-26)

**Grade:** tool contract, grounded in issue #305's reported capture semantics.
**Scope:** offline grading of text logs only. No console, probe execution, network, or exploitation is involved.

## Why

Issue #305 reports that the `document.fonts.check()` u32 oracle can separate heap pointers from text pointers by reading at bsearch offset **+2** (bytes 2–5 of a 64-bit word) instead of the old +3 offset. The reported +2 values are:

| Family | +2 u32 range | Interpretation |
|---|---|---|
| zero/small | `< 0x10000` | no pointer evidence |
| text (`0x01XX…`) | `0x10000`–`0x1FFFF` | byte4 = `0x01` |
| heap (`0x10XX…`) | `0x100000`–`0x10FFFF` | byte4 = `0x10` |
| all-false ceiling | `> 0x10FFFF` (e.g. `0x110000`) | unreadable; **not** pointer evidence |

Each bsearch costs 21 `check()` calls; SELF discovery costs 3; a page load has a ~120-call budget, i.e. at most five reads per probe.

`tools/analyze_oracle_scan.py` applies those rules to a committed beacon/console log and grades the claim instead of trusting the probe's own annotation.

## Usage

```
python tools/analyze_oracle_scan.py results/walk5.log
python tools/analyze_oracle_scan.py beacons.log --uid ABC123 --json
```

Accepted tokens are `<REGION>+<OFFSET>=<value>` +2 reads (e.g. `P3+0=0x1A201`), plus `SELF=`, `CALLS=`, `VTAB=` and `UID=`. nginx `BEACON` lines and `%3D`/`%26`-encoded messages are decoded first. Runs are grouped by UID; `--uid` selects one.

Full-width evidence uses separate tokens, so it is not charged to the +2 call budget:

| Token | Meaning |
|---|---|
| `FW_<REGION>+<OFFSET>=<0x…>` | full-width qword read at that slot |
| `GEN=<n>` | generation stamp applied to subsequent `FW_` reads (default 1) |
| `MARK_<REGION>+<OFFSET>=<0x…>` | planted byte signature for that slot |
| `ECHO_MASK=<0x…>` | bits that must echo across generations; **default `0xFFFFFFFFFFFF` (full 48 bits)** |

The default is deliberately full-width. Narrowing it with `ECHO_MASK` is an explicit, recorded choice, never a silent truncation.

## Verdict ladder

| Verdict | Meaning |
|---|---|
| `FULLWIDTH_CONFIRMED` | all `TEXT_PTR_CONFIRMED` conditions, plus full-width byte-echo agreement on the same slot across two generations, with no flip-class value |
| `TEXT_PTR_CONFIRMED` | text-family read + same-object `+2` confirm + an in-band `VTAB` claim, with a valid call budget |
| `FLIP_CLASS_SUSPECT` | a full-width read's low dword is `0x80000004` or `0x7FFFFFF4` — cobrajet302gt's 7/7-boot stale-alias flip class; downgraded even if the +2 checks passed |
| `TEXT_FAMILY_CONFIRMED` | read + confirm agree, but no full VTAB claim was supplied |
| `TEXT_FAMILY_ONLY` | a text-family read exists but was not confirmed |
| `NO_TEXT_POINTER` | no text-family read; a clean negative |
| `INVALID_RUN` | malformed value/token, budget overrun, call-count mismatch, or out-of-band VTAB |

Echo failures are downgrades, not errors: the record keeps `TEXT_PTR_CONFIRMED` and adds a `FULLWIDTH_ECHO_FAILED:<slot>:<reason>` note (`NEED_TWO_GENERATIONS`, `MARKER_MISMATCH`, or `ECHO_MISMATCH`). When a `MARK_` is present, every generation must echo it under `ECHO_MASK`; without a marker, the generations must agree with each other.

Exit code is 0 when every selected run is internally consistent, 1 otherwise. A clean negative is not a failure: the tool grades the *quality of the evidence*, not the desirability of the finding.

## What it does not prove

- It does not reconstruct a module base or identify a C++ class from a +2 value. The issue's own VTAB value must be supplied explicitly and is only checked for the `0x1XXXXXXXX` band.
- A `TEXT_PTR_CONFIRMED` verdict means the capture is internally consistent with the reported oracle semantics; it is **not** an independent device measurement and not a proof of a usable arbitrary read. `FULLWIDTH_CONFIRMED` raises the evidence bar but is still a log grade, not a device result.
- The 4-byte `+2` regime is known to false-positive (`0x80000004↔0x7FFFFFF4`, 7/7 boots on cobrajet302gt's unit #3); this is why the full-width tier exists. It does not retroactively validate earlier +2-only claims.
- No claim about firmware other than the bench that produced the log is made. Firmware 14.10 captures and 13.20/13.60 captures must be graded separately.

## Tests

`tools/test_analyze_oracle_scan.py` uses only synthetic logs (17 cases: class table, confirmation ladder, budget/call/VTAB failures, encoded beacons, UID filtering, malformed input, clean negative, full-width promotion, echo mismatch, no-truncation, explicit mask, flip class, single generation). The module is registered in `tools/verify_offline.py` and pinned in `tests/test_offline_verification.py`; the bounded gate passes with **431 tests and 7–8 skipped depending on optional deps** (`lupa`, `capstone`) — the original 424-test gate was independently reproduced by cobrajet302gt on 2026-11-26 with 8 skips.

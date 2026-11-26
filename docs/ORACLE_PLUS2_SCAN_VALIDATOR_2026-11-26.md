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

Accepted tokens are `<REGION>+<OFFSET>=<value>` reads (e.g. `P3+0=0x1A201`), plus `SELF=`, `CALLS=`, `VTAB=` and `UID=`. nginx `BEACON` lines and `%3D`/`%26`-encoded messages are decoded first. Runs are grouped by UID; `--uid` selects one.

## Verdict ladder

| Verdict | Meaning |
|---|---|
| `TEXT_PTR_CONFIRMED` | text-family read + same-object `+2` confirm + an in-band `VTAB` claim, with a valid call budget |
| `TEXT_FAMILY_CONFIRMED` | read + confirm agree, but no full VTAB claim was supplied |
| `TEXT_FAMILY_ONLY` | a text-family read exists but was not confirmed |
| `NO_TEXT_POINTER` | no text-family read; a clean negative |
| `INVALID_RUN` | malformed value, budget overrun, call-count mismatch, or out-of-band VTAB |

Exit code is 0 when every selected run is internally consistent, 1 otherwise. A clean negative is not a failure: the tool grades the *quality of the evidence*, not the desirability of the finding.

## What it does not prove

- It does not reconstruct a module base or identify a C++ class from a +2 value. The issue's own VTAB value must be supplied explicitly and is only checked for the `0x1XXXXXXXX` band.
- A `TEXT_PTR_CONFIRMED` verdict means the capture is internally consistent with the reported oracle semantics; it is **not** an independent device measurement and not a proof of a usable arbitrary read.
- No claim about firmware other than the bench that produced the log is made. Firmware 14.10 captures and 13.20/13.60 captures must be graded separately.

## Tests

`tools/test_analyze_oracle_scan.py` uses only synthetic logs (10 cases: class table, confirmation ladder, budget/call/Vtab failures, encoded beacons, UID filtering, malformed input, clean negative). The module is registered in `tools/verify_offline.py` and pinned in `tests/test_offline_verification.py`; the bounded gate passes (424 tests, 7 skipped).

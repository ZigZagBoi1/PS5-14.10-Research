# fonts.check oracle polarity fix — boundary() word reader repair

Date: 2026-11-19 (corrected 2026-11-27)
Type: offline probe repair (no console run)
Scope: 19 main probes plus two adapted-guide-entry variants carrying the `boundary()` bug
Reference: PR #303 session doc (docs/SESSION_2026-11-18.md, §2/CAL38) — hex0x42424242's
on-device calibration of the `document.fonts.check` oracle. Flagged there as "boundary()
had inverted polarity since birth; fixed in p693 (still to propagate to p691/p672/p809)".
This document is the propagation.

## Oracle semantics (as calibrated on-device in p693 v7, grade [M] there)

`document.fonts.check(c) === true  <=>  from <= c <= to`, where `from`/`to` are
the u32 pair at the address the forge-read aims at (a `unicode-range` pair in the
reclaimed FontFace lane). The probe helpers use two conventions:

- Raw helper: `chk(c) = document.fonts.check(...)`; largest `chk(c)===true` is TO.
- Negated helper: `chk(c) = document.fonts.check(...)===false`; largest
  `chk(c)===false` is TO.

The planted signature `check(0x1000)T ∧ check(0xFFF)F ∧ check(0x2000)T ∧
check(0x2001)F` is exactly the range `[0x1000, 0x2000]` — the two words the probe
planted at +0x38/+0x3C.

## The bug (corrected 2026-11-27)

The 19 main-directory probes use the negated helper, but their `boundary()` loops
searched for the largest `chk(c)===true` — the largest **uncovered** codepoint,
normally `0x10FFFF`, not the TO word. The old `chk(0)!==true` pre-gate rejected
zero-based ranges and passed `from>0` ranges; removing it alone did not repair the
polarity. The two adapted-guide-entry variants use the raw helper but carried the
opposite largest-false loop, so they had the mirror-image failure.

## The fix

Remove the `chk(0)` pre-gate and match the search polarity to the helper:

- Main-directory negated helpers search for the largest `chk(c)===false`.
- Adapted raw helpers search for the largest `chk(c)===true`.
- The adapted p811 status3 liveness check also tests `chk(0x10FFFF)===false`, so a
  zero-based range that covers all three sampled points still reaches the scan.

No other probe logic is changed. Historical boundary-derived beacons remain
no-data; the four-point signature beacons are unaffected.

## Files changed (19)

p672-iterateclients-callback-dispatch, p690-walk-forge-oracle, p691-walk-forge-fixed,
p804-vtable-verify, p807-base-discovery, p809-elf-got-reader, p809v24b, p809v25d,
p809v25e, p809v25e10, p809v25e37, p811-addrof-read, p812-heap-scan, p813-arw-read,
p813v2-feng-shui, p814-ur-fengshui, p815-wide-rs, p816-diag, p817-magic-base-discovery.

## NOT changed, and why

- `probes/phase13_webkit/data-gather/probe-modules.html`: uses `chk()` only as the
  four-point signature test (`chk(0x1000)T∧chk(0xFFF)F∧chk(0x2000)T∧chk(0x2001)F`),
  which is CORRECT under the range semantics — it is the exact test that decoded the
  oracle. No boundary() reader exists there; tester beacons are unaffected.
- p693 (PR #303): already fixed by its author (v7/v10 boundary/toOf with an
  additional semantic change — boundary() returns `from`, the smallest true).
  Divergence note: this repair keeps `boundary()` = TO-word reader, matching how the
  19 probes consume it (they planted to=0x2000 and expected 0x2000 back; e.g.
  p691-walk-forge-fixed:358 `Number(boundary(cd))-0x1000` where cd aimed at a
  (0x1000,0x2000) pair). p693's smallest-true version returns `from`; adopting it
  here would change what every existing consumer receives. Both are valid readers;
  the repo's call sites expect the largest covered codepoint, expressed as
  largest-true or largest-false according to the helper's polarity.

## Offline verification (Node harness)

Method per repo convention: functions extracted verbatim from the patched probes and
driven by a simulated oracle (u32-pair range semantics), old body vs new body.

| Pair (from,to) | old negated-helper boundary() | corrected boundary() | Correct `to` |
|---|---|---|---|
| (0x1000, 0x2000) | 0x10ffff | 0x2000 | 0x2000 |
| (0, 0x5000) | -1 (pre-gate rejects) | 0x5000 | 0x5000 |
| (0x3000, 0x1000) empty | 0x10ffff | -1 | -1 |
| (1, 0x2000) engine-ptr-shaped | 0x10ffff | 0x2000 | 0x2000 |
| (0x40, 0x100) | 0x10ffff | 0x100 | 0x100 |

All 19 extracted main-directory functions plus both adapted variants: expected
results across the five cases (105 checks total). The regression module is
`tools/test_fonts_oracle_polarity.py`.

Known limitation (pre-existing, shared by old and new code, NOT introduced by this
fix): the binary search reads `to` exactly only when `to` is reachable by the
[0, 0x10FFFF] halving sequence. A width-1 pair whose point lies off that sequence
returns -1. Probe-planted `to` values (0x2000 etc.) and engine high-dwords (small
ints) are always reachable, so this does not affect any existing call site.

## Beacon-evidence hygiene

Any historical beacon line whose value was derived from a `boundary()` call in the
19 probes above should be read as -1/no-data, not as a measurement. The four-point
chk signature beacons (SELF/VTAB/L1/L2 plants) are unaffected.
## Residual sweep (2026-11-23)

Two adapted-guide-entry variants carried the same inverted family and were
outside the 19-file list (they are not the probe-modules.html exception):

- `probes/phase13_webkit/adapted-guide-entry/p691c-oracle-fix.html`:
  `boundary()` gated on `chk(0)===false` AND searched the largest
  NON-covered c — under the range semantics that is 0x10FFFF for every
  reachable pair (or -1 for zero-based pairs), never the TO word. Every
  `B-*` beacon from this file reads as no-data.
- `probes/phase13_webkit/adapted-guide-entry/p811-oracle-status3.html`:
  the inline boundary scan used the same largest-false loop;
  `BOUNDARY-10ffff` on every live-oracle run.

Both adapted variants now use the raw helper's largest-true reader. The p811
status3 liveness condition also checks the range ceiling, so zero-based ranges
reach the scan instead of being mislabeled `ORACLE-STILL-DEAD`. Historic beacons
from these two files follow the hygiene rule above.

The 2026-11-27 follow-up also corrects the main-directory family: all 19 use the
negated helper, so their `boundary()` loops now search for largest-false (largest
covered) rather than largest-true (largest uncovered). The earlier statement that
the main-directory twins were already fixed was incorrect.


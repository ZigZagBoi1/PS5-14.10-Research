# fonts.check oracle polarity fix — boundary() word reader repair

Date: 2026-11-19
Type: offline probe repair (no console run)
Scope: 19 probes in probes/phase13_webkit/ carrying the historic `boundary()` bug
Reference: PR #303 session doc (docs/SESSION_2026-11-18.md, §2/CAL38) — hex0x42424242's
on-device calibration of the `document.fonts.check` oracle. Flagged there as "boundary()
had inverted polarity since birth; fixed in p693 (still to propagate to p691/p672/p809)".
This document is the propagation.

## Oracle semantics (as calibrated on-device in p693 v7, grade [M] there)

`chk(c) === true  <=>  from <= c <= to`, where `from`/`to` are the u32 pair at the
address the forge-read aims at (a `unicode-range` pair in the reclaimed FontFace lane).

The planted signature `chk(0x1000)T ∧ chk(0xFFF)F ∧ chk(0x2000)T ∧ chk(0x2001)F` is
exactly the range `[0x1000, 0x2000]` — the two words the probe planted at +0x38/+0x3C.

## The bug

All 19 probes carried this `boundary(tgt)`:

    setR(tgt);
    if(chk(0)!==true)return -1;          // <- pre-gate
    var lo=0,hi=0x10FFFF,res=-1;
    while(lo<=hi){...if(r===true){res=mid;lo=mid+1;}else hi=mid-1;}
    return res;

Under the range semantics:

1. The loop finds the LARGEST c with chk(c) true = the `to` word. That much is a
   correct reader of `u32@(aim+4)`.
2. But the `chk(0)` pre-gate requires `from <= 0`, i.e. `from == 0`. Every planted
   pair in these probes uses `from = 0x1000` (or an engine high-dword = 1), so the
   gate fails and `boundary()` returns -1 for essentially every target. The word
   reader never worked in any probe that used this signature — every
   `boundary(...) >= 0` gate downstream was dead, and every derived value was -1.

## The fix

Delete the `chk(0)` pre-gate line only. The binary search is left byte-identical:
it already computes `to` (largest covered c). A comment recording the semantics and
the reason for the gate removal replaces the deleted line. No other probe logic is
touched: `boundary()` previously returned -1 everywhere, so no downstream code path
can regress — paths that never fired now can.

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
  the repo's call sites were written against the largest-true semantics.

## Offline verification (Node harness)

Method per repo convention: functions extracted verbatim from the patched probes and
driven by a simulated oracle (u32-pair range semantics), old body vs new body.

| Pair (from,to) | old boundary() | new boundary() | Correct `to` |
|---|---|---|---|
| (0x1000, 0x2000) | -1 (gate fails — the historic bug) | 0x2000 | 0x2000 |
| (0, 0x5000) | 0x5000 (gate passes; only case that ever worked) | 0x5000 | 0x5000 |
| (0x3000, 0x1000) empty | -1 | -1 | -1 |
| (1, 0x2000) engine-ptr-shaped | -1 | 0x2000 | 0x2000 |
| (0x40, 0x100) | -1 | 0x100 | 0x100 |

All 19 extracted functions: identical results, 5/5 cases each (95 checks total).

Known limitation (pre-existing, shared by old and new code, NOT introduced by this
fix): the binary search reads `to` exactly only when `to` is reachable by the
[0, 0x10FFFF] halving sequence. A width-1 pair whose point lies off that sequence
returns -1; values landing exactly on the search path (e.g. 0x10FFFF) also escape.
Probe-planted `to` values (0x2000 etc.) and engine high-dwords (small ints) are
always reachable, so this does not affect any existing call site.

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

Both now use the calibrated largest-true reader (pre-gate removed where
present), matching the 2026-11-19 repair. Historic beacons from these two
files follow the hygiene rule above. The main-directory twins
(p691-walk-forge-fixed, p811-addrof-read) were already fixed; these
adapted-entry copies were silently skipped by the 19-file sweep.


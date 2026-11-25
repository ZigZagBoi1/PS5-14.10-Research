# Data-gather walk fail-closed repair

Date: 2026-11-25
Type: offline probe/tooling repair (no console run)
Scope: `probes/phase13_webkit/data-gather/probe-modules.html` and `tools/parse_beacons.py`
Branch note: stacked on PR #318, which repairs the pre-existing pinned-module
tuple drift needed to register the new offline test.

## Problem

The tester rig had two independent overclaim paths:

1. `probe-modules.html` set `walkOK=true` as soon as the forged vtable read
   returned 128 hex characters. It never checked that the eight decoded slots
   were nonzero, internally consistent, or members of the expected FontFace
   Client vtable. A garbage read could therefore display `SUCCESS` and emit
   `COMPLETE`.
2. `parse_beacons.py` treated a match against one absolute reference family as
   `MATCH_1360_LAYOUT` and emitted a `base_candidate`. Issue #295 subsequently
   measured the same slot deltas with `VP_RVA=0x724DB28`, while the reference
   family uses `0xC6A1B28`. Relative slot deltas validate the walk shape; they
   cannot select an absolute module base. The uniform-shift branch had the same
   problem: a relative shift is not an independently anchored RVA.

## Fix

### Probe

- Added the pure `validWalkSlots()` helper. It requires module-band pointers,
  the deleting-destructor pair (`S1 == S0 + 0x30`), the ICF-folded empty bodies
  (`S2 == S4 == S5`), and the measured VP-relative deltas:

  | Slot | `VP - slot` |
  |---|---:|
  | S0 | `0x1710B78` |
  | S1 | `0x1710B48` |
  | S2/S4/S5 | `0x324C3D8` |
  | S3 | `0x1710478` |
  | S6 | `0x1ABA728` |
  | S7 | `0x1710318` |

- The production call site now uses the helper instead of assigning `true`.
- The success UI reports `VP` but says `base RVA unresolved`.
- The existing `BASE` beacon is retained for protocol compatibility and parser
  consistency checks, but it is explicitly the probe's assumption-relative
  claim, not a measured base.

### Parser

- Renamed the structural verdicts to `MATCH_REFERENCE_DELTAS` and
  `UNIFORM_SHIFT_REFERENCE_DELTAS`.
- Removed `vp_rva_assumed`, `vp_rva_candidate`, and `base_candidate` outputs.
  Every valid run now carries
  `absolute_rva=unresolved` and an explicit address-inference warning.
- Separated capture consistency from layout recognition. A complete, non-zero,
  self-consistent run with an unknown slot fingerprint keeps `run_valid=true`
  for diagnostics but remains `MISMATCH_MANUAL_REVIEW` and exits 1. Malformed,
  incomplete, contradictory, failed, or zero-slot runs are `INVALID_RUN` and
  also exit 1. Only recognized reference-relative fingerprints exit 0, and they
  still carry no absolute base claim.
- Updated reference comments and JSON field names to stop describing the
  p691-run3 family as a universal 13.60/14.10 layout.

## Files changed

- `probes/phase13_webkit/data-gather/probe-modules.html`
- `tools/parse_beacons.py`
- `tools/test_parse_beacons.py`
- `tools/test_beacon_validity.py`
- `tools/test_data_gather_walk.py` (new)
- `tools/test_probe_js_syntax.py`
- `tools/verify_offline.py`
- `tests/test_offline_verification.py`
- `results/INDEX.md`

Intentionally unchanged: the main p691 probe and its adapted-guide-entry twins.
They do not implement the data-gather beacon protocol and have separate slot
selection logic.

## Offline verification

- Parser regression reproduces issue #295: identical deltas at a different
  absolute VP now return `MATCH_REFERENCE_DELTAS`, `run_valid=true`, and no
  absolute base candidate.
- Node harness extracts `validWalkSlots()` from the real HTML and accepts both
  known absolute layout families while rejecting zero slots, a broken ICF
  collapse, a wrong slot delta, and a low pointer.
- Integration guard asserts the production call site uses the helper and the
  old unconditional `walkOK=true` expression is absent. The guard fails against
  `origin/master`.
- The data-gather page is now parse-checked as a classic script.
- Focused parser/probe/validity/syntax suites: 25 tests, OK.
- Full offline gate: `.venv/bin/python tools/verify_offline.py` — 420 tests,
  OK (7 skipped).

## Evidence hygiene and remaining work

Historical `SUCCESS`/`COMPLETE` beacons from the old probe are not proof that the
decoded slots were valid. Re-run `parse_beacons.py` against the raw slot values;
a fingerprint match still does not establish an absolute RVA.

No console measurement was made. A tester should confirm that a known-good walk
still passes the stricter gate and that an intentionally corrupted slot fails
closed before this is treated as on-device validated.

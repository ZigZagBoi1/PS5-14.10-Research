// CRASH_CLASS: MODERATE
// PROBE 172: JavaScriptCore case runner
//
// Context: the engine was cut at Safari 17.0, so every JSC bug fixed after
// September 2023 is still present. WebKit's own JSTests/stress tree contains one
// regression case per such fix, and those tests were written to crash on the
// engine that lacks the fix. 510 of them are wrapped as pages in the corpus
// (list: /corpus/jsc.json) with harness shims, so a missing `shouldBe` throws
// inside the case instead of stopping it.
//
// One case per document. The first version of this probe loaded each case in an
// iframe of a single document and walked the whole list in one page load. The
// console browser refused at index 288 with "there is not enough free system
// memory": a document that has opened several hundred realms holds what they
// created, and tearing an iframe down does not give it back. After that refusal
// a fresh document died on its eighth case, because the process keeps it. So the
// case page beacons `BEFORE-i`, runs its body, beacons `OK-i` and `GAP-i`, and
// hands control back here for the next index: the document that allocated the
// memory is destroyed at the end of every case.
//
// Protocol, unchanged from p166 so the server's cursor and crash record work as
// before: `BEFORE-i` is emitted at the start of a case and `OK-i` at the end. A
// case that takes the WebProcess down leaves a BEFORE with no OK. The server
// rewrites an unknown path to this probe with ?start=<cursor>, so reloading the
// guide after a crash continues after the case that died.
//
// Query: ?start=N&count=M&list=jsc.json. The runner reads the list, announces
// the range with `BOOT-<total>-from-<start>-to-<end>`, and navigates to the case
// at `start`; each case navigates back here with the following index, so a run
// of any length is a chain of one-case documents.

(function() {
  var BASE = location.protocol + '//' + location.host;

  function param(name, def) {
    var m = new RegExp('[?&]' + name + '=([^&]*)').exec(location.search);
    return m ? decodeURIComponent(m[1]) : def;
  }

  // A session tag separates two loads of this page in one log, and a per-beacon
  // counter makes a beacon's identity. That is not decoration: this browser
  // delivers an async beacon more than once (a single navigator.sendBeacon()
  // call produced two POSTs 3 ms apart, and the XHR version behaved the same),
  // so analysis dedupes on (session, n).
  // The session and its counter live in sessionStorage: the case pages of one
  // run share them, so the log shows one session per guide load with a
  // monotonic beacon number, and the runner's own BOOT beacons continue that
  // numbering instead of restarting it on every hop.
  var SESSION = null;
  var SEQ = 0;
  try {
    SESSION = sessionStorage.getItem('v172s');
    SEQ = +(sessionStorage.getItem('v172n') || 0);
  } catch (e) {}
  if (!SESSION) {
    SESSION = Math.random().toString(36).slice(2, 8);
    try { sessionStorage.setItem('v172s', SESSION); } catch (e) {}
  }

  function B(tag) {
    SEQ = SEQ + 1;
    try { sessionStorage.setItem('v172n', SEQ); } catch (e) {}
    var url = BASE + '/beacon/V172-' + SESSION + '-' + tag + '?t=' + Date.now() + '&n=' + SEQ;
    try {
      if (navigator.sendBeacon && navigator.sendBeacon(url)) return;
    } catch (e) {}
    try {
      var x = new XMLHttpRequest();
      x.open('GET', url, true);
      x.send();
    } catch (e) {}
  }

  // One chain per guide load. A document that was left running when the next
  // one started used to keep walking the corpus in parallel - two chains, two
  // copies of the beacon counter, cases from both ends of the list in one log.
  // Every hop carries the generation that claimed the run, and a document whose
  // generation is not the current one stops instead of competing.
  var genParam = parseInt(param('g', '0'), 10) || 0;
  var gen = 0;
  try {
    gen = +(sessionStorage.getItem('v172g') || 0);
    if (genParam && genParam < gen) { B('STALE-' + genParam); return; }
    gen = genParam || (gen + 1);
    sessionStorage.setItem('v172g', gen);
  } catch (e) {
    gen = genParam || 1;
  }

  var start = parseInt(param('start', '0'), 10) || 0;
  var count = parseInt(param('count', '40'), 10) || 40;

  // A case page left in the console's cache carries the handoff it was built
  // with, and one measured run jumped from index 363 back to 30 when such a
  // page was replayed - the corpus then walked 265 cases a second time and died
  // on a case it had already passed. The highest index this document has
  // reached is the floor for the next hop, so a stale handoff can only repeat
  // nothing.
  try {
    var reached = +(sessionStorage.getItem('v172l') || 0);
    if (reached > start) { B('CLAMP-' + start + '-to-' + reached); start = reached; }
  } catch (e) {}

  var xhr = new XMLHttpRequest();
  xhr.open('GET', BASE + '/corpus/' + param('list', 'jsc.json') + '?t=' + Date.now(), true);
  xhr.onload = function() {
    var list;
    try {
      list = JSON.parse(xhr.responseText);
    } catch (e) {
      B('LIST-BROKEN');
      return;
    }
    var end = Math.min(start + count, list.length);
    try { sessionStorage.setItem('v172l', String(start)); } catch (e) {}
    B('BOOT-' + list.length + '-from-' + start + '-to-' + end);
    if (start >= list.length) {
      B('CORPUS-DONE-' + (list.length - 1));
      return;
    }
    if (start >= end) {
      B('CORPUS-DONE-' + (end - 1));
      return;
    }
    var entry = list[start];
    // The session id doubles as a cache key: a case page left in the console's
    // cache from an earlier build carries an older handoff, and one measured
    // run jumped back to index 0 when such a page was replayed.
    location.replace(BASE + '/corpus/' + entry.file +
                     '?i=' + start + '&next=' + (start + 1) + '&e=' + end +
                     '&c=' + count + '&v=' + SESSION + '&g=' + gen);
  };
  xhr.onerror = function() { B('LIST-FETCH-FAIL'); };
  xhr.send();
})();

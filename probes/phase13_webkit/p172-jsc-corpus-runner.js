// CRASH_CLASS: MODERATE
// PROBE 172: JavaScriptCore case runner
//
// Context: the engine was cut at Safari 17.0, so every JSC bug fixed after
// September 2023 is still present. WebKit's own JSTests/stress tree contains one
// regression case per such fix, and those tests were written to crash on the
// engine that lacks the fix. 518 of them are wrapped as pages in the corpus
// (list: /corpus/jsc.json) with harness shims, so a missing `shouldBe` throws
// inside the case instead of stopping it.
//
// Same protocol as p166: each case loads in its own iframe, `BEFORE-i` is
// emitted before the load and `OK-i` after it, and a case that takes the
// WebProcess down leaves a BEFORE with no OK. The server rewrites an unknown
// path to this probe with ?start=<cursor>, so reloading the guide after a crash
// continues after the case that died.
//
// Query: ?start=N&count=M&timeout=4000&list=jsc.json&reload=1. Forty cases per
// load by default: the run is long enough to be worth one page load, and a crash
// costs one manual reload of the console page.
//
// A batch ends by navigating the document to the next batch. That is not
// cosmetic: the cases run as iframes of one document, and a document that has
// opened several hundred realms is refused by the console's WebProcess with
// "there is not enough free system memory" (measured at index 288 of 513). A
// top-level navigation destroys the document and everything its cases allocated,
// so the next batch starts from the same memory a fresh guide load would have.

(function() {
  var BASE = location.protocol + '//' + location.host;

  function param(name, def) {
    var m = new RegExp('[?&]' + name + '=([^&]*)').exec(location.search);
    return m ? decodeURIComponent(m[1]) : def;
  }

  // A session tag separates two loads of this page in one log, and a per-case
  // token makes a stale load event a no-op instead of a second advance().
  var SESSION = Math.random().toString(36).slice(2, 8);
  var SEQ = 0;

  // Every beacon carries a per-session name and a monotonic counter `n`. That is
  // not decoration: this browser delivers an async beacon more than once (a single
  // navigator.sendBeacon() call produced two POSTs 3 ms apart, and the XHR version
  // behaved the same), so the counter is the beacon's identity. Analysis dedupes on
  // (session, n); a crash is still read from a BEFORE with no OK after it.
  function B(tag) {
    var url = BASE + '/beacon/V172-' + SESSION + '-' + tag + '?t=' + Date.now() + '&n=' + (++SEQ);
    try {
      if (navigator.sendBeacon && navigator.sendBeacon(url)) return;
    } catch (e) {}
    try {
      var x = new XMLHttpRequest();
      x.open('GET', url, true);
      x.send();
    } catch (e) {}
  }

  var start = parseInt(param('start', '0'), 10) || 0;
  // A batch of 120 keeps the peak well under the measured wall at 288 while
  // staying long enough that the navigation overhead is noise.
  var count = Math.min(parseInt(param('count', '40'), 10) || 40, 120);
  var reload = param('reload', '1') !== '0';
  var stall = parseInt(param('timeout', '4000'), 10) || 4000;

  var list = null;
  var active = null;

  // The next batch is a fresh document. The server rebuilds the redirect from
  // its own cursor, so this asks for the same deep path the User's Guide asks
  // for and lets the server decide where the batch starts; "/" would be the
  // index page, not the runner.
  function nextBatch() {
    location.assign(BASE + param('nav', '/document/en/ps5/support/index.html'));
  }

  function advance(i, end) {
    if (i >= end) {
      if (end < list.length && reload) {
        B('BATCH-END-' + (end - 1));
        setTimeout(nextBatch, 200);
        return;
      }
      B('CORPUS-DONE-' + (end - 1));
      return;
    }
    var entry = list[i];
    B('BEFORE-' + i);

    var frame = document.createElement('iframe');
    var token = {};
    var timer = null;
    active = token;

    function finish(kind) {
      if (active !== token) return;
      active = null;
      clearTimeout(timer);
      B(kind + '-' + i + '-' + entry.file.replace(/[^A-Za-z0-9._-]/g, ''));
      try { frame.parentNode.removeChild(frame); } catch (e) {}
      // Emitted after the frame is gone: OK-i without GAP-i means the process
      // died while tearing that case down, which is a different bug location
      // from a crash while the next case loads.
      B('GAP-' + i);
      // The iframe is gone but its realm is only collectable; ask for a
      // collection when the page has the controller, which it does here.
      try { if (window.GCController) GCController.collectAll(); } catch (e) {}
      setTimeout(function() { advance(i + 1, end); }, 80);
    }

    frame.onload = function() { finish('OK'); };
    frame.onerror = function() { finish('ERR'); };
    frame.style.cssText = 'width:320px;height:200px;border:1px solid #ccc';
    frame.src = BASE + '/corpus/' + entry.file;
    document.body.appendChild(frame);

    timer = setTimeout(function() { finish('STALL'); }, stall);
  }

  var xhr = new XMLHttpRequest();
  xhr.open('GET', BASE + '/corpus/' + param('list', 'jsc.json') + '?t=' + Date.now(), true);
  xhr.onload = function() {
    try {
      list = JSON.parse(xhr.responseText);
    } catch (e) {
      B('LIST-BROKEN');
      return;
    }
    var end = Math.min(start + count, list.length);
    B('BOOT-' + list.length + '-from-' + start + '-to-' + end);
    if (start >= list.length) {
      B('LIST-EMPTY');
      return;
    }
    advance(start, end);
  };
  xhr.onerror = function() { B('LIST-FETCH-FAIL'); };
  xhr.send();
})();

// CRASH_CLASS: MODERATE
// PROBE 166: layout-test corpus runner
//
// Context: the console's engine was cut around Safari 17.0 while the firmware
// shipped in 2026, so three years of WebKit crash fixes are absent from it.
// WebKit's own layout tests reproduce those crashes and are public; this page
// replays them one at a time and lets the beacon log say which one, if any,
// kills the WebProcess here.
//
// Each case is loaded into its own iframe. A case that merely throws still
// reaches the iframe's load event, so `OK-<i>-<file>` is emitted; a case that
// takes the process down emits nothing, and the last `BEFORE-<i>` in the log
// names it. `STALL-<i>` covers the third outcome, a test that never finishes
// loading because it waits on a harness hook this browser does not provide.
//
// Query: ?start=N&count=M&timeout=4000. The server rewrites an unknown path to
// this probe with ?start=<cursor>, where the cursor is the first case that has
// not closed yet. The server keeps that cursor per load of this page, so a
// case that takes the WebProcess down is skipped and the next guide load
// resumes after it: reloading the console page walks the whole corpus.
//
// The case list is /corpus/list.json (path, file, subject) served from
// results/webkit/corpus by tools/webkit_server.py --corpus.

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
    var url = BASE + '/beacon/V166-' + SESSION + '-' + tag + '?t=' + Date.now() + '&n=' + (++SEQ);
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
  var count = parseInt(param('count', '25'), 10) || 25;
  var stall = parseInt(param('timeout', '4000'), 10) || 4000;

  var list = null;
  var active = null;

  function advance(i, end) {
    if (i >= end) {
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
  xhr.open('GET', BASE + '/corpus/list.json?t=' + Date.now(), true);
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

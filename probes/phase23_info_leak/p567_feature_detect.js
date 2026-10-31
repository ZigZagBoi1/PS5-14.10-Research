// PROBE P567: WebKit feature detection for info leak planning
//
// GOAL: Determine which APIs are available on PS5 14.10 WebKit
//       to plan the info leak approach. Tests non-FPU byte access
//       paths, memory sharing, and async primitives.
//
// DELIVERY: host.py DNS spoofing + HTTPS (User Guide redirect)

(() => {
  const B = (tag, extra = '') => {
    new Image().src = '/beacon/P567-' + encodeURIComponent(tag) +
      (extra ? '-' + encodeURIComponent(extra) : '') +
      '?t=' + performance.now().toFixed(0);
  };

  B('BOOT');

  const features = {};
  const check = (name, fn) => {
    try {
      const v = fn();
      features[name] = v === undefined ? 'YES' : String(v);
    } catch (e) {
      features[name] = 'NO:' + e.name;
    }
  };

  // Integer types (no FPU, bypass DAZ)
  check('BigInt', () => typeof BigInt(0));
  check('BigUint64Array', () => typeof BigUint64Array);
  check('BigInt64Array', () => typeof BigInt64Array);
  check('DataView.getBigUint64', () => typeof DataView.prototype.getBigUint64);

  // Memory sharing (cross-thread access)
  check('SharedArrayBuffer', () => typeof SharedArrayBuffer);
  check('Atomics', () => typeof Atomics);

  // WebAssembly (non-FPU memory access via i64)
  check('WebAssembly', () => typeof WebAssembly);
  check('WebAssembly.Memory', () => typeof WebAssembly.Memory);
  check('WebAssembly.instantiate', () => typeof WebAssembly.instantiate);

  // Canvas variants
  check('OffscreenCanvas', () => typeof OffscreenCanvas);
  check('createImageBitmap', () => typeof createImageBitmap);
  check('ImageBitmap', () => typeof ImageBitmap);

  // ArrayBuffer operations
  check('ArrayBuffer.transfer', () => typeof ArrayBuffer.prototype.transfer);
  check('ArrayBuffer.resize', () => typeof ArrayBuffer.prototype.resize);
  check('structuredClone', () => typeof structuredClone);

  // GC observation
  check('WeakRef', () => typeof WeakRef);
  check('FinalizationRegistry', () => typeof FinalizationRegistry);

  // Workers
  check('Worker', () => typeof Worker);
  check('Blob', () => typeof Blob);
  check('URL.createObjectURL', () => typeof URL.createObjectURL);

  // Timing precision
  check('performance.now', () => {
    const samples = [];
    for (let i = 0; i < 20; i++) {
      const t0 = performance.now();
      let t1 = t0;
      while (t1 === t0) t1 = performance.now();
      samples.push(t1 - t0);
    }
    const min = Math.min(...samples);
    return min.toFixed(4) + 'ms';
  });

  // requestAnimationFrame
  check('requestAnimationFrame', () => typeof requestAnimationFrame);

  // Canvas2D specific
  check('Path2D', () => typeof Path2D);
  check('CanvasPattern', () => typeof CanvasPattern);
  check('CSS.registerProperty', () => typeof CSS?.registerProperty);

  // TextEncoder/Decoder (byte manipulation)
  check('TextEncoder', () => typeof TextEncoder);

  // Crypto (random bytes)
  check('crypto.getRandomValues', () => typeof crypto?.getRandomValues);

  // Report all features
  for (const [k, v] of Object.entries(features)) {
    B('FEAT', k + '=' + v);
  }

  // === PHASE B: BigUint64Array pointer read test ===
  // If BigUint64Array works, we can read FontFace-leaked pointers as integers
  // (not float64), completely bypassing DAZ
  try {
    const ab = new ArrayBuffer(16);
    const dv = new DataView(ab);
    // Write a fake "pointer" pattern: 0x0000001012345678
    dv.setUint32(0, 0x12345678, true); // low 32
    dv.setUint32(4, 0x00000010, true); // high 32 (heap range)

    // Read as BigUint64
    const bu64 = new BigUint64Array(ab);
    const val = bu64[0];
    const hex = val.toString(16);
    B('BIGINT-READ', hex);

    // Also test DataView.getBigUint64
    if (typeof dv.getBigUint64 === 'function') {
      const val2 = dv.getBigUint64(0, true);
      B('DV-BIGINT', val2.toString(16));
    }
  } catch (e) {
    B('BIGINT-READ-ERR', e.name + ':' + e.message.slice(0, 60));
  }

  // === PHASE C: Wasm i64 test ===
  // If Wasm works, we can load/store i64 values without FPU
  try {
    if (typeof WebAssembly !== 'undefined') {
      // Minimal Wasm module that reads i64 from memory
      const bytes = new Uint8Array([
        0x00, 0x61, 0x73, 0x6D, // magic
        0x01, 0x00, 0x00, 0x00, // version
        // Type section: (i32) -> i64
        0x01, 0x06, 0x01, 0x60, 0x01, 0x7F, 0x01, 0x7E,
        // Import section: memory
        0x02, 0x0B, 0x01, 0x02, 0x6A, 0x73, 0x03, 0x6D, 0x65, 0x6D, 0x02, 0x00, 0x01,
        // Function section
        0x03, 0x02, 0x01, 0x00,
        // Export section: "r" = func 0
        0x07, 0x05, 0x01, 0x01, 0x72, 0x00, 0x00,
        // Code section: i64.load from offset arg
        0x0A, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x29, 0x03, 0x00, 0x0B
      ]);
      const mod = new WebAssembly.Module(bytes);
      const mem = new WebAssembly.Memory({ initial: 1 });
      const inst = new WebAssembly.Instance(mod, { js: { mem: mem } });

      // Write test pointer pattern to Wasm memory
      const view = new DataView(mem.buffer);
      view.setUint32(0, 0xDEADBEEF, true);
      view.setUint32(4, 0x00000010, true);

      // Read via Wasm i64.load
      const result = inst.exports.r(0);
      B('WASM-I64', typeof result + ':' + String(result).slice(0, 30));
    }
  } catch (e) {
    B('WASM-ERR', e.name + ':' + e.message.slice(0, 80));
  }

  // === PHASE D: Inline Worker test ===
  try {
    const code = 'self.postMessage("alive")';
    const blob = new Blob([code], { type: 'application/javascript' });
    const url = URL.createObjectURL(blob);
    const w = new Worker(url);
    w.onmessage = (e) => {
      B('WORKER', e.data);
      w.terminate();
      URL.revokeObjectURL(url);
    };
    w.onerror = (e) => {
      B('WORKER-ERR', e.message?.slice(0, 60) || 'unknown');
    };
    setTimeout(() => B('WORKER-TIMEOUT'), 2000);
  } catch (e) {
    B('WORKER-ERR', e.name);
  }

  B('DONE');
  setTimeout(() => B('ALIVE-5s'), 5000);
})();

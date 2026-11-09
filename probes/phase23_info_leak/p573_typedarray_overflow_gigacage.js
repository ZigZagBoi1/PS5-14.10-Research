// PROBE P573: TypedArray/DataView integer overflow + Gigacage verification
//
// TWO critical questions:
// 1. Is Gigacage disabled on PS5 14.10? (ArrayBuffer shares heap with JSC objects)
// 2. Do TypedArray/DataView large-offset operations overflow to OOB access?
//
// If Gigacage is OFF and overflow works → direct OOB R/W, no UAF needed.
// Uses BigUint64Array to read raw 64-bit values (bypasses DAZ).

(function() {
  var B = location.protocol + '//' + location.host + '/beacon.php?tag=';
  function send(msg) {
    try { navigator.sendBeacon(B + encodeURIComponent(msg)); } catch(e) {
      try { new Image().src = B + encodeURIComponent(msg); } catch(e2) {}
    }
  }
  function hx32(v) { return ('00000000' + (v >>> 0).toString(16)).slice(-8); }

  send('P573-BOOT');

  // === PHASE A: Feature detection (critical for exploit planning) ===
  var features = [];
  try { features.push('BI:' + (typeof BigInt !== 'undefined' ? 'Y' : 'N')); } catch(e) { features.push('BI:ERR'); }
  try { features.push('BU64:' + (typeof BigUint64Array !== 'undefined' ? 'Y' : 'N')); } catch(e) { features.push('BU64:ERR'); }
  try { features.push('SC:' + (typeof structuredClone !== 'undefined' ? 'Y' : 'N')); } catch(e) { features.push('SC:ERR'); }
  try { features.push('WA:' + (typeof WebAssembly !== 'undefined' ? 'Y' : 'N')); } catch(e) { features.push('WA:ERR'); }
  try { features.push('SAB:' + (typeof SharedArrayBuffer !== 'undefined' ? 'Y' : 'N')); } catch(e) { features.push('SAB:ERR'); }
  try {
    var dvt = new DataView(new ArrayBuffer(8));
    features.push('DV64:' + (typeof dvt.getBigUint64 === 'function' ? 'Y' : 'N'));
  } catch(e) { features.push('DV64:ERR'); }
  try {
    var w = new Worker(URL.createObjectURL(new Blob(['postMessage(1)'],{type:'application/javascript'})));
    w.onmessage = function() { send('P573-WORKER-OK'); w.terminate(); };
    w.onerror = function() { send('P573-WORKER-FAIL'); };
    setTimeout(function() { try { w.terminate(); } catch(e) {} }, 2000);
  } catch(e) { features.push('WK:N'); }
  send('P573-FEAT|' + features.join(','));

  // === PHASE B: Gigacage probe ===
  // If Gigacage is active, ArrayBuffer backing stores are in a separate 32GB region.
  // If disabled, they share the heap with JSC objects.
  // Test: compare addresses of adjacent ArrayBuffer backing stores and JS object pointers.
  try {
    var bufs = [];
    for (var i = 0; i < 100; i++) {
      var ab = new ArrayBuffer(256);
      var u8 = new Uint8Array(ab);
      // Write sentinel pattern
      for (var j = 0; j < 256; j++) u8[j] = 0xBB;
      bufs.push({ab: ab, u8: u8});
    }

    // Check if BigUint64Array is available for raw pointer reads
    if (typeof BigUint64Array !== 'undefined') {
      // Read backing store addresses by creating adjacent buffers and checking
      // whether their data appears near JSC object addresses
      var ab1 = new ArrayBuffer(64);
      var ab2 = new ArrayBuffer(64);
      var dv1 = new DataView(ab1);
      var dv2 = new DataView(ab2);
      // Write markers
      dv1.setUint32(0, 0xAAAAAAAA, true);
      dv2.setUint32(0, 0xBBBBBBBB, true);

      // Try to detect address range via toString representation
      send('P573-GC-AB1|' + ab1.toString() + '|len=' + ab1.byteLength);

      // Test ArrayBuffer.transfer if available (detach + relocate)
      if (typeof ab1.transfer === 'function') {
        send('P573-GC-TRANSFER|available');
      } else {
        send('P573-GC-TRANSFER|unavailable');
      }

      send('P573-GC-DONE|bufs=' + bufs.length);
    } else {
      send('P573-GC-NOBI|no BigUint64Array');
    }
  } catch(e) {
    send('P573-GC-ERR|' + e.name + ':' + (e.message || '').substring(0, 50));
  }

  // === PHASE C: DataView large-offset overflow test ===
  // If internal offset calc overflows, dv.getUint8(huge_offset) reads OOB
  try {
    var testBuf = new ArrayBuffer(256);
    var testU8 = new Uint8Array(testBuf);
    // Fill with sentinel
    for (var i = 0; i < 256; i++) testU8[i] = 0xCC;

    var dv = new DataView(testBuf);
    var results = [];

    // Test large offsets that might overflow internal calculations
    var offsets = [
      0x7FFFFFFF,          // INT32_MAX
      0x80000000,          // INT32_MAX + 1
      0xFFFFFFFF,          // UINT32_MAX
      0x100000000,         // UINT32_MAX + 1
      0x1FFFFFFFFFFFFF,    // MAX_SAFE_INTEGER
      -1,                  // Negative
      -256,                // Negative aligned
      4294967040,          // 0xFFFFFF00 — wraps to -256 as int32
      0x7FFFFFF0           // Large aligned
    ];

    for (var oi = 0; oi < offsets.length; oi++) {
      var off = offsets[oi];
      try {
        var val = dv.getUint8(off);
        // If we get here without RangeError, the offset was accepted!
        results.push('OFF' + oi + ':' + off + '=0x' + hx32(val) + (val !== 0xCC ? '!OOB!' : ''));
      } catch(e) {
        results.push('OFF' + oi + ':' + off + '=' + e.name.substring(0, 5));
      }
    }
    send('P573-DV|' + results.join(','));
  } catch(e) {
    send('P573-DV-ERR|' + e.name);
  }

  // === PHASE D: TypedArray.subarray with overflow offsets ===
  try {
    var srcBuf = new ArrayBuffer(1024);
    var srcU8 = new Uint8Array(srcBuf);
    for (var i = 0; i < 1024; i++) srcU8[i] = 0xDD;

    var subResults = [];

    // subarray(begin, end) — what if begin > length but wraps?
    var subOffsets = [
      [0, 1024],           // Normal (baseline)
      [0x7FFFFFFF, 0x80000000], // INT32 overflow
      [-1, 10],            // Negative begin
      [0xFFFFFFFF, 0x100000000], // UINT32 wrap
      [1024, 0],           // Reversed
      [0, -1]              // Negative end
    ];

    for (var si = 0; si < subOffsets.length; si++) {
      try {
        var sub = srcU8.subarray(subOffsets[si][0], subOffsets[si][1]);
        subResults.push('S' + si + ':len=' + sub.length);
        // Check if any byte is not 0xDD (OOB data)
        var nonDD = 0;
        for (var j = 0; j < Math.min(sub.length, 64); j++) {
          if (sub[j] !== 0xDD) nonDD++;
        }
        if (nonDD > 0) subResults.push('S' + si + ':OOB=' + nonDD + '!');
      } catch(e) {
        subResults.push('S' + si + ':' + e.name.substring(0, 8));
      }
    }
    send('P573-SUB|' + subResults.join(','));
  } catch(e) {
    send('P573-SUB-ERR|' + e.name);
  }

  // === PHASE E: TypedArray.set with length confusion ===
  try {
    var dst = new ArrayBuffer(64);
    var dstU8 = new Uint8Array(dst);
    for (var i = 0; i < 64; i++) dstU8[i] = 0xEE;

    var setResults = [];

    // set(source, offset) — try offset that causes overflow
    var setOffsets = [0, 32, 63, 64, 128, 0x7FFFFFFF, -1];
    var smallSrc = new Uint8Array([0x41, 0x42, 0x43, 0x44]);

    for (var si = 0; si < setOffsets.length; si++) {
      try {
        dstU8.set(smallSrc, setOffsets[si]);
        // Check if write went OOB
        setResults.push('W' + si + ':ok');
      } catch(e) {
        setResults.push('W' + si + ':' + e.name.substring(0, 8));
      }
    }

    // Check dst buffer state after all writes
    var changed = 0;
    for (var i = 0; i < 64; i++) {
      if (dstU8[i] !== 0xEE && dstU8[i] !== 0x41 && dstU8[i] !== 0x42 &&
          dstU8[i] !== 0x43 && dstU8[i] !== 0x44) changed++;
    }
    setResults.push('chg=' + changed);
    send('P573-SET|' + setResults.join(','));
  } catch(e) {
    send('P573-SET-ERR|' + e.name);
  }

  // === PHASE F: ArrayBuffer slice with overflow ===
  try {
    var sliceBuf = new ArrayBuffer(256);
    var sliceU8 = new Uint8Array(sliceBuf);
    for (var i = 0; i < 256; i++) sliceU8[i] = 0xFF;

    var sliceResults = [];
    var sliceArgs = [
      [0, 256],            // Normal
      [0, 0x7FFFFFFF],     // Huge end
      [-1, 256],           // Negative start
      [0x80000000, 0x80000100], // Both huge
      [128, -1],           // Negative end
      [0, -128]            // Negative end smaller
    ];

    for (var si = 0; si < sliceArgs.length; si++) {
      try {
        var s = sliceBuf.slice(sliceArgs[si][0], sliceArgs[si][1]);
        var su8 = new Uint8Array(s);
        var nonFF = 0;
        for (var j = 0; j < Math.min(su8.length, 64); j++) {
          if (su8[j] !== 0xFF) nonFF++;
        }
        sliceResults.push('L' + si + ':len=' + s.byteLength + (nonFF > 0 ? ',oob=' + nonFF + '!' : ''));
      } catch(e) {
        sliceResults.push('L' + si + ':' + e.name.substring(0, 8));
      }
    }
    send('P573-SLICE|' + sliceResults.join(','));
  } catch(e) {
    send('P573-SLICE-ERR|' + e.name);
  }

  // === PHASE G: Structured clone behavior (Relapse-class technique) ===
  try {
    if (typeof structuredClone !== 'undefined') {
      var origAB = new ArrayBuffer(128);
      var origU8 = new Uint8Array(origAB);
      for (var i = 0; i < 128; i++) origU8[i] = i;

      // Clone normally
      var cloned = structuredClone(origAB);
      var clonedU8 = new Uint8Array(cloned);
      var match = true;
      for (var i = 0; i < 128; i++) {
        if (clonedU8[i] !== i) { match = false; break; }
      }
      send('P573-SC|clone=' + (match ? 'OK' : 'MISMATCH') + ',origLen=' + origAB.byteLength + ',cloneLen=' + cloned.byteLength);

      // Clone with transfer (detaches original)
      try {
        var origAB2 = new ArrayBuffer(64);
        new Uint8Array(origAB2).fill(0x77);
        var cloned2 = structuredClone(origAB2, { transfer: [origAB2] });
        send('P573-SC-TFR|origLen=' + origAB2.byteLength + ',cloneLen=' + cloned2.byteLength);
        // After transfer, origAB2 should be detached (byteLength = 0)
        // If origAB2.byteLength is still 64, something is wrong
      } catch(e) {
        send('P573-SC-TFR-ERR|' + e.name + ':' + (e.message || '').substring(0, 40));
      }

      // Clone TypedArray with weird length
      try {
        var weirdTA = new Uint8Array(new ArrayBuffer(256), 0, 256);
        var clonedTA = structuredClone(weirdTA);
        send('P573-SC-TA|origLen=' + weirdTA.length + ',cloneLen=' + clonedTA.length +
             ',origBuf=' + weirdTA.buffer.byteLength + ',cloneBuf=' + clonedTA.buffer.byteLength);
      } catch(e) {
        send('P573-SC-TA-ERR|' + e.name);
      }
    } else {
      send('P573-SC|unavailable');
    }
  } catch(e) {
    send('P573-SC-ERR|' + e.name);
  }

  // === PHASE H: ImageData dimension overflow ===
  try {
    var imgResults = [];
    // new ImageData(w, h) allocates w*h*4 bytes
    // Try values where w*h*4 overflows
    var dims = [
      [4, 4],              // Normal (64 bytes)
      [65536, 1],          // 256KB
      [16384, 16384],      // 1GB — should fail
      [0x7FFFFFFF, 1],     // INT32_MAX * 4 overflow
      [1, 0x7FFFFFFF],     // Same via height
      [65536, 65536],      // 16GB — should fail
      [0, 1],              // Zero width
      [1, 0]               // Zero height
    ];

    for (var di = 0; di < dims.length; di++) {
      try {
        var id = new ImageData(dims[di][0], dims[di][1]);
        imgResults.push('D' + di + ':' + id.width + 'x' + id.height + ',len=' + id.data.length);
      } catch(e) {
        imgResults.push('D' + di + ':' + e.name.substring(0, 8));
      }
    }
    send('P573-IMG|' + imgResults.join(','));
  } catch(e) {
    send('P573-IMG-ERR|' + e.name);
  }

  send('P573-DONE');
})();

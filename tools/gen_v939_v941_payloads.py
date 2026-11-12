"""Generate v939/v941 fuzz payloads under tools/browser_runner/fuzzcases/.

Fonts: OUTLOOK.TTF (17KB) as base -> sfnt mutants + a WOFF wrapper (no
compression) + WOFF mutants. Images: PIL-generated minimal files per format
+ byte-level malformed mutants. Everything is written flat into
fuzzcases/fonts/ and fuzzcases/images/ and served by the existing
/fuzzcases/ handler (exact paths, no allowlist needed).
"""
import struct
import pathlib
from PIL import Image

HERE = pathlib.Path(__file__).resolve().parent
FUZZ = HERE / 'browser_runner' / 'fuzzcases'
FONT_DIR = FUZZ / 'fonts'
IMG_DIR = FUZZ / 'images'
FONT_DIR.mkdir(parents=True, exist_ok=True)
IMG_DIR.mkdir(parents=True, exist_ok=True)

BASE = pathlib.Path(r'C:\Windows\Fonts\OUTLOOK.TTF')
ttf = BASE.read_bytes()

# ---------------- sfnt helpers ----------------

def sfnt_tables(data):
    num = struct.unpack('>H', data[4:6])[0]
    out = []
    for i in range(num):
        off = 12 + 16 * i
        tag, cks, toff, tlen = struct.unpack('>4sIII', data[off:off + 16])
        out.append((tag, cks, toff, tlen))
    return out

def patch_at(data, off, raw):
    return data[:off] + raw + data[off + len(raw):]

fonts = {}

fonts['f00_valid.ttf'] = ttf  # control

# f01: sfnt magic flipped 0x00010000 -> 0x00020000
fonts['f01_badmagic.ttf'] = patch_at(ttf, 0, struct.pack('>I', 0x00020000))
# f02: numTables inflated to 0xFFFF
fonts['f02_numtables_ffff.ttf'] = patch_at(ttf, 4, struct.pack('>H', 0xFFFF))
# f03: truncated at half
fonts['f03_trunc_half.ttf'] = ttf[:len(ttf) // 2]
# f04: truncated right after the 12-byte header
fonts['f04_trunc_hdr.ttf'] = ttf[:12]
# f05: OTTO magic on a TrueType body (format confusion)
fonts['f05_otto.ttf'] = patch_at(ttf, 0, b'OTTO')
# f06: numTables = 0 (no tables declared)
fonts['f11_zero_tables.ttf'] = patch_at(ttf, 4, struct.pack('>H', 0))

tabs = sfnt_tables(ttf)
# f06/f07: length lies on head and cmap
for tag, name in [(b'head', 'f06_head_len_lie.ttf'), (b'cmap', 'f07_cmap_len_lie.ttf')]:
    entry = 12 + 16 * next(i for i, t in enumerate(tabs) if t[0] == tag)
    fonts[name] = patch_at(ttf, entry + 12, struct.pack('>I', 0x7FFFFFF0))
# f09: last table offset points beyond EOF
last = max(tabs, key=lambda t: t[2])
entry = 12 + 16 * next(i for i, t in enumerate(tabs) if t[0] == last[0])
fonts['f09_table_oob.ttf'] = patch_at(ttf, entry + 8, struct.pack('>I', len(ttf) + 0x1000))
# f10: all checksums zeroed
z = bytearray(ttf)
for i, (tag, cks, toff, tlen) in enumerate(tabs):
    patch_off = 12 + 16 * i + 4
    z[patch_off:patch_off + 4] = b'\x00' * 4
fonts['f10_zero_checksums.ttf'] = bytes(z)
# f08: 8KB trailing garbage
fonts['f08_trailing_garbage.ttf'] = ttf + b'\xAA' * 8192

# ---------------- WOFF wrapper (tables stored uncompressed) ----------------

def build_woff(sfnt, num_tables_override=None, oob_offset=False):
    num = struct.unpack('>H', sfnt[4:6])[0]
    flavor = sfnt[0:4]
    tabs = sfnt_tables(sfnt)
    hdr_len = 44
    dir_len = 20 * num
    table_start = hdr_len + dir_len
    offsets = []
    cur = table_start
    body = bytearray()
    for tag, cks, toff, tlen in tabs:
        tbl = sfnt[toff:toff + tlen]
        offsets.append((tag, cur, len(tbl), tlen, cks))
        body += tbl
        pad = (-len(tbl)) % 4
        body += b'\x00' * pad
        cur += len(tbl) + pad
    total = table_start + len(body)
    # header: sig4 flavor4 total4 numTables2 reserved2 sfntSize4 maj1 min1
    #         pad2 metaOff4 metaLen4 metaOrig4 privOff4 privLen4
    hdr = b'wOFF' + flavor + struct.pack('>IHHI', total,
        num if num_tables_override is None else num_tables_override, 0, len(sfnt))
    hdr += struct.pack('>BBH', 1, 0, 0)
    hdr += struct.pack('>IIIIII', 0, 0, 0, 0, 0, 0)
    d = bytearray()
    for tag, off, clen, olen, cks in offsets:
        real_off = off + 0x7FFFFFF0 if oob_offset else off
        d += tag + struct.pack('>IIII', real_off, clen, olen, cks)
    return bytes(hdr) + bytes(d) + bytes(body)

fonts['f12_woff_valid.woff'] = build_woff(ttf)
fonts['f13_woff_badnum.woff'] = build_woff(ttf, num_tables_override=0xFFFF)
fonts['f14_woff_oob_offset.woff'] = build_woff(ttf, oob_offset=True)
fonts['f15_ttf_as_woff2.woff2'] = ttf  # magic mismatch: TTF body named .woff2

for name, data in fonts.items():
    (FONT_DIR / name).write_bytes(data)

# ---------------- images ----------------

imgs = {}

base = Image.new('RGB', (8, 8), (255, 0, 0))
import io

def save(img, fmt, **kw):
    b = io.BytesIO()
    img.save(b, fmt, **kw)
    return b.getvalue()

imgs['i00_valid.png'] = save(base, 'PNG')
imgs['i00_valid.gif'] = save(base, 'GIF')
imgs['i00_valid.bmp'] = save(base, 'BMP')
imgs['i00_valid.jpg'] = save(base, 'JPEG', quality=40)
imgs['i00_valid.ico'] = save(base, 'ICO')
imgs['i00_valid.tif'] = save(base, 'TIFF')
try:
    imgs['i00_valid.webp'] = save(base, 'WEBP')
except Exception as e:
    print('webp save failed:', e)
imgs['i00_valid.svg'] = (b'<svg xmlns="http://www.w3.org/2000/svg" width="8" height="8">'
    b'<rect width="8" height="8" fill="#00ff00"/></svg>')
# avif/jxl garbage-with-magic: magic-sniff test only
imgs['i10_avif_magic.bin'] = b'\x00\x00\x00\x20ftypavif\x00\x00\x00\x00avifmif1' + b'\x00' * 40
imgs['i11_jxl_magic.bin'] = b'\xff\x0a' + b'\x00' * 40

png = imgs['i00_valid.png']
# IHDR width/height lie (0xFFFF x 0xFFFF)
ihdr_off = png.find(b'IHDR') + 4
imgs['i20_png_dims_lie.png'] = patch_at(png, ihdr_off, struct.pack('>II', 0xFFFF, 0xFFFF))
# truncated after IDAT (no IEND)
imgs['i21_png_no_iend.png'] = png[:-12]
# CRC corrupt on IHDR
imgs['i22_png_bad_crc.png'] = patch_at(png, ihdr_off + 13, b'\xDE\xAD\xBE\xEF')
# truncated at half
imgs['i23_png_trunc_half.png'] = png[:len(png) // 2]

gif = imgs['i00_valid.gif']
imgs['i30_gif_trunc.png'.replace('.png', '.gif')] = gif[:len(gif) // 2]
# logical screen descriptor size lie
imgs['i31_gif_dims_lie.gif'] = patch_at(gif, 6, struct.pack('<HH', 0xFFFF, 0xFFFF))

jpg = imgs['i00_valid.jpg']
imgs['i40_jpg_trunc.jpg'] = jpg[:len(jpg) // 2]
# SOF dims lie: find SOF0 marker (C0)
sof = jpg.find(b'\xc0') 
imgs['i41_jpg_dims_lie.jpg'] = patch_at(jpg, sof + 5, struct.pack('>HH', 0xFFFF, 0xFFFF)) if sof > 0 else jpg

bmp = imgs['i00_valid.bmp']
# pixel-data offset beyond EOF
imgs['i50_bmp_offset_oob.bmp'] = patch_at(bmp, 10, struct.pack('<I', len(bmp) + 0x10000))

ico = imgs['i00_valid.ico']
imgs['i60_ico_count255.ico'] = patch_at(ico, 2, struct.pack('>H', 255))

webp = imgs.get('i00_valid.webp')
if webp:
    # RIFF size lie
    imgs['i70_webp_riff_lie.webp'] = patch_at(webp, 4, struct.pack('<I', 0xFFFFFF00))
    imgs['i71_webp_trunc.webp'] = webp[:len(webp) // 2]

for name, data in imgs.items():
    (IMG_DIR / name).write_bytes(data)

print('fonts:', len(fonts), 'images:', len(imgs))
for n in sorted(p.name for p in FONT_DIR.iterdir()):
    print(' font', n, (FONT_DIR / n).stat().st_size)
for n in sorted(p.name for p in IMG_DIR.iterdir()):
    print(' img ', n, (IMG_DIR / n).stat().st_size)

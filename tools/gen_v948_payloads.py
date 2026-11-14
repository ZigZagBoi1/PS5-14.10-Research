"""v948 payloads: CONTENT-LEVEL WOFF2 discriminators with byte-exact aim.

Directory cumulative offsets in the decompressed buffer (fonttools g01):
  OS/2 86 | VDMX 1504 | cmap 360 | cvt 310 | fpgm 1210 | gasp 16 |
  glyf(tx) 4902 | head 54 | hhea 36 | hmtx 64 | loca(tx) 0 | maxp 32 |
  name 1142 | post 138 | prep 232  -> total 10086
Offsets: OS/2@0, VDMX@86, cmap@1590, cvt@1950, fpgm@2260, gasp@3470,
  glyf@3486(ends 8388), head@8388, hhea@8442, hmtx@8478(64B, ends 8542).
hmtx is UNTRANSFORMED: its bytes pass through the brotli stream verbatim
and feed the metrics - corrupting them MUST mutate measureText if the
decoder builds JS-visible state from stream content ("state from lies"
discriminator). glyf header corruption (numGlyphs=0xFFFF / indexFormat
broken) aims at the FreeType reconstruction path itself.
"""
import struct, pathlib, brotli

HERE = pathlib.Path(__file__).resolve().parent
FDIR = HERE / 'browser_runner' / 'fuzzcases' / 'fonts'
base = (FDIR / 'g01_valid_woff2.woff2').read_bytes()

def read_base128(data, off):
    result = 0
    for i in range(5):
        b = data[off]; off += 1
        if i == 0 and b == 0x80: raise ValueError
        result = (result << 7) | (b & 0x7F)
        if not (b & 0x80):
            return result, off
    raise ValueError

def find_dstart(data):
    num = struct.unpack('>H', data[12:14])[0]
    off = 48
    KNOWN_GLYF_LOCA = (10, 11); HMTX = 3
    for i in range(num):
        flags = data[off]; off += 1
        tb = flags & 0x3F
        ver = flags >> 6
        orig, off = read_base128(data, off)
        transformed = (tb in KNOWN_GLYF_LOCA and ver != 3) or (tb == HMTX and ver == 1)
        if transformed:
            _, off = read_base128(data, off)
    return off

def rebuild(mutated_dec):
    cs = brotli.compress(bytes(mutated_dec), mode=brotli.MODE_FONT)
    out = bytearray(base[:DSTART])
    struct.pack_into('>I', out, 20, len(cs))
    struct.pack_into('>I', out, 8, DSTART + len(cs))
    return bytes(out) + cs

DSTART = find_dstart(base)
clen = struct.unpack('>I', base[20:24])[0]
dec = bytearray(brotli.decompress(base[DSTART:DSTART + clen]))
assert len(dec) == 10086, len(dec)

out = {}
# w12: hmtx advances -> 0xFFFF (humongous widths)
d = bytearray(dec)
for i in range(0, 64, 2):
    struct.pack_into('>H', d, 8478 + i, 0xFFFF)
out['x12_hmtx_maxadv.woff2'] = rebuild(d)

# w13: hmtx advances -> 0 (zero-width glyphs)
d = bytearray(dec)
for i in range(0, 64, 2):
    struct.pack_into('>H', d, 8478 + i, 0x0000)
out['x13_hmtx_zerowidth.woff2'] = rebuild(d)

# w14: glyf transformed header -> 0xFF (numGlyphs/indexFormat garbage)
d = bytearray(dec)
d[3486:3494] = b'\xFF' * 8
out['x14_glyf_header_ff.woff2'] = rebuild(d)

# w15: both - hmtx max + glyf header garbage (combined state)
d = bytearray(dec)
for i in range(0, 64, 2):
    struct.pack_into('>H', d, 8478 + i, 0xFFFF)
d[3486:3494] = b'\xFF' * 8
out['x15_hmtx_and_glyf.woff2'] = rebuild(d)

for name, data in out.items():
    (FDIR / name).write_bytes(data)
    print(name, len(data))

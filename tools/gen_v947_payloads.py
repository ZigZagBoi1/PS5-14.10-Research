"""v947 payloads: WOFF2 mutant battery riding the known-good g01 (fonttools/brotli).

Classes: header lies, table-directory corruption (flags/lengths), compressed
stream mutations (truncate/flip), and decompressed-content corruption
(decompress -> corrupt transformed glyf -> recompress) - the class the
brotli/FreeType path actually parses.
"""
import struct, pathlib, brotli

HERE = pathlib.Path(__file__).resolve().parent
FDIR = HERE / 'browser_runner' / 'fuzzcases' / 'fonts'
base = (FDIR / 'g01_valid_woff2.woff2').read_bytes()

def read_base128(data, off):
    result = 0
    for i in range(5):
        b = data[off]; off += 1
        if i == 0 and b == 0x80: raise ValueError('leading zero')
        result = (result << 7) | (b & 0x7F)
        if not (b & 0x80):
            return result, off
    raise ValueError('base128 too long')

def parse_dir(data):
    """Return (entries, data_start). entries: (idx, flags_off, entry_kind)."""
    num = struct.unpack('>H', data[12:14])[0]  # WOFF2 header: numTables at offset 12
    off = 48
    entries = []
    for i in range(num):
        flags_off = off
        flags = data[off]; off += 1
        tag_byte = flags & 0x3F
        if tag_byte == 0x3F:
            off += 4  # custom tag
        orig, off = read_base128(data, off)
        ver = flags >> 6
        # WOFF2 spec known tag order: 0 cmap 1 head 2 hhea 3 hmtx 4 maxp 5 name
        # 6 OS/2 7 post 8 cvt 9 fpgm 10 glyf 11 loca 12 prep ... 3F custom
        glyf_loca = tag_byte in (10, 11)
        hmtx = tag_byte == 3
        transformed = (glyf_loca and ver == 0) or (hmtx and ver == 1)
        if transformed:
            tlen, off = read_base128(data, off)
        entries.append((i, flags_off, off))
    return entries, off

def patch(data, off, raw):
    return data[:off] + raw + data[off + len(raw):]

out = {}
out['w00_valid_control.woff2'] = base

# header lies
out['w01_length_lie.woff2'] = patch(base, 8, struct.pack('>I', 0xFFFFFF00))
out['w02_numtables_ffff.woff2'] = patch(base, 12, struct.pack('>H', 0xFFFF))
out['w04_sfntsize_lie.woff2'] = patch(base, 16, struct.pack('>I', 0xFFFFFF00))
out['w05_meta_oob.woff2'] = patch(base, 28, struct.pack('>I', len(base) + 0x10000)) \
    .replace(b'', b'', 1)
# metaOffset at offset 24? header: sig4 flavor4 length4 numTables2 reserved2
# totalSfntSize4 totalCompressedSize4 major2 minor2 metaOffset4 metaLength4
# metaOrigLength4 privOffset4 privLength4 = 48
ent, dstart = parse_dir(base)
cstream = base[dstart:]
out['w03_compsize_small.woff2'] = patch(base, 20, struct.pack('>I', 64))
out['w05b_priv_oob.woff2'] = patch(base, 40, struct.pack('>I', len(base) + 0x10000))
out['w05c_privlen.woff2'] = patch(base, 44, struct.pack('>I', 0x1000))

# first entry flags flip (add transform bit to a non-transformed entry)
first_flags = ent[0][1]
out['w06_first_flags_x40.woff2'] = patch(base, first_flags, bytes([base[first_flags] ^ 0x40]))

# first entry origLength inflate (overwrite first base128 byte with 0xFF)
first_len_off = ent[0][2]
out['w07_first_origlen_inflate.woff2'] = patch(base, first_len_off, bytes([base[first_len_off] | 0x80, base[first_len_off] & 0x7F]))
# NOTE: this shifts subsequent bytes by one - intentionally malformed

# compressed stream mutations
out['w08_stream_trunc_half.woff2'] = base[:len(base) - len(cstream) // 2]
flipped = bytearray(cstream)
for k in range(6):
    p = (len(flipped) // 7) * (k + 1)
    flipped[p % len(flipped)] ^= 0xFF
out['w09_stream_flips.woff2'] = base[:dstart] + bytes(flipped)
out['w10_dir_trunc.woff2'] = base[:48 + 8]

# decompressed-content corruption: decompress, corrupt transformed glyf, recompress
try:
    clen = struct.unpack('>I', base[20:24])[0]     # totalCompressedSize
    dec = brotli.decompress(base[dstart:dstart + clen])  # exact slice (trailing pad rejected)
    # corrupt 4 spots inside the decompressed table data (bbox/gid regions)
    d = bytearray(dec)
    for p in (len(d) // 3, len(d) // 2, (len(d) * 2) // 3, len(d) - 16):
        if 0 <= p < len(d):
            d[p:p + 4] = b'\xFF\xFF\xFF\xFF'
    recompressed = brotli.compress(bytes(d), mode=brotli.MODE_FONT)
    w11 = bytearray(base[:dstart])
    struct.pack_into('>I', w11, 20, len(recompressed))          # totalCompressedSize
    struct.pack_into('>I', w11, 8, dstart + len(recompressed))  # length
    out['w11_content_corrupt.woff2'] = bytes(w11) + recompressed
    print('w11 decompressed len', len(dec), '-> recompressed', len(recompressed))
except Exception as e:
    print('w11 failed:', e)

for name, data in out.items():
    (FDIR / name).write_bytes(data)
    print(name, len(data))

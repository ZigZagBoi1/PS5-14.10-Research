"""v943 payloads: minimal media containers (hand-built) + malformed mutants.

Readout is the MediaError class per file; a WebProcess death is the signal.
Valid-ish controls exercise the demuxer even when the codec is absent.
"""
import struct, pathlib

HERE = pathlib.Path(__file__).resolve().parent
MED = HERE / 'browser_runner' / 'fuzzcases' / 'media'
MED.mkdir(parents=True, exist_ok=True)

# ---------------- WAV (PCM 8-bit 8kHz, 100ms) ----------------

def wav(rate=8000, chans=1, bits=8, frames=800, fmt_extra=b''):
    data = bytes((i * 7) % 256 for i in range(frames * chans * bits // 8))
    fmt = struct.pack('<HHIIHH', 1, chans, rate, rate * chans * bits // 8,
                      chans * bits // 8, bits) + fmt_extra
    body = b'WAVE' + b'fmt ' + struct.pack('<I', 16 + len(fmt_extra)) + fmt
    body += b'data' + struct.pack('<I', len(data)) + data
    return b'RIFF' + struct.pack('<I', len(body)) + body

MED.joinpath('m00_valid.wav').write_bytes(wav())
w = MED.joinpath('m00_valid.wav').read_bytes()
# RIFF size lie (declares 4GB)
MED.joinpath('m01_wav_riff_lie.wav').write_bytes(w[:4] + struct.pack('<I', 0xFFFFFF00) + w[8:])
# fmt channels=255
fmt_off = w.find(b'fmt ') + 8
MED.joinpath('m02_wav_chans_255.wav').write_bytes(w[:fmt_off] + struct.pack('<H', 255) + w[fmt_off + 2:])
# sample rate = 0xFFFFFFFF
MED.joinpath('m03_wav_rate_max.wav').write_bytes(w[:fmt_off + 4] + struct.pack('<I', 0xFFFFFFFF) + w[fmt_off + 8:])
# data size beyond EOF
data_off = w.find(b'data') + 4
MED.joinpath('m04_wav_data_lie.wav').write_bytes(w[:data_off] + struct.pack('<I', 0x7FFFFFF0) + w[data_off + 4:])
# truncated mid-data
MED.joinpath('m05_wav_trunc.wav').write_bytes(w[:len(w) // 2])
# bit depth = 0
MED.joinpath('m06_wav_bits_0.wav').write_bytes(w[:fmt_off + 14] + struct.pack('<H', 0) + w[fmt_off + 16:])

# ---------------- MP3 (ID3 + 3 Layer3 frames) ----------------

def mp3_frame():
    # MPEG1 Layer3 44.1kHz 128kbps: header 0xFFFB9000, 417-byte frames
    hdr = bytes([0xFF, 0xFB, 0x90, 0x00])
    return hdr + b'\x55' * 413

mp3 = b'ID3\x03\x00\x00\x00\x00\x00\x00' + mp3_frame() * 3
MED.joinpath('m10_valid.mp3').write_bytes(mp3)
MED.joinpath('m11_mp3_trunc.mp3').write_bytes(mp3[:len(mp3) // 2])
# ID3 size lie (declares 1GB of tags)
MED.joinpath('m12_mp3_id3_lie.mp3').write_bytes(
    b'ID3\x03\x00\x00' + bytes([0x10, 0x00, 0x00, 0x00]) + mp3_frame() * 3)

# ---------------- FLAC (STREAMINFO) ----------------

si = struct.pack('>HH', 8000, 8000)          # min/max blocksize
si += b'\x00' * 6                            # min/max framesize (unknown)
si += bytes([0x0A]) + b'\x00\x01'            # 8kHz mono-ish bits packed
si += struct.pack('>I', 800)[:3] + struct.pack('>I', 800)[:5]
si += b'\x00' * 8                            # md5
flac = b'fLaC' + bytes([0x80]) + struct.pack('>I', 34)[1:] + si   # last-header-block flag
MED.joinpath('m20_valid.flac').write_bytes(flac)
# STREAMINFO block length lie
MED.joinpath('m21_flac_len_lie.flac').write_bytes(
    b'fLaC' + bytes([0x80]) + struct.pack('>I', 0x7FFFFFF0)[1:] + si)

# ---------------- OGG (CRC-correct minimal BOS page) ----------------

ogg_crc_table = []
for i in range(256):
    r = i << 24
    for _ in range(8):
        r = ((r << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if r & 0x80000000 else (r << 1) & 0xFFFFFFFF
    ogg_crc_table.append(r)

def ogg_crc(data):
    crc = 0
    for b in data:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ ogg_crc_table[((crc >> 24) & 0xFF) ^ b]
    return crc

def ogg_page(head_type, granule, serial, seq, payload):
    hdr = b'OggS' + bytes([0, head_type]) + struct.pack('<qII', granule, serial, seq)
    hdr += b'\x00\x00\x00\x00'                   # crc placeholder
    hdr += bytes([1, len(payload)])              # 1 segment, lacing
    page = hdr + payload
    crc = ogg_crc(page)
    return page[:22] + struct.pack('<I', crc) + page[26:]

vorbis_id = b'\x01vorbis' + struct.pack('<I', 0) + bytes([2, 0, 0, 0, 0]) + \
    struct.pack('<I', 8000) + struct.pack('<I', 8000) + struct.pack('<II', 0, 0) + bytes([0])
ogg = ogg_page(2, 0, 0x1234, 0, vorbis_id)
MED.joinpath('m30_valid.ogg').write_bytes(ogg)
# CRC corrupted
MED.joinpath('m31_ogg_bad_crc.ogg').write_bytes(ogg[:22] + struct.pack('<I', 0xDEADBEEF) + ogg[26:])
# serial number lie on a continuation-less second page -> truncation chaos
MED.joinpath('m32_ogg_trunc.ogg').write_bytes(ogg[:len(ogg) // 2])

# ---------------- MP4 ----------------

def box(t, *payload):
    body = b''.join(payload)
    return struct.pack('>I', 8 + len(body)) + t + body

ftyp = box(b'ftyp', b'isom' + struct.pack('>I', 512) + b'isommp42')

def mvhd(timescale=1000, dur=1000):
    return box(b'mvhd', b'\x00' * 4 + struct.pack('>IIII', 0, 0, timescale, dur) +
               struct.pack('>HH', 0x0100, 0) + b'\x00' * 8 +
               struct.pack('>9I', 0x10000, 0, 0, 0, 0x10000, 0, 0, 0, 0x40000000) +
               b'\x00' * 24 + struct.pack('>I', 2))

def tkhd(w=8, h=8, dur=1000):
    return box(b'tkhd', b'\x00' * 4 + struct.pack('>IIIII', 0, 0, 1, 0, dur) +
               b'\x00' * 8 + struct.pack('>HHHH', 0, 0, 0, 0) +
               struct.pack('>9I', 0x10000, 0, 0, 0, 0x10000, 0, 0, 0, 0x40000000) +
               struct.pack('>II', w << 16, h << 16))

def mdhd(dur=1000):
    return box(b'mdhd', b'\x00' * 4 + struct.pack('>IIIII', 0, 0, 1000, dur, 0) +
               struct.pack('>HH', 0x55C4, 0))

hdlr = box(b'hdlr', b'\x00' * 4 + b'\x00' * 4 + b'vide' + b'\x00' * 12 + b'v943\x00')
vmhd = box(b'vmhd', b'\x00' * 4 + struct.pack('>HHHH', 0, 0, 0, 0))
dref = box(b'dref', struct.pack('>I', 1) + box(b'url ', b'\x00' * 4))
# avc1 sample entry with a fake avcC (3-byte SPS header, no real SPS)
avc1 = struct.pack('>6H', 0, 0, 0, 0, 0, 0) + struct.pack('>HH', 1, 0) + \
       struct.pack('>HH', 0, 0) + struct.pack('>HH', 8, 8) + \
       struct.pack('>4H', 0x0028, 0x0048, 0xFFFF, 0) + \
       box(b'avcC', bytes([1, 0x64, 0x00, 0x1F, 0xFF, 0xE1, 0x00, 0x02, 0x67, 0x64, 0x00,
                           1, 0x01, 0x00, 0x04, 0x68, 0xEB, 0xEC, 0xB2]))
stsd = box(b'stsd', struct.pack('>I', 0) + struct.pack('>I', 1) + box(b'avc1', avc1))
stts = box(b'stts', struct.pack('>I', 0))
stsc = box(b'stsc', struct.pack('>I', 0))
stsz = box(b'stsz', struct.pack('>II', 0, 1) + struct.pack('>I', 100))
stco = box(b'stco', struct.pack('>I', 1) + struct.pack('>I', 200))

stbl = box(b'stbl', stsd, stts, stsc, stsz, stco)
minf = box(b'minf', vmhd, box(b'dinf', dref), stbl)
mdia = box(b'mdia', mdhd(), hdlr, minf)
trak = box(b'trak', tkhd(), mdia)
moov = box(b'moov', mvhd(), trak)

MED.joinpath('m40_ftyp_only.mp4').write_bytes(ftyp)
MED.joinpath('m41_ftyp_mdat.mp4').write_bytes(ftyp + box(b'mdat', b'\x11' * 64))
MED.joinpath('m42_min_mp4.mp4').write_bytes(ftyp + moov)
# moov box-size lie (declares far beyond EOF)
m42 = MED.joinpath('m42_min_mp4.mp4').read_bytes()
moov_off = m42.find(b'moov') - 4
MED.joinpath('m43_mp4_moov_lie.mp4').write_bytes(m42[:moov_off] + struct.pack('>I', 0xFFFFFF00) + m42[moov_off + 4:])
# mdhd duration overflow (huge duration, timescale 1)
mdhd2 = box(b'mdhd', b'\x00' * 4 + struct.pack('>IIIII', 0, 0, 1, 0xFFFFFFFF, 0) + struct.pack('>HH', 0x55C4, 0))
mdia2 = box(b'mdia', mdhd2, hdlr, minf)
trak2 = box(b'trak', tkhd(), mdia2)
MED.joinpath('m44_mp4_dur_max.mp4').write_bytes(ftyp + box(b'moov', mvhd(), trak2))

# ---------------- WebM (EBML) ----------------

def ebml_id(i):
    return struct.pack('>I', i)[4 - ((i.bit_length() + 7) // 8):]

def ebml_vint(i, minlen=1):
    n = minlen
    while n < 8 and i >= (1 << (7 * n - 1)):
        n += 1
    if n == 1:
        return bytes([0x80 | i])
    first = (1 << (8 - n)) | (i >> (8 * (n - 1)))
    low = i & ((1 << (8 * (n - 1))) - 1)
    return bytes([first]) + low.to_bytes(n - 1, 'big')

def el(i, payload):
    if isinstance(payload, int):
        payload = payload.to_bytes(max(1, (payload.bit_length() + 7) // 8), 'big')
    return ebml_id(i) + ebml_vint(len(payload)) + payload

ebml_hdr = el(0x1A45DFA3, el(0x4282, b'matroska') + el(0x4287, 4) + el(0x4285, b'matroska'))
seg = el(0x18538067,
         el(0x1549A966, el(0x4489, ebml_vint(1000, 2)) + el(0x2AD7B1, ebml_vint(1000000, 3))) +
         el(0x1654AE6B,
            el(0xAE, el(0xD7, 1) + el(0x83, 1) + el(0x86, b'V_VP8') +
               el(0xE0, el(0xB0, 8) + el(0xBA, 8)))))

MED.joinpath('m50_valid.webm').write_bytes(ebml_hdr + seg)
MED.joinpath('m51_webm_trunc.webm').write_bytes((ebml_hdr + seg)[:60])
# EBML header size lie
hdr_len_off = ebml_hdr.find(ebml_id(0x1A45DFA3)) + 4
bad_size = bytes([0x7F])   # header claims 127 bytes while the real body is larger
MED.joinpath('m52_webm_hdr_lie.webm').write_bytes(ebml_hdr[:hdr_len_off] + bad_size + ebml_hdr[hdr_len_off + 4:])

for p in sorted(MED.iterdir()):
    print(p.name, p.stat().st_size)

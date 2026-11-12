"""v945 payloads: REAL mp4/webm via ffmpeg + byte-level mutants.

Hand-built boxes never reached the demuxer (v943: all SRC_UNSUPPORTED at
sniff stage). ffmpeg-generated H.264+AAC MP4 / VP8 WebM exercise the real
paths; mutants target the box system, sample tables and codec records.
"""
import subprocess, struct, pathlib, shutil

HERE = pathlib.Path(__file__).resolve().parent
MED = HERE / 'browser_runner' / 'fuzzcases' / 'media'
MED.mkdir(parents=True, exist_ok=True)
FF = 'ffmpeg'

def run(args):
    r = subprocess.run([FF, '-y', '-loglevel', 'error'] + args, capture_output=True)
    if r.returncode:
        raise RuntimeError(r.stderr.decode(errors='replace')[:300])

SRC = MED / 'gen_src.mp4'
run(['-f', 'lavfi', '-i', 'testsrc=duration=1:size=64x64:rate=10',
     '-f', 'lavfi', '-i', 'sine=duration=1',
     '-c:v', 'libx264', '-profile:v', 'baseline', '-pix_fmt', 'yuv420p',
     '-c:a', 'aac', '-shortest', '-movflags', 'faststart', str(SRC)])
SRC_WEBM = MED / 'gen_src.webm'
run(['-f', 'lavfi', '-i', 'testsrc=duration=1:size=64x64:rate=10',
     '-c:v', 'libvpx', '-b:v', '100k', '-an', str(SRC_WEBM)])

mp4 = SRC.read_bytes()
shutil.copy(SRC_WEBM, MED / 'r00_valid.webm')
MED.joinpath('r00_valid.mp4').write_bytes(mp4)

def patch(data, off, raw):
    return data[:off] + raw + data[off + len(raw):]

# find top-level boxes
def boxes(data):
    out = []
    o = 0
    while o + 8 <= len(data):
        size = struct.unpack('>I', data[o:o + 4])[0]
        typ = data[o + 4:o + 8]
        out.append((typ, o, size))
        if size == 0: break
        o += size
    return out

bx = boxes(mp4)
# r01: every top-level box size inflated (parser will read past EOF)
b = bytearray(mp4)
for typ, off, size in bx:
    b[off:off + 4] = struct.pack('>I', size + 0x1000000)
MED.joinpath('r01_mp4_sizes_lie.mp4').write_bytes(bytes(b))
# r02: stco chunk-offset lie (points past file) - decode reads sample data OOB
stco = mp4.find(b'stco')
co_off = mp4.find(b'\x00\x00\x00\x01', stco) + 4
MED.joinpath('r02_mp4_stco_oob.mp4').write_bytes(patch(mp4, co_off, struct.pack('>I', len(mp4) + 0x100000)))
# r03: stsz sample-size lie (declares every sample 1MB)
stsz = mp4.find(b'stsz')
# stsz: version/flags(4) samplesize(4) count(4); if samplesize!=0 all samples use it
MED.joinpath('r03_mp4_stsz_lie.mp4').write_bytes(patch(mp4, stsz + 8, struct.pack('>I', 0x100000)))
# r04: avcC SPS/PPS length lie inside stsd
avcc = mp4.find(b'avcC')
if avcc > 0:
    MED.joinpath('r04_mp4_avcc_lie.mp4').write_bytes(patch(mp4, avcc + 4, struct.pack('>H', 0xFFFF)))
# r05: truncate inside mdat (frame data cut)
mdat = next(off for typ, off, size in bx if typ == b'mdat')
MED.joinpath('r05_mp4_mdat_trunc.mp4').write_bytes(mp4[:mdat + 16])
# r06: moov before ftyp removed (no ftyp at all)
ftyp = next(off for typ, off, size in bx if typ == b'ftyp')
MED.joinpath('r06_mp4_no_ftyp.mp4').write_bytes(mp4[:ftyp] + mp4[ftyp + 28:])
# r07: trak with 256 sample entries? skip; instead stts entry count lie
stts = mp4.find(b'stts')
MED.joinpath('r07_mp4_stts_count_lie.mp4').write_bytes(patch(mp4, stts + 8, struct.pack('>I', 0xFFFFFFF0)))
# r08: duration lie in mvhd (huge)
mvhd = mp4.find(b'mvhd')
MED.joinpath('r08_mp4_dur_lie.mp4').write_bytes(patch(mp4, mvhd + 20, struct.pack('>I', 0xFFFFFFF0)))
# r09: webm - segment size lie (infinite segment)
webm = SRC_WEBM.read_bytes()
seg = webm.find(bytes.fromhex('18538067'))
MED.joinpath('r09_webm_seg_inf.webm').write_bytes(webm[:seg + 4] + bytes([0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]) + webm[seg + 12:])
# r10: webm truncated at half
MED.joinpath('r10_webm_trunc.webm').write_bytes(webm[:len(webm) // 2])

for p in sorted(MED.glob('r*')):
    print(p.name, p.stat().st_size)

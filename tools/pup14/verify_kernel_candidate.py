"""Read-only validation of the extracted kernel candidate and small metadata."""

import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import re
import struct


def digest_stream(file, size):
    h = hashlib.sha256()
    while size:
        data = file.read(min(size, 4 * 1024 * 1024))
        if not data:
            raise EOFError('short read')
        h.update(data)
        size -= len(data)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('run', type=Path)
    parser.add_argument('--source', type=Path)
    args = parser.parse_args()
    pup = args.run / 'PS5_1410_PS5UPDATE1.PUP.dec'
    kernel = args.run / 'extracted/PS5_1410_PS5UPDATE1/5_kernel.bin'
    with pup.open('rb') as file:
        file.seek(0x20 + 16 * 32)
        flags, flags2, offset, compressed, uncompressed = struct.unpack('<IIQQQ', file.read(32))
        file.seek(offset)
        pup_digest = digest_stream(file, compressed)
    with kernel.open('rb') as file:
        kernel_digest = digest_stream(file, kernel.stat().st_size)
    counts = Counter()
    signatures = {name: 0 for name in (b'\x7fELF', b'FreeBSD', b'SceKernel', b'BSD', b'SCE')}
    strings = 0
    with kernel.open('rb') as file:
        for block in iter(lambda: file.read(1024 * 1024), b''):
            counts.update(block)
            for token in signatures:
                signatures[token] += block.count(token)
            strings += len(re.findall(rb'[\x20-\x7e]{12,}', block))
    entropy = -sum((n / kernel.stat().st_size) * math.log2(n / kernel.stat().st_size)
                   for n in counts.values())
    metadata = {}
    for filename in ('12_version_name.xml', '15_bd_firm_info.json'):
        path = args.run / 'extracted/PS5_1410_PS5UPDATE1' / filename
        metadata[filename] = path.read_text(encoding='utf-8', errors='replace')[:3000]
    print(json.dumps({'kernel': {'segment_index': 16, 'flags': hex(flags), 'flags2': flags2,
                                 'offset': offset, 'compressed_size': compressed,
                                 'uncompressed_size': uncompressed,
                                 'extracted_size': kernel.stat().st_size,
                                 'extracted_sha256': kernel_digest, 'pup_segment_sha256': pup_digest,
                                 'equal_to_pup_segment': kernel_digest == pup_digest,
                                 'whole_file_entropy': round(entropy, 6),
                                 'zero_percent': round(counts[0] * 100 / kernel.stat().st_size, 4),
                                 'signatures': {k.hex(): v for k, v in signatures.items()},
                                 'ascii_runs_12_or_more': strings}, 'metadata': metadata}, indent=2))


if __name__ == '__main__':
    main()

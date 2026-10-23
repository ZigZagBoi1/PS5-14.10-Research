"""Read-only inventory of nested BLS and SELF-like extracted components."""

import argparse
import json
from pathlib import Path
import struct


def bls(path):
    with path.open('rb') as file:
        header = file.read(32)
        magic, version, flags, count, blocks = struct.unpack_from('<4sIIII', header)
        if magic != b'SLB2' or count > 256:
            return {'error': 'not a supported BLS header'}
        records = []
        for _ in range(count):
            raw = file.read(48)
            block_offset, size = struct.unpack_from('<II', raw)
            name = raw[16:48].split(b'\0')[0].decode('ascii', 'replace')
            records.append({'name': name, 'offset': block_offset * 512, 'size': size})
        for item in records:
            file.seek(item['offset'])
            item['head_hex'] = file.read(16).hex()
        return {'size': path.stat().st_size, 'version': version, 'flags': flags,
                'file_count': count, 'block_count': blocks, 'entries': records}


def self_like(path):
    with path.open('rb') as file:
        head = file.read(65536)
    elf = head.find(b'\x7fELF')
    return {'size': path.stat().st_size, 'head_hex': head[:32].hex(),
            'elf_at': elf if elf >= 0 else None,
            'elf_head_hex': head[elf:elf + 32].hex() if elf >= 0 else None}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('run', type=Path)
    args = parser.parse_args()
    root = args.run / 'extracted/PS5_1410_PS5UPDATE1'
    results = {}
    for path in sorted(root.glob('*.bls')):
        results[path.name] = bls(path)
    results['2_updatemode.self'] = self_like(root / '2_updatemode.self')
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()

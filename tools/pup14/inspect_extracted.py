"""Read-only structural inventory of an unpacked PS5 PUP run."""

import argparse
from collections import Counter
import json
import math
from pathlib import Path
import struct


def entropy(data):
    counts = Counter(data)
    return round(-sum((n / len(data)) * math.log2(n / len(data)) for n in counts.values()), 4) if data else 0


def inspect(path):
    size = path.stat().st_size
    positions = sorted({0, min(size // 4, max(0, size - 65536)),
                        min(size // 2, max(0, size - 65536)),
                        min(3 * size // 4, max(0, size - 65536)),
                        max(0, size - 65536)})
    samples = []
    with path.open('rb') as file:
        for pos in positions:
            file.seek(pos)
            data = file.read(65536)
            printable = sum(32 <= byte < 127 or byte in (9, 10, 13) for byte in data)
            samples.append({'offset': pos, 'length': len(data), 'entropy': entropy(data),
                            'zero_percent': round(data.count(0) * 100 / len(data), 2) if data else 0,
                            'printable_percent': round(printable * 100 / len(data), 2) if data else 0,
                            'elf_magic_count': data.count(b'\x7fELF'),
                            'sce_magic_count': data.count(b'\x53\x43\x45\x00'),
                            'head_hex': data[:32].hex()})
    return {'path': str(path), 'size': size, 'samples': samples}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('run', type=Path)
    args = parser.parse_args()
    report = json.loads((args.run / 'extraction_report.json').read_text())
    segments = {}
    for entry in (1, 2):
        path = args.run / f'PS5_1410_PS5UPDATE{entry}.PUP.dec'
        with path.open('rb') as pup:
            header = pup.read(0x20)
            count = struct.unpack_from('<H', header, 0x18)[0]
            table = pup.read(count * 32)
        segments[str(entry)] = [dict(index=i, flags=hex(flags), id=flags >> 20,
                                     offset=offset, compressed=compressed,
                                     uncompressed=uncompressed)
                                for i in range(count)
                                for flags, flags2, offset, compressed, uncompressed in
                                [struct.unpack_from('<IIQQQ', table, i * 32)]]
    paths = [args.run / 'extracted' / item['path'] for item in report['files']
             if any(term in item['path'].lower() for term in
                    ('kernel', 'updatemode', 'ssd0.system', 'ssd0.preinst', 'eap_kbl'))]
    print(json.dumps({'segments': segments, 'components': [inspect(path) for path in paths]}, indent=2))


if __name__ == '__main__':
    main()

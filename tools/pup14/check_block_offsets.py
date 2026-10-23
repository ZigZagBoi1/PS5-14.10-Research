"""Compare saved PUP block offsets with the SDK decryptor's sequential reads."""

import argparse
import json
from pathlib import Path
import struct


def entries(file):
    file.seek(0)
    header = file.read(32)
    count = struct.unpack_from('<H', header, 0x18)[0]
    table = file.read(count * 32)
    return [dict(index=i, flags=flags, flags2=flags2, offset=offset, compressed=compressed,
                 uncompressed=uncompressed)
            for i in range(count)
            for flags, flags2, offset, compressed, uncompressed in
            [struct.unpack_from('<IIQQQ', table, i * 32)]]


def check(file, segment, table):
    block_size = 1 << (((segment['flags'] & 0xf000) >> 12) + 12)
    count = (block_size + segment['uncompressed'] - 1) // block_size
    file.seek(table['offset'] + 32 * count)
    raw = file.read(8 * count)
    if len(raw) != 8 * count:
        return {'error': 'short table'}
    pos = 0
    first_drift = None
    largest = 0
    examples = []
    tail = segment['uncompressed'] % block_size or block_size
    mask = 0x1ff if segment['flags2'] & 1 else 0xf
    for i in range(count):
        off, size = struct.unpack_from('<II', raw, 8 * i)
        delta = pos - off
        if delta and first_drift is None:
            first_drift = i
        if abs(delta) > abs(largest):
            largest = delta
        if i in (0, 1, 2, first_drift, count - 1):
            examples.append({'block': i, 'table_offset': off, 'sequential_offset': pos,
                             'drift': delta, 'size': size})
        unpadded = (size & ~mask) - (size & mask)
        read_size = block_size if unpadded == block_size else size
        if i != count - 1 or tail != size:
            read_size &= ~mask
        pos += read_size
    return {'block_size': block_size, 'blocks': count, 'first_drift': first_drift,
            'largest_drift': largest, 'examples': examples}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('run', type=Path)
    args = parser.parse_args()
    results = []
    for entry in (1, 2):
        path = args.run / f'PS5_1410_PS5UPDATE{entry}.PUP.dec'
        with path.open('rb') as file:
            segments = entries(file)
            for seg in segments:
                if not (seg['flags'] & 0x800 and seg['flags'] & 8):
                    continue
                tables = [t for t in segments if t['flags'] & 1 and t['flags'] >> 20 == seg['index']]
                if len(tables) != 1:
                    results.append({'entry': entry, 'index': seg['index'], 'error': 'table missing'})
                    continue
                results.append({'entry': entry, 'index': seg['index'], 'id': seg['flags'] >> 20,
                                **check(file, seg, tables[0])})
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()

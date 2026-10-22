"""Sample PUP block compression after the console's outer decryption."""

import argparse
import json
from pathlib import Path
import struct
import zlib


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('run', type=Path)
    args = parser.parse_args()
    results = []
    for entry, seg_index, table_index, indices in (
            (1, 30, 29, (0, 1, 2, 139, 140, 141, 142, 915)),
            (1, 32, 31, (0, 1, 2, 100, 2298)),
            (2, 10, 9, (0, 1, 2, 100, 559))):
        path = args.run / f'PS5_1410_PS5UPDATE{entry}.PUP.dec'
        with path.open('rb') as file:
            file.seek(0x20 + seg_index * 32)
            flags, flags2, offset, compressed, uncompressed = struct.unpack('<IIQQQ', file.read(32))
            file.seek(0x20 + table_index * 32)
            _, _, table_offset, _, _ = struct.unpack('<IIQQQ', file.read(32))
            block_size = 1 << (((flags & 0xf000) >> 12) + 12)
            count = (uncompressed + block_size - 1) // block_size
            mask = 0x1ff if flags2 & 1 else 0xf
            for i in indices:
                if i >= count:
                    continue
                file.seek(table_offset + 32 * count + i * 8)
                off, size = struct.unpack('<II', file.read(8))
                read_size = size & ~mask
                file.seek(offset + off)
                data = file.read(read_size)
                record = {'entry': entry, 'segment': seg_index, 'block': i,
                          'offset': off, 'size_field': size, 'read_size': read_size,
                          'head_hex': data[:16].hex(), 'all_zero': not any(data)}
                if read_size != block_size:
                    try:
                        inflater = zlib.decompressobj(15 + 32)
                        inflated = inflater.decompress(data, block_size + 1)
                        record['inflate_size'] = len(inflated)
                        record['inflate_head'] = inflated[:16].hex()
                        record['inflate_eof'] = inflater.eof
                    except zlib.error as exc:
                        record['inflate_error'] = str(exc)
                results.append(record)
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()

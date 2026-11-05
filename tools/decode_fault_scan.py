#!/usr/bin/env python3
"""Decode fault oracle scan output from probe 1199a.

The probe output interleaves text lines (UTF-8) with 0x100-byte binary
mcontext dumps from child thread faults. Each text line like
  [T003] 0xFFFFFFFF80600000
is followed by a 256-byte binary blob written by the signal handler chain.

Within each blob, offset 0x18 (= ucontext 0xD8 - dump start 0xC0) holds
the trap error word. Nibble (value & 0xF):
  5 = page present (mapped, supervisor)
  4 = not present (unmapped)

Usage:
    python3 tools/decode_fault_scan.py results/phase17_new_vectors/1199a_*.txt
"""

import re
import struct
import sys
from pathlib import Path


BLOB_SIZE = 0x100
# Offset of the discriminator byte within the 0x100-byte dump
# ctx+0xD8 in the full ucontext; dump starts at ctx+0xC0 → offset 0x18
DISC_OFFSET = 0x18


def decode(data: bytes):
    """Parse mixed text+binary output, yield (address, nibble) tuples."""
    pos = 0
    pending_addr = None

    while pos < len(data):
        # Try to find a text line starting with [T
        # Text lines end with \n and are ASCII
        if data[pos:pos+2] == b'[T' or (data[pos] == ord('[') and pos + 1 < len(data)):
            # Scan for newline
            nl = data.find(b'\n', pos)
            if nl == -1:
                break
            line = data[pos:nl].decode('utf-8', errors='replace').strip()
            pos = nl + 1

            m = re.match(r'\[T(\d+)\]\s+(0x[0-9A-Fa-f]+)', line)
            if m:
                pending_addr = int(m.group(2), 16)
                # The next BLOB_SIZE bytes should be the binary dump
                if pos + BLOB_SIZE <= len(data):
                    blob = data[pos:pos + BLOB_SIZE]
                    pos += BLOB_SIZE
                    # Read the discriminator as a little-endian u32
                    disc = struct.unpack_from('<I', blob, DISC_OFFSET)[0]
                    nibble = disc & 0xF
                    yield (pending_addr, nibble, disc)
                    pending_addr = None
                else:
                    # Not enough data for blob
                    break
            # else: non-target text line, skip
            continue

        # Skip any other bytes (text lines not starting with [T, etc.)
        nl = data.find(b'\n', pos)
        if nl == -1:
            break
        pos = nl + 1


def main():
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <result_file>', file=sys.stderr)
        sys.exit(1)

    path = Path(sys.argv[1])
    data = path.read_bytes()

    print(f'File: {path.name} ({len(data)} bytes)')
    print()

    results = list(decode(data))
    if not results:
        print('No fault oracle entries found in the output.')
        print('The output may be pure text (no binary blobs) or the format is different.')
        # Try to show text content
        text = data.decode('utf-8', errors='replace')
        print('\n--- Raw text ---')
        print(text[:2000])
        return

    mapped = []
    unmapped = []

    for addr, nibble, raw in results:
        status = 'MAPPED' if nibble == 5 else 'unmapped' if nibble == 4 else f'unknown({nibble})'
        if nibble == 5:
            mapped.append(addr)
        else:
            unmapped.append(addr)

    # Print summary
    print(f'Total probes: {len(results)}')
    print(f'Mapped (present): {len(mapped)}')
    print(f'Unmapped: {len(unmapped)}')
    print()

    if not mapped:
        print('No mapped kernel pages found in this range.')
        return

    # Find contiguous runs of mapped pages
    mapped.sort()
    runs = []
    run_start = mapped[0]
    run_end = mapped[0]
    for addr in mapped[1:]:
        if addr == run_end + 0x200000:  # contiguous at 2MB step
            run_end = addr
        else:
            runs.append((run_start, run_end))
            run_start = addr
            run_end = addr
    runs.append((run_start, run_end))

    print('Mapped runs (2 MB steps):')
    for rstart, rend in runs:
        n_steps = (rend - rstart) // 0x200000 + 1
        size_mb = n_steps * 2
        print(f'  0x{rstart:016X} - 0x{rend + 0x1FFFFF:016X}  '
              f'{n_steps} steps ({size_mb} MB)')

    print()

    # KASLR analysis
    if len(runs) == 1:
        base, rend0 = runs[0]
        n = (rend0 - base) // 0x200000 + 1
        size = n * 0x200000
        slide = base - 0xFFFFFFFF80200000  # typical kernel load after stub
        print(f'Kernel image base: 0x{base:016X}')
        print(f'Kernel image size: {size // (1024*1024)} MB (0x{size:X})')
        print(f'KASLR slide from 0xFFFFFFFF80200000: +0x{slide:X}')
    elif len(runs) == 2:
        # First run is likely the stub page at canonical base
        stub = runs[0]
        image = runs[1]
        stub_steps = (stub[1] - stub[0]) // 0x200000 + 1
        img_steps = (image[1] - image[0]) // 0x200000 + 1
        img_size = img_steps * 0x200000
        print(f'Stub page(s): 0x{stub[0]:016X} ({stub_steps} steps)')
        print(f'Kernel image: 0x{image[0]:016X} - 0x{image[1] + 0x1FFFFF:016X} '
              f'({img_steps} steps, {img_size // (1024*1024)} MB)')
        print(f'KASLR slide: +0x{image[0] - 0xFFFFFFFF80000000:X} from canonical base')
    else:
        print(f'{len(runs)} separate mapped regions found')
        for i, (rstart, rend) in enumerate(runs):
            n = (rend - rstart) // 0x200000 + 1
            print(f'  Run {i}: 0x{rstart:016X} - 0x{rend + 0x1FFFFF:016X} ({n} steps)')

    # Dump all results for verification
    print()
    print('--- Full scan (first/last 20 of each class) ---')
    for addr, nibble, raw in results[:20]:
        tag = 'P' if nibble == 5 else '.'
        print(f'  {tag} 0x{addr:016X}  disc=0x{raw:08X}')
    if len(results) > 40:
        print(f'  ... ({len(results) - 40} more entries) ...')
    for addr, nibble, raw in results[-20:]:
        tag = 'P' if nibble == 5 else '.'
        print(f'  {tag} 0x{addr:016X}  disc=0x{raw:08X}')


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Extract physical memory read data from probe output with binary trace.

Probe 562m injects 64 bytes into stdout via child ROP write(1):
  +0x00: 0xAABBCCDD11223344 (start marker 1)
  +0x08: 0x55667788AABBCCDD (start marker 2)
  +0x10: qword[0] from physical memory
  +0x18: qword[1]
  +0x20: qword[2]
  +0x28: qword[3]
  +0x30: 0xDEADFACECAFEBABE (end marker — confirms child completed reads)
  +0x38: 0xFEEDBABE12345678 (end marker 2 — pre-filled, unchanged if child dies)

Usage: python3 tools/extract_phys_read.py results/phase32_aio_race/562m_*.txt
"""
import sys, struct

START1 = struct.pack('<Q', 0xAABBCCDD11223344)
START2 = struct.pack('<Q', 0x55667788AABBCCDD)
END_OK = struct.pack('<Q', 0xDEADFACECAFEBABE)
END_PRE = struct.pack('<Q', 0xDEADFACE00C0FFEE)
CAL1 = struct.pack('<Q', 0xCAFECAFE11111111)
CAL2 = struct.pack('<Q', 0xBEEFBEEF22222222)

def extract(path):
    with open(path, 'rb') as f:
        data = f.read()

    print(f"File: {path} ({len(data)} bytes)")

    # Count trace blocks
    TRACE_MARKER = b'\x37\x13\x37\x13'
    trace_count = data.count(TRACE_MARKER)
    print(f"Trace blocks (0x13371337): {trace_count}")

    found = False

    # Strategy 0: Calibration markers (562n dual-child)
    cal_full = CAL1 + CAL2
    cal_pos = data.find(cal_full)
    if cal_pos >= 0:
        print(f"\n*** CALIBRATION BLOCK (16 bytes) at offset {cal_pos} (0x{cal_pos:X}) ***")
        print(f"  CAFECAFE11111111 + BEEFBEEF22222222 — clean child fn_addr write(1) WORKS")
    else:
        cal1_pos = data.find(CAL1)
        if cal1_pos >= 0:
            print(f"\nCAL1 (CAFECAFE11111111) at offset {cal1_pos} (0x{cal1_pos:X}) — partial cal")
        else:
            print(f"\nNo calibration markers found — clean child write(1) may not have executed")

    # Strategy 1: Find the full 16-byte start marker
    full_start = START1 + START2
    pos = data.find(full_start)
    if pos >= 0:
        print(f"\nFULL START MARKER found at offset {pos} (0x{pos:X})")
        if pos + 64 <= len(data):
            print_block(data[pos:pos+64])
            found = True

    # Strategy 2: Find just the first 8-byte marker
    if not found:
        pos = data.find(START1)
        if pos >= 0:
            print(f"\nSTART1 found at offset {pos} (0x{pos:X})")
            if pos + 64 <= len(data):
                print_block(data[pos:pos+64])
                found = True
            else:
                print(f"  Only {len(data) - pos} bytes after marker (need 64)")

    # Strategy 3: Search for end markers
    for marker_bytes, name in [(END_OK, "DEADFACECAFEBABE"), (END_PRE, "DEADFACE00C0FFEE")]:
        epos = data.find(marker_bytes)
        if epos >= 0:
            print(f"\n{name} found at offset {epos} (0x{epos:X})")
            start = epos - 0x30
            if start >= 0 and not found:
                print(f"  Reconstructing block from end marker:")
                print_block(data[start:start+64])
                found = True

    # Strategy 4: Search for DEADFACE (4-byte LE)
    deadface4 = b'\xCE\xFA\xAD\xDE'
    positions = []
    search_pos = 0
    while search_pos < len(data):
        idx = data.find(deadface4, search_pos)
        if idx < 0:
            break
        positions.append(idx)
        search_pos = idx + 1

    if positions:
        print(f"\nDEADFACE 4-byte pattern at {len(positions)} positions:")
        for p in positions[:10]:
            ctx = data[max(0,p-8):min(len(data),p+16)]
            hexdump = ' '.join(f'{b:02X}' for b in ctx)
            print(f"  offset {p} (0x{p:X}): ...{hexdump}...")

    # Strategy 5: Look at gaps between trace blocks
    trace_positions = []
    i = 0
    while i < len(data) - 3:
        if data[i:i+4] == TRACE_MARKER:
            trace_positions.append(i)
            i += 4
        else:
            i += 1

    if trace_positions and len(trace_positions) > 1:
        block_size = trace_positions[1] - trace_positions[0]
        gaps = []

        # Before first block
        if trace_positions[0] > 0:
            gaps.append((0, trace_positions[0], "before-traces"))

        # Between blocks
        for j in range(len(trace_positions) - 1):
            end_cur = trace_positions[j] + block_size
            start_next = trace_positions[j+1]
            if start_next > end_cur + 4:
                gaps.append((end_cur, start_next, f"between-{j}-{j+1}"))

        # After last block
        last_end = trace_positions[-1] + block_size
        if last_end < len(data):
            gaps.append((last_end, len(data), "after-traces"))

        if gaps:
            print(f"\n{len(gaps)} gaps found around {len(trace_positions)} trace blocks (block_size={block_size}):")
            for start, end, label in gaps:
                gap = data[start:end]
                hexdump = ' '.join(f'{b:02X}' for b in gap[:80])
                text = ''.join(chr(b) if 32 <= b < 127 else '.' for b in gap[:80])
                print(f"  [{label}] offset {start}-{end} ({end-start} bytes)")
                print(f"    hex: {hexdump}")
                print(f"    txt: {text}")
                # Check if our markers are in this gap
                if START1 in gap:
                    rel = gap.find(START1)
                    print(f"    >>> START1 marker at gap+{rel}!")
                    if rel + 64 <= len(gap) and not found:
                        print_block(gap[rel:rel+64])
                        found = True

    if not found:
        print("\nNo injected data block found.")

    return found

def print_block(block):
    if len(block) < 64:
        print(f"  (only {len(block)} bytes, need 64)")
        return

    vals = [struct.unpack_from('<Q', block, i)[0] for i in range(0, 64, 8)]
    m1, m2, q0, q1, q2, q3, e1, e2 = vals

    ok1 = m1 == 0xAABBCCDD11223344
    ok2 = m2 == 0x55667788AABBCCDD
    completed = e1 == 0xDEADFACECAFEBABE

    print(f"\n  *** PHYSICAL MEMORY AT 0x100000000 ***")
    print(f"  marker1 = 0x{m1:016X} {'OK' if ok1 else 'MISMATCH'}")
    print(f"  marker2 = 0x{m2:016X} {'OK' if ok2 else 'MISMATCH'}")

    for i, val in enumerate([q0, q1, q2, q3]):
        lo = val & 0xFFFFFFFF
        hi = (val >> 32) & 0xFFFFFFFF
        tag = ""
        if lo == 0x464C457F:
            tag = " *** ELF HEADER! ***"
        if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF:
            tag += " KPTR?"
        print(f"  phys[+0x{i*8:02X}] = 0x{hi:08X}_{lo:08X}{tag}")

    print(f"  end_mark = 0x{e1:016X} {'READS DONE' if completed else 'child may have died before completing'}")
    print(f"  end_pre  = 0x{e2:016X}")

    if not ok1 or not ok2:
        print("  WARNING: start markers corrupted — data may be unreliable")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 tools/extract_phys_read.py <result_file>")
        sys.exit(1)
    for path in sys.argv[1:]:
        extract(path)
        print()

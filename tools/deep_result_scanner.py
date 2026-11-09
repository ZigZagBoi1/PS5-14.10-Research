#!/usr/bin/env python3
"""Deep forensic scanner for PS5 probe result files.

Scans for patterns beyond standard kernel pointer checks:
- Kernel pointers (0xFFFF8xxx range)
- Obfuscated kernel pointers (x ^ (x >> 4) reversal)
- Code pointers (userland module range 0x00000008-0x0000000F)
- Heap metadata patterns
- Non-standard return values
- Timing patterns across runs
"""

import re
import os
import sys
from collections import defaultdict
from pathlib import Path

RESULTS_DIR = Path(__file__).parent.parent / "results"

# Regex to find hex values in output
HEX64_RE = re.compile(r'0x([0-9a-fA-F]{8,16})\b')
HEX64_SPLIT_RE = re.compile(r'0x([0-9a-fA-F]{8})_([0-9a-fA-F]{8})')
RET_RE = re.compile(r'ret\s*=\s*(-?\d+)')
RV_RE = re.compile(r'rv\s*=\s*(-?\d+)')
HEXVAL_RE = re.compile(r'0x([0-9a-fA-F]{1,16})')

def deobfuscate_ptr(val):
    """Reverse f(x) = x ^ (x >> 4) iteratively.
    Since the top 4 bits are unchanged, we can recover x 4 bits at a time."""
    x = val
    # Iterative reversal: top 4 bits are correct, use them to recover next 4, etc.
    for _ in range(16):  # 64 bits / 4 bits per step
        x = val ^ (x >> 4)
    return x

def is_kernel_ptr(val):
    """Check if a 64-bit value looks like a kernel pointer."""
    h = (val >> 32) & 0xFFFFFFFF
    return h >= 0xFFFF8000 and h < 0xFFFFFFFF

def is_userland_code_ptr(val):
    """Check for userland module addresses (0x00000008xx-0x0000000Fxx)."""
    h = (val >> 32) & 0xFFFFFFFF
    return h >= 0x00000008 and h <= 0x0000000F

def is_heap_metadata(val):
    """Check for heap chunk-like patterns (small size | flags)."""
    # jemalloc/FreeBSD malloc patterns: lower bits are flags, upper is size
    # Look for values where upper 48 bits look like a reasonable size
    # and lower 16 bits have flag-like patterns
    if val == 0 or val == 0xFFFFFFFFFFFFFFFF:
        return False
    size = val >> 4
    if 0x10 <= size <= 0x100000 and (val & 0xF) in (0, 1, 2, 3, 4, 5, 6, 7, 8):
        return True
    return False

def is_interesting_nonzero(val):
    """Check if value is non-zero and not a common sentinel."""
    sentinels = {0, 0xFFFFFFFF, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFF,
                 0x100000000, 0xDEADBEEF, 0xCAFEBABE}
    return val != 0 and val not in sentinels

def is_data_line(stripped):
    """Check whether a line reads as console readback rather than a probe input.

    Mirrors the gate in tools/analyze_result.py: kernel-pointer candidates
    come only from hexdump lines, buffer views, return values, probe
    markers, or indexed one-value-per-line read rows. Timing rows, verify
    echoes, and arithmetic labels are excluded.
    """
    if re.match(r"\[\d+\]\s+0x[0-9a-fA-F]{8}_[0-9a-fA-F]{8}$", stripped):
        return True
    return any(x in stripped for x in [
        "buf[", "ret=", "+0x", "+00", "KPTR", ">>>"
    ]) or re.match(r"\s+\+[0-9A-Fa-f]{3}:", stripped) is not None

def extract_64bit_values(line):
    """Extract all 64-bit hex values from a line."""
    values = []
    # Match 0xHHHHHHHH_LLLLLLLL format
    for m in HEX64_SPLIT_RE.finditer(line):
        h = int(m.group(1), 16)
        l = int(m.group(2), 16)
        val = (h << 32) | l
        values.append(val)
    # Match plain 0xHEX format (8+ chars)
    for m in HEX64_RE.finditer(line):
        hexstr = m.group(1)
        if len(hexstr) >= 8:
            val = int(hexstr, 16)
            # Check not already captured as split format
            if val not in values:
                values.append(val)
    return values

def extract_return_values(line):
    """Extract return values from a line."""
    rets = []
    for m in RET_RE.finditer(line):
        rets.append(int(m.group(1)))
    for m in RV_RE.finditer(line):
        rets.append(int(m.group(1)))
    return rets

def scan_file(filepath):
    """Scan a single result file for interesting patterns."""
    findings = {
        'kernel_ptrs': [],
        'deobfuscated_kptrs': [],
        'userland_code_ptrs': [],
        'heap_metadata': [],
        'unusual_returns': [],
        'nonzero_buffers': [],
        'all_returns': [],
    }

    try:
        with open(filepath, 'r', errors='replace') as f:
            lines = f.readlines()
    except Exception as e:
        return findings, f"ERROR: {e}"

    for lineno, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        # Only values from console readback become pointer candidates;
        # probe inputs echoed back are excluded by the data-line gate.
        data_line = is_data_line(line)
        vals = extract_64bit_values(line)
        for val in vals:
            # Standard kernel pointer check
            if data_line and is_kernel_ptr(val):
                findings['kernel_ptrs'].append((lineno, val, line[:120]))

            # Deobfuscation check
            if data_line and val != 0 and not is_kernel_ptr(val):
                deob = deobfuscate_ptr(val)
                if is_kernel_ptr(deob):
                    findings['deobfuscated_kptrs'].append((lineno, val, deob, line[:120]))

            # Userland code pointer check
            if is_userland_code_ptr(val):
                findings['userland_code_ptrs'].append((lineno, val, line[:120]))

            # Heap metadata check
            if is_heap_metadata(val):
                findings['heap_metadata'].append((lineno, val, line[:120]))

            # Non-zero buffer data (in buf[] context)
            if 'buf[' in line.lower() or 'buf =' in line.lower():
                if is_interesting_nonzero(val):
                    findings['nonzero_buffers'].append((lineno, val, line[:120]))

        # Extract return values
        rets = extract_return_values(line)
        for rv in rets:
            findings['all_returns'].append((lineno, rv, line[:120]))
            # Unusual returns: not 0, -1, or small positive
            if rv not in (0, -1, -999) and not (1 <= rv <= 100):
                findings['unusual_returns'].append((lineno, rv, line[:120]))

    return findings, None

def compare_runs(files_by_probe):
    """Compare values across multiple runs of the same probe."""
    diffs = []
    for probe, files in files_by_probe.items():
        if len(files) < 2:
            continue
        # Extract all hex values from each file
        file_vals = {}
        for f in files:
            try:
                with open(f, 'r', errors='replace') as fh:
                    content = fh.read()
                vals = set()
                for m in HEX64_SPLIT_RE.finditer(content):
                    h = int(m.group(1), 16)
                    l = int(m.group(2), 16)
                    vals.add((h << 32) | l)
                file_vals[f] = vals
            except:
                pass

        # Find values that differ
        all_files = list(file_vals.keys())
        for i in range(len(all_files)):
            for j in range(i+1, len(all_files)):
                f1, f2 = all_files[i], all_files[j]
                only_in_1 = file_vals[f1] - file_vals[f2]
                only_in_2 = file_vals[f2] - file_vals[f1]
                if only_in_1 or only_in_2:
                    diffs.append({
                        'probe': probe,
                        'file1': str(f1),
                        'file2': str(f2),
                        'only_in_1': sorted(only_in_1)[:20],
                        'only_in_2': sorted(only_in_2)[:20],
                    })
    return diffs

def main():
    output_lines = []
    def log(msg=""):
        output_lines.append(msg)
        print(msg)

    log("# Deep Result File Forensic Scan")
    log(f"# Date: 2026-10-18")
    log(f"# Scanner: deep_result_scanner.py")
    log("")

    # Collect all result files
    result_files = sorted(RESULTS_DIR.rglob("*.txt"))
    log(f"Total result files: {len(result_files)}")
    log("")

    # Group by probe name for cross-run comparison
    files_by_probe = defaultdict(list)
    for f in result_files:
        # Extract probe name (everything before the timestamp)
        stem = f.stem
        parts = stem.rsplit('_', 2)
        if len(parts) >= 3 and len(parts[-1]) == 6 and len(parts[-2]) == 8:
            probe_name = '_'.join(parts[:-2])
        else:
            probe_name = stem
        files_by_probe[probe_name].append(f)

    # Aggregate findings
    all_findings = {}
    total_kptrs = 0
    total_deob = 0
    total_code = 0
    total_heap = 0
    total_unusual = 0
    total_nonzero = 0

    for f in result_files:
        findings, err = scan_file(f)
        if err:
            log(f"  ERROR scanning {f.name}: {err}")
            continue

        rel = f.relative_to(RESULTS_DIR)
        has_any = any(findings[k] for k in findings if k != 'all_returns')
        if has_any:
            all_findings[str(rel)] = findings

        total_kptrs += len(findings['kernel_ptrs'])
        total_deob += len(findings['deobfuscated_kptrs'])
        total_code += len(findings['userland_code_ptrs'])
        total_heap += len(findings['heap_metadata'])
        total_unusual += len(findings['unusual_returns'])
        total_nonzero += len(findings['nonzero_buffers'])

    log("## Summary Statistics")
    log(f"- Kernel pointer candidates: {total_kptrs}")
    log(f"- Deobfuscated kernel pointer candidates: {total_deob}")
    log(f"- Userland code pointer candidates: {total_code}")
    log(f"- Heap metadata candidates: {total_heap}")
    log(f"- Unusual return values: {total_unusual}")
    log(f"- Non-zero buffer data: {total_nonzero}")
    log("")

    # === DETAILED FINDINGS ===
    log("## Detailed Findings by File")
    log("")

    for fname, findings in sorted(all_findings.items()):
        log(f"### {fname}")

        if findings['kernel_ptrs']:
            log("**KERNEL POINTERS:**")
            for lineno, val, ctx in findings['kernel_ptrs']:
                log(f"  Line {lineno}: 0x{val:016X}")
                log(f"    Context: {ctx}")
            log("")

        if findings['deobfuscated_kptrs']:
            log("**DEOBFUSCATED KERNEL POINTERS (x ^ (x>>4) reversal):**")
            for lineno, orig, deob, ctx in findings['deobfuscated_kptrs']:
                log(f"  Line {lineno}: 0x{orig:016X} -> deobfuscated -> 0x{deob:016X}")
                log(f"    Context: {ctx}")
            log("")

        if findings['userland_code_ptrs']:
            log("**USERLAND CODE POINTERS:**")
            for lineno, val, ctx in findings['userland_code_ptrs'][:10]:
                log(f"  Line {lineno}: 0x{val:016X}")
                log(f"    Context: {ctx}")
            if len(findings['userland_code_ptrs']) > 10:
                log(f"  ... and {len(findings['userland_code_ptrs'])-10} more")
            log("")

        if findings['heap_metadata']:
            log("**HEAP METADATA CANDIDATES:**")
            for lineno, val, ctx in findings['heap_metadata'][:10]:
                log(f"  Line {lineno}: 0x{val:016X} (size=0x{val>>4:X}, flags=0x{val&0xF:X})")
                log(f"    Context: {ctx}")
            if len(findings['heap_metadata']) > 10:
                log(f"  ... and {len(findings['heap_metadata'])-10} more")
            log("")

        if findings['unusual_returns']:
            log("**UNUSUAL RETURN VALUES (not 0, -1, or small positive):**")
            for lineno, rv, ctx in findings['unusual_returns'][:10]:
                log(f"  Line {lineno}: ret={rv} (0x{rv & 0xFFFFFFFF:08X})")
                log(f"    Context: {ctx}")
            if len(findings['unusual_returns']) > 10:
                log(f"  ... and {len(findings['unusual_returns'])-10} more")
            log("")

        if findings['nonzero_buffers']:
            log("**NON-ZERO BUFFER DATA:**")
            for lineno, val, ctx in findings['nonzero_buffers'][:10]:
                log(f"  Line {lineno}: 0x{val:016X}")
                log(f"    Context: {ctx}")
            if len(findings['nonzero_buffers']) > 10:
                log(f"  ... and {len(findings['nonzero_buffers'])-10} more")
            log("")

    # === CROSS-RUN COMPARISON ===
    log("## Cross-Run Value Comparison")
    log("")

    diffs = compare_runs(files_by_probe)
    if diffs:
        for d in diffs:
            log(f"### Probe: {d['probe']}")
            log(f"  Files: {Path(d['file1']).name} vs {Path(d['file2']).name}")
            if d['only_in_1']:
                log(f"  Values only in file 1: {len(d['only_in_1'])}")
                for v in d['only_in_1'][:5]:
                    h = (v >> 32) & 0xFFFFFFFF
                    tag = ""
                    if is_kernel_ptr(v):
                        tag = " *** KERNEL PTR ***"
                    elif is_userland_code_ptr(v):
                        tag = " [code ptr]"
                    log(f"    0x{v:016X}{tag}")
            if d['only_in_2']:
                log(f"  Values only in file 2: {len(d['only_in_2'])}")
                for v in d['only_in_2'][:5]:
                    h = (v >> 32) & 0xFFFFFFFF
                    tag = ""
                    if is_kernel_ptr(v):
                        tag = " *** KERNEL PTR ***"
                    elif is_userland_code_ptr(v):
                        tag = " [code ptr]"
                    log(f"    0x{v:016X}{tag}")
            log("")
    else:
        log("No significant value differences found across runs.")
        log("")

    # === SPECIFIC TARGETED ANALYSIS ===
    log("## Targeted Analysis")
    log("")

    # 1. sys 624 from 51b
    log("### sys 624 Values (from 51b)")
    for f in result_files:
        if '51b_accessible' in f.name:
            try:
                with open(f, 'r', errors='replace') as fh:
                    for lineno, line in enumerate(fh, 1):
                        if '624' in line:
                            log(f"  {f.name}:{lineno}: {line.strip()}")
            except:
                pass
    log("")

    # 2. sys 572 results
    log("### sys 572 Values")
    for f in result_files:
        fname = f.name
        try:
            with open(f, 'r', errors='replace') as fh:
                for lineno, line in enumerate(fh, 1):
                    if '572' in line and ('ret' in line.lower() or 'buf' in line.lower()):
                        log(f"  {fname}:{lineno}: {line.strip()}")
        except:
            pass
    log("")

    # 3. AF_ROUTE 43o
    log("### AF_ROUTE 43o Detailed Scan")
    for f in result_files:
        if '43o' in f.name:
            try:
                with open(f, 'r', errors='replace') as fh:
                    content = fh.read()
                    log(f"  File: {f.name} ({len(content)} bytes)")
                    for lineno, line in enumerate(content.splitlines(), 1):
                        line = line.strip()
                        if line:
                            log(f"  L{lineno}: {line}")
                            vals = extract_64bit_values(line)
                            for v in vals:
                                deob = deobfuscate_ptr(v)
                                if is_kernel_ptr(v):
                                    log(f"    *** KERNEL PTR: 0x{v:016X} ***")
                                elif is_kernel_ptr(deob):
                                    log(f"    *** DEOBFUSCATED KPTR: 0x{v:016X} -> 0x{deob:016X} ***")
                                elif is_userland_code_ptr(v):
                                    log(f"    [userland code ptr: 0x{v:016X}]")
            except Exception as e:
                log(f"  ERROR: {e}")
    log("")

    # 4. Look for any hex dumps that contain kptr-range bytes
    log("### Hex Dump Deep Scan (looking for kptr bytes in raw dumps)")
    hexdump_re = re.compile(r'([0-9a-fA-F]{8}\s+){2,}')
    for f in result_files:
        try:
            with open(f, 'r', errors='replace') as fh:
                for lineno, line in enumerate(fh, 1):
                    # Look for hex dump lines
                    if re.search(r'\+0x[0-9a-fA-F]+:', line) or re.search(r'^[0-9a-fA-F]{4,8}:', line):
                        # Extract all 32-bit values
                        words = re.findall(r'\b([0-9a-fA-F]{8})\b', line)
                        for i in range(0, len(words) - 1, 2):
                            try:
                                # Try both endianness for adjacent 32-bit words
                                hi = int(words[i], 16)
                                lo = int(words[i+1], 16)
                                val_be = (hi << 32) | lo
                                val_le = (lo << 32) | hi
                                for val, order in [(val_be, "BE"), (val_le, "LE")]:
                                    if is_kernel_ptr(val):
                                        log(f"  {f.relative_to(RESULTS_DIR)}:{lineno} ({order}): 0x{val:016X}")
                                        log(f"    Context: {line.strip()[:120]}")
                            except:
                                pass
        except:
            pass
    log("")

    # 5. Specific: look for values close to known kernel text base 0xffffffff8a9c0000
    log("### Values Near Known Kernel Text Base (0xffffffff8a9c0000)")
    KNOWN_BASE = 0xffffffff8a9c0000
    for f in result_files:
        try:
            with open(f, 'r', errors='replace') as fh:
                content = fh.read()
            for m in HEX64_SPLIT_RE.finditer(content):
                h = int(m.group(1), 16)
                l = int(m.group(2), 16)
                val = (h << 32) | l
                if abs(val - KNOWN_BASE) < 0x10000000 and val != 0:
                    log(f"  {f.relative_to(RESULTS_DIR)}: 0x{val:016X} (delta from base: 0x{abs(val-KNOWN_BASE):X})")
        except:
            pass
    log("")

    # Write output
    outpath = Path(__file__).parent.parent / "evidence" / "deep_result_scan.md"
    outpath.parent.mkdir(parents=True, exist_ok=True)
    with open(outpath, 'w') as f:
        f.write('\n'.join(output_lines))
    log(f"\nOutput saved to {outpath}")

if __name__ == '__main__':
    main()

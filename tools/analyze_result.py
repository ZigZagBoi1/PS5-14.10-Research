#!/usr/bin/env python3
"""
Probe result auto-analyzer for PS5 14.10 kernel research.
Scans probe output for kernel pointers, success indicators, and anomalies.

Usage: python tools/analyze_result.py results/phase14_final_push/54f_*.txt
       python tools/analyze_result.py results/  (analyzes all .txt in dir)
"""

import re
import sys
import os
import glob

# ANSI colors
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Known sysent RVA offset (stable across 13.60 and 14.10)
SYSENT_RVA = 0xe6e5c0

# Blocked syscalls that would be significant if they returned non-error
BLOCKED_SYSCALLS = {
    2: "fork", 251: "rfork", 430: "thr_new", 54: "ioctl",
    90: "dup2", 306: "kldfind", 307: "kldnext", 308: "kldstat",
    309: "kldfirstmod", 310: "kldsym", 556: "cpuset_getid", 484: "kenv",
}

# Sony syscalls known to return non-error (for baseline)
KNOWN_ACCESSIBLE = {596, 585, 572, 624, 563, 564, 565, 566, 606, 643, 640, 593, 620}


def is_kernel_ptr(hi, lo):
    """Check if a 64-bit value (hi:lo) looks like a kernel pointer."""
    return hi >= 0xFFFF8000 and hi < 0xFFFFFFFF


def deobfuscate_ptr(val):
    """Reverse f(x) = x ^ (x >> 4) — iterative recovery."""
    # For 64-bit: recover top bits first, then work down
    result = val
    shift = 4
    while shift < 64:
        result = val ^ (result >> shift)
        shift *= 2  # not exact but close enough for detection
    return result


def parse_hex_value(s):
    """Parse '0xHHHHHHHH_LLLLLLLL' or '0xHHHHHHHHLLLLLLLL' into (hi, lo)."""
    s = s.strip().replace("_", "")
    if s.startswith("0x") or s.startswith("0X"):
        s = s[2:]
    try:
        val = int(s, 16)
    except ValueError:
        return None, None
    hi = (val >> 32) & 0xFFFFFFFF
    lo = val & 0xFFFFFFFF
    return hi, lo


def full_val(hi, lo):
    return (hi << 32) | lo


class Finding:
    def __init__(self, level, line_num, line, message, detail=None):
        self.level = level  # "RED", "YELLOW", "GREEN"
        self.line_num = line_num
        self.line = line.rstrip()
        self.message = message
        self.detail = detail


def analyze_file(filepath):
    findings = []
    kptrs_found = []
    crashes = []
    successes = []

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"{RED}ERROR: Cannot read {filepath}: {e}{RESET}")
        return

    for i, line in enumerate(lines, 1):
        stripped = line.strip()

        # 1. Our probe markers
        # Pointer markers share the validated 64-bit scan below.
        marked_ptr_line = ">>> KPTR" in stripped or ">>> KERNEL POINTER" in stripped

        if "WRMSR SUCCEEDED" in stripped or "WRMSR SUCCESS" in stripped:
            findings.append(Finding("RED", i, line, "*** WRMSR WORKS — MSR WRITE FROM USERLAND ***"))

        if "NEWLY ACCESSIBLE" in stripped:
            findings.append(Finding("RED", i, line, "PREVIOUSLY BLOCKED SYSCALL NOW WORKS"))

        if "RWX" in stripped and "ret=0" in stripped:
            findings.append(Finding("RED", i, line, "RWX MEMORY GRANTED — W^X BYPASS"))

        # Only match KASLR defeat in actual result lines, not probe titles/headers
        if ("KASLR DEFEAT" in stripped or "KASLR defeat" in stripped) and \
           not stripped.startswith("===") and "PROBE" not in stripped:
            findings.append(Finding("RED", i, line, "KASLR DEFEAT INDICATOR"))

        # 2. Kernel pointer patterns in hex values
        # Skip lines that are just printing test addresses (timing probes, probe inputs)
        # Real leaks appear in "buf[N]=", return values, hexdump lines (+XXX:), or KPTR markers
        is_data_line = any(x in stripped for x in [
            "buf[", "ret=", "+0x", "+00", "KPTR", ">>>"
        ]) or re.match(r"\s+\+[0-9A-Fa-f]{3}:", stripped)

        for m in re.finditer(r"0x([0-9a-fA-F]{8})[_]?([0-9a-fA-F]{8})", stripped):
            hi_s, lo_s = m.group(1), m.group(2)
            try:
                hi = int(hi_s, 16)
                lo = int(lo_s, 16)
            except ValueError:
                continue

            if is_kernel_ptr(hi, lo):
                # Only classify values from data output, not printed test inputs.
                if is_data_line:
                    if marked_ptr_line:
                        message = "PROBE FOUND KERNEL POINTER"
                    else:
                        message = f"KERNEL POINTER: 0x{hi:08X}_{lo:08X}"
                    findings.append(Finding("RED", i, line, message))
                    kptrs_found.append((i, hi, lo, stripped))

            # Check for obfuscated pointers — try deobfuscation
            elif hi != 0 and hi != 0xFFFFFFFF and lo != 0:
                val = full_val(hi, lo)
                deob = deobfuscate_ptr(val)
                deob_hi = (deob >> 32) & 0xFFFFFFFF
                deob_lo = deob & 0xFFFFFFFF
                if is_kernel_ptr(deob_hi, deob_lo):
                    findings.append(Finding("YELLOW", i, line,
                        f"POSSIBLE OBFUSCATED KPTR: 0x{hi:08X}_{lo:08X} -> deobf: 0x{deob_hi:08X}_{deob_lo:08X}"))
                    kptrs_found.append((i, deob_hi, deob_lo, f"(deobfuscated from line {i})"))

        # 3. Return value patterns (match "ret=N" but not "ret=0x...")
        ret_m = re.search(r"ret=(-?\d+)(?!\s*\(0x)", stripped)
        # Skip if the ret value is actually part of a hex display
        if ret_m and re.search(r"ret=0x[0-9a-fA-F]", stripped):
            ret_m = None
        if ret_m:
            ret_val = int(ret_m.group(1))

            # Check for success on blocked syscalls
            sc_m = re.search(r"(\d{1,3})\s+(\w+)\s+ret=", stripped)
            if sc_m:
                sc_num = int(sc_m.group(1))
                sc_name = sc_m.group(2)
                if sc_num in BLOCKED_SYSCALLS and ret_val >= 0:
                    findings.append(Finding("RED", i, line,
                        f"BLOCKED SYSCALL {sc_num} ({BLOCKED_SYSCALLS[sc_num]}) RETURNED {ret_val}!"))
                    successes.append((sc_num, sc_name, ret_val))

            # Syscall number in different format: "626(..." or "661(..."
            # Only match "ret=0" or "ret=0 " (not ret=0x... which is hex)
            if re.search(r"ret=0(?:\s|$|[^x0-9a-fA-F])", stripped):
                sc_m2 = re.search(r"(\d{3})\(", stripped)
                if sc_m2:
                    sc_num = int(sc_m2.group(1))
                    if sc_num not in KNOWN_ACCESSIBLE and sc_num >= 500:
                        findings.append(Finding("YELLOW", i, line,
                            f"Sony syscall {sc_num} returned SUCCESS (0)"))

        # 4. Crash detection (match "CRASHED:" from pcall failures, not section headers or "NO CRASH")
        if "CRASHED:" in stripped or "CRASHED =" in stripped:
            findings.append(Finding("YELLOW", i, line, "CRASH DETECTED"))
            crashes.append((i, stripped))

        # 5. Non-zero buffer data after ret=0
        if "buf[0]=" in stripped and "ret=0" in stripped:
            buf_m = re.search(r"buf\[0\]=(0x[0-9a-fA-F_]+)", stripped)
            if buf_m:
                hi, lo = parse_hex_value(buf_m.group(1))
                if hi is not None and (hi != 0 or lo != 0):
                    findings.append(Finding("YELLOW", i, line,
                        f"NON-ZERO BUFFER after success: 0x{hi:08X}_{lo:08X}"))

        # 6. Data output markers
        if "<<< DATA" in stripped or "NON-ZERO PMC" in stripped:
            findings.append(Finding("YELLOW", i, line, "DATA OUTPUT FROM KERNEL"))

        # 7. CHANGING! marker (counter detected)
        if "CHANGING!" in stripped:
            findings.append(Finding("YELLOW", i, line, "LIVE COUNTER DETECTED — TIMING ORACLE"))

        # 8. BUFFER MODIFIED marker
        if "BUFFER MODIFIED" in stripped:
            findings.append(Finding("YELLOW", i, line, "KERNEL WROTE TO OUTPUT BUFFER"))

    # === PRINT REPORT ===
    print(f"\n{BOLD}{'='*70}{RESET}")
    print(f"{BOLD} PROBE RESULT ANALYSIS: {os.path.basename(filepath)}{RESET}")
    print(f"{BOLD}{'='*70}{RESET}")
    print(f" File: {filepath}")
    print(f" Lines: {len(lines)}")
    print()

    # Group by severity
    reds = [f for f in findings if f.level == "RED"]
    yellows = [f for f in findings if f.level == "YELLOW"]

    if reds:
        print(f"{RED}{BOLD}*** CRITICAL FINDINGS ({len(reds)}) ***{RESET}")
        print()
        for f in reds:
            print(f"  {RED}[!!!] Line {f.line_num}: {f.message}{RESET}")
            print(f"        {f.line}")
            if f.detail:
                print(f"        {f.detail}")
        print()

    if yellows:
        print(f"{YELLOW}{BOLD}*** NOTABLE FINDINGS ({len(yellows)}) ***{RESET}")
        print()
        for f in yellows:
            print(f"  {YELLOW}[!] Line {f.line_num}: {f.message}{RESET}")
            print(f"      {f.line}")
        print()

    if crashes:
        print(f"{YELLOW}Crashes: {len(crashes)}{RESET}")
        for line_num, text in crashes[:10]:
            print(f"  Line {line_num}: {text[:100]}")
        print()

    # === KERNEL POINTER ANALYSIS ===
    if kptrs_found:
        print(f"{RED}{BOLD}{'='*70}{RESET}")
        print(f"{RED}{BOLD} KERNEL POINTER ANALYSIS — KASLR DEFEAT{RESET}")
        print(f"{RED}{BOLD}{'='*70}{RESET}")
        print()

        seen_bases = {}
        for line_num, hi, lo, context in kptrs_found:
            val = full_val(hi, lo)
            # Align to 2MB boundary for kernel base estimate
            base = val & ~0x1FFFFF
            if base not in seen_bases:
                seen_bases[base] = []
            seen_bases[base].append((line_num, val, context))

        for base in sorted(seen_bases.keys()):
            ptrs = seen_bases[base]
            sysent = base + SYSENT_RVA
            base_hi = (base >> 32) & 0xFFFFFFFF
            base_lo = base & 0xFFFFFFFF
            sysent_hi = (sysent >> 32) & 0xFFFFFFFF
            sysent_lo = sysent & 0xFFFFFFFF

            print(f"  {CYAN}Candidate kernel base: 0x{base_hi:08X}_{base_lo:08X}{RESET}")
            print(f"  {CYAN}Estimated sysent addr: 0x{sysent_hi:08X}_{sysent_lo:08X}{RESET}")
            print(f"  Pointers in this range ({len(ptrs)}):")
            for ln, v, ctx in ptrs[:5]:
                v_hi = (v >> 32) & 0xFFFFFFFF
                v_lo = v & 0xFFFFFFFF
                print(f"    Line {ln}: 0x{v_hi:08X}_{v_lo:08X}")
            print()

            # Print Lua code to use these values
            print(f"  {GREEN}-- Lua: use these values in follow-up probes --{RESET}")
            print(f"  {GREEN}local kernel_base = uint64(\"0x{base_hi:08X}{base_lo:08X}\"){RESET}")
            print(f"  {GREEN}local sysent_addr = uint64(\"0x{sysent_hi:08X}{sysent_lo:08X}\"){RESET}")
            print()
    else:
        print(f"{GREEN}No kernel pointers found in this result.{RESET}")

    # === SUMMARY ===
    print()
    if reds:
        print(f"{RED}{BOLD}VERDICT: {len(reds)} CRITICAL FINDING(S) — INVESTIGATE IMMEDIATELY{RESET}")
    elif yellows:
        print(f"{YELLOW}{BOLD}VERDICT: {len(yellows)} notable finding(s) — worth reviewing{RESET}")
    else:
        print(f"{GREEN}{BOLD}VERDICT: No significant findings in this result.{RESET}")
    print()

    return len(reds), len(yellows), len(kptrs_found)


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <result_file_or_dir> [...]")
        print(f"  Analyzes probe output for kernel pointers and anomalies.")
        print(f"  Pass a directory to analyze all .txt files in it.")
        sys.exit(1)

    files = []
    for arg in sys.argv[1:]:
        if os.path.isdir(arg):
            files.extend(sorted(glob.glob(os.path.join(arg, "**/*.txt"), recursive=True)))
        elif os.path.isfile(arg):
            files.append(arg)
        else:
            # Try glob pattern
            matched = sorted(glob.glob(arg))
            if matched:
                files.extend(matched)
            else:
                print(f"{RED}Not found: {arg}{RESET}")

    if not files:
        print(f"{RED}No result files found.{RESET}")
        sys.exit(1)

    total_reds = 0
    total_yellows = 0
    total_kptrs = 0

    for f in files:
        result = analyze_file(f)
        if result:
            r, y, k = result
            total_reds += r
            total_yellows += y
            total_kptrs += k

    if len(files) > 1:
        print(f"\n{BOLD}{'='*70}{RESET}")
        print(f"{BOLD} AGGREGATE: {len(files)} files analyzed{RESET}")
        print(f"  Critical: {total_reds}  Notable: {total_yellows}  Kernel ptrs: {total_kptrs}")
        print(f"{'='*70}")


if __name__ == "__main__":
    main()

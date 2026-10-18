#!/usr/bin/env python3
"""
Disassemble PS5 13.60 Sony syscall handler .bin files using Capstone.

The handler_NNN.bin dumps are 4KB pages starting at each handler's sy_call
address. In the PS5 kernel, the sysent sy_call entries point into a thunk
table: each entry is a 5-byte JMP rel32 followed by 3 INT3 bytes (8-byte
stride). The real handler implementations are at the JMP targets.

This script:
  1. Parses each .bin to extract the thunk table entries (JMP targets)
  2. Groups handlers by their real implementation address
  3. Identifies unique vs shared implementations
  4. Counts thunk entries per handler (more thunks = larger dispatch table)
  5. Computes RVAs for Ghidra cross-referencing

Usage:
    pip install capstone
    python tools/disasm_handlers.py [--dir docs/dumps_13.60] [--json sysent_index.json]
                                     [--full NNN] [--out report.txt]
"""

import argparse
import glob
import json
import os
import struct
import sys
from collections import Counter, defaultdict

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
except ImportError:
    print("ERROR: capstone not installed. Run: pip install capstone", file=sys.stderr)
    sys.exit(1)


THUNK_STRIDE = 8  # 5-byte jmp + 3 int3


def parse_thunks(data, base_addr):
    """Parse a thunk table from raw bytes. Returns list of (thunk_addr, target_addr)."""
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    thunks = []
    # Disassemble expecting jmp/int3 pattern
    insns = list(md.disasm(data, base_addr))
    i = 0
    while i < len(insns):
        insn = insns[i]
        if insn.mnemonic == "jmp" and insn.op_str.startswith("0x"):
            try:
                target = int(insn.op_str, 16)
                thunks.append((insn.address, target))
            except ValueError:
                pass
            # Skip expected int3 padding
            i += 1
            while i < len(insns) and insns[i].mnemonic == "int3":
                i += 1
        elif insn.mnemonic == "int3" or insn.mnemonic == "nop":
            i += 1
        else:
            # Not a thunk -- might be inline code or end of table
            break
    return thunks


def disassemble_raw(data, base_addr):
    """Full disassembly for display purposes."""
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    return list(md.disasm(data, base_addr))


def format_disassembly(insns, max_lines=80):
    """Format instructions as text."""
    lines = []
    for i, insn in enumerate(insns):
        if max_lines and i >= max_lines:
            lines.append("  ... (%d more instructions)" % (len(insns) - max_lines))
            break
        hexbytes = " ".join("%02x" % b for b in insn.bytes)
        lines.append("  0x%x:  %-20s  %s %s" % (insn.address, hexbytes, insn.mnemonic, insn.op_str))
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Disassemble PS5 Sony syscall handlers")
    parser.add_argument("--dir", default=None, help="Directory with handler_NNN.bin files")
    parser.add_argument("--json", default=None, help="Path to sysent_index.json")
    parser.add_argument("--full", type=int, action="append", default=[], help="Print full disasm for handler NNN")
    parser.add_argument("--out", default=None, help="Output file")
    parser.add_argument("--top", type=int, default=30, help="Show top N handlers by thunk count")
    args = parser.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(script_dir)
    dump_dir = args.dir or os.path.join(repo_root, "docs", "dumps_13.60")
    json_path = args.json or os.path.join(dump_dir, "sysent_index.json")

    if not os.path.isdir(dump_dir):
        print("ERROR: dump directory not found: %s" % dump_dir, file=sys.stderr)
        sys.exit(1)

    # Load sysent metadata
    sysent = {}
    kernel_base = 0
    if os.path.exists(json_path):
        with open(json_path) as f:
            data = json.load(f)
        kernel_base = int(data["kernel_base"], 16)
        for e in data["entries"]:
            sysent[e["num"]] = e
    else:
        print("WARNING: sysent_index.json not found", file=sys.stderr)

    bins = sorted(glob.glob(os.path.join(dump_dir, "handler_*.bin")))
    if not bins:
        print("ERROR: no handler_*.bin files found", file=sys.stderr)
        sys.exit(1)

    out = open(args.out, "w") if args.out else sys.stdout
    def p(text=""):
        print(text, file=out)

    p("=" * 76)
    p("PS5 13.60 Sony Syscall Handler Analysis")
    p("Kernel base: 0x%x" % kernel_base)
    p("Handlers: %d files from %s" % (len(bins), dump_dir))
    p("=" * 76)
    p()

    # Collect all data
    handler_data = {}  # num -> {thunks, narg, base, ...}
    all_targets = Counter()  # target_addr -> count of thunks pointing there
    target_to_handlers = defaultdict(list)  # target_addr -> [syscall nums]

    for bin_path in bins:
        basename = os.path.basename(bin_path)
        num = int(basename.replace("handler_", "").replace(".bin", ""))

        with open(bin_path, "rb") as f:
            raw = f.read()

        base = int(sysent[num]["sy_call"], 16) if num in sysent else 0
        narg = sysent[num]["narg"] if num in sysent else "?"
        rva = int(sysent[num]["sy_call_off"], 16) if num in sysent else 0

        thunks = parse_thunks(raw, base)

        # Unique targets from this handler's thunk table
        unique_targets = set(t for _, t in thunks)

        for _, target in thunks:
            all_targets[target] += 1
            if num not in target_to_handlers[target]:
                target_to_handlers[target].append(num)

        handler_data[num] = {
            "num": num,
            "narg": narg,
            "base": base,
            "rva": rva,
            "thunk_count": len(thunks),
            "unique_targets": len(unique_targets),
            "targets": [t for _, t in thunks],
            "unique_target_set": unique_targets,
            "first_target": thunks[0][1] if thunks else None,
            "raw": raw,
        }

    # Print full disassembly for requested handlers
    for num in args.full:
        if num not in handler_data:
            p("Handler %d not found" % num)
            continue
        hd = handler_data[num]
        p("-" * 76)
        p("FULL DISASSEMBLY: sony_syscall_%d (narg=%s, base=0x%x, RVA=+0x%x)" % (
            num, hd["narg"], hd["base"], hd["rva"]))
        p("-" * 76)
        insns = disassemble_raw(hd["raw"], hd["base"])
        p(format_disassembly(insns))
        p()
        p("Thunk entries: %d (unique targets: %d)" % (hd["thunk_count"], hd["unique_targets"]))
        for i, target in enumerate(hd["targets"][:20]):
            rva = target - kernel_base
            p("  [%2d] -> 0x%x (RVA +0x%x)" % (i, target, rva))
        if len(hd["targets"]) > 20:
            p("  ... (%d more)" % (len(hd["targets"]) - 20))
        p()

    # Summary: handlers ranked by thunk count (more thunks = bigger dispatch surface)
    ranked = sorted(handler_data.values(), key=lambda h: h["thunk_count"], reverse=True)

    p("HANDLER SUMMARY (ranked by thunk count -- more thunks = larger dispatch table):")
    p("-" * 76)
    p("%-8s %-5s %-7s %-8s %-14s  %-s" % (
        "Syscall", "narg", "Thunks", "Unique", "Entry RVA", "First target RVA"))
    p("-" * 76)

    for hd in ranked[:args.top]:
        first_rva = (hd["first_target"] - kernel_base) if hd["first_target"] else 0
        p("%-8d %-5s %-7d %-8d +0x%-12x +0x%x" % (
            hd["num"], hd["narg"], hd["thunk_count"], hd["unique_targets"],
            hd["rva"], first_rva))

    p()

    # Category breakdown
    no_thunk = [h for h in ranked if h["thunk_count"] == 0]
    single = [h for h in ranked if h["thunk_count"] == 1]
    multi = [h for h in ranked if h["thunk_count"] > 1]
    large = [h for h in ranked if h["thunk_count"] >= 50]

    p("CATEGORIES:")
    p("  Total handlers:     %d" % len(handler_data))
    p("  No thunks (inline): %d  %s" % (len(no_thunk), [h["num"] for h in no_thunk]))
    p("  Single thunk:       %d" % len(single))
    p("  Multi-thunk:        %d" % len(multi))
    p("  Large (>=50):       %d  %s" % (len(large), [h["num"] for h in large]))
    p()

    # Shared implementation targets (same real function used by multiple handlers)
    p("SHARED IMPLEMENTATION TARGETS:")
    p("(Real kernel functions called by JMP thunks from multiple syscall handlers)")
    p("-" * 76)
    shared = [(t, nums) for t, nums in target_to_handlers.items() if len(nums) > 1]
    shared.sort(key=lambda x: len(x[1]), reverse=True)
    for target, nums in shared[:30]:
        rva = target - kernel_base
        p("  0x%x (RVA +0x%x) shared by %d handlers: %s" % (
            target, rva, len(nums), nums[:15]))
    if not shared:
        p("  (none found)")
    p()

    # Most-referenced target addresses (hot kernel functions)
    p("TOP 30 MOST-REFERENCED TARGETS (hot kernel functions for Ghidra labeling):")
    p("-" * 76)
    for target, count in all_targets.most_common(30):
        rva = target - kernel_base
        callers = target_to_handlers[target]
        p("  0x%x (RVA +0x%06x) referenced %3d times by: %s" % (
            target, rva, count, callers[:10]))
    p()

    # Handlers with unique-only targets (most interesting -- dedicated implementations)
    p("HANDLERS WITH ALL UNIQUE TARGETS (dedicated implementations):")
    p("-" * 76)
    for hd in ranked:
        if hd["thunk_count"] == 0:
            continue
        all_unique = True
        for t in hd["unique_target_set"]:
            if all_targets[t] > 1 and len(target_to_handlers[t]) > 1:
                # This target is shared with OTHER handlers
                other = [n for n in target_to_handlers[t] if n != hd["num"]]
                if other:
                    all_unique = False
                    break
        if all_unique:
            first_rva = (hd["first_target"] - kernel_base) if hd["first_target"] else 0
            p("  syscall %d: %d thunks, %d unique targets, narg=%s, first=+0x%x" % (
                hd["num"], hd["thunk_count"], hd["unique_targets"], hd["narg"], first_rva))
    p()

    # Handlers whose first target is the nosys stub (0x265760)
    nosys_rva = 0x265760
    nosys_handlers = []
    real_handlers = []
    for hd in ranked:
        if hd["first_target"] and (hd["first_target"] - kernel_base) == nosys_rva:
            nosys_handlers.append(hd["num"])
        elif hd["thunk_count"] > 0:
            real_handlers.append(hd)

    p("NOSYS STUBS (first target = nosys at +0x%x): %d handlers" % (nosys_rva, len(nosys_handlers)))
    if nosys_handlers:
        p("  %s" % nosys_handlers)
    p()
    p("REAL HANDLERS (non-nosys): %d" % len(real_handlers))
    p("-" * 76)
    for hd in sorted(real_handlers, key=lambda h: h["thunk_count"], reverse=True)[:40]:
        first_rva = (hd["first_target"] - kernel_base) if hd["first_target"] else 0
        p("  syscall %-4d  narg=%-2s  thunks=%-4d  unique=%-4d  impl=+0x%x" % (
            hd["num"], hd["narg"], hd["thunk_count"], hd["unique_targets"], first_rva))
    p()

    p("=" * 76)
    p("USAGE NOTES:")
    p("  --full NNN    Full disassembly of handler NNN")
    p("  --top N       Show more/fewer in the summary table")
    p("  --out FILE    Write to file")
    p()
    p("In Ghidra, navigate to the RVA targets (kernel_base + RVA) to find the")
    p("real handler implementations. The thunk table entries are JMP trampolines.")
    p("=" * 76)

    if args.out:
        out.close()
        print("Report written to %s" % args.out)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Disassemble PS5 13.60 Sony syscall handler .bin files using Capstone.

Reads handler_NNN.bin files from docs/dumps_13.60/, disassembles each,
and produces an analysis summary flagging interesting/exploitable patterns.

Usage:
    pip install capstone
    python tools/disasm_handlers.py [--dir docs/dumps_13.60] [--json sysent_index.json]
                                     [--full NNN] [--out report.txt]

Options:
    --dir DIR       Directory containing handler_NNN.bin files
    --json FILE     Path to sysent_index.json for metadata
    --full NNN      Print full disassembly for handler NNN (repeatable)
    --out FILE      Write report to file instead of stdout
    --top N         Show top N most interesting handlers (default: 20)
"""

import argparse
import glob
import json
import os
import struct
import sys

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
except ImportError:
    print("ERROR: capstone not installed. Run: pip install capstone", file=sys.stderr)
    sys.exit(1)


# Known kernel function call targets (by common instruction patterns)
INTERESTING_CALLS = {
    "copyin": "Copies user->kernel (potential overflow if length unchecked)",
    "copyout": "Copies kernel->user (potential info leak)",
    "copyinstr": "String copy from user (length issues)",
    "malloc": "Heap allocation (use-after-free potential)",
    "free": "Heap free (double-free potential)",
    "m_copydata": "mbuf data copy",
    "sooptcopyin": "Socket option copy in",
    "sooptcopyout": "Socket option copy out",
    "creat": "Credential create",
    "prison_check": "Jail/sandbox check (bypass target)",
    "priv_check": "Privilege check (bypass target)",
    "mac_check": "MAC policy check",
    "suser": "Superuser check",
}

# RIP-relative LEA patterns suggest data/string references
# CALL patterns suggest function calls
# CMP with immediate suggest switch/case dispatch


def disassemble_handler(data, base_addr=0):
    """Disassemble binary data, return list of (addr, size, mnemonic, op_str)."""
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    insns = []
    for i in md.disasm(data, base_addr):
        insns.append(i)
    return insns


def analyze_handler(insns, raw_data):
    """Analyze disassembled instructions for interesting patterns."""
    result = {
        "total_insns": len(insns),
        "calls": 0,
        "jumps": 0,
        "conditional_branches": 0,
        "ret_count": 0,
        "rip_relative_lea": 0,
        "memory_reads": 0,
        "memory_writes": 0,
        "syscall_insns": 0,
        "interesting_patterns": [],
        "call_targets": [],
        "cmp_immediates": [],
        "function_size": 0,  # bytes until first RET
    }

    base_addr = insns[0].address if insns else 0
    found_ret = False
    for i, insn in enumerate(insns):
        # Track function size (until first ret)
        if not found_ret:
            if insn.mnemonic == "ret" or insn.mnemonic == "retq":
                result["function_size"] = (insn.address - base_addr) + insn.size
                found_ret = True

        # Count by type
        if insn.mnemonic.startswith("call"):
            result["calls"] += 1
            result["call_targets"].append((insn.address, insn.op_str))
        elif insn.mnemonic.startswith("j") and insn.mnemonic != "jmp":
            result["conditional_branches"] += 1
            result["jumps"] += 1
        elif insn.mnemonic == "jmp":
            result["jumps"] += 1
        elif insn.mnemonic in ("ret", "retq"):
            result["ret_count"] += 1
        elif insn.mnemonic == "syscall":
            result["syscall_insns"] += 1

        # RIP-relative LEA (data references)
        if insn.mnemonic == "lea" and "rip" in insn.op_str:
            result["rip_relative_lea"] += 1

        # CMP with immediate (switch/case)
        if insn.mnemonic == "cmp" and "$" in insn.op_str:
            try:
                imm = insn.op_str.split("$")[-1].strip().rstrip(",")
                result["cmp_immediates"].append((insn.address, imm))
            except:
                pass

        # Memory operations (rough heuristic)
        op_str = insn.op_str
        if insn.mnemonic.startswith("mov"):
            if "[" in op_str:
                # Determine read vs write by position
                parts = op_str.split(",")
                if len(parts) == 2:
                    if "[" in parts[1]:
                        result["memory_reads"] += 1
                    if "[" in parts[0]:
                        result["memory_writes"] += 1

    if not found_ret and len(insns) > 0:
        result["function_size"] = (insns[-1].address - base_addr) + insns[-1].size

    # Detect nosys stub pattern: very short, just returns ENOSYS (78)
    if result["total_insns"] <= 5 and result["ret_count"] >= 1:
        result["interesting_patterns"].append("TRIVIAL (likely nosys/stub)")

    # Detect copyin/copyout-like patterns (calls with specific arg setup)
    if result["calls"] >= 3:
        result["interesting_patterns"].append("MULTI_CALL (%d calls)" % result["calls"])
    if result["conditional_branches"] >= 5:
        result["interesting_patterns"].append("COMPLEX_LOGIC (%d branches)" % result["conditional_branches"])
    if result["rip_relative_lea"] >= 3:
        result["interesting_patterns"].append("DATA_REFS (%d LEA rip)" % result["rip_relative_lea"])
    if result["function_size"] >= 512:
        result["interesting_patterns"].append("LARGE_FUNC (%d bytes)" % result["function_size"])
    if result["memory_writes"] >= 5:
        result["interesting_patterns"].append("HEAVY_MEMWRITE (%d writes)" % result["memory_writes"])

    return result


def compute_score(analysis):
    """Score a handler for exploit interest (higher = more interesting)."""
    score = 0
    score += analysis["calls"] * 3
    score += analysis["conditional_branches"] * 2
    score += analysis["function_size"] // 64
    score += analysis["memory_writes"] * 2
    score += analysis["rip_relative_lea"] * 1
    score += analysis["cmp_immediates"].__len__() * 1
    # Penalize trivial stubs
    if "TRIVIAL (likely nosys/stub)" in analysis["interesting_patterns"]:
        score = 0
    return score


def format_disassembly(insns, max_lines=None):
    """Format instructions as text."""
    lines = []
    for i, insn in enumerate(insns):
        if max_lines and i >= max_lines:
            lines.append("  ... (%d more instructions)" % (len(insns) - max_lines))
            break
        hexbytes = " ".join("%02x" % b for b in insn.bytes)
        lines.append("  0x%04x:  %-24s  %s %s" % (insn.address, hexbytes, insn.mnemonic, insn.op_str))
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Disassemble PS5 Sony syscall handlers")
    parser.add_argument("--dir", default=None, help="Directory with handler_NNN.bin files")
    parser.add_argument("--json", default=None, help="Path to sysent_index.json")
    parser.add_argument("--full", type=int, action="append", default=[], help="Print full disasm for handler NNN")
    parser.add_argument("--out", default=None, help="Output file")
    parser.add_argument("--top", type=int, default=20, help="Show top N most interesting")
    args = parser.parse_args()

    # Find directories
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(script_dir)

    dump_dir = args.dir or os.path.join(repo_root, "docs", "dumps_13.60")
    json_path = args.json or os.path.join(dump_dir, "sysent_index.json")

    if not os.path.isdir(dump_dir):
        print("ERROR: dump directory not found: %s" % dump_dir, file=sys.stderr)
        sys.exit(1)

    # Load sysent metadata
    sysent = {}
    if os.path.exists(json_path):
        with open(json_path) as f:
            data = json.load(f)
        kernel_base = int(data["kernel_base"], 16)
        for e in data["entries"]:
            sysent[e["num"]] = e
    else:
        kernel_base = 0
        print("WARNING: sysent_index.json not found, metadata unavailable", file=sys.stderr)

    # Find all handler bins
    bins = sorted(glob.glob(os.path.join(dump_dir, "handler_*.bin")))
    if not bins:
        print("ERROR: no handler_*.bin files in %s" % dump_dir, file=sys.stderr)
        sys.exit(1)

    out = open(args.out, "w") if args.out else sys.stdout

    def p(text=""):
        print(text, file=out)

    p("=" * 72)
    p("PS5 13.60 Sony Syscall Handler Analysis")
    p("Handlers: %d files from %s" % (len(bins), dump_dir))
    p("=" * 72)
    p()

    results = {}

    for bin_path in bins:
        basename = os.path.basename(bin_path)
        num = int(basename.replace("handler_", "").replace(".bin", ""))

        with open(bin_path, "rb") as f:
            raw = f.read()

        # Determine base address from sysent
        base = 0
        narg = "?"
        if num in sysent:
            base = int(sysent[num]["sy_call"], 16)
            narg = sysent[num]["narg"]

        insns = disassemble_handler(raw, base)
        analysis = analyze_handler(insns, raw)
        analysis["num"] = num
        analysis["narg"] = narg
        analysis["base"] = base
        analysis["score"] = compute_score(analysis)
        analysis["insns"] = insns
        results[num] = analysis

    # Print full disassembly for requested handlers
    for num in args.full:
        if num not in results:
            p("Handler %d not found" % num)
            continue
        r = results[num]
        p("-" * 72)
        p("FULL DISASSEMBLY: sony_syscall_%d (narg=%s, addr=0x%x)" % (num, r["narg"], r["base"]))
        p("-" * 72)
        p(format_disassembly(r["insns"]))
        p()

    # Sort by score
    ranked = sorted(results.values(), key=lambda x: x["score"], reverse=True)

    # Summary table
    p("TOP %d MOST INTERESTING HANDLERS (by exploit potential score):" % args.top)
    p("-" * 72)
    p("%-8s %-6s %-6s %-6s %-6s %-6s %-6s  %s" % (
        "Syscall", "Score", "narg", "Size", "Calls", "Branch", "MemWr", "Patterns"))
    p("-" * 72)

    for r in ranked[:args.top]:
        patterns = ", ".join(r["interesting_patterns"]) if r["interesting_patterns"] else "-"
        p("%-8d %-6d %-6s %-6d %-6d %-6d %-6d  %s" % (
            r["num"], r["score"], r["narg"], r["function_size"],
            r["calls"], r["conditional_branches"], r["memory_writes"],
            patterns))

    p()

    # Category summary
    trivial = [r for r in ranked if r["score"] == 0]
    interesting = [r for r in ranked if r["score"] > 0]
    large = [r for r in ranked if r["function_size"] >= 256]
    multi_call = [r for r in ranked if r["calls"] >= 3]
    complex_logic = [r for r in ranked if r["conditional_branches"] >= 5]
    heavy_write = [r for r in ranked if r["memory_writes"] >= 5]

    p("CATEGORY SUMMARY:")
    p("  Total handlers:       %d" % len(results))
    p("  Trivial/stub:         %d" % len(trivial))
    p("  Non-trivial:          %d" % len(interesting))
    p("  Large (>=256B):       %d  %s" % (len(large), [r["num"] for r in large]))
    p("  Multi-call (>=3):     %d  %s" % (len(multi_call), [r["num"] for r in multi_call]))
    p("  Complex logic (>=5):  %d  %s" % (len(complex_logic), [r["num"] for r in complex_logic]))
    p("  Heavy mem-write (>=5):%d  %s" % (len(heavy_write), [r["num"] for r in heavy_write]))
    p()

    # Exploit candidates
    p("EXPLOIT CANDIDATES (score >= 15):")
    p("-" * 72)
    candidates = [r for r in ranked if r["score"] >= 15]
    if not candidates:
        p("  None found with score >= 15. Lowering threshold...")
        candidates = ranked[:10]

    for r in candidates:
        p("  sony_syscall_%d (score=%d, narg=%s)" % (r["num"], r["score"], r["narg"]))
        p("    Size: %d bytes, Calls: %d, Branches: %d, Mem writes: %d" % (
            r["function_size"], r["calls"], r["conditional_branches"], r["memory_writes"]))
        if r["call_targets"]:
            p("    Call targets: %s" % ", ".join("0x%x" % t[0] for t in r["call_targets"][:8]))
        if r["cmp_immediates"]:
            p("    CMP values: %s" % ", ".join(v for _, v in r["cmp_immediates"][:8]))
        p("    Patterns: %s" % (", ".join(r["interesting_patterns"]) or "none"))
        p()

    # Print call target addresses across all handlers for cross-reference
    p("SHARED CALL TARGETS (functions called by multiple handlers):")
    p("-" * 72)
    from collections import Counter
    all_targets = Counter()
    for r in results.values():
        for addr, op_str in r["call_targets"]:
            # Resolve relative call target
            if op_str.startswith("0x"):
                try:
                    target = int(op_str, 16)
                    all_targets[target] += 1
                except:
                    pass

    for target, count in all_targets.most_common(20):
        if count >= 2:
            callers = [r["num"] for r in results.values()
                       if any(op_str.startswith("0x") and int(op_str, 16) == target
                              for _, op_str in r["call_targets"]
                              if op_str.startswith("0x"))]
            rva = target - kernel_base if kernel_base else target
            p("  0x%x (RVA +0x%x) called by %d handlers: %s" % (
                target, rva, count, callers[:10]))

    p()
    p("=" * 72)
    p("Use --full NNN to see full disassembly of a specific handler.")
    p("Use --top N to show more/fewer ranked handlers.")
    p("=" * 72)

    if args.out:
        out.close()
        print("Report written to %s" % args.out)


if __name__ == "__main__":
    main()

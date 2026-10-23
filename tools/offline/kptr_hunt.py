#!/usr/bin/env python3
"""KASLR-leak candidate hunt across 13.60 Sony syscall handlers.

Scans every real handler (532-676) for call sites of copyout-like helpers
and classifies the source operand (rdi at call time):
  - OBJECT  : mov rdi, [reg+off] / mov rdi, [reg]  -> kernel heap pointer contents copied out
  - STACK   : lea rdi, [rbp-x]                     -> scalar on stack (boring unless struct)
  - OTHER   : unknown provenance

Object-sourced copyouts are the interesting class: they dump kernel-heap data
(lists, tables, blobs) to userland; if the buffer contains kernel pointers it
is a KASLR leak on any firmware that kept the code.

Usage: python tools/offline/kptr_hunt.py [--verbose]
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from handler_extract import DUMPS, TEXT, load_sysent, thunk_target, estimate_size

COPYOUT = 0x2591d0
COPYIN = 0x259280
UIOMOVE = None  # filled by pattern scan later if needed
md = Cs(CS_ARCH_X86, CS_MODE_64)


TRACK = {"rdi", "rsi", "rdx", "rax", "rbx", "rcx", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"}


def classify_site(insns, idx, depth=0, reg="rdi"):
    """Walk back from call idx to find what set `reg` (transitively through moves)."""
    if depth > 3:
        return ("UNKNOWN", f"deep:{reg}", None)
    for j in range(idx - 1, max(0, idx - 150), -1):
        m, ops = insns[j][0], insns[j][1]
        if m == "mov" and ops.startswith(reg + ","):
            src = ops[len(reg) + 1:].strip()
            if src.startswith("qword ptr [") or src.startswith("["):
                inner = src[src.index("[") + 1:src.rindex("]")]
                return ("OBJECT", inner, insns[j][2])
            if src in TRACK:
                # follow the register's own provenance
                r = classify_site(insns, j, depth + 1, src)
                if r[0] != "UNKNOWN":
                    return r
                return ("REG-CHAIN", src, insns[j][2])
            return ("IMM", src, insns[j][2])
        if m == "lea" and ops.startswith(reg + ","):
            src = ops[len(reg) + 1:].strip()
            if "rbp" in src or "rsp" in src:
                return ("STACK", src, insns[j][2])
            return ("LEA-GLOBAL", src, insns[j][2])
    return ("UNKNOWN", "?", None)


def walk_calls(rva, size, syent_names):
    insns = []
    for i in md.disasm(TEXT[rva:rva+size], rva):
        insns.append((i.mnemonic, i.op_str, i.address, i.bytes))
    sites = []
    for idx, (m, ops, addr, raw) in enumerate(insns):
        if m == "call" and ops.startswith("0x"):
            try:
                tgt = int(ops, 16)
            except ValueError:
                continue
            if tgt == COPYOUT:
                prov = classify_site(insns, idx)
                # find rdx (len) provenance quickly
                sites.append(("copyout", addr, prov))
            elif tgt == COPYIN:
                prov = classify_site(insns, idx)
                sites.append(("copyin", addr, prov))
    return sites


def main():
    syent = load_sysent()
    names = {}
    for line in open(os.path.join(DUMPS, "..", "sysent-names-13.60.csv")):
        parts = line.strip().split(",")
        if len(parts) >= 2 and parts[0].isdigit():
            names[int(parts[0])] = parts[1]
    verbose = "--verbose" in sys.argv
    report = {}
    for num in range(532, 677):
        e = syent[num]
        tgt = thunk_target(e["sy_call_off"])
        size = estimate_size(tgt)
        sites = walk_calls(tgt, size, names)
        if sites:
            report[num] = {"name": names.get(num, "?"), "sites": sites}
    obj_sites = []
    for num, r in report.items():
        for kind, addr, prov in r["sites"]:
            if kind == "copyout" and prov[0] == "OBJECT":
                obj_sites.append((num, r["name"], prov))
    print(f"handlers with copyout/copyin sites: {len(report)}/145")
    print(f"OBJECT-sourced copyout sites (leak candidates): {len(obj_sites)}")
    print()
    for num, name, prov in sorted(obj_sites):
        print(f"  sys {num} {name:24s} copyout from [{prov[1]}] (set @ {prov[2]:#x})")
    if verbose:
        print("\n--- all sites ---")
        for num in sorted(report):
            r = report[num]
            for kind, addr, prov in r["sites"]:
                print(f"  {num} {r['name']:24s} {kind} @{addr:#x} src={prov[0]}:{prov[1]}")
    json.dump({str(n): [{"kind": k, "addr": hex(a), "src": list(p)} for k, a, p in r["sites"]]
               for n, r in report.items()}, open("/tmp/kptr_hunt.json", "w"), indent=1)
    print("\nwrote /tmp/kptr_hunt.json")


if __name__ == "__main__":
    main()

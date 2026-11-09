#!/usr/bin/env python3
"""Disassemble arbitrary RVAs from docs/dumps_13.60/kernel_text.bin."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TEXT = open(os.path.join(ROOT, "docs", "dumps_13.60", "kernel_text.bin"), "rb").read()
md = Cs(CS_ARCH_X86, CS_MODE_64)

def dis(rva, size=0x200):
    for i in md.disasm(TEXT[rva:rva+size], rva):
        print(f"  {i.address:#010x}  {i.bytes.hex():<24} {i.mnemonic} {i.op_str}")

if __name__ == "__main__":
    rva = int(sys.argv[1], 16)
    size = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x200
    dis(rva, size)

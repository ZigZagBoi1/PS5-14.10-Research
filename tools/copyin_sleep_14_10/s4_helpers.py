
import sys
sys.path.insert(0,r"C:\PS5contrib\tools\copyin_sleep_14_10")
from kc import *
targets=[0xc1a3e0,0x6fd6b0,0x4c6fa0,0x4c6a00,0x2591d0,0xc08df0,0x259280,0xc08b50,0x72b380,0x25d410,0x258ff0,0x4c7520,0x399eb0,0xadfa30,0xc4c4b0,0x44f8c0,0x4c78b0,0x2bc220,0xb078d0]
for t in targets:
    seen,calls,order=walk(t,max_ins=60,window=0x200)
    print("===== %08x (%d insns) ====="%(t,len(order)))
    for a in order[:14]:
        i=seen[a]; print("  %08x  %-22s %s %s"%(a,i.bytes.hex(),i.mnemonic,i.op_str))

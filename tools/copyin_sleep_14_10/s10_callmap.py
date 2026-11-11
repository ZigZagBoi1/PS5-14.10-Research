
import sys, pickle, time
sys.path.insert(0,r"C:\PS5contrib\tools\copyin_sleep_14_10")
from kc import *
import capstone
md2=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64); md2.detail=False

t0=time.time()
calls=[]
CH=0x10000
for s in range(0,len(data),CH):
    for i in md2.disasm(data[s:s+CH], BASE+s):
        if i.mnemonic=='call':
            o=i.op_str
            if o.startswith('0x'):
                tgt=int(o,16)-BASE
                calls.append((i.address-BASE,tgt))
pickle.dump(calls, open(r"C:\PS5contrib\tools\copyin_sleep_14_10\calls.pkl","wb"))
print("calls",len(calls),"time %.1f"%(time.time()-t0))

# find exact start of the context switch around 0x2522ac
import re
seg=data[0x252100:0x2522c0]
for m in re.finditer(b'\x55\x48\x89\xe5', seg):
    print("prologue at %08x"%(0x252100+m.start()))
for i in md2.disasm(data[0x252240:0x2522c0], BASE+0x252240):
    print("%08x %-16s %s %s"%(i.address-BASE,i.bytes.hex(),i.mnemonic,i.op_str))

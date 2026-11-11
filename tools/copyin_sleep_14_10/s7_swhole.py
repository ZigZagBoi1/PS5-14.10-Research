
import sys
sys.path.insert(0,r"C:\PS5contrib\tools\copyin_sleep_14_10")
from kc import *
import capstone, time

md2=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
md2.detail=False
t0=time.time()
hits_rsp=[]; hits_swapgs=[]; hits_stac=[]
n=0
CH=0x10000
for s in range(0,len(data),CH):
    blob=data[s:s+CH]
    for i in md2.disasm(blob, BASE+s):
        n+=1
        m=i.mnemonic
        if m=='mov' and i.op_str.startswith('rsp, qword ptr ['):
            hits_rsp.append((i.address-BASE,i.op_str))
        elif m=='swapgs':
            hits_swapgs.append(i.address-BASE)
print("insns",n,"time %.1fs"%(time.time()-t0))
print("mov rsp,[mem] sites:",len(hits_rsp))
for a,o in hits_rsp[:40]: print("  %08x  %s"%(a,o))
print("swapgs sites:",len(hits_swapgs), [hex(x) for x in hits_swapgs[:20]])

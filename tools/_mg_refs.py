
import json, struct, bisect
P=r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin"; D=r"C:\PS5contrib\docs\dumps_13.60\kernel_data.bin"
BASE=0xffffffff8a9c0000
data=open(P,"rb").read(); N=len(data)
dat=open(D,"rb").read()
fs=[int(x) for x in json.load(open(r"C:\PS5contrib\docs\_mg_starts.json"))["starts"]]
fset=set(fs)
lo,hi=BASE,BASE+N
# 1) data pointers into text
ptrs=set(); hits=0
for off in range(0,len(dat)-7,8):
    v=int.from_bytes(dat[off:off+8],"little")
    if lo<=v<hi: ptrs.add(v-BASE); hits+=1
print("data qwords pointing into text:",hits,"distinct rvas:",len(ptrs))
def snap(rva):
    j=bisect.bisect_right(fs,rva)-1
    if j<0: return None
    s=fs[j]
    return s if rva-s<0x800 else None
dsnap=set(filter(None,(snap(r) for r in ptrs)))
print("distinct funcs referenced by data pointers:",len(dsnap))
json.dump(sorted(dsnap),open(r"C:\PS5contrib\docs\_mg_dataref.json","w"))
# 2) lea rip-relative address-taken, and mov imm64
addr_taken=set()
import re
for m in re.finditer(rb"\x48\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", data):
    o=m.start()
    if o+7>N: continue
    disp=struct.unpack_from("<i",data,o+3)[0]
    tgt=(BASE+o+7+disp)-BASE
    if 0<=tgt<N:
        s=snap(tgt)
        if s is not None: addr_taken.add(tgt if tgt in fset else s)
print("lea-materialised func addresses:",len(addr_taken))
json.dump(sorted(addr_taken),open(r"C:\PS5contrib\docs\_mg_addrtaken.json","w"))

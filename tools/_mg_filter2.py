
import capstone, json
P  = r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin"; BASE=0xffffffff8a9c0000
data=open(P,"rb").read()
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail=True
rows=json.load(open(r"C:\PS5contrib\docs\_mg_rows2.json"))
def pow2(x): return x>0 and (x&(x-1))==0
keep=[]
for r in rows:
    imm=r["imm"]
    s = imm-0x100000000 if imm>=0x80000000 else imm
    if -0x100000 <= s < 0: continue          # -1 / -EINVAL style sentinels
    if imm in (0x7fffffff,0x7ffffffe,0x80000000): continue  # INT_MAX clamps
    r["simm"]=s
    keep.append(r)
print("after sentinel filter:",len(keep))
cla=[r for r in keep if r["imm"]>=0x10000000 and not pow2(r["imm"])]
clb=[r for r in keep if 0x1000<=r["imm"]<0x10000000 and not pow2(r["imm"])]
clc=[r for r in keep if r["imm"]<0x1000]
print("class A (>=0x10000000 distinctive):",len(cla)," class B (mid distinctive):",len(clb)," other:",len(clc))
# how many class A are syscall reachable
print("class A reachable from syscall:",sum(1 for r in cla if r["depth"] is not None))
print("class B reachable:",sum(1 for r in clb if r["depth"] is not None))
# distinct immediates
import collections
ca=collections.Counter(r["imm"] for r in cla); cb=collections.Counter(r["imm"] for r in clb)
print()
print("class A top immediates:", ", ".join("0x%08x:%d"%(k,v) for k,v in ca.most_common(18)))
print()
print("class B top immediates:", ", ".join("0x%x:%d"%(k,v) for k,v in cb.most_common(18)))
json.dump(keep,open(r"C:\PS5contrib\docs\_mg_keep.json","w"))

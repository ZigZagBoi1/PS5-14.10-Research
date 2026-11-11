
import capstone, json
P=r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin"; BASE=0xffffffff8a9c0000
data=open(P,"rb").read(); N=len(data)
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail=True
FS=set(int(x) for x in json.load(open(r"C:\PS5contrib\docs\_mg_starts.json"))["starts"])
def dump(f,n,label):
    print("=== 0x%x %s"%(f,label))
    for i in md.disasm(data[f:f+n],BASE+f):
        t=""
        if i.mnemonic in ("call","jmp") or i.mnemonic.startswith("j"):
            o=i.op_str
            if o.startswith("0x"): t="  ->0x%x"%((int(o,16)-BASE))
        print("  %7x %-20s %s %s%s"%(i.address-BASE,i.bytes.hex(),i.mnemonic,i.op_str,t))
dump(0x5f9f30,0x70,"0x5f9f5b cmp ecx,0x10000000 d2 sys12/56/59")
dump(0x45e4d0,0x50,"0x45e4e8 cmp r13d,0x10000 d0 sys44")
# constants inside the big dispatcher
e=min([x for x in FS if x>0xaecd70]+[N])
cnt={}
for i in md.disasm(data[0xaecd70:e],BASE+0xaecd70):
    if i.mnemonic=="cmp" and i.op_str.startswith("esi, 0x"):
        v=int(i.op_str.split(", ")[1],16)
        cnt[v]=cnt.get(v,0)+1
print()
print("dispatcher 0xaecd70..0x%x size=%d distinct cmp esi,imm constants=%d" % (e,e-0xaecd70,len(cnt)))
hi=[v for v in cnt if v>=0x78000000]
print("  of which >=0x78000000:",len(hi))
print("  sample:", ", ".join("0x%x"%v for v in sorted(hi)[:14]))

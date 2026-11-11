
import capstone, json, numpy as np, time
P  = r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin"
BASE = 0xffffffff8a9c0000
data=open(P,"rb").read(); N=len(data)
fs=[int(x) for x in json.load(open(r"C:\PS5contrib\docs\_mg_starts.json"))["starts"]]
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail=True
t0=time.time()
hits=[]
ncmp=0
fails=0
for k,s in enumerate(fs):
    e = fs[k+1] if k+1<len(fs) else N
    e = min(e, s+0x2000, N)
    if e<=s: continue
    try:
        insns=list(md.disasm(data[s:e], BASE+s))
    except Exception:
        fails+=1; continue
    n=0
    for ins in insns:
        n+=1
        if n>1200: break
        if ins.mnemonic!="cmp" or len(ins.operands)!=2: continue
        o0,o1=ins.operands
        if o1.type!=capstone.x86.X86_OP_IMM: continue
        imm=o1.imm & 0xffffffff
        if imm < 0x1000: continue
        if o0.type==capstone.x86.X86_OP_MEM:
            if o0.size!=4: continue
            d={"base":ins.reg_name(o0.mem.base),"index":ins.reg_name(o0.mem.index),"scale":o0.mem.scale,"disp":o0.mem.disp}
            kind="mem32"
        elif o0.type==capstone.x86.X86_OP_REG:
            if o0.size!=4: continue
            d={"reg":ins.reg_name(o0.reg)}; kind="reg32"
        else: continue
        hits.append({"rva":ins.address-BASE,"imm":imm,"text":ins.mnemonic+" "+ins.op_str,
                     "kind":kind,"detail":d,"func":s,"func_len":e-s,"bytes":ins.bytes.hex()})
        ncmp+=1
print("func-sweep %.1fs funcs=%d cmp-imm32>=0x1000 hits=%d fails=%d" % (time.time()-t0,len(fs),ncmp,fails))
json.dump(hits, open(r"C:\PS5contrib\docs\_mg_func_hits.json","w"))
# sanity: is 0xabb9d3 present?
print("0xabb9d3 present:", any(h["rva"]==0xabb9d3 for h in hits))
print("distinct funcs with hits:", len(set(h["func"] for h in hits)))

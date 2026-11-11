
import capstone, json
P=r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin"; BASE=0xffffffff8a9c0000
data=open(P,"rb").read(); N=len(data)
fs=[int(x) for x in json.load(open(r"C:\PS5contrib\docs\_mg_starts.json"))["starts"]]
fset=set(fs)
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail=True
X=capstone.x86
ARG=["rdi","rsi","rdx","rcx","r8","r9","r10"]  # r10 not arg, drop
ARGSET={"rdi","rsi","rdx","rcx","r8","r9"}
CALLER={"rax","rcx","rdx","rsi","rdi","r8","r9","r10","r11"}
def norm(r):
    if not r: return ""
    # map sub-registers to parent
    m={"eax":"rax","ax":"rax","al":"rax","ah":"rax","ebx":"rbx","bx":"rbx","bl":"rbx","bh":"rbx",
       "ecx":"rcx","cx":"rcx","cl":"rcx","edx":"rdx","dx":"rdx","dl":"rdx","esi":"rsi","si":"rsi","sil":"rsi",
       "edi":"rdi","di":"rdi","dil":"rdi","ebp":"rbp","bp":"rbp","bpl":"rbp","esp":"rsp","sp":"rsp","spl":"rsp"}
    if r in m: return m[r]
    if len(r)>2 and r[0]=="r" and r[1].isdigit():
        base = r.split("d")[0] if "d" in r else r
        for suf in ("d","w","b","l"):
            if r.endswith(suf): base=r[:-len(suf)]
        return base
    return r
out=[]
for k,s in enumerate(fs):
    e=fs[k+1] if k+1<len(fs) else N
    e=min(e,s+0x2000,N)
    if e<=s: continue
    insns=list(md.disasm(data[s:e],BASE+s))
    lvl={r:1 for r in ARGSET}
    for ins in insns:
        mn=ins.mnemonic; ops=ins.operands
        if mn=="cmp" and len(ops)==2 and ops[1].type==X.X86_OP_IMM:
            imm=ops[1].imm & 0xffffffff
            if imm>=0x1000:
                o0=ops[0]
                if o0.type==X.X86_OP_MEM and o0.size==4:
                    b=norm(ins.reg_name(o0.mem.base)); ix=norm(ins.reg_name(o0.mem.index)) if o0.mem.index else None
                    L=lvl.get(b)
                    if ix and lvl.get(ix) is not None: L=min(L,lvl[ix]) if L is not None else lvl[ix]
                    out.append({"rva":ins.address-BASE,"imm":imm,"text":"cmp "+ins.op_str,"func":s,
                        "kind":"mem","base":b,"disp":int(o0.mem.disp),"lvl":L,
                        "argsrc":"uap+0x%x"%o0.mem.disp if (b in ("rsi","rdi") or L==1) else None})
                elif o0.type==X.X86_OP_REG and o0.size==4:
                    r=norm(ins.reg_name(o0.reg))
                    out.append({"rva":ins.address-BASE,"imm":imm,"text":"cmp "+ins.op_str,"func":s,
                        "kind":"reg","base":r,"disp":None,"lvl":lvl.get(r),"argsrc":None})
            continue
        # taint propagation
        if mn=="mov" and len(ops)==2:
            d,src=ops
            if d.type==X.X86_OP_REG:
                dr=norm(ins.reg_name(d.reg))
                if src.type==X.X86_OP_REG:
                    lvl[dr]=lvl.get(norm(ins.reg_name(src.reg)))
                elif src.type==X.X86_OP_MEM:
                    b=norm(ins.reg_name(src.mem.base))
                    L=lvl.get(b)
                    lvl[dr]= None if L is None else L+1
                else: lvl[dr]=None
            continue
        if mn=="lea" and len(ops)==2 and ops[0].type==X.X86_OP_REG and ops[1].type==X.X86_OP_MEM:
            dr=norm(ins.reg_name(ops[0].reg)); b=norm(ins.reg_name(ops[1].mem.base))
            lvl[dr]=lvl.get(b); continue
        if mn=="call":
            for r in CALLER: lvl[r]=None
            continue
        # any other instruction writing a register invalidates it
        if ops and ops[0].type==X.X86_OP_REG and mn not in ("cmp","test","push","nop"):
            try:
                if ops[0].access & X.CS_AC_WRITE or mn in ("xor","sub","add","and","or","pop","imul","movzx","movsx","shl","shr","sar","inc","dec","neg","not","setne","sete","movsxd","cdqe","movabs"):
                    lvl[norm(ins.reg_name(ops[0].reg))]=None
            except Exception: pass
json.dump(out,open(r"C:\PS5contrib\docs\_mg_taint.json","w"))
print("hits:",len(out))
import collections
c=collections.Counter(str(h["lvl"]) for h in out)
print("arg-derived level distribution:",dict(c))
print("mem-arg hits with lvl<=1:",sum(1 for h in out if h["kind"]=="mem" and h["lvl"] is not None and h["lvl"]<=1))
print("sanity 0xabb9d3:",[h for h in out if h["rva"]==0xabb9d3])
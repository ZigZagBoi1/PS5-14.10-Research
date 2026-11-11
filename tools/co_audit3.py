import json, sys, bisect, capstone
sys.path.insert(0, r"C:\PS5contrib\tools")
import co_audit as A
from co_func import fstart, FS
d = A.d
H = json.load(open(r"C:\PS5contrib\tools\co_handlers.json"))
BODIES = {int(k,16): sorted(v) for k,v in H["bodies"].items()}

class Fn:
    def __init__(self, fs, end):
        self.fs=fs; self.end=end
        self.ins = A.dis_window(fs, min(end, len(d)))
        self.addr = {i.address-A.BASE:k for k,i in enumerate(self.ins)}
        self.memo={}
    def preds(self, addr):
        out=[]
        for k,i in enumerate(self.ins):
            m=i.mnemonic
            if m in ("jmp","je","jne","jb","jbe","ja","jae","jl","jle","jg","jge","js","jns","jo","jno","jp","jnp","jz","jnz","jecxz","loop"):
                if len(i.operands)==1 and i.operands[0].type==capstone.x86.X86_OP_IMM:
                    if i.operands[0].imm - A.BASE == addr: out.append(k)
        return out
    def block_start(self, idx):
        k=idx-1
        while k>=0:
            m=self.ins[k].mnemonic
            if m in ("ret","jmp","int3","ud2","hlt"): return k+1
            k-=1
        return 0
    def back(self, reg, idx, depth=0, seen=None):
        """abstract value of reg just before instruction idx"""
        if seen is None: seen=set()
        key=(reg,idx)
        if key in seen or depth>7: return ("unknown","recursion")
        seen=seen|{key}
        k=idx-1
        while k>=0:
            ins=self.ins[k]
            if A.writes(ins, reg):
                return self.value(reg, k, depth, seen)
            if ins.mnemonic in ("ret","jmp","int3","ud2","hlt"):
                break
            k-=1
        bs=self.block_start(idx)
        if bs==0:
            return ("arg", reg)
        ps=self.preds(self.ins[bs].address-A.BASE)
        vals=[]
        for p in ps:
            v=self.back(reg,p+1,depth+1,seen)
            if v not in vals: vals.append(v)
        if not vals: return ("unknown","no-pred")
        if len(vals)==1: return vals[0]
        return ("phi", "|".join(fmt(v) for v in vals))
    def value(self, reg, k, depth, seen):
        ins=self.ins[k]; ops=ins.operands; mn=ins.mnemonic
        if mn in ("mov","movabs") and len(ops)==2:
            if ops[1].type==capstone.x86.X86_OP_IMM:
                return ("imm", ops[1].imm)
            if ops[1].type==capstone.x86.X86_OP_REG:
                return self.back(A.nreg(ins.reg_name(ops[1].reg)), k, depth+1, seen)
            if ops[1].type==capstone.x86.X86_OP_MEM:
                return self.via_mem(ins, k, 1, depth, seen)
        if mn in ("movzx","movsx","movsxd") and len(ops)==2 and ops[1].type==capstone.x86.X86_OP_MEM:
            return self.via_mem(ins, k, 1, depth, seen, narrow=True)
        if mn=="xor" and len(ops)==2 and ops[0].type==capstone.x86.X86_OP_REG and ops[1].type==capstone.x86.X86_OP_REG and ops[0].reg==ops[1].reg:
            return ("imm",0)
        if mn=="lea" and len(ops)==2 and ops[1].type==capstone.x86.X86_OP_MEM:
            m=ops[1].mem; base=A.nreg(ins.reg_name(m.base)) if m.base else None
            if base=="rip": return ("global", ins.op_str)
            return ("lea", ins.op_str)
        if mn in ("add","sub","and","or","shl","shr","sar","imul","adc","sbb","xor","not","neg") and len(ops)>=2:
            l=self.back(reg,k,depth+1,seen) if ops[0].type==capstone.x86.X86_OP_REG else ("unknown","")
            if ops[1].type==capstone.x86.X86_OP_IMM: r=("imm",ops[1].imm)
            elif ops[1].type==capstone.x86.X86_OP_REG: r=self.back(A.nreg(ins.reg_name(ops[1].reg)),k,depth+1,seen)
            else: r=("unknown","")
            return ("op:%s"%mn,(l,r))
        if mn=="call": return ("ret",ins.op_str)
        if mn=="pop": return ("pop",ins.op_str)
        return ("unknown","%s %s"%(mn,ins.op_str))
    def via_mem(self, ins, k, oi, depth, seen, narrow=False):
        b=A.mem_base(ins,oi)
        if b is None: return ("unknown","mem")
        base,disp,idxr=b
        if base is None: return ("unknown","abs")
        if base in ("rbp","rsp"):
            slot=self.stack_slot(base,disp,k,seen)
            return slot
        src=self.back(base,k,depth+1,seen)
        if src[0]=="arg":
            return ("mem:arg:%s"%src[1], "+0x%x"%disp if disp>=0 else "-0x%x"%(-disp))
        if src[0]=="mem:arg:rsi":
            return ("mem:uap2","+0x%x"%disp)
        return ("mem:%s"%fmt(src), "+0x%x"%disp)
    def stack_slot(self, base, disp, k, seen):
        for j in range(k-1,-1,-1):
            ii=self.ins[j]; o0=ii.operands[0] if ii.operands else None
            if o0 is None: continue
            if o0.type==capstone.x86.X86_OP_MEM and (o0.access & capstone.CS_AC_WRITE):
                b2=A.mem_base(ii,0)
                if b2 and b2[0]==base and b2[1]==disp:
                    if ii.mnemonic in ("mov","movabs") and len(ii.operands)==2:
                        if ii.operands[1].type==capstone.x86.X86_OP_IMM: return ("slot:imm", ii.operands[1].imm)
                        if ii.operands[1].type==capstone.x86.X86_OP_REG:
                            return ("slot", self.back(A.nreg(ii.reg_name(ii.operands[1].reg)), j, 1, seen))
                        if ii.operands[1].type==capstone.x86.X86_OP_MEM:
                            return ("slot", self.via_mem(ii,j,1,1,seen))
                    if ii.mnemonic=="movzx" and len(ii.operands)==2 and ii.operands[1].type==capstone.x86.X86_OP_MEM:
                        return ("slot", self.via_mem(ii,j,1,1,seen,narrow=True))
                    return ("slot:store", "%s %s"%(ii.mnemonic,ii.op_str))
            if ii.mnemonic in ("ret","jmp","int3"): break
        return ("slot", "nostore")

def fmt(v, depth=0):
    if v is None: return "?"
    t=v[0]
    if t=="imm": return "imm=0x%x"%v[1]
    if t=="arg": return "ARG:%s"%v[1]
    if t=="mem:arg:rsi": return "uap%s"%(v[1] if len(v)>1 else "")
    if t.startswith("mem:arg:rsi"): return "uap%s"%v[1]
    if t.startswith("mem:arg:"): return "%s%s"%(t[8:],v[1])
    if t.startswith("mem:"): return "deref(%s)%s"%(t[4:],v[1] if len(v)>1 else "")
    if t=="slot": return "slot(%s)"%fmt(v[1]) if len(v)>1 else "slot"
    if t.startswith("slot:imm"): return "slot_imm(0x%x)"%v[1]
    if t=="op:add": return "(%s + %s)"%(fmt(v[1][0]),fmt(v[1][1]))
    if t=="op:and": return "(%s & %s)"%(fmt(v[1][0]),fmt(v[1][1]))
    if t.startswith("op:"): return "(%s %s %s)"%(fmt(v[1][0]), t[3:], fmt(v[1][1]))
    if t=="ret": return "ret%s"%("...")
    if t=="global": return "global"
    if t=="lea": return "lea(%s)"%v[1]
    if t=="phi": return "PHI{%s}"%v[1]
    if t=="pop": return "pop"
    return t

def function_of(site):
    fs=fstart(site)
    if fs is None: return None
    nxt=bisect.bisect_right(FS, fs)
    end=FS[nxt] if nxt<len(FS) else len(d)
    return Fn(fs, min(end, fs+0x4000))

out=[]
for site in A.CALLS+A.JUMPS:
    rec={"site":site,"kind":"call" if site in A.CALLS else "jump"}
    f=function_of(site)
    if f is None or site not in f.addr:
        rec["rdx"]="NOFUNC"; rec["rdi"]="NOFUNC"; out.append(rec); continue
    k=f.addr[site]
    rec["fs"]=f.fs
    rec["handler"]=BODIES.get(f.fs)
    rdx=f.back("rdx",k); rdi=f.back("rdi",k)
    rec["rdx"]=fmt(rdx); rec["rdi"]=fmt(rdi)
    out.append(rec)
json.dump(out, open(r"C:\PS5contrib\tools\co_class3.json","w"), default=str)
from collections import Counter
import re
def norm(s): return re.sub(r"0x[0-9a-f]+","N",s)
print("total",len(out))
for k,v in Counter(norm(r.get("rdx","")) for r in out).most_common(35): print("%5d %s"%(v,k))
print("--- unassigned fs:", sum(1 for r in out if "fs" not in r))

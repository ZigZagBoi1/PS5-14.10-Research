import sys, json, capstone
sys.path.insert(0, r"C:\PS5contrib\tools")
import co_audit as A
from co_func import fstart

def analyze(site):
    fs = fstart(site)
    if fs is None: return None
    il = A.dis_window(fs, site+0x10)
    k = None
    for j,ins in enumerate(il):
        if ins.address-A.BASE == site: k=j; break
        if ins.address-A.BASE > site: break
    if k is None: return None
    info = A.classify(il, k, "rdx")
    # find definition index of rdx
    w = A.find_writer(il, k, "rdx")
    guards = []
    lo = (w+1) if w is not None else 0
    # carrier: the register whose value lands in rdx at the call
    carrier = "rdx"
    if w is not None:
        di = il[w]
        if di.mnemonic in ("mov","movabs") and len(di.operands)==2 and di.operands[1].type==capstone.x86.X86_OP_REG:
            carrier = A.nreg(di.reg_name(di.operands[1].reg))
        elif di.mnemonic in ("mov","movabs") and len(di.operands)==2 and di.operands[1].type==capstone.x86.X86_OP_IMM:
            carrier = "rdx"
    families = {carrier}
    for r64,txt in [("rdx",("rdx","edx","dl","dx")),("r15",("r15","r15d","r15w","r15b"))]:
        pass
    def names(reg):
        out={reg}
        m={"rax":["eax","ax","al"],"rbx":["ebx","bx","bl"],"rcx":["ecx","cx","cl"],"rdx":["edx","dx","dl"],
           "rsi":["esi","si","sil"],"rdi":["edi","di","dil"],"rbp":["ebp","bp","bpl"],
           "r8":["r8d","r8w","r8b"],"r9":["r9d","r9w","r9b"],"r10":["r10d","r10w","r10b"],
           "r11":["r11d","r11w","r11b"],"r12":["r12d","r12w","r12b"],"r13":["r13d","r13w","r13b"],
           "r14":["r14d","r14w","r14b"],"r15":["r15d","r15w","r15b"]}
        out |= set(m.get(reg,[]))
        return out
    nm = names(carrier)
    info["carrier"] = carrier
    if carrier != "rdx":
        w2 = A.find_writer(il, w, carrier)
        if w2 is not None: lo = w2+1
    for j in range(lo, k):
        ins = il[j]
        if ins.mnemonic in ("cmp","test","sub"):
            txt = ins.op_str
            first = txt.split(",")[0].strip()
            if first in nm:
                nxt = il[j+1] if j+1 < k else None
                if nxt is not None and nxt.mnemonic.startswith("j") and nxt.mnemonic not in ("jmp",):
                    guards.append("%06x %s %s / %06x %s %s"%(ins.address-A.BASE, ins.mnemonic, txt, nxt.address-A.BASE, nxt.mnemonic, nxt.op_str))
                else:
                    guards.append("%06x %s %s (no jcc)"%(ins.address-A.BASE, ins.mnemonic, txt))
    src = A.classify(il, k, "rdi")
    return {"site":site,"fs":fs,"idx":k,"rdx":info,"rdi":src,"guards":guards,
            "ndef":("%06x %s %s"%(il[w].address-A.BASE, il[w].mnemonic, il[w].op_str)) if w is not None else None}

if __name__=="__main__":
    sites = sorted(set(A.CALLS) | set(A.JUMPS))
    rows=[]
    for s in sites:
        r = analyze(s)
        if r: rows.append(r)
    json.dump(rows, open(r"C:\PS5contrib\tools\co_final.json","w"), indent=0)
    from collections import Counter
    print("analyzed", len(rows))
    print(Counter(r["rdx"]["cls"] for r in rows).most_common())
    print("with guard cand:", sum(1 for r in rows if r["guards"]))
    print("nonimm no-guard:", sum(1 for r in rows if r["rdx"]["cls"] not in ("imm",) and not r["guards"]))

import json, struct, bisect, capstone, sys, re
IMG = r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin"
BASE = 0xffffffff8a9c0000
COPYOUT = 0x2591d0
d = open(IMG,'rb').read()
sites = json.load(open(r"C:\PS5contrib\tools\co_sites.json"))
CALLS = sites["calls"]; JUMPS = sites["jumps"]

MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
MD.detail = True
MD.skipdata = False

REGS64 = {"rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","r8","r9","r10","r11","r12","r13","r14","r15"}
ALIAS = {}
for r in REGS64:
    ALIAS[r]=r
for r,b in [("rax","al"),("rax","ah"),("rax","ax"),("rax","eax"),
            ("rbx","bl"),("rbx","bh"),("rbx","bx"),("rbx","ebx"),
            ("rcx","cl"),("rcx","ch"),("rcx","cx"),("rcx","ecx"),
            ("rdx","dl"),("rdx","dh"),("rdx","dx"),("rdx","edx"),
            ("rsi","sil"),("rsi","si"),("rsi","esi"),
            ("rdi","dil"),("rdi","di"),("rdi","edi"),
            ("rbp","bpl"),("rbp","bp"),("rbp","ebp"),
            ("rsp","spl"),("rsp","sp"),("rsp","esp")]:
    ALIAS[b]=r

def nreg(name):
    return ALIAS.get(name)

def dis_window(start, end):
    code = d[start:end]
    out=[]
    for ins in MD.disasm(code, BASE+start):
        out.append(ins)
    return out

def good_window(site, back=0x180):
    """find an alignment where an instruction ends exactly at site and site is the call"""
    best=None
    for st in range(site-back, site):
        if st<0: continue
        ins_list = dis_window(st, site+0x20)
        if not ins_list: continue
        hit=None
        for k,ins in enumerate(ins_list):
            if ins.address-BASE == site:
                hit=k; break
            if ins.address-BASE > site: break
        if hit is not None and hit>3:
            # prefer longest
            best=(st, ins_list, hit); break
    return best

def writes(ins, reg):
    if not ins.operands: return False
    op0 = ins.operands[0]
    if op0.type != capstone.x86.X86_OP_REG: return False
    if not (op0.access & capstone.CS_AC_WRITE): return False
    return nreg(ins.reg_name(op0.reg)) == reg

def mem_base(ins, i=0):
    """return (base_reg_name or None, disp, index_reg) for operand i memory operand"""
    if len(ins.operands) <= i: return None
    op0 = ins.operands[i]
    if op0.type != capstone.x86.X86_OP_MEM: return None
    m = op0.mem
    base = ins.reg_name(m.base) if m.base else None
    idx  = ins.reg_name(m.index) if m.index else None
    return (nreg(base) if base else None, m.disp, nreg(idx) if idx else None)

def find_writer(ins_list, end_idx, reg):
    for k in range(end_idx-1, -1, -1):
        ins = ins_list[k]
        if writes(ins, reg):
            return k
        # stop at unconditional control transfer that ends a block
        if ins.mnemonic in ("ret","jmp") : return None
        if ins.mnemonic=="int3": return None
    return None

def classify(ins_list, idx, reg, depth=0, seen=None):
    """classify value of reg just before instruction idx"""
    if seen is None: seen=set()
    key=(idx,reg)
    if key in seen or depth>6: return {"cls":"unknown","detail":"depth"}
    seen.add(key)
    w = find_writer(ins_list, idx, reg)
    if w is None:
        return {"cls":"live_in","detail":reg}
    ins = ins_list[w]
    mn = ins.mnemonic
    ops = ins.operands
    # immediate move
    if mn in ("mov","movabs") and len(ops)==2 and ops[1].type==capstone.x86.X86_OP_IMM:
        v = ops[1].imm
        return {"cls":"imm","value":v,"detail":"%s %s"%(mn,ins.op_str)}
    if mn=="xor" and len(ops)==2 and ops[0].type==capstone.x86.X86_OP_REG and ops[1].type==capstone.x86.X86_OP_REG and ops[0].reg==ops[1].reg:
        return {"cls":"imm","value":0,"detail":"xor self"}
    if mn in ("mov","movabs") and len(ops)==2 and ops[1].type==capstone.x86.X86_OP_REG:
        return classify(ins_list, w, nreg(ins.reg_name(ops[1].reg)), depth+1, seen)
    if mn in ("movzx","movsx","movsxd","movzx") and len(ops)==2 and ops[1].type==capstone.x86.X86_OP_MEM:
        b = mem_base(ins,1)
        return load_class(ins_list, w, b, depth, seen, ins.op_str, narrow=True)
    if mn.startswith("mov") and len(ops)==2 and ops[1].type==capstone.x86.X86_OP_MEM:
        b = mem_base(ins,1)
        return load_class(ins_list, w, b, depth, seen, ins.op_str)
    if mn=="lea" and len(ops)==2 and ops[1].type==capstone.x86.X86_OP_MEM:
        m=ops[1].mem
        base = nreg(ins.reg_name(m.base)) if m.base else None
        if base=="rip":
            return {"cls":"global_addr","detail":ins.op_str}
        if base in ("rbp","rsp"):
            return {"cls":"stack_addr","detail":ins.op_str}
        return {"cls":"derived_addr","detail":ins.op_str}
    if mn in ("add","sub","and","or","shl","shr","sar","imul","mul","adc") and len(ops)>=2:
        # result derived from dst and src
        left = classify(ins_list, w, reg, depth+1, seen) if ops[0].type==capstone.x86.X86_OP_REG else {"cls":"unknown"}
        right = None
        if ops[1].type==capstone.x86.X86_OP_IMM:
            right={"cls":"imm","value":ops[1].imm}
        elif ops[1].type==capstone.x86.X86_OP_REG:
            right = classify(ins_list, w, nreg(ins.reg_name(ops[1].reg)), depth+1, seen)
        return {"cls":"arith","detail":"%s %s"%(mn,ins.op_str),"left":left,"right":right}
    if mn=="pop":
        return {"cls":"stack_pop","detail":ins.op_str}
    if mn=="call":
        return {"cls":"call_ret","detail":ins.op_str}
    if mn=="movbe": pass
    return {"cls":"unknown","detail":"%s %s"%(mn,ins.op_str)}

def load_class(ins_list, w, base_tuple, depth, seen, text, narrow=False):
    base, disp, idxr = base_tuple
    if base is None:
        return {"cls":"unknown","detail":text}
    if base in ("rsi",) and depth==0:
        return {"cls":"uap","detail":text,"disp":disp}
    if base in ("rbp","rsp"):
        # find last store to that slot
        slot = (base, disp)
        for k in range(w-1,-1,-1):
            ii = ins_list[k]
            if not ii.operands: continue
            o0=ii.operands[0]
            if o0.type==capstone.x86.X86_OP_MEM:
                b2 = mem_base(ii)
                if b2 and b2[0]==base and b2[1]==disp and (o0.access & capstone.CS_AC_WRITE):
                    if ii.mnemonic in ("mov","movabs") and len(ii.operands)==2 and ii.operands[1].type==capstone.x86.X86_OP_IMM:
                        return {"cls":"stack_imm","value":ii.operands[1].imm,"detail":text+" <- %s"%ii.op_str}
                    if ii.mnemonic in ("mov","movabs") and len(ii.operands)==2 and ii.operands[1].type==capstone.x86.X86_OP_REG:
                        sub = classify(ins_list, k, nreg(ii.reg_name(ii.operands[1].reg)), depth+1, seen)
                        return {"cls":"stack_"+sub["cls"],"detail":text+" <- %s"%ii.op_str,"sub":sub}
                    return {"cls":"stack_store","detail":text+" <- %s"%ii.op_str}
            if ii.mnemonic in ("ret","jmp","int3"): break
        return {"cls":"stack_slot","detail":text}
    # base is a register: trace it
    sub = classify(ins_list, w, base, depth+1, seen)
    c = sub["cls"]
    if c=="uap":
        return {"cls":"uap_ind","detail":text,"base":sub}
    if c in ("call_ret",):
        return {"cls":"call_ret_derived","detail":text,"base":sub}
    return {"cls":c if c!="imm" else "ptr_imm","detail":text,"base":sub}

def fmt(c, depth=0):
    if c is None: return "?"
    s = c["cls"]
    if s=="imm": return "imm=0x%x"%c["value"]
    if s=="arith":
        l=fmt(c.get("left"),depth+1); r=fmt(c.get("right"),depth+1)
        return "(%s %s)"%(l, r)
    if s in ("stack_imm",): return "stack[imm]=0x%x"%c["value"]
    if s.startswith("stack_") and "sub" in c: return "stack:"+fmt(c["sub"],depth+1)
    if s in ("stack_slot","stack_addr"): return "stack"
    if s in ("uap","uap_ind"): return "uap"
    if s=="call_ret": return "ret(%s)"%c["detail"]
    if s=="call_ret_derived": return "ret:"+fmt(c.get("base"),depth+1)
    if s=="global_addr": return "global"
    if s=="live_in": return "live_in:%s"%c["detail"]
    return s

if __name__=='__main__':
    results=[]
    for site in CALLS+JUMPS:
        g = good_window(site)
        rec = {"site":site,"kind":"call" if site in CALLS else "jump"}
        if not g:
            rec["err"]="no-align"
            results.append(rec); continue
        st, il, hit = g
        ins = il[hit]
        rdx = classify(il, hit, "rdx")
        rdi = classify(il, hit, "rdi")
        rec["insn"]="%s %s"%(ins.mnemonic, ins.op_str)
        rec["rdx"]=fmt(rdx); rec["rdi"]=fmt(rdi)
        rec["rdx_raw"]=rdx; rec["rdi_raw"]=rdi
        rec["n_ins"]=hit
        rec["start"]=st
        results.append(rec)
    
    json.dump(results, open(r"C:\PS5contrib\tools\co_class.json","w"), default=str)
    from collections import Counter
    def norm(s):
        s = re.sub(r"0x[0-9a-f]+","N",s)
        return s
    print("total", len(results))
    print("--- rdx classes ---")
    for k,v in Counter(norm(r.get("rdx","ERR")) for r in results).most_common(40): print("%5d %s"%(v,k))
    print("--- rdi classes ---")
    for k,v in Counter(norm(r.get("rdi","ERR")) for r in results).most_common(40): print("%5d %s"%(v,k))

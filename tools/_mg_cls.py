
import capstone, json
P=r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin"; BASE=0xffffffff8a9c0000
data=open(P,"rb").read(); N=len(data)
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail=True
X=capstone.x86
FS=set(int(x) for x in json.load(open(r"C:\PS5contrib\docs\_mg_starts.json"))["starts"])
hits=json.load(open(r"C:\PS5contrib\docs\_mg_taint.json"))
# cache function insn lists
cache={}
def func_insns(f):
    if f in cache: return cache[f]
    e=min(f+0x2000, N)
    lst=[(i.address-BASE,i.mnemonic,i.op_str,i.bytes.hex()) for i in md.disasm(data[f:e],BASE+f)]
    cache[f]=lst; return lst
def follow(lst, idx, budget=0x60, maxn=28):
    """walk linearly from idx, following direct jmps once, return (list, saw_ret, ret_imm, saw_lea_rip_ret, calls)"""
    out=[]; calls=[]; ret_imm=None; lea_ret=False; saw_ret=False
    n=0; i=idx; start=None
    while i<len(lst) and n<maxn:
        rva,mn,ops,_=lst[i]
        if start is None: start=rva
        if rva-start>budget: break
        out.append((rva,mn,ops)); n+=1
        if mn=="call" and ops.startswith("0x"): calls.append(int(ops,16)-BASE)
        if mn=="ret": saw_ret=True; break
        if mn=="lea" and ops.startswith("rax,") and "rip" in ops:
            if i+1<len(lst) and lst[i+1][1]=="ret": lea_ret=True
        if mn=="mov" and ops.startswith("eax, 0x"):
            if i+1<len(lst) and lst[i+1][1] in ("ret","pop"): ret_imm=int(ops.split(", ")[1],16)
            if i+2<len(lst) and lst[i+1][1]=="pop" and lst[i+2][1]=="ret": ret_imm=int(ops.split(", ")[1],16)
        if mn=="jmp" and ops.startswith("0x"):
            t=int(ops,16)-BASE
            j=next((k for k,(r,_,_,_) in enumerate(lst) if r==t), None)
            if j is not None and j>i:
                i=j; continue
            if j is not None and j<=i: break
            break
        i+=1
    return out,saw_ret,ret_imm,lea_ret,calls
res=[]
for h in hits:
    rva=h["rva"]; f=h["func"]
    lst=func_insns(f)
    idx=next((k for k,(r,_,_,_) in enumerate(lst) if r==rva), None)
    if idx is None: continue
    nxt=lst[idx+1] if idx+1<len(lst) else None
    if not nxt or not nxt[1].startswith("j") or nxt[1]=="jmp": 
        clas="NO-JCC"
        res.append(dict(h,cls=clas)); continue
    jmn=nxt[1]; jtgt=int(nxt[2],16)-BASE if nxt[2].startswith("0x") else None
    fall,fr,fi,fl,fc=follow(lst,idx+1)
    tk,tr,ti,tl,tc=follow(lst,idxand:=None) if False else ([],False,None,False,[])
    # taken path
    j=next((k for k,(r,_,_,_) in enumerate(lst) if r==jtgt), None)
    if j is not None: tk,tr,ti,tl,tc=follow(lst,j)
    def score(path,ret_imm,lea_ret,calls):
        return len(calls)*3+(6 if lea_ret else 0)+len(path)*0.3
    fs_,ts_=score(fall,fi,fl,fc),score(tk,ti,tl,tc)
    if fl and tl: clas="LOOKUP-BOTH"
    elif fl or tl: clas="LOOKUP"
    elif (fr or tr) and (fc or tc): clas="GATE"
    elif (fi is not None or ti is not None) and (fc or tc): clas="GATE"
    elif len(fall)<4 and len(tk)<4: clas="CLAMP"
    else: clas="OTHER"
    res.append(dict(h,cls=clas,jcc=jmn,jtgt=jtgt,nerr=(fi if fi is not None else ti),
        calls_fall=fc[:3],calls_taken=tc[:3],nfall=len(fall),ntaken=len(tk),lea=(fl or tl)))
json.dump(res,open(r"C:\PS5contrib\docs\_mg_cls.json","w"))
import collections
print(collections.Counter(r["cls"] for r in res))
print()
print("GATE rows:",sum(1 for r in res if r["cls"] in ("GATE","GATE-ERR")))
g=[r for r in res if r["cls"]=="GATE"]
print("GATE with lvl<=2:",sum(1 for r in g if r["lvl"] is not None and r["lvl"]<=2))
for r in [x for x in g if x["lvl"] is not None and x["lvl"]<=2][:20]:
    print("  %7s 0x%08x L%s f=%-7s %-32s %s -> %s calls=%s" % (hex(r["rva"]),r["imm"],r["lvl"],hex(r["func"]),
       r["text"][:32], r["jcc"], hex(r["jtgt"]) if r["jtgt"] is not None else "-", [hex(c) for c in r["calls_fall"][:2]]))

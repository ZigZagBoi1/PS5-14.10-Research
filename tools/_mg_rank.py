
import capstone, json, collections
P  = r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin"
BASE = 0xffffffff8a9c0000
data=open(P,"rb").read()
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail=True
hits=json.load(open(r"C:\PS5contrib\docs\_mg_func_hits.json"))
edges={int(k):v for k,v in json.load(open(r"C:\PS5contrib\docs\_mg_gcall.json")).items()}
sysent=json.load(open(r"C:\PS5contrib\docs\_mg_sysent.json"))
sys_of={}
for num,narg,th,t in sysent:
    if t is not None: sys_of.setdefault(t,[]).append(num)
depth={}; reach={}
for f,ns in sys_of.items(): depth[f]=0; reach[f]=set(ns)
frontier=list(sys_of.keys()); d=0
while frontier and d<6:
    for f in frontier:
        for c in edges.get(f,()):
            if c not in depth: depth[c]=d+1
    for f in frontier:
        for c in edges.get(f,()):
            if depth.get(c)==d+1: reach.setdefault(c,set()).update(reach.get(f,()))
    frontier=[c for f in frontier for c in edges.get(f,()) if depth.get(c)==d+1]
    frontier=list(dict.fromkeys(frontier)); d+=1

def dis(rva,n):
    return [(i.address-BASE,i.mnemonic,i.op_str) for i in md.disasm(data[rva:rva+n],BASE+rva)]
def pow2(x): return x>0 and (x&(x-1))==0
SIZEY=set([0x1000,0x1800,0x2000,0x3000,0x4000,0x6000,0x8000,0xc000,0x10000,0x18000,0x20000,0x30000,0x40000,
 0x80000,0x100000,0x180000,0x200000,0x400000,0x800000,0x1000000,0x2000000,0x4000000,0x8000000])
rows=[]
for h in hits:
    rva=h["rva"]; imm=h["imm"]; f=h["func"]
    w=dis(rva,0x28)
    nxt=w[1] if len(w)>1 else None
    nxt2=w[2] if len(w)>2 else None
    guard=bool(nxt and nxt[1].startswith("j"))
    jtgt=None; jcc=None
    if guard:
        jcc=nxt[1]
        if nxt[2].startswith("0x"): jtgt=int(nxt[2],16)-BASE
    dd=depth.get(f)
    score=0
    score += {0:70,1:58,2:46,3:34,4:22,5:10}.get(dd,0)
    if guard: score+=25
    if imm>=0x10000000: score+=35
    if pow2(imm) and imm<0x10000000: score-=40
    if imm in SIZEY: score-=60
    if imm>=0x1000 and imm<0x10000: score-=10
    base=h["detail"].get("base","") or h["detail"].get("reg","")
    if base in ("rsi","rdi","rdx","rcx","r8","r9"): score+=18
    # what's guarded: count calls in next 0x80 bytes
    body=dis(rva,0x80)
    calls=[hex(b[0]) for b in body if b[1]=="call"][:3]
    if calls: score+=12
    rows.append({"rva":rva,"imm":imm,"text":h["text"],"func":f,"func_len":h["func_len"],
        "base":base,"disp":h["detail"].get("disp"),"depth":dd,"syscalls":sorted(reach.get(f,set()))[:8],
        "guard":guard,"jcc":jcc,"jtgt":jtgt,"calls":calls,"score":score})
rows.sort(key=lambda x:(-x["score"],x["rva"]))
json.dump(rows,open(r"C:\PS5contrib\docs\_mg_rows2.json","w"))
print("rows:",len(rows),"funcs:",len(hits))
print("guard-shaped:",sum(1 for r in rows if r["guard"]))
print("flag-like(>=0x10000000):",sum(1 for r in rows if r["imm"]>=0x10000000))
print("non-pow2 & >=0x10000000:",sum(1 for r in rows if r["imm"]>=0x10000000 and not pow2(r["imm"])))
print("syscall-reachable rows:",sum(1 for r in rows if r["depth"] is not None))
print()
for r in rows[:45]:
    print("%7s imm=0x%08x d=%-4s f=%-7s sys=%-18s %-30s %s -> %s" % (hex(r["rva"]),r["imm"],r["depth"],
      hex(r["func"]), str(r["syscalls"][:3]), r["text"][:30], r["jcc"] or "-", hex(r["jtgt"]) if r["jtgt"] is not None else "-"))

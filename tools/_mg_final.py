
import capstone, json, collections
P=r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin"; BASE=0xffffffff8a9c0000
data=open(P,"rb").read(); N=len(data)
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail=True
hits=json.load(open(r"C:\PS5contrib\docs\_mg_taint.json"))
rows={r["rva"]:r for r in json.load(open(r"C:\PS5contrib\docs\_mg_rows2.json"))}
edges={int(k):v for k,v in json.load(open(r"C:\PS5contrib\docs\_mg_gcall.json")).items()}
sysent=json.load(open(r"C:\PS5contrib\docs\_mg_sysent.json"))
sys_of={}
argc={}
for num,narg,th,t in sysent:
    if t is not None: sys_of.setdefault(t,[]).append(num); argc[t]=narg
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
    frontier=list(dict.fromkeys(c for f in frontier for c in edges.get(f,()) if depth.get(c)==d+1)); d+=1
FLOAT={0x3f800000,0xbf800000,0x3f000000,0xbf000000,0x40800000,0xc0800000,0x7ff00000,0x3f7fffff,0x3e22f982,0x3e22f983,0xc0000000,0x40000000}
def pow2(x): return x>0 and (x&(x-1))==0
def lowmask(x): return (x&0xffffffff)==0xffffffff or ((x&0xffffffff)&((x&0xffffffff)+1))==0
def ismask(x):
    x&=0xffffffff; inv=(~x)&0xffffffff
    return (x and (x&(x+1))==0) or (inv and (inv&(inv+1))==0)
SIZEY={0x1000,0x1800,0x2000,0x3000,0x4000,0x6000,0x8000,0xc000,0x10000,0x18000,0x20000,0x30000,0x40000,0x80000,0x100000,0x200000,0x400000,0x800000,0x1000000,0x2000000}
def dis(rva,n): return [(i.address-BASE,i.mnemonic,i.op_str) for i in md.disasm(data[rva:rva+n],BASE+rva)]
out=[]
for h in hits:
    imm=h["imm"]; s=imm-0x100000000 if imm>=0x80000000 else imm
    if -0x100000<=s<0: continue
    if imm in (0x7fffffff,0x7ffffffe,0x80000000): continue
    rva=h["rva"]; f=h["func"]; lvl=h["lvl"]
    w=dis(rva,0x30)
    nxt=w[1] if len(w)>1 else None
    guard=bool(nxt and nxt[1].startswith("j") and nxt[1]!="jmp")
    jcc=nxt[1] if guard else None; jtgt=None
    if guard and nxt[2].startswith("0x"): jtgt=int(nxt[2],16)-BASE
    dd=depth.get(f); sc=0
    sc += {0:90,1:70,2:50,3:35,4:22,5:12}.get(dd,0)
    if lvl==1: sc+=85
    elif lvl==2: sc+=62
    elif lvl==3: sc+=34
    if guard: sc+=22
    if imm>=0x10000000 and not pow2(imm): sc+=28
    if imm in FLOAT: sc-=45
    if ismask(imm): sc-=55
    if imm in SIZEY: sc-=55
    if pow2(imm) and imm<0x10000000: sc-=35
    body=dis(rva,0x90)
    calls=[hex(b[0]) for b in body if b[1]=="call"][:3]
    if calls: sc+=8
    out.append({"rva":rva,"imm":imm,"text":h["text"],"func":f,"kind":h["kind"],"base":h["base"],
      "disp":h["disp"],"lvl":lvl,"argsrc":h["argsrc"],"depth":dd,"syscalls":sorted(reach.get(f,set()))[:8],
      "narg":argc.get(f),"guard":guard,"jcc":jcc,"jtgt":jtgt,"calls":calls,"score":sc})
out.sort(key=lambda x:(-x["score"],x["rva"]))
json.dump(out,open(r"C:\PS5contrib\docs\_mg_final.json","w"))
print("candidates after exclusion:",len(out),"| syscall-body(depth0):",sum(1 for x in out if x["depth"]==0),
      "| arg-derived lvl1:",sum(1 for x in out if x["lvl"]==1))
print()
for x in out[:44]:
    print("%7s 0x%08x L%-4s d%-4s f=%-7s sys=%-16s %-34s %s" % (hex(x["rva"]),x["imm"],x["lvl"],x["depth"],
      hex(x["func"]),str(x["syscalls"][:3]).replace(" ",""),x["text"][:34],(x["jcc"] or "")+" "+(hex(x["jtgt"]) if x["jtgt"] is not None else "")))

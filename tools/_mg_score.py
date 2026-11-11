
import json, bisect, collections, numpy as np, struct
P  = r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin"
BASE = 0xffffffff8a9c0000
data = open(P,"rb").read(); N=len(data)
fs = np.array(json.load(open(r"C:\PS5contrib\docs\_mg_starts.json"))["starts"], dtype=np.int64)
sysent = json.load(open(r"C:\PS5contrib\docs\_mg_sysent.json"))
edges = {int(k):v for k,v in json.load(open(r"C:\PS5contrib\docs\_mg_gcall.json")).items()}
sys_of = {}
for num,narg,th,t in sysent:
    if t is not None: sys_of.setdefault(t,[]).append(num)
# reverse map for depth: BFS forward from sysent impls
depth={}; reach={}
frontier=list(sys_of.keys())
for f in frontier: depth[f]=0; reach[f]=set(sys_of[f])
d=0
while frontier and d<6:
    nxt={}
    for f in frontier:
        for c in edges.get(f,()):
            if c not in depth:
                nxt.setdefault(c,set())
    for c in nxt:
        depth[c]=d+1
    for f in frontier:
        for c in edges.get(f,()):
            if depth.get(c)==d+1:
                reach.setdefault(c,set()).update(reach.get(f,()))
    frontier=list(nxt.keys())
    d+=1
print("functions reachable from a syscall body:", len(depth))
print("  at depth 1:", sum(1 for v in depth.values() if v==1))

rows=json.load(open(r"C:\PS5contrib\docs\_mg_rows.json"))
def pow2(x): return x>0 and (x&(x-1))==0
SIZEY=set([0x1000,0x2000,0x3000,0x4000,0x6000,0x8000,0xc000,0x10000,0x18000,0x20000,0x40000,0x80000,
           0x100000,0x200000,0x400000,0x800000,0x1000000,0x2000000,0x4000000,0x20000000])
def nearest_start(rva):
    j=bisect.bisect_right(fs, rva)-1
    return int(fs[j]) if j>=0 else None

def dis(rva,n):
    import capstone
    md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail=True
    return [(i.address-BASE, i.bytes.hex(), i.mnemonic, i.op_str) for i in md.disasm(data[rva:rva+n], BASE+rva)]

out=[]
for r in rows:
    rva=r["rva"]; imm=r["imm"]
    fsx=nearest_start(rva)
    # sanity: gate must be within 0x1400 of start
    if fsx is None or rva-fsx>0x1400: pass
    w=dis(rva,0x20)
    nxt=w[1] if len(w)>1 else None
    guard=bool(nxt and nxt[2].startswith("j") and nxt[2]!="jmp")
    jt=None
    if guard and nxt[3].startswith("0x"):
        jt=int(nxt[3],16)-BASE
    score=0
    if imm>=0x10000000: score+=40
    if guard: score+=30
    dd=depth.get(fsx)
    score += {0:60,1:50,2:40,3:30,4:20,5:10}.get(dd,0)
    if imm in SIZEY: score-=50
    if pow2(imm) and imm<0x10000000: score-=45
    base=r["detail"].get("base","")
    if base in ("rsi","rdi","rdx","rcx","r8","r9"): score+=20
    out.append({"rva":rva,"imm":imm,"text":r["text"],"base":base,"disp":r["detail"].get("disp"),
                "func":fsx,"depth":dd,"syscalls":sorted(reach.get(fsx,set()))[:6],
                "guard":guard,"jtgt":jt,"score":score})
out.sort(key=lambda x:(-x["score"], x["rva"]))
json.dump(out, open(r"C:\PS5contrib\docs\_mg_scored.json","w"))
print("scored rows:", len(out))
print("top 40:")
for x in out[:40]:
    print("  %7s imm=0x%08x d=%s sys=%s %-28s %s" % (hex(x["rva"]), x["imm"], x["depth"], x["syscalls"][:3], x["text"][:44], "guard" if x["guard"] else ""))

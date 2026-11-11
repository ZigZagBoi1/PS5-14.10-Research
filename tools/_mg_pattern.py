
import struct, json, collections
P  = r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin"
BASE = 0xffffffff8a9c0000
data = open(P,"rb").read(); N=len(data)
def ok_modrm(m):
    return ((m>>3)&7)==7 and (m>>6)!=3
pat_hits=[]
for i in range(N-6):
    b=data[i]
    if b==0x81:
        m=data[i+1]
        if ok_modrm(m):
            pat_hits.append((i,"no-rex",m))
    elif b in (0x41,0x42,0x43,0x44,0x45,0x46,0x47):
        if data[i+1]==0x81 and ok_modrm(data[i+2]):
            pat_hits.append((i,"rex",data[i+2]))
print("pattern candidates (81 /7, any alignment):", len(pat_hits))
hits = json.load(open(r"C:\PS5contrib\docs\_mg_raw.json"))
ls = set(h["rva"] for h in hits)
pc = set(p[0] for p in pat_hits)
print("linear-sweep hits:", len(ls))
print("pattern set:", len(pc), " intersect:", len(ls & pc))
print("in pattern not in linear sweep:", len(pc-ls))
print("in linear sweep not in pattern:", len(ls-pc))
# immediates distribution among pattern hits with imm>=0x1000 and positive
pos=0; 
for (o,kind,m) in pat_hits:
    ilen = 0
    mod = m>>6
    off = o + (2 if kind=="no-rex" else 3) + (0 if mod==0 else (1 if mod==1 else 4))
    if off+4>N: continue
    imm = struct.unpack_from("<I", data, off)[0]
    if imm>=0x1000 and imm < 0x80000000: pos+=1
print("pattern hits with positive imm>=0x1000:", pos)

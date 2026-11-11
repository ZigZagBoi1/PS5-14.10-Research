
import capstone, json, collections
P = r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin"
BASE = 0xffffffff8a9c0000
data = open(P,"rb").read()
N=len(data)
hits = json.load(open(r"C:\PS5contrib\docs\_mg_raw.json"))
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail=True  # skipdata OFF

def clean_fwd(rva, n):
    end = min(rva+n, N)
    got = 0; cnt=0
    for ins in md.disasm(data[rva:end], BASE+rva):
        got += ins.size; cnt+=1
    return got, cnt

def clean_bwd(rva):
    # find an instruction boundary at rva from some start in [rva-15, rva-1], clean through rva
    for k in range(15,0,-1):
        st = rva-k
        if st < 0: continue
        pos = 0; ok=False; clean=True
        for ins in md.disasm(data[st:rva+1], BASE+st):
            pos += ins.size
            if pos == k:
                ok = True
            if pos > k:
                clean=False; break
        if clean and ok:
            return k
    return None

surv=[]
for h in hits:
    rva=h["rva"]
    got,cnt = clean_fwd(rva, 0x100)
    if got < 0x100 or cnt < 15: continue
    if rva < 32 or rva+0x100 >= N: continue
    b = clean_bwd(rva)
    if b is None: continue
    h["bwd"]=b
    surv.append(h)
print("survive clean-window filter:", len(surv))
def is_pow2(x): return x>0 and (x&(x-1))==0
print("  pow2:", sum(1 for h in surv if is_pow2(h["imm"])))
print("  non-pow2:", sum(1 for h in surv if not is_pow2(h["imm"])))
c=collections.Counter(h["imm"] for h in surv)
for v,n in c.most_common(25):
    print("   0x%08x %5d" % (v,n))
json.dump(surv, open(r"C:\PS5contrib\docs\_mg_surv.json","w"), indent=0)

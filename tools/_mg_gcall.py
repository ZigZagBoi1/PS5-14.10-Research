
import numpy as np, json, struct, time
P  = r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin"
BASE = 0xffffffff8a9c0000
data = open(P,"rb").read(); N=len(data)
b = np.frombuffer(data, dtype=np.uint8)
# --- function starts ---
starts=set()
pat=b"\x55\x48\x89\xe5"
i=data.find(pat)
while i!=-1:
    if i>0 and data[i-1] in (0xc3,0xcc,0x90,0x5d,0x00,0xe9,0xeb):
        starts.add(i)
    i=data.find(pat,i+1)
print("prologue starts (sanity-filtered):", len(starts))
cc=0
for o in range(16,N-16,16):
    if data[o-1]==0xcc and data[o]!=0xcc:
        starts.add(o); cc+=1
print("cc-padded added:", cc)
sj=json.load(open(r"C:\PS5contrib\docs\dumps_13.60\sysent_index.json"))
sysent=[];impls={}
for e in sj["entries"]:
    th=int(e["sy_call_off"],16) if isinstance(e["sy_call_off"],str) else e["sy_call_off"]
    t=None
    if th+5<=N and data[th]==0xe9:
        t=th+5+struct.unpack_from("<i",data,th+1)[0]
    sysent.append([e["num"],e.get("narg",0),th,t])
    if t is not None:
        impls.setdefault(t,[]).append(e["num"]); starts.add(t)
fs=np.array(sorted(starts), dtype=np.int64)
print("total function starts:", len(fs))
# --- global call-edge scan (e8 rel32) ---
t0=time.time()
idx=np.nonzero(b==0xe8)[0]
idx=idx[idx+5<N]
rel=np.frombuffer(data, dtype=np.int32, count=len(idx), offset=0) if False else None
rel=np.array([struct.unpack_from("<i",data,int(i)+1)[0] for i in idx[:0]])  # placeholder
rel=np.frombuffer(data[1:], dtype=np.int32, count=0) if False else None
# vectorized int32 read at idx+1
raw=np.frombuffer(data, dtype=np.uint8)
pos=(idx+1).astype(np.int64)
w = (raw[pos].astype(np.int64) | (raw[pos+1].astype(np.int64)<<8) | (raw[pos+2].astype(np.int64)<<16) | (raw[pos+3].astype(np.int64)<<24))
rel=w.copy()
rel[w>=0x80000000] = w[w>=0x80000000] - (1<<32)
tgt = idx.astype(np.int64)+5+rel
ok = (tgt>=0)&(tgt<N)
idx=idx[ok]; tgt=tgt[ok]
j = np.searchsorted(fs, tgt)
j[j>=len(fs)]=0
hit = fs[j]==tgt
print("e8 sites: %d, land exactly on a known function start: %d (%.1fs)" % (len(idx), int(hit.sum()), time.time()-t0))
src = idx[hit]; dst = tgt[hit]
# caller function = nearest preceding start
ci = np.searchsorted(fs, src, side='right')-1
okc = ci>=0
srcf = fs[ci[okc]]; dstf=dst[okc]
edges={}
for a_,b_ in zip(srcf.tolist(), dstf.tolist()):
    edges.setdefault(a_,set()).add(b_)
print("edges(func->func):", sum(len(v) for v in edges.values()), "callers:", len(edges))
json.dump({str(k):sorted(v) for k,v in edges.items()}, open(r"C:\PS5contrib\docs\_mg_gcall.json","w"))
json.dump({"starts":fs.tolist()}, open(r"C:\PS5contrib\docs\_mg_starts.json","w"))
json.dump(sysent, open(r"C:\PS5contrib\docs\_mg_sysent.json","w"))

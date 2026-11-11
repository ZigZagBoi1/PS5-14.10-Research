import json, sys, struct, bisect
sys.path.insert(0, r"C:\PS5contrib\tools")
import co_audit as A
from co_func import fstart, FS
d = A.d
H = json.load(open(r"C:\PS5contrib\tools\co_handlers.json"))
BODIES = {int(k,16): sorted(v) for k,v in H["bodies"].items()}
cl3 = json.load(open(r"C:\PS5contrib\tools\co_class3.json"))
# functions containing copyout sites
byf={}
for r in cl3:
    byf.setdefault(r.get("fs"), []).append(r)

# index all e8 calls
calls=[]
for i in range(len(d)-5):
    if d[i]==0xE8:
        rel=struct.unpack_from('<i',d,i+1)[0]
        calls.append((i, i+5+rel))
print("total e8 calls", len(calls))

def cls_rdx_at(site):
    f=fstart(site)
    if f is None: return None, None
    nxt=bisect.bisect_right(FS,f); end=FS[nxt] if nxt<len(FS) else len(d)
    il=A.dis_window(f, min(end, site+0x10))
    k=None
    for j,ins in enumerate(il):
        if ins.address-A.BASE==site: k=j; break
        if ins.address-A.BASE>site: break
    if k is None: return None, None
    return A.fmt(A.classify(il,k,"rdx")), A.fmt(A.classify(il,k,"rdi"))

targets=[f for f in byf if f]
tgt=set(targets)
callers={}
for (site,t) in calls:
    if t in tgt:
        callers.setdefault(t,[]).append(site)
res={}
for f in sorted(targets):
    lst=[]
    for cs in callers.get(f,[]):
        rd,ri = cls_rdx_at(cs)
        lst.append((cs,rd,ri))
    res[f]=lst
json.dump({str(k):v for k,v in res.items()}, open(r"C:\PS5contrib\tools\co_callers.json","w"), default=str)
from collections import Counter
cnt=Counter()
for f,lst in res.items():
    for cs,rd,ri in lst:
        cnt[A.fmt] and None
        cnt[str(rd).split("=")[0]]+=1
print("functions with copyout:", len(targets))
print("caller sites found:", sum(len(v) for v in res.values()))
for k,v in cnt.most_common(20): print(v,k)

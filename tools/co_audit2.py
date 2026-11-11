import json, sys, capstone, re
sys.path.insert(0, r"C:\PS5contrib\tools")
import co_audit as A
from co_func import fstart
from collections import Counter
d = A.d

def func_window(site):
    fs = fstart(site)
    if fs is None: return None, None
    il = A.dis_window(fs, site+0x30)
    hit=None
    for k,ins in enumerate(il):
        if ins.address-A.BASE == site: hit=k; break
        if ins.address-A.BASE > site: return None, fs
    if hit is None: return None, fs
    # keep only up to call
    return il[:hit+1], fs

res=[]
for site in A.CALLS + A.JUMPS:
    il, fs = func_window(site)
    rec={"site":site,"kind":"call" if site in A.CALLS else "jump","fs":fs}
    if il is None:
        rec["rdx"]="NOFUNC"; rec["rdi"]="NOFUNC"; res.append(rec); continue
    hit=len(il)-1
    rdx=A.classify(il,hit,"rdx"); rdi=A.classify(il,hit,"rdi")
    rec["rdx"]=A.fmt(rdx); rec["rdi"]=A.fmt(rdi)
    rec["rdx_raw"]=rdx; rec["rdi_raw"]=rdi
    rec["flen"]=site-fs
    res.append(rec)
json.dump(res, open(r"C:\PS5contrib\tools\co_class2.json","w"), default=str)
def norm(s): return re.sub(r"0x[0-9a-f]+","N",s)
print("total",len(res))
for k,v in Counter(norm(r.get("rdx","")) for r in res).most_common(45): print("%5d %s"%(v,k))
print("--- rdi ---")
for k,v in Counter(norm(r.get("rdi","")) for r in res).most_common(30): print("%5d %s"%(v,k))
print("--- func start None:", sum(1 for r in res if r.get("fs") is None))


import sys, json, collections, struct
sys.path.insert(0,r"C:\PS5contrib\tools\copyin_sleep_14_10")
from kc import *

tm=thunk_map()
hs=sorted(set(h for tr,h in tm.values()))
print("handlers",len(hs))
allcalls={}
body={}
for h in hs:
    seen,calls,order=walk(h, max_ins=4000)
    body[h]=(seen,calls,order)
    allcalls[h]=calls
cnt=collections.Counter()
for h,calls in allcalls.items():
    for a,t,o in calls:
        if t is not None: cnt[t]+=1
print("distinct call targets",len(cnt))
print("--- top 40 callees by #handlers ---")
for t,c in cnt.most_common(40):
    print("%6d  %08x"%(c,t))
# who calls copyin
print("--- handlers calling 0x259280 ---")
print(sorted(hex(h) for h in allcalls if any(t==0x259280 for a,t,o in allcalls[h])))

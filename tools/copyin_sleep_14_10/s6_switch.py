
import sys, collections
sys.path.insert(0,r"C:\PS5contrib\tools\copyin_sleep_14_10")
from kc import *

tm=thunk_map()
hs=sorted(set(h for tr,h in tm.values()))
allcalls={}; bodies={}
for h in hs:
    seen,calls,order=walk(h, max_ins=4000)
    bodies[h]=(seen,calls,order)
    allcalls[h]=calls
callees=set()
for h,calls in allcalls.items():
    for a,t,o in calls:
        if t is not None: callees.add(t)
print("distinct direct callees", len(callees))

info={}
for t in sorted(callees):
    seen,calls,order=walk(t, max_ins=500, window=0x2000)
    if not order: 
        info[t]=None; continue
    feats=set()
    for a in order:
        i=seen[a]; m=i.mnemonic; o=i.op_str
        if m=='swapgs': feats.add('swapgs')
        if m=='mov' and o.startswith('rsp,'): feats.add('mov_rsp:'+o)
        if m=='mov' and o.endswith(', rsp'): feats.add('to_rsp:'+o)
        if 'gs:' in o: feats.add('gs')
        if m=='sti': feats.add('sti')
        if m=='cli': feats.add('cli')
    info[t]=(len(order),feats,calls)

print("--- candidates with mov rsp from memory or swapgs ---")
for t,(n,feats,calls) in sorted(info.items(), key=lambda kv: kv[0]):
    if feats is None: continue
    if any(f.startswith('mov_rsp') for f in feats) or 'swapgs' in feats:
        print("%08x n=%-4d %s"%(t,n,sorted(feats)))

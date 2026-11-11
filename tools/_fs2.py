
import sys, json, struct
sys.path.insert(0,r'C:\PS5contrib\tools')
from slicer2 import *
from array import array
own=array('i',[-1])*len(data)
own.frombytes(open(r'C:\PS5contrib\tools\_own.bin','rb').read())
sites=json.load(open(r'C:\PS5contrib\tools\_copyin_sites.json'))

def lands(E,S):
    cur=E
    for i in md.disasm(data[E:S], BASE+E):
        if i.address-BASE!=cur: return None
        cur+=i.size
    return cur==S

def prev_cc_run(S, limit=0x2000):
    # find largest P<=S with data[P-1]==0xcc
    for P in range(S, max(0,S-limit), -1):
        if data[P-1]==0xcc: return P
    return None

def find_start(S):
    cands=[]
    P=prev_cc_run(S)
    while P and P>0:
        if lands(P,S): cands.append(P)
        P=prev_cc_run(P-1)
        if len(cands)>3: break
    if own[S]!=-1:
        return own[S],'recdesc',cands
    if cands:
        return cands[0],'ccpad',cands
    return None,'fail',cands

bad=0; stat={}
res=[]
for S in sites:
    st,how,cands=find_start(S)
    stat[how]=stat.get(how,0)+1
    res.append({'site':S,'fstart':st,'how':how})
    if st is None: bad+=1
print(stat,'fail',bad)
json.dump(res, open(r'C:\PS5contrib\tools\_fstart2.json','w'))
for S in sites[:6]:
    print(hex(S), find_start(S))
print('problem site 0x6bdffc ->', find_start(0x6bdffc))

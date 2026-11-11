
import sys, json, struct
sys.path.insert(0,r'C:\PS5contrib\tools')
from slicer2 import *
from array import array
N=len(data)
own=array('i',[-1])*N
own.frombytes(open(r'C:\PS5contrib\tools\_own.bin','rb').read())

# call/jmp instruction start set
callstarts=bytearray(N)
for i in range(N-5):
    if data[i] in (0xe8,0xe9):
        rel=struct.unpack_from('<i',data,i+1)[0]
        t=i+5+rel
        if 0<=t<N: callstarts[i]=1

sites=json.load(open(r'C:\PS5contrib\tools\_copyin_sites.json'))

def decode(E,S):
    out=[];cur=E
    for i in md.disasm(data[E:S], BASE+E):
        if i.address-BASE!=cur: return None
        out.append(i); cur+=i.size
    if cur!=S: return None
    return out

def score(ins):
    bad=0; span=[]
    for i in ins:
        a=i.address-BASE
        for p in range(a+1,a+i.size):
            if callstarts[p]: bad+=1
            if own[p]!=-1: bad+=1
        span.append(a)
    return bad

def find(S):
    best=None
    P=S
    tried=0
    while True:
        # nearest previous cc
        P=None
        for q in range(min(P-1 if P else S-1, S-1), max(0,S-0x4000), -1):
            if data[q]==0xcc:
                P=q+1
                break
        if P is None: break
        ins=decode(P,S)
        if ins is not None:
            sc=score(ins)
            cand=(sc, -P, P, ins)
            if best is None or cand[:2]<best[:2]: best=cand
            if sc==0: break   # perfect and nearest
        tried+=1
        if tried>200: break
        P=P-1
        if P<=0: break
    return best

stats={'ok0':0,'okN':0,'fail':0}
res=[]
for S in sites:
    b=find(S)
    if b is None:
        res.append({'site':S,'fstart':None,'score':None}); stats['fail']+=1; continue
    sc,negP,P,ins=b
    if sc==0: stats['ok0']+=1
    else: stats['okN']+=1
    res.append({'site':S,'fstart':P,'score':sc,'ninsn':len(ins)})
print(stats)
json.dump(res, open(r'C:\PS5contrib\tools\_fstart3.json','w'))
for S in [0x6bdffc,0x5304eb,0x279814,0x2bace8]:
    b=find(S); print(hex(S),'->', None if b is None else (hex(b[2]), b[0], len(b[3])))

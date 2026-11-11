
import sys, json, struct
sys.path.insert(0,r'C:\PS5contrib\tools')
from slicer2 import *
from array import array
N=len(data)
own=array('i',[-1])*N
own.frombytes(open(r'C:\PS5contrib\tools\_own.bin','rb').read())
callstarts=bytearray(N); calltgt=bytearray(N)
for i in range(N-5):
    if data[i] in (0xe8,0xe9):
        rel=struct.unpack_from('<i',data,i+1)[0]
        t=i+5+rel
        if 0<=t<N: callstarts[i]=1; calltgt[t]=1
sites=json.load(open(r'C:\PS5contrib\tools\_copyin_sites.json'))
PAD=set([0xcc,0x90])
def decode(E,S):
    out=[];cur=E
    for i in md.disasm(data[E:S], BASE+E):
        if i.address-BASE!=cur: return None
        out.append(i); cur+=i.size
    return out if cur==S else None
def badness(ins):
    bad=0
    for i in ins:
        a=i.address-BASE
        for p in range(a+1,a+i.size):
            if callstarts[p] or own[p]!=-1: bad+=1
    return bad
def find(S):
    best=None
    q=S-1
    limit=max(0,S-0x6000)
    tested=0
    while q>limit:
        if data[q] in PAD:
            P=q+1
            ins=decode(P,S) if P<S else None
            if ins is not None:
                sc=badness(ins)
                key=(sc, 0 if calltgt[P] else 1, -P)
                if best is None or key<best[0]: best=(key,P,ins)
                if sc==0 and calltgt[P]: break
                tested+=1
                if tested>60: break
        q-=1
    return best
stats={'own':0,'ok0':0,'okN':0,'fail':0}; res=[]
for S in sites:
    if own[S]!=-1:
        E=own[S]; ins=decode(E,S) or []
        res.append({'site':S,'fstart':E,'how':'own','score':badness(ins)}); stats['own']+=1; continue
    b=find(S)
    if b is None:
        res.append({'site':S,'fstart':None,'how':'fail'}); stats['fail']+=1; continue
    key,P,ins=b
    stats['ok0' if key[0]==0 else 'okN']+=1
    res.append({'site':S,'fstart':P,'how':'pad','score':key[0]})
print(stats)
json.dump(res, open(r'C:\PS5contrib\tools\_fstart4.json','w'))
for S in [0x6bdffc,0x5304eb,0x279814,0x2bace8,0x3c313a]:
    b=find(S); print(hex(S),'->',None if b is None else (hex(b[1]),b[0][0]))
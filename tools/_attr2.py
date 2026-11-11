
import json,struct
from array import array
from collections import defaultdict,deque
N=15132096
own=array('i'); own.frombytes(open(r'C:\PS5contrib\tools\_own.bin','rb').read())
print('boundaries',len(own))
data=open(r'C:\PS5contrib\docs\dumps_13.60\kernel_text.bin','rb').read()
print('sanity own[0x530480]',own[0x530480],'own[0x5304eb]',own[0x5304eb])
h2n=json.load(open(r'C:\PS5contrib\tools\_h2n.json'))
h2n={int(k,16):v for k,v in h2n.items()}
edges=defaultdict(list)
n=0
for p in range(N-5):
    if own[p]!=-1 and data[p]==0xe8:
        rel=struct.unpack_from('<i',data,p+1)[0]
        t=p+5+rel
        if 0<=t<N:
            edges[t].append(p); n+=1
print('verified call edges',n)
recs=json.load(open(r'C:\PS5contrib\tools\_census2.json'))
out=[]
for r in recs:
    fs=r['fstart']
    r2=dict(r)
    nums=set(h2n.get(fs,[])); dist=0 if nums else None
    if not nums:
        seen={fs}; q=deque([(fs,0)]); hops=None
        while q:
            f,d=q.popleft()
            if d>=6: continue
            for c in edges.get(f,[]):
                if c in seen: continue
                seen.add(c)
                if c in h2n:
                    nums.update(h2n[c]); hops=d+1
                    # keep expanding for more
                q.append((c,d+1))
        dist=hops
    r2['syscalls']=sorted(nums); r2['hops']=dist
    out.append(r2)
json.dump(out, open(r'C:\PS5contrib\tools\_census4.json','w'))
c=sum(1 for r in out if r['syscalls'])
print('attributed',c,'of',len(out))
from collections import Counter
print(Counter(r['hops'] for r in out).most_common())
print()
for r in out:
    if r['cls']!='stack':
        print('%08x fs=%08x %-18s hops=%s n=%d %s'%(r['site'],r['fstart'],r['cls'],r['hops'],len(r['syscalls']),r['syscalls'][:8]))

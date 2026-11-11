
import json,struct
from collections import defaultdict,deque
BASE=0xffffffff8a9c0000
data=open(r'C:\PS5contrib\docs\dumps_13.60\kernel_text.bin','rb').read()
N=len(data)
sy=json.load(open(r'C:\PS5contrib\docs\dumps_13.60\sysent_index.json'))
h2n=defaultdict(list)
for e in sy['entries']:
    off=int(e['sy_call_off'],16)
    rel=struct.unpack_from('<i',data,off+1)[0]
    h2n[off+5+rel].append(e['num'])
json.dump({hex(k):v for k,v in h2n.items()}, open(r'C:\PS5contrib\tools\_h2n.json','w'))
# reverse call map
callers=defaultdict(list)
for i in range(N-5):
    if data[i]==0xe8:
        rel=struct.unpack_from('<i',data,i+1)[0]
        t=i+5+rel
        if 0<=t<N: callers[t].append(i)
recs=json.load(open(r'C:\PS5contrib\tools\_census2.json'))
out=[]
for r in recs:
    fs=r['fstart']
    nums=set(h2n.get(fs,[]))
    how='direct' if nums else ''
    if not nums:
        # BFS up to 3 levels
        seen={fs}; frontier=[fs]; lvl=0
        while frontier and lvl<3 and not nums:
            nxt=[]
            for f in frontier:
                for c in callers.get(f,[]):
                    if c in seen: continue
                    seen.add(c); nxt.append(c)
                    if c in h2n: nums.update(h2n[c])
            frontier=nxt; lvl+=1
        how='via%d'%lvl
    r2=dict(r); r2['syscalls']=sorted(nums); r2['attr']=how
    out.append(r2)
json.dump(out, open(r'C:\PS5contrib\tools\_census3.json','w'))
none=[r for r in out if not r['syscalls']]
print('sites with no syscall attribution:', len(none))
print('sites attributed:', 432-len(none))
from collections import Counter
print(Counter(r['attr'] for r in out).most_common())
print()
for r in out:
    if r['cls']!='stack':
        print('%08x fs=%08x %-18s sc=%s %s'%(r['site'],r['fstart'],r['cls'],r['syscalls'][:6],r['attr']))

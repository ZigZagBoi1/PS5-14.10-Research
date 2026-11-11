
import sys,json
sys.path.insert(0,r'C:\PS5contrib\tools')
from slicer2 import *
recs=json.load(open(r'C:\PS5contrib\tools\_census2.json'))
h2n={int(k,16):v for k,v in json.load(open(r'C:\PS5contrib\tools\_h2n.json')).items()}
# callers map restricted to verified boundaries
from array import array
from collections import defaultdict
own=array('i'); own.frombytes(open(r'C:\PS5contrib\tools\_own.bin','rb').read())
edges=defaultdict(list)
for p in range(len(data)-5):
    if own[p]!=-1 and data[p]==0xe8:
        rel=int.from_bytes(data[p+1:p+5],'little',signed=True)
        t=p+5+rel
        if 0<=t<len(data): edges[t].append(p)
rows=[]
for r in recs:
    d=r.get('dec') or {}
    l=r.get('len') or '-'
    rows.append({'site':r['site'],'fs':r['fstart'],'cls':r['cls'],'root':r.get('root'),
      'derefs':r.get('derefs'),'expr':r.get('expr'),'dec':d,'len':l,
      'sys':sorted(h2n.get(r['fstart'],[]))})
json.dump(rows, open(r'C:\PS5contrib\tools\_final.json','w'), indent=0)
print('total',len(rows))
# uap-derived pointer candidates
for r in rows:
    if r['root']=='entry:rsi' and (r['derefs'] or 0)>0:
        print('UAP-PTR', '%08x'%r['site'], r['expr'], r['cls'], r['dec'])
print('---')
for r in rows:
    if r['root'] in ('entry:rsi',):
        print('UAP', '%08x'%r['site'], 'deref=%s'%r['derefs'], r['expr'])

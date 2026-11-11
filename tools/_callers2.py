
import sys,json
sys.path.insert(0,r'C:\PS5contrib\tools')
from slicer2 import *
from array import array
from collections import defaultdict
own=array('i'); own.frombytes(open(r'C:\PS5contrib\tools\_own.bin','rb').read())
recs=json.load(open(r'C:\PS5contrib\tools\_final.json'))
edges=defaultdict(list)
for p in range(len(data)-5):
    if own[p]!=-1 and data[p]==0xe8:
        t=p+5+int.from_bytes(data[p+1:p+5],'little',signed=True)
        if 0<=t<len(data): edges[t].append(p)
cands=[r for r in recs if r['root']=='entry:rsi']
for r in cands:
    fs=r['fs']
    cs=edges.get(fs,[])
    print('--- site %08x fs %08x derefs %s %s  callers=%d'%(r['site'],fs,r['derefs'],r['expr'],len(cs)))
    for c in cs[:6]:
        a=max(0,c-0x30); ins=list(md.disasm(data[a:c+5],BASE+a))
        txt=' ; '.join('%s %s'%(i.mnemonic,i.op_str) for i in ins[-7:])
        print('   @%08x: %s'%(c,txt))

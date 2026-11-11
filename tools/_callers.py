
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
    fs=r['fs']; tgt=[t for t in edges if fs<=t<fs+0x600]
    print('--- site %08x fs %08x derefs %s %s'%(r['site'],fs,r['derefs'],r['expr']))
    n=0
    for t in sorted(tgt):
        for c in edges[t][:3]:
            n+=1
            a=max(0,c-0x50)
            ins=list(md.disasm(data[a:c+5],BASE+a))
            print('  caller@%08x -> %08x'%(c,t))
            for i in ins[-9:]:
                print('     %08x %-12s %s %s'%(i.address-BASE,i.bytes.hex(),i.mnemonic,i.op_str))
    if not n: print('  (no direct e8 caller in dump)')


import sys,json
sys.path.insert(0,r'C:\PS5contrib\tools')
from slicer2 import *
recs=json.load(open(r'C:\PS5contrib\tools\_final.json'))
h2n={int(k,16):v for k,v in json.load(open(r'C:\PS5contrib\tools\_h2n.json')).items()}
# stats
from collections import Counter
c=Counter(r['cls'] for r in recs); lc=Counter(r['len'] for r in recs)
print('CLS',c.most_common())
print('LEN',lc.most_common(5))
print('const max', max([int(r['len'],16) for r in recs if r['len'].startswith('0x')] or [0]))
print('len>0x1000', sum(1 for r in recs if r['len'].startswith('0x') and int(r['len'],16)>0x1000))
print('inhandler', sum(1 for r in recs if r['fs'] in h2n))
print('distinct fs', len(set(r['fs'] for r in recs)))
# table
out=[]
out.append('| # | site RVA | syscalls | class | deciding insn | len |')
out.append('|---|---|---|---|---|---|')
for i,r in enumerate(sorted(recs,key=lambda x:x['site']),1):
    d=r['dec'] or {}
    dec='%s %s'%(d.get('mnem','?'),d.get('op','?'))
    if d.get('rva') is not None and d['rva']!=r['site']:
        dec='%08x %s'%(d['rva'],dec)
    sysn=','.join(str(x) for x in r['sys']) if r['sys'] else '-'
    out.append('| %d | 0x%08x | %s | %s | %s | %s |'%(i,r['site'],sysn,r['cls'],dec,r['len']))
open(r'C:\PS5contrib\tools\_table.md','w',encoding='ascii',errors='replace').write('\n'.join(out)+'\n')
print('table rows',len(out))

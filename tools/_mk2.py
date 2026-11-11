
import sys,json
sys.path.insert(0,r'C:\PS5contrib\tools')
from slicer2 import *
recs=json.load(open(r'C:\PS5contrib\tools\_final.json'))
vals=[]
for r in recs:
    l=r['len']
    if l.startswith('const '): vals.append(int(l.split()[1],16))
print('const n',len(vals),'max',hex(max(vals)),'sum>0x1000',sum(1 for v in vals if v>0x1000),'>0x400',sum(1 for v in vals if v>0x400))
print('const hist',{hex(k):v for k,v in sorted(__import__('collections').Counter(vals).items())})
SITE=[0x50cb65,0xb71f8b,0x44708e,0xc89127,0xc89404,0x313acc,0x3ef463,0x3b6dfa,0x31d2e8,0x985f76,0x9aa62d,0x34c950,0x37e93f,0x3b04f3,0x34cd7c,0x0b7ea2c if 0 else 0xb7ea2c,0x6bd5ce,0x5304eb]
for s_ in SITE:
    r=[x for x in recs if x['site']==s_]
    if not r: print('MISSING %08x'%s_); continue
    print('#### %08x fs %08x cls %s expr %s derefs %s len %s sys %s'%(s_,r[0]['fs'],r[0]['cls'],r[0]['expr'],r[0]['derefs'],r[0]['len'],r[0]['sys']))

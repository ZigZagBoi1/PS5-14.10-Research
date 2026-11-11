
import json,re
from collections import Counter
recs=json.load(open(r'C:\PS5contrib\tools\_final.json'))
c=Counter()
for r in recs:
    if r['root']=='retval':
        m=re.findall(r'call@0x([0-9a-f]+)', r['expr'])
        c[m[0] if m else '?']+=1
print(sorted(c.items(), key=lambda x:-x[1]))
print('stackgroup', sum(v for k,v in Counter(r['cls'] for r in recs).items() if k in ('stack','derived:frame','derived:entry:rsp','derived:stackmem','derived:spill','derived:entry:rbx')))
print('arg', sum(v for k,v in Counter(r['cls'] for r in recs).items() if k in ('derived:entry:rsi','derived:entry:rdi','derived:entry:r8')))
print('unres', sum(v for k,v in Counter(r['cls'] for r in recs).items() if k in ('derived:unknown','derived:clobbered','loadfrom:clobbered')))
print('static', sum(v for k,v in Counter(r['cls'] for r in recs).items() if k in ('global','derived:global')))

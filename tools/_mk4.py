
import json,re
from collections import Counter
import sys
sys.path.insert(0,r'C:\PS5contrib\tools')
from slicer2 import data
recs=json.load(open(r'C:\PS5contrib\tools\_final.json'))
c=Counter()
for r in recs:
    if r['root']!='retval': continue
    m=re.findall(r'call@0x([0-9a-f]+)', r['expr'])
    if not m: c['?']+=1; continue
    a=int(m[0],16)
    if data[a]==0xe8:
        t=a+5+int.from_bytes(data[a+1:a+5],'little',signed=True)
        c['%x'%t]+=1
    else: c['noncall']+=1
print(sorted(c.items(), key=lambda x:-x[1])[:12])
print('malloc pair', c.get('c08b50',0)+c.get('794ee0',0), 'distinct', len(c))


import json,struct,re,sys
sys.path.insert(0,r'C:\PS5contrib\tools')
from slicer2 import *
from collections import Counter,defaultdict
recs=json.load(open(r'C:\PS5contrib\tools\_census2.json'))
def calltgt(rva):
    if data[rva]!=0xe8: return None
    return rva+5+struct.unpack_from('<i',data,rva+1)[0]
B=defaultdict(list)
for r in recs: B[r['cls']].append(r)
for cls in ['derived:retval','derived:unknown','derived:imm','derived:spill','loadfrom:clobbered','global','none-in-window']:
    print('===',cls,len(B[cls]))
    for r in B[cls]:
        d=r.get('dec') or {}
        extra=''
        m=re.search(r'call@(0x[0-9a-f]+)',r.get('expr') or '')
        if m:
            t=calltgt(int(m.group(1),16))
            extra=' callee=%s'%(('0x%06x'%t) if t is not None else '?')
        print('  %08x fs=%08x sc=%s | %s %s | root=%s deref=%s expr=%s%s'%(r['site'],r['fstart'],r.get('score'),d.get('mnem',''),d.get('op',''),r.get('root'),r.get('derefs'),r.get('expr'),extra))
    print()
print('retval callees:', Counter((lambda m: '0x%06x'%calltgt(int(m.group(1),16)) if m and calltgt(int(m.group(1),16)) is not None else '?')(re.search(r'call@(0x[0-9a-f]+)',r['expr'] or '')) for r in B['derived:retval']).most_common())

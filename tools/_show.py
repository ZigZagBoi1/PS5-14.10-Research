
import json
from collections import Counter, defaultdict
recs=json.load(open(r'C:\PS5contrib\tools\_copyin_census.json'))
buckets=defaultdict(list)
for r in recs: buckets[r.get('cls','ERR')].append(r)
for cls in ['uap-value','user-scalar','kernel-object','object-field','td-addr','memload:global','stack-spill','global','const','none-in-window','other:unknown','other:entry:rax','other:entry:r12','uap-addr']:
    v=buckets.get(cls,[])
    print('=== %s (%d) ==='%(cls,len(v)))
    for r in v[:40]:
        d=r.get('dec') or {}
        print('  site %#08x fstart %#08x handler=%s  dec %#08x %s %s | root=%s expr=%s derefs=%s'%(
            r['site'], r['fstart'], r.get('fname_is_handler'), d.get('rva',0), d.get('mnem',''), d.get('op',''), r.get('root'), r.get('expr'), r.get('derefs')))
    print()


import json
from collections import Counter,defaultdict
recs=json.load(open(r'C:\PS5contrib\tools\_census2.json'))
B=defaultdict(list)
for r in recs: B[r['cls']].append(r)
for cls in sorted(B):
    if cls=='stack': continue
    print('=== %s (%d)'%(cls,len(B[cls])))
    for r in B[cls]:
        d=r.get('dec') or {}
        print('  %08x fs=%08x sc=%s | %-22s %s %s | root=%-12s deref=%s expr=%s'%(
          r['site'],r['fstart'],r.get('score'),d.get('mnem',''),d.get('op',''),'',r.get('root'),r.get('derefs'),r.get('expr')))
    print()
# stack sites: check for index regs
idx=[r for r in B['stack'] if '+' in (r.get('expr') or '') and 'rsp' not in (r.get('expr') or '') and 'rbp' not in (r.get('expr') or '')]
print('stack sites with unusual expr:', len(idx))
for r in B['stack'][:8]: print('  ', hex(r['site']), r['dec']['mnem'], r['dec']['op'])
print('...')
print('stack exprs sample:', Counter(r['expr'] for r in B['stack']).most_common(12))

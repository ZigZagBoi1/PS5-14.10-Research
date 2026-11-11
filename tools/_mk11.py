
import json
recs=json.load(open(r'C:\PS5contrib\tools\_final.json'))
sel=('derived:entry:rdi','derived:entry:r8','derived:unknown','derived:clobbered','loadfrom:clobbered')
rows=[]
for r in sorted(recs,key=lambda x:x['site']):
    if r['cls'] in sel:
        d=r['dec'] or {}
        rows.append('| 0x%08x | %s | %s | %s | %s %s | %s |'%(r['site'],r['cls'],r['derefs'],r['expr'],d.get('mnem','?'),d.get('op','?'),r['len']))
print('\n'.join(rows)); print(len(rows))

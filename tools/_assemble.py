import json,sys
sys.path.insert(0,r'C:\PS5contrib\tools')
recs=json.load(open(r'C:\PS5contrib\tools\_final.json'))
h2n={int(k,16):v for k,v in json.load(open(r'C:\PS5contrib\tools\_h2n.json')).items()}
from collections import defaultdict,Counter
g=defaultdict(list)
for r in recs:
    if r['fs'] in h2n: g[r['fs']].append(r)
rows=[]
for fs in sorted(g):
    rs=sorted(g[fs],key=lambda x:x['site'])
    ns=','.join(str(n) for n in sorted(h2n[fs]))
    cells=', '.join('0x%08x (%s)'%(x['site'],x['cls']) for x in rs)
    rows.append('| 0x%08x | %s | %d | %s |'%(fs,ns,len(rs),cells))
tbl=['| handler body RVA | syscall numbers | sites | site RVAs and classes |',
     '|---|---|---|---|']+rows
p1=open(r'C:\PS5contrib\tools\_p1.md').read().replace('@@HANDLERS@@','\n'.join(tbl))
p3=open(r'C:\PS5contrib\tools\_p3.md').read()
p3=p3.replace('@@P311@@',open(r'C:\PS5contrib\tools\_p311.md').read())
p3=p3.replace('@@P312@@',open(r'C:\PS5contrib\tools\_p312.md').read())
table=open(r'C:\PS5contrib\tools\_table.md').read()
doc=(p1+table+p3).replace('\r\n','\n')
assert all(ord(c)<128 for c in doc)
open(r'C:\PS5contrib\docs\COPYIN_DEST_PROVENANCE_14_10.md','w',encoding='ascii',newline='\n').write(doc)
print('bytes',len(doc),'lines',doc.count('\n'),'sites',table.count('\n')-2,'handlers',len(rows))
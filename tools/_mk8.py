
import json
recs=json.load(open(r'C:\PS5contrib\tools\_final.json'))
for r in recs:
    if r['cls'] in ('derived:imm',):
        print('%08x %s len %s %s'%(r['site'],r['expr'],r['len'],r['dec']))

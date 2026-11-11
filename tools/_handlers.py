
import json,struct
BASE=0xffffffff8a9c0000
data=open(r'C:\PS5contrib\docs\dumps_13.60\kernel_text.bin','rb').read()
sy=json.load(open(r'C:\PS5contrib\docs\dumps_13.60\sysent_index.json'))
ents=sy['entries']
bad=0
h={}
for e in ents:
    off=int(e['sy_call_off'],16)
    if data[off]!=0xe9: bad+=1; continue
    rel=struct.unpack_from('<i',data,off+1)[0]
    body=off+5+rel
    h.setdefault(body,[]).append(e['num'])
print('entries',len(ents),'bad',bad,'distinct bodies',len(h))
print('sample', [(hex(k), v[:5]) for k,v in list(h.items())[:5]])
# distribution of how many nums per body
from collections import Counter
print(Counter(len(v) for v in h.values()))
json.dump({str(k):v for k,v in h.items()}, open(r'C:\PS5contrib\tools\_handlers.json','w'))

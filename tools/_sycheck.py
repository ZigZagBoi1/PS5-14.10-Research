
import json,struct
BASE=0xffffffff8a9c0000
data=open(r'C:\PS5contrib\docs\dumps_13.60\kernel_text.bin','rb').read()
sy=json.load(open(r'C:\PS5contrib\docs\dumps_13.60\sysent_index.json'))
print({k:sy[k] for k in sy if k!='entries'})
ents=sy['entries']
for e in ents[:6]:
    off=int(e['sy_call_off'],16) if isinstance(e['sy_call_off'],str) else e['sy_call_off']
    print(e['num'], hex(int(e['sy_call'],16)), hex(off), data[off:off+16].hex())
from collections import Counter
c=Counter()
for e in ents:
    off=int(e['sy_call_off'],16)
    c[data[off]]+=1
print(c.most_common(10))

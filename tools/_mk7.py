
import json,re,sys
sys.path.insert(0,r'C:\PS5contrib\tools')
from slicer2 import *
recs=json.load(open(r'C:\PS5contrib\tools\_final.json'))
for r in recs:
    if r['root']!='retval': continue
    m=re.findall(r'call@0x([0-9a-f]+)', r['expr'])
    if not m: continue
    a=int(m[0],16)
    t=a+5+int.from_bytes(data[a+1:a+5],'little',signed=True) if data[a]==0xe8 else 0
    if t in (0xc08b50,0x794ee0): continue
    print('=== site %08x expr %s callee %08x len %s'%(r['site'],r['expr'],t,r['len']))
    ins=list(md.disasm(data[max(0,r['site']-0x40):r['site']+9], BASE+max(0,r['site']-0x40)))
    for i in ins[-12:]:
        print('   %s %08x %-16s %s %s'%('>>' if i.address-BASE==r['site'] else '  ',i.address-BASE,i.bytes.hex(),i.mnemonic,i.op_str))

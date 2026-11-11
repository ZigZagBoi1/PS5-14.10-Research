
import sys,json
sys.path.insert(0,r'C:\PS5contrib\tools')
from slicer2 import *
recs=json.load(open(r'C:\PS5contrib\tools\_census2.json'))
cache={}
def fn(E):
    if E not in cache: cache[E]=list(md.disasm(data[E:E+0x8000], BASE+E))
    return cache[E]
def idx(ins,S):
    for k,i in enumerate(ins):
        if i.address-BASE==S: return k
    return None
SEL={'entry:rsi','entry:rdi','entry:r8','entry:rbx','entry:rsp','imm','clobbered','unknown','stackmem','spill'}
for r in recs:
    if r.get('root') in SEL or r['cls'] in ('global','derived:global'):
        E=r['fstart']; ins=fn(E); k=idx(ins,r['site'])
        print('### %08x fs=%08x %s derefs=%s expr=%s'%(r['site'],E,r['cls'],r.get('derefs'),r.get('expr')))
        if k is None: print('   (site not in decode)'); continue
        for i in ins[max(0,k-9):k+1]:
            print('   %s %08x %-18s %s %s'%('>>' if i.address-BASE==r['site'] else '  ',i.address-BASE,i.bytes.hex(),i.mnemonic,i.op_str))

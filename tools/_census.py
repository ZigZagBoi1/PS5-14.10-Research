
import struct, json
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_AC_WRITE
from capstone.x86 import X86_OP_REG, X86_OP_MEM, X86_OP_IMM

BASE = 0xffffffff8a9c0000
DUMP = r'C:\PS5contrib\docs\dumps_13.60\kernel_text.bin'
data = open(DUMP,'rb').read()
COPYIN = 0x259280
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

RSI_FAM = {'rsi','esi','si','sil'}
def is_rsi_write(insn):
    # check explicit first operand write
    if not insn.operands: return False
    op = insn.operands[0]
    if op.type == X86_OP_REG and (op.access & CS_AC_WRITE):
        if insn.reg_name(op.reg) in RSI_FAM:
            return True
    return False

def disasm_window(start, end):
    return list(md.disasm(data[start:end], BASE+start))

def find_aligned(site, span=0x200):
    lo = max(0, site-span)
    for k in range(0, 16):
        s = lo + k
        if s >= site: break
        ins = list(md.disasm(data[s:site], BASE+s))
        if not ins: continue
        ok = True
        cur = s
        for i in ins:
            if i.address != BASE+cur: ok=False; break
            cur += i.size
        if ok and cur == site:
            return s, ins
    return None, None

sites = json.load(open(r'C:\PS5contrib\tools\_copyin_sites.json'))
print('sites', len(sites))
fail=0; res=[]
for s in sites:
    st, ins = find_aligned(s)
    if st is None:
        fail+=1
        res.append({'site':s,'ok':False,'window_start':None,'n_insn':0,'last_write':None,'class':'NO-ALIGN'})
        continue
    lw = None
    for i in ins:
        if is_rsi_write(i):
            lw = i
    res.append({'site':s,'ok':True,'window_start':st,'n_insn':len(ins),
                'last_write': None if lw is None else {
                    'rva': lw.address-BASE, 'mnem': lw.mnemonic, 'op': lw.op_str,
                    'bytes': lw.bytes.hex(), 'size': lw.size},
                'class': 'none' if lw is None else 'write'})
json.dump(res, open(r'C:\PS5contrib\tools\_copyin_census_raw.json','w'), indent=0)
print('align fail:', fail)
from collections import Counter
c = Counter()
for r in res:
    if not r['ok']: c['NO-ALIGN']+=1
    elif r['last_write'] is None: c['none-in-window']+=1
    else:
        c[r['last_write']['mnem']]+=1
for k,v in c.most_common(): print(' ', k, v)

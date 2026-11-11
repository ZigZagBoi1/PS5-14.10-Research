
import struct, json, re
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_AC_WRITE
from capstone.x86 import X86_OP_REG, X86_OP_MEM, X86_OP_IMM

BASE = 0xffffffff8a9c0000
DUMP = r'C:\PS5contrib\docs\dumps_13.60\kernel_text.bin'
data = open(DUMP,'rb').read()
COPYIN = 0x259280
md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True

FAM = {}
for r64,r32,r16,r8 in [('rax','eax','ax','al'),('rbx','ebx','bx','bl'),('rcx','ecx','cx','cl'),
    ('rdx','edx','dx','dl'),('rsi','esi','si','sil'),('rdi','edi','di','dil'),
    ('rbp','ebp','bp','bpl'),('rsp','esp','sp','spl')]:
    for x in (r64,r32,r16,r8): FAM[x]=r64
for i in range(8,16):
    for suf in ('','d','w','b'):
        FAM[f'r{i}{suf}']=f'r{i}'
def fam(n):
    if n is None: return None
    return FAM.get(n, n)

def wregs(insn):
    out=[]
    for op in insn.operands:
        if op.type==X86_OP_REG and (op.access & CS_AC_WRITE):
            out.append(fam(insn.reg_name(op.reg)))
    m=insn.mnemonic
    if m=='pop' and insn.operands and insn.operands[0].type==X86_OP_REG:
        out.append(fam(insn.reg_name(insn.operands[0].reg)))
    return out

# ---------- function start candidates ----------
starts=set([0])
for p in range(1,len(data)-4):
    b=data[p]
    prev=data[p-1]
    if prev in (0xcc,0xc3,0x90) or p==0:
        if b==0x55 or b==0x53 or b==0x56 or b==0x57 or b==0x41 or (b==0x48 and data[p+1] in (0x83,0x81,0x89)):
            if p not in starts: starts.add(p)
    if data[p:p+4]==b'\xf3\x0f\x1e\xfa': starts.add(p)
starts=sorted(starts)
print('prologue candidates', len(starts))

# sysent
sy=json.load(open(r'C:\PS5contrib\docs\dumps_13.60\sysent_index.json'))
ents=sy['entries']
def read_rel32(off):
    return struct.unpack_from('<i', data, off+1)[0]
handlers={}
for e in ents:
    va=int(e['sy_call'],16)
    th=va-BASE
    if not (0 <= th < len(data)-5): continue
    if data[th]!=0xe8: continue
    body = th+5+read_rel32(th)
    handlers.setdefault(body,[]).append(e['num'])
print('distinct handler bodies', len(handlers))
hstart=sorted(handlers.keys())

allsorted=sorted(set(starts)|set(hstart))

import bisect
def find_fstart(site):
    i=bisect.bisect_right(allsorted, site)-1
    while i>=0:
        p=allsorted[i]
        if site-p > 0x20000: break
        ins=list(md.disasm(data[p:site], BASE+p))
        cur=p; ok=True
        for x in ins:
            if x.address!=BASE+cur: ok=False;break
            cur+=x.size
        if ok and cur==site:
            return p
        i-=1
    return None

sites=json.load(open(r'C:\PS5contrib\tools\_copyin_sites.json'))
out=[]
for s in sites:
    fs=find_fstart(s)
    out.append({'site':s,'fstart':fs})
    if fs is None: print('NO FSTART', hex(s))
json.dump(out, open(r'C:\PS5contrib\tools\_copyin_fstart.json','w'))
print('done; failures:', sum(1 for o in out if o['fstart'] is None))
# handler containment
contained=0
for o in out:
    for h in hstart:
        if h<=o['fstart'] and o['site']<h+0x8000:
            pass
print('sample fstarts', [(hex(o['site']), hex(o['fstart']) if o['fstart'] is not None else None) for o in out[:10]])


import struct, json, bisect
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_AC_WRITE
from capstone.x86 import X86_OP_REG, X86_OP_MEM, X86_OP_IMM

BASE = 0xffffffff8a9c0000
DUMP = r'C:\PS5contrib\docs\dumps_13.60\kernel_text.bin'
data = open(DUMP,'rb').read()
md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True

FAM={}
for r64,r32,r16,r8 in [('rax','eax','ax','al'),('rbx','ebx','bx','bl'),('rcx','ecx','cx','cl'),
    ('rdx','edx','dx','dl'),('rsi','esi','si','sil'),('rdi','edi','di','dil'),
    ('rbp','ebp','bp','bpl'),('rsp','esp','sp','spl')]:
    for x in (r64,r32,r16,r8): FAM[x]=r64
for i in range(8,16):
    for suf in ('','d','w','b'): FAM[f'r{i}{suf}']=f'r{i}'
def fam(n):
    return None if n is None else FAM.get(n,n)

def writes(i):
    out=[]
    for op in i.operands:
        if op.type==X86_OP_REG and (op.access & CS_AC_WRITE):
            out.append(fam(i.reg_name(op.reg)))
    return out

def memstr(i, mm):
    b = fam(i.reg_name(mm.base)) if mm.base else None
    x = fam(i.reg_name(mm.index)) if mm.index else None
    s=''
    if b: s+=b
    if x:
        s+=('+' if s else '')+x
        if mm.scale>1: s+='*%d'%mm.scale
    if mm.disp:
        s+=('%+#x'%mm.disp) if s else ('%#x'%mm.disp)
    return s or 'abs'

class R:
    __slots__=('root','expr','rva','derefs','note')
    def __init__(s,root,expr,rva,derefs=0,note=''):
        s.root,s.expr,s.rva,s.derefs,s.note = root,expr,rva,derefs,note

CLOBBER={'rax','rcx','rdx','rsi','rdi','r8','r9','r10','r11'}
def resolve(ins, idx, reg, hops=0):
    if hops>8: return R('unknown','hoplimit',None)
    for j in range(idx-1,-1,-1):
        i=ins[j]
        if reg in writes(i):
            return cls(ins, j, reg, hops)
        if i.mnemonic=='call':
            if reg=='rax': return R('retval','ret(call@%#x)'%(i.address-BASE), i.address-BASE)
            if reg in CLOBBER: return R('clobbered','clobbered@%#x'%(i.address-BASE), i.address-BASE)
    return R('entry:'+reg, reg, None)

def cls(ins, j, reg, hops):
    i=ins[j]; m=i.mnemonic; ops=i.operands; rva=i.address-BASE
    if m=='lea' and len(ops)>=2 and ops[1].type==X86_OP_MEM:
        mm=ops[1].mem; b=fam(i.reg_name(mm.base)) if mm.base else None
        if b in ('rsp','rbp'): return R('frame','[%s]'%memstr(i,mm),rva)
        if b=='rip' or b is None: return R('global','[%s]'%memstr(i,mm),rva)
        bb=resolve(ins,j,b,hops+1)
        return R(bb.root, bb.expr+('%+#x'%mm.disp if mm.disp else ''), rva, bb.derefs)
    if m=='mov' and len(ops)>=2:
        s=ops[1]
        if s.type==X86_OP_IMM: return R('imm','%#x'%s.imm,rva)
        if s.type==X86_OP_REG:
            return resolve(ins,j,fam(i.reg_name(s.reg)),hops+1)
        if s.type==X86_OP_MEM:
            sm=s.mem
            b=fam(i.reg_name(sm.base)) if sm.base else None
            if b in ('rsp','rbp'):
                slot=b,sm.disp
                for k in range(j-1,-1,-1):
                    ii=ins[k]
                    if not ii.operands: continue
                    o0=ii.operands[0]
                    if o0.type!=X86_OP_MEM: continue
                    b2=fam(ii.reg_name(o0.mem.base)) if o0.mem.base else None
                    if b2 in ('rsp','rbp') and o0.mem.disp==sm.disp and ii.mnemonic.startswith('mov'):
                        if len(ii.operands)>1 and ii.operands[1].type==X86_OP_REG:
                            r=resolve(ins,k,fam(ii.reg_name(ii.operands[1].reg)),hops+1)
                            return R(r.root,'spill[%s]='%memstr(ii,o0.mem)+r.expr,rva,r.derefs)
                        if len(ii.operands)>1 and ii.operands[1].type==X86_OP_IMM:
                            return R('imm','spill[%s]=%#x'%(memstr(ii,o0.mem),ii.operands[1].imm),rva)
                return R('spill','[%s]'%memstr(i,sm),rva)
            if b=='rip' or b is None:
                return R('global','[%s]'%memstr(i,sm),rva,1)
            bb=resolve(ins,j,b,hops+1)
            return R(bb.root,'*('+bb.expr+')',rva,bb.derefs+1)
    if m=='pop': return R('stackmem','pop %s'%i.op_str,rva,1)
    if m in ('movsxd','movsx','movzx','movsxd') and len(ops)>=2 and ops[1].type==X86_OP_MEM:
        pass
    if m in ('add','sub','and','or','xor','shl','shr','sar','imul','neg','not','inc','dec','adc','sbb','movsxd','movsx','movzx') \
       and len(ops)>=2 and ops[0].type==X86_OP_REG and m not in ('xor','sub') or \
       (m in ('xor','sub') and len(ops)>=2 and ops[0].type==X86_OP_REG and ops[1].type!=X86_OP_REG):
        if m in ('movsxd','movsx','movzx') and ops[1].type==X86_OP_MEM:
            sm=ops[1].mem; b=fam(i.reg_name(sm.base)) if sm.base else None
            if b in ('rsp','rbp'):
                return R('spill','[%s]'%memstr(i,sm),rva,1)
            bb=resolve(ins,j,b,hops+1)
            return R(bb.root,'*(%s)'%bb.expr,rva,bb.derefs+1)
        r0=resolve(ins,j,fam(i.reg_name(ops[0].reg)),hops+1)
        if ops[1].type==X86_OP_IMM:
            return R(r0.root,'(%s)%s %#x'%(r0.expr,m,ops[1].imm),rva,r0.derefs)
        if ops[1].type==X86_OP_MEM:
            return R(r0.root,'(%s)%s *([%s])'%(r0.expr,m,memstr(i,ops[1].mem)),rva,max(r0.derefs,1))
        return R(r0.root,'(%s)%s reg'%(r0.expr,m),rva,r0.derefs)
    if m in ('xor','sub') and len(ops)>=2 and ops[0].type==X86_OP_REG and ops[1].type==X86_OP_REG \
       and fam(i.reg_name(ops[0].reg))==fam(i.reg_name(ops[1].reg)):
        return R('imm','0',rva)
    if ops and ops[0].type==X86_OP_REG:
        r0=resolve(ins,j,fam(i.reg_name(ops[0].reg)),hops+1)
        return R(r0.root,'(%s)[%s]'%(r0.expr,m),rva,r0.derefs)
    for op in ops[1:]:
        if op.type==X86_OP_REG:
            r=resolve(ins,j,fam(i.reg_name(op.reg)),hops+1)
            return R(r.root,r.expr+'"'"' [%s]'"'"'%m,rva,r.derefs)
    return R('unknown','%s %s'%(m,i.op_str),rva)
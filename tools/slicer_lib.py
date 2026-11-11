
import struct, json, re, bisect
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_AC_WRITE
from capstone.x86 import X86_OP_REG, X86_OP_MEM, X86_OP_IMM

BASE = 0xffffffff8a9c0000
data = open(r'C:\PS5contrib\docs\dumps_13.60\kernel_text.bin','rb').read()
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

def writes(insn):
    out=[]
    for op in insn.operands:
        if op.type==X86_OP_REG and (op.access & CS_AC_WRITE):
            out.append(fam(insn.reg_name(op.reg)))
    if insn.mnemonic in ('pop','lodsb','lodsw','lodsd','lodsq'):
        if insn.operands and insn.operands[0].type==X86_OP_REG:
            out.append(fam(insn.reg_name(insn.operands[0].reg)))
    return out

ARGS={'rdi':'(td)','rsi':'(uap)','rdx':'(arg2)','rcx':'(arg3)','r8':'(arg4)','r9':'(arg5)'}

class Res:
    __slots__=('kind','text','insn','depth')
    def __init__(s,k,t,i=None,d=0): s.kind,s.text,s.insn,s.depth=k,t,i,d

def memstr(insn, op):
    base = fam(insn.reg_name(op.mem.base)) if op.mem.base else None
    idx  = fam(insn.reg_name(op.mem.index)) if op.mem.index else None
    d = op.mem.disp
    s=''
    if base: s+=base
    if idx:
        s+=('+' if s else '')+idx
        if op.mem.scale>1: s+='*%d'%op.mem.scale
    if d:
        s+= ('%+#x'%d) if s else ('%#x'%d)
    if not s: s+='abs'
    return s

def analyze_func(fstart):
    ins = list(md.disasm(data[fstart:fstart+0x4000], BASE+fstart))
    return ins

def find_def(ins, idx, reg, hops=0, seen=None):
    """walk backwards from index idx (exclusive) to find def of reg; return Res"""
    if seen is None: seen=set()
    key=(reg, idx)
    if hops>6: return Res('unknown','<hoplimit>')
    for j in range(idx-1, -1, -1):
        i=ins[j]
        if reg in writes(i):
            return classify_def(ins, j, reg, hops+1, seen)
    # reached function start
    if reg in ARGS: return Res('arg', ARGS[reg], None, hops)
    return Res('unknown','<%s@entry>'%reg)

def classify_def(ins, j, reg, hops, seen):
    i=ins[j]
    m=i.mnemonic
    ops=i.operands
    if m=='lea' and len(ops)>=2 and ops[1].type==X86_OP_MEM:
        base = fam(i.reg_name(ops[1].mem.base)) if ops[1].mem.base else None
        rv = Res('addr', memstr(i, ops[1]), i.address-BASE, hops)
        if base in ('rsp','rbp'):
            rv.kind='stack'; return rv
        if base=='rip':
            rv.kind='global'; return rv
        if base is None:
            rv.kind='global'; return rv
        base_r = find_def(ins, j, base, hops, seen)
        rv.text = base_r.text + ('%+#x'%ops[1].mem.disp if ops[1].mem.disp else '')
        rv.kind = combine(base_r.kind, 'addr')
        rv.rootk = base_r.kind
        return rv
    if m=='mov' and len(ops)>=2:
        src=ops[1]
        if src.type==X86_OP_IMM:
            return Res('imm','%#x'%src.imm, i.address-BASE, hops)
        if src.type==X86_OP_REG:
            r2=fam(i.reg_name(src.reg))
            d=find_def(ins, j, r2, hops, seen)
            return Res(d.kind, d.text, d.insn, hops)
        if src.type==X86_OP_MEM:
            base = fam(i.reg_name(src.mem.base)) if src.mem.base else None
            ms = memstr(i, src)
            if base in ('rsp','rbp'):
                # trace the stack slot
                for k in range(j-1,-1,-1):
                    ii=ins[k]
                    if ii.mnemonic in ('mov','movzx','movsx','movaps','movups','movdqu','movq') and ii.operands:
                        o0=ii.operands[0]
                        if o0.type==X86_OP_MEM:
                            b2=fam(ii.reg_name(o0.mem.base)) if o0.mem.base else None
                            if b2 in ('rsp','rbp') and o0.mem.disp==src.mem.disp:
                                if len(ii.operands)>1 and ii.operands[1].type==X86_OP_REG:
                                    r3=fam(ii.reg_name(ii.operands[1].reg))
                                    d=find_def(ins, k, r3, hops+1, seen)
                                    return Res(d.kind, 'local[%s]<-'%ms + d.text, d.insn, hops)
                                if len(ii.operands)>1 and ii.operands[1].type==X86_OP_IMM:
                                    return Res('imm','local[%s]<-%#x'%(ms,ii.operands[1].imm), ii.address-BASE, hops)
                return Res('stackload','local[%s]'%ms, i.address-BASE, hops)
            if base is None or base=='rip':
                return Res('global','[%s]'%ms, i.address-BASE, hops)
            b_r = find_def(ins, j, base, hops, seen)
            rv = Res(combine(b_r.kind,'deref'), '*(' + b_r.text + ')', i.address-BASE, hops)
            rv.rootk=b_r.kind
            if src.mem.disp: rv.text = '*(' + b_r.text + '%+#x'%src.mem.disp + ')'
            return rv
    if m=='pop':
        return Res('stackload', i.op_str, i.address-BASE, hops)
    if m in ('xor','sub') and len(ops)>=2 and ops[0].type==X86_OP_REG and ops[1].type==X86_OP_REG:
        if fam(i.reg_name(ops[0].reg))==fam(i.reg_name(ops[1].reg)):
            return Res('imm','0', i.address-BASE, hops)
    if m in ('add','sub','and','or','shl','shr','sar','inc','dec','movsx','movsxd','movzx','neg','not'):
        for op in ops[1:]:
            if op.type==X86_OP_REG:
                d=find_def(ins, j, fam(i.reg_name(op.reg)), hops, seen)
                return Res(d.kind, d.text + (' %s'%m), d.insn, hops)
        return Res('unknown','%s %s'%(m,i.op_str), i.address-BASE, hops)
    return Res('unknown','%s %s'%(m,i.op_str), i.address-BASE, hops)

def combine(rootk, op):
    if op=='deref':
        if rootk=='arg':
            return 'deref'
        if rootk in ('stack','stackload','local'):
            return 'deref'
        return 'deref'
    return rootk

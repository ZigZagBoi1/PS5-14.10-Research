
import struct, json
from array import array
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM
BASE=0xffffffff8a9c0000
data=open(r'C:\PS5contrib\docs\dumps_13.60\kernel_text.bin','rb').read()
N=len(data)
md=Cs(CS_ARCH_X86, CS_MODE_64); md.detail=True

seeds=set([0])
for i in range(N-5):
    if data[i] in (0xe8,0xe9):
        rel=struct.unpack_from('<i',data,i+1)[0]
        t=i+5+rel
        if 0<=t<N: seeds.add(t)
sy=json.load(open(r'C:\PS5contrib\docs\dumps_13.60\sysent_index.json'))
for e in sy['entries']:
    off=int(e['sy_call_off'],16)
    rel=struct.unpack_from('<i',data,off+1)[0]
    seeds.add(off+5+rel)
print('seeds', len(seeds))

own=array('i',[-1])*N
TERM={'ret','retf','iret','iretq','int3','hlt','ud2'}
COND=set('''jo jno js jns je jz jne jnz jb jnae jc jnb jae jnc jbe jna ja jnbe jl jnge jge jnl jle jng jg jnle jp jpe jnp jpo jcxz jecxz jrcxz loop loope loopne'''.split())
count=0
for s0 in sorted(seeds):
    if own[s0]!=-1: continue
    stack=[s0]
    n_local=0
    while stack:
        a=stack.pop()
        if a<0 or a>=N or own[a]!=-1: continue
        g=md.disasm(data[a:a+15], BASE+a)
        try: ins=next(g)
        except StopIteration: continue
        if ins.size==0 or own[a]!=-1: continue
        own[a]=s0; count+=1; n_local+=1
        m=ins.mnemonic; nxt=a+ins.size
        if m=='jmp':
            if ins.operands and ins.operands[0].type==X86_OP_IMM:
                t=ins.operands[0].imm-BASE
                if 0<=t<N: stack.append(t)
            continue
        if m in TERM: continue
        if m in COND and ins.operands and ins.operands[0].type==X86_OP_IMM:
            t=ins.operands[0].imm-BASE
            if 0<=t<N: stack.append(t)
        if nxt<N: stack.append(nxt)
print('decoded instrs', count)
open(r'C:\PS5contrib\tools\_own.bin','wb').write(own.tobytes())
sites=json.load(open(r'C:\PS5contrib\tools\_copyin_sites.json'))
res=[]; miss=[]
for s in sites:
    o=own[s]
    res.append({'site':s,'owner':o if o!=-1 else None})
    if o==-1: miss.append(s)
json.dump(res, open(r'C:\PS5contrib\tools\_owners.json','w'))
print('sites owned:', len(sites)-len(miss), 'missing:', len(miss), [hex(x) for x in miss[:10]])
print('distinct enclosing funcs:', len(set(r['owner'] for r in res)))

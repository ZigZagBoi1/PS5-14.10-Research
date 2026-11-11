
import sys, json
sys.path.insert(0, r'C:\PS5contrib\tools')
from slicer2 import *
sites=json.load(open(r'C:\PS5contrib\tools\_copyin_sites.json'))
fs={o['site']:o for o in json.load(open(r'C:\PS5contrib\tools\_fstart4.json'))}
ins_cache={}
def getfns(E):
    if E not in ins_cache:
        ins_cache[E]=list(md.disasm(data[E:E+0x8000], BASE+E))
    return ins_cache[E]
def idx_of(ins,rva):
    for k,i in enumerate(ins):
        if i.address-BASE==rva: return k
    return None
recs=[]
for S in sites:
    E=fs[S]['fstart']; ins=getfns(E); k=idx_of(ins,S)
    d={'site':S,'fstart':E,'score':fs[S].get('score')}
    if k is None:
        d['cls']='ERR-idx'; recs.append(d); continue
    lw=None;lwk=None
    for j in range(k-1,max(-1,k-600),-1):
        if 'rsi' in writes(ins[j]): lw=ins[j];lwk=j;break
    if lw is None:
        d['cls']='none-in-window'; d['dec']=None; recs.append(d); continue
    d['dec']={'rva':lw.address-BASE,'mnem':lw.mnemonic,'op':lw.op_str,'bytes':lw.bytes.hex()}
    # classify
    if lw.mnemonic=='lea' and lw.operands[1].type==X86_OP_MEM:
        mm=lw.operands[1].mem; b=fam(lw.reg_name(mm.base)) if mm.base else None
        if b in ('rsp','rbp'): d.update(cls='stack',root='frame',expr='[%s]'%memstr(lw,mm),derefs=0)
        elif b=='rip' or b is None: d.update(cls='global',root='global',expr='[%s]'%memstr(lw,mm),derefs=0)
        else:
            r=resolve(ins,lwk,b); d.update(root=r.root,expr=r.expr,derefs=r.derefs)
            d['cls']='derived:'+r.root
    elif lw.mnemonic=='mov' and lw.operands[1].type==X86_OP_REG:
        r=resolve(ins,lwk,fam(lw.reg_name(lw.operands[1].reg)))
        d.update(root=r.root,expr=r.expr,derefs=r.derefs)
        d['cls']='derived:'+r.root
    elif lw.mnemonic=='mov' and lw.operands[1].type==X86_OP_MEM:
        r=resolve(ins,lwk,'rsi'); d.update(root=r.root,expr=r.expr,derefs=r.derefs)
        d['cls']='loadfrom:'+r.root
    elif lw.mnemonic=='pop':
        d.update(cls='stack',root='frame',expr='pop',derefs=0)
    else:
        d.update(cls='other:'+lw.mnemonic, root='?', expr=lw.op_str, derefs=0)
    # length reg rdx
    dl=None
    for j in range(k-1,max(-1,k-600),-1):
        if 'rdx' in writes(ins[j]): dl=ins[j];break
    d['len_dec']= None if dl is None else {'rva':dl.address-BASE,'mnem':dl.mnemonic,'op':dl.op_str}
    if dl is not None:
        if dl.mnemonic=='mov' and dl.operands[1].type==X86_OP_IMM:
            d['len']='const %#x'%dl.operands[1].imm
        else:
            r2=resolve(ins,ins.index(dl),'rdx')
            d['len']='derived:'+r2.root
    recs.append(d)
json.dump(recs, open(r'C:\PS5contrib\tools\_census2.json','w'), indent=0)
from collections import Counter
print(Counter(r.get('cls','?') for r in recs).most_common())
print()
print('roots', Counter(r.get('root','-') for r in recs).most_common())
print()
print('len', Counter(r.get('len','-').split(' ')[0] if r.get('len') else '-' for r in recs).most_common())

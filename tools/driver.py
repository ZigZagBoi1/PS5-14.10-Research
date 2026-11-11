
import sys, json, struct, bisect
sys.path.insert(0, r'C:\PS5contrib\tools')
from slicer2 import *

sites = json.load(open(r'C:\PS5contrib\tools\_copyin_sites.json'))
fsmap = {o['site']:o['fstart'] for o in json.load(open(r'C:\PS5contrib\tools\_copyin_fstart.json'))}
handlers = {int(k):v for k,v in json.load(open(r'C:\PS5contrib\tools\_handlers.json')).items()}

ins_cache={}
def getfns(fs):
    if fs in ins_cache: return ins_cache[fs]
    r=list(md.disasm(data[fs:fs+0x6000], BASE+fs))
    ins_cache[fs]=r
    return r

def idx_of(ins, rva):
    # first instruction starting at rva
    for k,i in enumerate(ins):
        if i.address-BASE==rva: return k
    return None

recs=[]
for s in sites:
    fs=fsmap[s]
    ins=getfns(fs)
    k=idx_of(ins, s)
    if k is None:
        recs.append({'site':s,'fstart':fs,'err':'call insn not found in stream'}); continue
    call=ins[k]
    # last write to rsi
    lw=None; lwk=None
    for j in range(k-1, max(-1,k-400), -1):
        if 'rsi' in writes(ins[j]):
            lw=ins[j]; lwk=j; break
    d={'site':s,'fstart':fs,'fname_is_handler':fs in handlers}
    if lw is None:
        d['cls']='none-in-window'; d['dec']=None
    else:
        d['dec']={'rva':lw.address-BASE,'mnem':lw.mnemonic,'op':lw.op_str,'bytes':lw.bytes.hex()}
        if lw.mnemonic=='lea' and lw.operands[1].type==X86_OP_MEM:
            b=fam(lw.reg_name(lw.operands[1].mem.base)) if lw.operands[1].mem.base else None
            if b in ('rsp','rbp'): d['cls']='stack'; d['root']='frame'; d['expr']='[%s]'%memstr(lw,lw.operands[1].mem)
            elif b=='rip' or b is None: d['cls']='global'; d['root']='global'; d['expr']='[%s]'%memstr(lw,lw.operands[1].mem)
            else:
                r=resolve(ins,lwk,b)
                d['root']=r.root; d['expr']=r.expr; d['derefs']=r.derefs
                d['cls']='object-field' if r.root not in ('entry:rsi','entry:rdx','entry:rcx','entry:r8','entry:r9','spill') else 'candidate'
                d['provenance']=r.expr+('' if not lw.operands[1].mem.disp else '')
        elif lw.mnemonic=='mov' and lw.operands[1].type==X86_OP_REG:
            r=resolve(ins,lwk,fam(lw.reg_name(lw.operands[1].reg)))
            d['root']=r.root; d['expr']=r.expr; d['derefs']=r.derefs
            if r.root=='frame': d['cls']='stack'
            elif r.root=='global': d['cls']='global'
            elif r.root=='imm': d['cls']='const'
            elif r.root=='spill': d['cls']='stack-spill'
            elif r.root=='entry:rsi' and r.derefs==0: d['cls']='uap-addr'
            elif r.root=='entry:rsi' and r.derefs>=1: d['cls']='uap-value'
            elif r.root=='entry:rdi' and r.derefs>=1: d['cls']='kernel-object'
            elif r.root=='entry:rdi' and r.derefs==0: d['cls']='td-addr'
            elif r.root in ('entry:rdx','entry:rcx','entry:r8','entry:r9'): d['cls']='user-scalar'
            else: d['cls']='other:'+r.root
        elif lw.mnemonic=='mov' and lw.operands[1].type==X86_OP_MEM:
            r=resolve(ins,lwk,'rsi')
            d['root']=r.root; d['expr']=r.expr; d['derefs']=r.derefs
            d['cls']='stack-spill' if r.root in ('spill','frame') else 'uap-value' if r.root=='entry:rsi' else 'memload:'+r.root
        else:
            d['cls']='other:'+lw.mnemonic
    recs.append(d)

json.dump(recs, open(r'C:\PS5contrib\tools\_copyin_census.json','w'), indent=0)
from collections import Counter
print('total', len(recs))
print(Counter(r.get('cls','ERR') for r in recs).most_common())
print()
print('roots:', Counter(r.get('root','-') for r in recs).most_common())
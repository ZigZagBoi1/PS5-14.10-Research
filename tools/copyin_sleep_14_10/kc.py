
import json, struct, collections
import capstone
D=r"C:\PS5contrib\docs\dumps_13.60"
BASE=0xffffffff8a9c0000
data=open(D+r"\kernel_text.bin",'rb').read()
idx=json.load(open(D+r"\sysent_index.json",encoding='utf-8'))
ents=idx['entries']
MD=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
MD.detail=True

def thunk_map():
    m={}
    for e in ents:
        tr=int(e['sy_call'],16)-BASE
        rel=struct.unpack('<i',data[tr+1:tr+5])[0]
        m[e['num']]=(tr, tr+5+rel)
    return m

CHUNK=0x10000
_cache={}
def chunk_insns(off):
    k=off//CHUNK
    if k not in _cache:
        s=k*CHUNK
        blob=data[s:s+CHUNK]
        ins=[]
        for i in MD.disasm(blob, BASE+s):
            ins.append(i)
        _cache[k]=ins
    return _cache[k]

def ins_at(rva):
    ins=chunk_insns(rva)
    # binary search
    lo,hi=0,len(ins)-1
    while lo<=hi:
        mid=(lo+hi)//2
        a=ins[mid].address-BASE
        if a==rva: return ins[mid]
        if a<rva: lo=mid+1
        else: hi=mid-1
    return None

def walk(start, max_ins=3000, window=0x4000):
    """recursive descent; returns dict addr->ins, plus list of call sites"""
    todo=[start]; seen={}; calls=[]; order=[]
    lo=max(0,start-0x100); hi=start+window
    n=0
    while todo and n<max_ins:
        a=todo.pop()
        while True:
            if a in seen or a<lo or a>=hi or a>=len(data): break
            i=ins_at(a)
            if i is None: break
            seen[a]=i; order.append(a); n+=1
            m=i.mnemonic; ops=i.op_str
            if m=='call':
                tgt=None
                if ops.startswith('0x'): tgt=int(ops,16)-BASE
                calls.append((a,tgt,ops))
                a=i.address-BASE+len(i.bytes); continue
            if m in ('ret','retf','ud2','int3','hlt'): break
            if m=='jmp':
                if ops.startswith('0x'):
                    t=int(ops,16)-BASE
                    if lo<=t<hi: a=t; continue
                break
            if m.startswith('j') and ops.startswith('0x'):
                t=int(ops,16)-BASE
                if lo<=t<hi: todo.append(t)
                a=i.address-BASE+len(i.bytes); continue
            a=i.address-BASE+len(i.bytes)
    return seen, calls, order

def show(rva, n=40, start=None):
    s=start if start is not None else rva
    seen,calls,order=walk(s)
    out=[]
    for a in order[:n]:
        i=seen[a]
        out.append("%08x  %-20s %s %s"%(a, i.bytes.hex(), i.mnemonic, i.op_str))
    return "\n".join(out)

if __name__=='__main__':
    tm=thunk_map()
    hs=collections.Counter(h for tr,h in tm.values())
    print("distinct",len(hs))
    print("=== 0x5620e0 (368 entries) ===")
    print(show(0x5620e0,20))
    print("=== 0x8fc810 (10) ===")
    print(show(0x8fc810,20))

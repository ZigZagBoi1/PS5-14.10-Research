
import json, struct, collections
D=r"C:\PS5contrib\docs\dumps_13.60"
BASE=0xffffffff8a9c0000
data=open(D+r"\kernel_text.bin",'rb').read()
idx=json.load(open(D+r"\sysent_index.json",encoding='utf-8'))
ents=idx['entries']
print("entries",len(ents))
thunks={}
bad=[]
for e in ents:
    sy=int(e['sy_call'],16); tr=sy-BASE
    if tr<0 or tr+5>len(data):
        bad.append((e['num'],hex(tr))); continue
    b=data[tr:tr+5]
    if b[0]!=0xE9: bad.append((e['num'],hex(tr),b.hex()))
    rel=struct.unpack('<i',b[1:5])[0]
    h=tr+5+rel
    thunks[e['num']]=(tr,h)
print("bad thunks",len(bad), bad[:10])
hs=collections.Counter(h for tr,h in thunks.values())
print("distinct handlers",len(hs))
print("min/max handler rva", hex(min(hs)), hex(max(hs)))
print("top repeated", [(hex(h),c) for h,c in hs.most_common(8)])
print("copyin first bytes @0x259280:", data[0x259280:0x259280+32].hex())
print("sysent_rva", hex(idx['sysent_rva']), "len data", hex(len(data)))

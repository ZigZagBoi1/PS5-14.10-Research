
import json, collections
P=r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin"
cls=json.load(open(r"C:\PS5contrib\docs\_mg_cls.json"))
fin={r["rva"]:r for r in json.load(open(r"C:\PS5contrib\docs\_mg_final.json"))}
def pow2(x): return x>0 and (x&(x-1))==0
def ismask(x):
    x&=0xffffffff; inv=(~x)&0xffffffff
    return (x and (x&(x+1))==0) or (inv and (inv&(inv+1))==0)
FLOAT={0x3f800000,0xbf800000,0x3f000000,0xbf000000,0x40800000,0xc0800000,0x7ff00000,0x3f7fffff,0x3e22f982,0x3e22f983}
def sentinel(imm):
    s=imm-0x100000000 if imm>=0x80000000 else imm
    return -0x100000<=s<0 or imm in (0x7fffffff,0x7ffffffe,0x80000000)
print("total raw hits:",len(cls))
print("sentinel(-1/errno/INT_MAX):",sum(1 for r in cls if sentinel(r["imm"])))
print("mask class:",sum(1 for r in cls if not sentinel(r["imm"]) and ismask(r["imm"])))
print("float literal class:",sum(1 for r in cls if r["imm"] in FLOAT))
print("class GATE:",sum(1 for r in cls if r["cls"]=="GATE"))
print("class GATE & lvl<=2:",sum(1 for r in cls if r["cls"]=="GATE" and r["lvl"] is not None and r["lvl"]<=2))
print("class GATE & lvl<=2 & depth<=3:",sum(1 for r in cls if r["cls"]=="GATE" and r["lvl"] is not None and r["lvl"]<=2 and (fin.get(r["rva"],{}).get("depth") is not None and fin[r["rva"]]["depth"]<=3)))
print("class NO-JCC:",sum(1 for r in cls if r["cls"]=="NO-JCC")," CLAMP:",sum(1 for r in cls if r["cls"]=="CLAMP")," OTHER:",sum(1 for r in cls if r["cls"]=="OTHER"))
order={r["rva"]:i for i,r in enumerate(json.load(open(r"C:\PS5contrib\docs\_mg_final.json")))}
sel=[]
for r in cls:
    if r["cls"]!="GATE": continue
    imm=r["imm"]
    if sentinel(imm) or ismask(imm) or imm in FLOAT: continue
    if imm<0x10000: continue
    lvl=r["lvl"]; f=fin.get(r["rva"],{}); d=f.get("depth")
    if lvl is None or lvl>2 or d is None or d>4: continue
    sel.append(dict(rva=r["rva"],imm=imm,func=r["func"],lvl=lvl,depth=d,syscalls=f.get("syscalls",[]),
        text=r["text"],calls=r.get("calls_fall",[])[:2],nerr=r.get("nerr")))
sel.sort(key=lambda x: order.get(x["rva"],9e9))
seen=set(); out=[]
for r in sel:
    if r["func"] in seen: continue
    seen.add(r["func"]); out.append(r)
print("relaxed distinct functions:",len(out))
for r in out[:30]:
    print("%7s 0x%08x L%s d%s sys=%-12s f=%-7s %-32s calls=%s" % (hex(r["rva"]),r["imm"],r["lvl"],r["depth"],
      str(r["syscalls"][:2]).replace(" ",""),hex(r["func"]),r["text"][:32],[hex(c) for c in r["calls"][:2]]))
json.dump(out,open(r"C:\PS5contrib\docs\_mg_table.json","w"))

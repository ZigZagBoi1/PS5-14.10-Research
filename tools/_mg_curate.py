
import json, collections
P=r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin"
rows=json.load(open(r"C:\PS5contrib\docs\_mg_cls.json"))
fin={r["rva"]:r for r in json.load(open(r"C:\PS5contrib\docs\_mg_final.json"))}
def pow2(x): return x>0 and (x&(x-1))==0
def ismask(x):
    x&=0xffffffff; inv=(~x)&0xffffffff
    return (x and (x&(x+1))==0) or (inv and (inv&(inv+1))==0)
FLOAT={0x3f800000,0xbf800000,0x3f000000,0xbf000000,0x40800000,0xc0800000,0x7ff00000,0x3f7fffff,0x3e22f982,0x3e22f983}
sel=[]
for r in rows:
    if r["cls"]!="GATE": continue
    imm=r["imm"]; s=imm-0x100000000 if imm>=0x80000000 else imm
    if -0x100000<=s<0: continue
    if imm in (0x7fffffff,0x7ffffffe,0x80000000): continue
    if ismask(imm) or imm in FLOAT: continue
    f=fin.get(r["rva"],{})
    d=f.get("depth"); lvl=r["lvl"]
    if d is None or d>3: continue
    if lvl is None or lvl>2: continue
    sel.append({"rva":r["rva"],"imm":imm,"func":r["func"],"lvl":lvl,"depth":d,"syscalls":f.get("syscalls",[]),
        "text":r["text"],"jcc":r["jcc"],"jtgt":r["jtgt"],"nerr":(r["nerr"]-0x100000000 if r["nerr"] and r["nerr"]>=0x80000000 else r["nerr"]),
        "calls":r.get("calls_fall",[])[:3],"nfall":r.get("nfall"),"ntaken":r.get("ntaken")})
# dedupe per function, keep first (highest score order preserved from _mg_final)
seen=set(); out=[]
order={r["rva"]:i for i,r in enumerate(json.load(open(r"C:\PS5contrib\docs\_mg_final.json")))}
sel.sort(key=lambda x: order.get(x["rva"],9e9))
for r in sel:
    if r["func"] in seen: continue
    seen.add(r["func"]); out.append(r)
print("distinct functions:",len(out))
for r in out[:34]:
    print("%7s 0x%08x L%s d%s sys=%-14s f=%-7s %-34s errno=%-6s calls=%s" % (hex(r["rva"]),r["imm"],r["lvl"],r["depth"],
      str(r["syscalls"][:2]).replace(" ",""),hex(r["func"]),r["text"][:34],r["nerr"],[hex(c) for c in r["calls"][:2]]))
json.dump(out,open(r"C:\PS5contrib\docs\_mg_curated.json","w"))

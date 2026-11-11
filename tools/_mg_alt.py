
import json
BASE=0xffffffff8a9c0000
cls={r["rva"]:r for r in json.load(open(r"C:\PS5contrib\docs\_mg_cls.json"))}
fin={r["rva"]:r for r in json.load(open(r"C:\PS5contrib\docs\_mg_final.json"))}
for r in (0x2b1e21,0x2b1e2a,0x2b1e33,0x27bb4a,0x33ef24,0x337111):
    c=cls.get(r) or {}
    f=fin.get(r,{})
    print("rva=%-9s va=0x%08x imm=0x%08x f=%-9s fva=0x%08x lvl=%-4s d=%-4s sys=%-12s cls=%-6s calls=%s | %s" % (
        hex(r),(0x8a9c0000+r)&0xffffffff,c.get("imm",0),hex(c.get("func",0)),(0x8a9c0000+c.get("func",0))&0xffffffff,
        c.get("lvl"),f.get("depth"),str(f.get("syscalls",[])[:3]).replace(" ",""),c.get("cls"),
        [hex(x) for x in (c.get("calls_fall") or [])[:2]], c.get("text")))

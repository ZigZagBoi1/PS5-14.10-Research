
import json
BASE=0xffffffff8a9c0000
cls={r["rva"]:r for r in json.load(open(r"C:\PS5contrib\docs\_mg_cls.json"))}
fin={r["rva"]:r for r in json.load(open(r"C:\PS5contrib\docs\_mg_final.json"))}
want=[0xae7028,0xa36b23,0xc9c4a6,0xabb9ed,0x5f9f5b,0x45e4e8,0x7b03e0,0x73b343,0xc02a34,0x60eb3e,
      0x313046,0x3133be,0xaba5e7,0xa0b467,0xaed25a,0xaed36c,0x9ebca2,0x8eeef1,0x8ee67d,0x9ed1e6,
      0x3b3bf4,0xaf2dc7,0x749b80,0x96ee72,0xb56101]
for r in want:
    c=cls.get(r); f=fin.get(r,{})
    if not c: print(hex(r),"MISSING"); continue
    print("rva=%-8s va=0x%08x imm=0x%08x f=%-8s fva=0x%08x lvl=%-4s d=%-4s sys=%-14s cls=%-5s | %s" % (
        hex(r), (0x8a9c0000+r)&0xffffffff, c["imm"], hex(c["func"]), (0x8a9c0000+c["func"])&0xffffffff,
        c["lvl"], f.get("depth"), str(f.get("syscalls",[])[:3]).replace(" ",""), c["cls"], c["text"]))

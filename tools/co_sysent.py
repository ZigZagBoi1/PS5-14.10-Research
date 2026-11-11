import json, struct
IMG = r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin"
BASE = 0xffffffff8a9c0000
d = open(IMG,'rb').read()
j = json.load(open(r"C:\PS5contrib\docs\dumps_13.60\sysent_index.json"))
ents = j["entries"]
def body_of(off):
    if off+5 > len(d): return None
    if d[off] != 0xE9:  # expect jmp rel32 thunk
        # maybe direct
        return None
    rel = struct.unpack_from("<i", d, off+1)[0]
    return off+5+rel
rows=[]
bad=0
for e in ents:
    off = int(e["sy_call_off"],16)
    b = body_of(off)
    if b is None: bad+=1; continue
    rows.append((e["num"], e["narg"], off, b))
print("entries", len(rows), "thunk-not-e9", bad)
# sanity: show a few
for r in rows[:5]: print(hex(r[2]), "->", hex(r[3]))
bodies = {}
for num,narg,off,b in rows:
    bodies.setdefault(b, []).append(num)
print("distinct bodies", len(bodies))
json.dump({"rows":rows,"bodies":{hex(k):v for k,v in bodies.items()}}, open(r"C:\PS5contrib\tools\co_handlers.json","w"))
print("body rva range", hex(min(bodies)), hex(max(bodies)))

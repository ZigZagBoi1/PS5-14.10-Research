import sys, json, struct, bisect
sys.path.insert(0, r"C:\PS5contrib\tools")
import co_audit as A
from co_func import FS   # candidate list

img = A.d
BASE = A.BASE
cands = sorted(FS)
def enc(a):
    i = bisect.bisect_left(cands, a)
    return cands[i-1] if i>0 else None

# scan all e8
rev = {}   # callee -> set(enclosing caller func)
n = len(img)
for off in range(0, n-5):
    if img[off] != 0xE8: continue
    rel = struct.unpack_from("<i", img, off+1)[0]
    tgt = off + 5 + rel
    if 0 <= tgt < n:
        f = enc(off)
        if f is None: continue
        rev.setdefault(tgt, set()).add(f)

h = json.load(open(r"C:\PS5contrib\tools\co_handlers.json"))
bodies = h["bodies"]
body_rva = {int(k,16): v for k,v in bodies.items()}

def reach(f, depth=2):
    seen = {f}
    cur = {f}
    for _ in range(depth):
        nxt = set()
        for c in cur:
            nxt |= rev.get(c, set())
        nxt -= seen
        seen |= nxt
        cur = nxt
        if not cur: break
    out = set()
    for b in seen:
        if b in body_rva: out |= set(body_rva[b])
    return sorted(out)

rows = json.load(open(r"C:\PS5contrib\tools\co_final.json"))
out=[]
for r in rows:
    f = enc(r["site"])
    nums = reach(f) if f is not None else []
    r2 = dict(r); r2["fs2"]=f; r2["nums"]=nums
    out.append(r2)
json.dump(out, open(r"C:\PS5contrib\tools\co_reach.json","w"))
from collections import Counter
print("sites", len(out))
print("with nums", sum(1 for r in out if r["nums"]))
print("no nums", sum(1 for r in out if not r["nums"]))
print(Counter(len(r["nums"])>0 for r in out))
print("sample", out[0]["site"], out[0]["nums"][:5])

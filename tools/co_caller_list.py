import json, sys, struct, bisect
sys.path.insert(0, r"C:\PS5contrib\tools")
import co_audit as A
from co_func import fstart, FS
H = json.load(open(r"C:\PS5contrib\tools\co_handlers.json"))
BODIES = {int(k,16): sorted(v) for k,v in H["bodies"].items()}
callers = json.load(open(r"C:\PS5contrib\tools\co_callers.json"))
def norm(s): return s
rows=[]
for f,lst in callers.items():
    f=int(f)
    for cs,rd,ri in lst:
        cfs = fstart(cs)
        h = BODIES.get(cfs)
        if rd and rd.startswith("imm"): continue
        rows.append((cfs, cs, f, rd, ri, h))
rows.sort(key=lambda r: (r[0] if r[0] is not None else -1, r[1]))
print("non-imm caller sites into copyout functions:", len(rows))
in_h = [r for r in rows if r[5]]
print("of which inside handler bodies:", len(in_h))
for cfs,cs,f,rd,ri,h in in_h:
    print("%06x->%06x  handler %-12s rdx=%-32s rdi=%s" % (cs, f, ",".join(map(str,h[:4])), rd, ri))

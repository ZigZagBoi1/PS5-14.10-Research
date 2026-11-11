import json, sys, re
sys.path.insert(0, r"C:\PS5contrib\tools")
from co_func import fstart
H = json.load(open(r"C:\PS5contrib\tools\co_handlers.json"))
bodies = {int(k,16): sorted(v) for k,v in H["bodies"].items()}
cl = {r["site"]: r for r in json.load(open(r"C:\PS5contrib\tools\co_class2.json"))}
from collections import defaultdict
def norm(s): return re.sub(r"0x[0-9a-f]+","N",s or "")
g=defaultdict(list)
for s,r in cl.items():
    fs = fstart(s) or -1
    g[fs].append((s,r))
nonimm_fns={}
for fs,items in g.items():
    ni=[(s,r) for s,r in items if not norm(r.get("rdx","")).startswith("imm")]
    if ni: nonimm_fns[fs]=ni
print("functions with copyout:", len(g))
print("functions with non-imm length:", len(nonimm_fns))
tot=sum(len(v) for v in nonimm_fns.values()); print("non-imm sites:", tot)
print()
for fs in sorted(nonimm_fns):
    tag = "HANDLER(%s)"%",".join(map(str,bodies[fs][:8])) if fs in bodies else "helper"
    items=nonimm_fns[fs]
    print("== %06x %s  sites=%d" % (fs, tag, len(items)))
    for s,r in items:
        print("   site=%06x rdx=%-30s rdi=%-30s %s" % (s, r.get("rdx"), r.get("rdi"), r.get("kind")))

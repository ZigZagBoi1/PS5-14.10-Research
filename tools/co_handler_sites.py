import json, sys, re
sys.path.insert(0, r"C:\PS5contrib\tools")
H = json.load(open(r"C:\PS5contrib\tools\co_handlers.json"))
bodies = {int(k,16): v for k,v in H["bodies"].items()}
cl = {r["site"]: r for r in json.load(open(r"C:\PS5contrib\tools\co_class2.json"))}
assigned = {int(k):v for k,v in json.load(open(r"C:\PS5contrib\tools\co_site_handler.json")).items()}
from collections import defaultdict
byf = defaultdict(list)
for s,fs in assigned.items(): byf[fs].append(s)
def norm(s): return re.sub(r"0x[0-9a-f]+","N",s or "")
imm=0; nonimm=[]
for fs in sorted(byf):
    nums = sorted(bodies[fs])
    for s in sorted(byf[fs]):
        r = cl.get(s,{})
        if norm(r.get("rdx","")).startswith("imm"): imm+=1
        else: nonimm.append((fs,nums,s,r))
print("handler-body sites: imm rdx =", imm, " non-imm =", len(nonimm))
for fs,nums,s,r in nonimm:
    print("h=%06x n=%-22s site=%06x rdx=%-28s rdi=%-20s | %s" % (fs, ",".join(map(str,nums[:6])), s, r.get("rdx"), r.get("rdi"), r.get("insn")))

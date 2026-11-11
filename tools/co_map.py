import json, sys, bisect
sys.path.insert(0, r"C:\PS5contrib\tools")
from co_func import fstart, FS
H = json.load(open(r"C:\PS5contrib\tools\co_handlers.json"))
bodies = {int(k,16): v for k,v in H["bodies"].items()}
sites = json.load(open(r"C:\PS5contrib\tools\co_sites.json"))
CALLS=sites["calls"]; JUMPS=sites["jumps"]
allsites = CALLS+JUMPS
hits=0; near=0; assigned={}
for s in allsites:
    fs = fstart(s)
    if fs in bodies:
        hits+=1; assigned[s]=fs
    else:
        # nearest preceding body with no other function start in between
        k = bisect.bisect_right(sorted(bodies), s)-1
        if k>=0:
            b = sorted(bodies)[k]
            if s-b < 0x1000 and fs is not None and fs<=b:
                near+=1; assigned[s]=b
print("sites", len(allsites), "exact-fstart==handler", hits, "near", near, "unassigned", len(allsites)-hits-near)
json.dump({str(k):v for k,v in assigned.items()}, open(r"C:\PS5contrib\tools\co_site_handler.json","w"))
# how many handlers have copyout sites
from collections import Counter
c=Counter(assigned.values())
print("handlers with sites:", len(c), "of", len(bodies))

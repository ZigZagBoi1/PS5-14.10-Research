
import json
rows=json.load(open(r"C:\PS5contrib\docs\_mg_scored.json"))
d={r["rva"]:r for r in rows}
print("674 gate 0xabb9d3 in rows:", 0xabb9d3 in d)
if 0xabb9d3 in d: print("  ", d[0xabb9d3])
# raw surv membership
surv=json.load(open(r"C:\PS5contrib\docs\_mg_surv.json"))
print("surv contains 0xabb9d3:", any(h["rva"]==0xabb9d3 for h in surv))
print("any surv hit near 0xabb9c0-0xabb9f0:", [hex(h["rva"]) for h in surv if 0xabb980<=h["rva"]<=0xabba20])

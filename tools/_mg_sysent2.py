
import json
j = json.load(open(r"C:\PS5contrib\docs\dumps_13.60\sysent_index.json"))
print("base", j["kernel_base"], "sysent_rva", hex(int(j["sysent_rva"],16)) if isinstance(j["sysent_rva"],str) else j["sysent_rva"])
e = j["entries"]
print("entries", len(e) if not isinstance(e,dict) else list(e.keys())[:5])
if isinstance(e, dict):
    k=list(e.keys())[0]; print("first", k, json.dumps(e[k])[:400])
else:
    print(json.dumps(e[:3])[:800])


import json
j = json.load(open(r"C:\PS5contrib\docs\dumps_13.60\sysent_index.json"))
print(type(j))
if isinstance(j, dict):
    ks = list(j.keys())[:8]
    print("keys sample:", ks)
    v = j[ks[0]]
    print("value type", type(v))
    print(json.dumps(v)[:600] if not isinstance(v,(str,int)) else v)
elif isinstance(j, list):
    print("len", len(j))
    print(json.dumps(j[:3])[:800])

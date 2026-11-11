
import os, re, json
root = r"C:\PS5contrib"
tested = {}
pat = re.compile(r"(?:call|make_syscall)\(\s*(\d{1,4})\b")
for dp, dn, fn in os.walk(root):
    if any(x in dp for x in (".git", "__pycache__", "node_modules")): continue
    for f in fn:
        if not f.endswith((".lua", ".py", ".md")): continue
        p = os.path.join(dp, f)
        try: s = open(p, encoding="utf-8", errors="ignore").read()
        except: continue
        for m in pat.finditer(s):
            n = int(m.group(1))
            if 1 <= n <= 679:
                tested.setdefault(n, set()).add(os.path.relpath(p, root).replace("\\","/"))
json.dump({str(k): sorted(v)[:4] for k, v in tested.items()}, open(root+r"\docs\_syscall_tested_map.json","w"), indent=0)
print("syscalls appearing in a call()/make_syscall() site:", len(tested))
hit = [k for k in tested if k in (7,44,99,102,105,113,118,133,289,290,379,393,475,476,477,499,532,535,543,548,604,622,626,628,657,663,669,670,671)]
print("of the 29 uap+0x18 handlers, referenced in some call site:", sorted(hit))

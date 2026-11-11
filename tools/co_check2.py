p = r"C:\PS5contrib\docs\COPYOUT_LENGTH_AUDIT_14_10.md"
s = open(p, encoding="ascii").read()
lines = s.splitlines()
cen = [l for l in lines if l.startswith("| 0x")]
print("census+verdict rows starting |0x:", len(cen))
i = s.index("## 3. Sites examined by hand")
print(s[i:i+900])
print("...")
k = s.index("## 4. Verdict")
print(s[k:k+700])

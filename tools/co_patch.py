p = r"C:\PS5contrib\tools\co_doc.py"
src = open(p, encoding="utf-8").read().splitlines()
F = 'w("' + chr(96)*3 + '")'
i = next(k for k,l in enumerate(src) if l.startswith('w("002591d0'))
j = next(k for k in range(i, len(src)) if src[k].strip() == F)
src[i:j] = ['w(dis(0x2591d0, 44))']
open(p,"w",encoding="utf-8",newline="\n").write("\n".join(src))
print("patched", i, j)

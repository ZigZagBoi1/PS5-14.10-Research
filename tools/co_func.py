import json, bisect
IMG = r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin"
d = open(IMG,'rb').read()
def funcstarts():
    cands=set(); n=len(d); i=0
    while i < n-8:
        b=d[i]
        if b==0x90 or b==0xCC:
            j=i
            while j<n and d[j]==b: j+=1
            if j-i>=3: cands.add(j)
            i=j
        else: i+=1
    return sorted(cands)
FS = funcstarts()
def fstart(site, maxback=0x2000):
    k = bisect.bisect_right(FS, site)-1
    if k>=0 and site-FS[k] <= maxback: return FS[k]
    return None

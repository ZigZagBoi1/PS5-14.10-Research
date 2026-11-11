import capstone
IMG = r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin"
BASE = 0xffffffff8a9c0000
d = open(IMG,'rb').read()
def funcstarts():
    cands=set()
    n=len(d)
    i=0
    while i < n-8:
        b=d[i]
        if b==0x90 or b==0xCC:
            j=i
            while j<n and d[j]==b: j+=1
            if j-i>=3:
                cands.add(j)
            i=j
        else:
            i+=1
    return sorted(cands)
if __name__=="__main__":
    cs=funcstarts()
    print("cands", len(cs))
    for t in (0x258ff0,0x2590b0,0x259280,0x2591d0):
        prior=[c for c in cs if c<=t][-3:]
        print(hex(t), "preceding cands", [hex(x) for x in prior])
    import bisect
    # distribution of gaps
    gaps=[cs[i+1]-cs[i] for i in range(len(cs)-1)]
    gaps.sort()
    print("median gap", gaps[len(gaps)//2], "min", gaps[0], "max", gaps[-1])

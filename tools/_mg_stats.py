
import capstone, json, collections, re
P = r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin"
BASE = 0xffffffff8a9c0000
data = open(P,"rb").read()
hits = json.load(open(r"C:\PS5contrib\docs\_mg_raw.json"))
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail=True; md.skipdata=True

def is_pow2(x):
    return x>0 and (x & (x-1))==0

c = collections.Counter(h["imm"] for h in hits)
print("distinct immediates:", len(c))
print("top 40 by frequency:")
for v,n in c.most_common(40):
    print("  0x%08x  %6d  pow2=%s" % (v,n,is_pow2(v)))
print()
print("hits whose imm is pow2:", sum(1 for h in hits if is_pow2(h["imm"])))
print("hits non-pow2:", sum(1 for h in hits if not is_pow2(h["imm"])))

# how many are followed by a jcc within 6 bytes
JCC = {0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7a,0x7b,0x7c,0x7d,0x7e,0x7f,0x0f}
guards = 0
for h in hits:
    nxt = h["rva"] + len(bytes.fromhex(h["bytes"]))
    b = data[nxt]
    if 0x70 <= b <= 0x7f: guards += 1
    elif b == 0x0f and 0x80 <= data[nxt+1] <= 0x8f: guards += 1
print("cmp immediately followed by jcc:", guards)

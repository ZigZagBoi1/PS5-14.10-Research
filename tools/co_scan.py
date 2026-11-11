import struct, json, sys, os
IMG = r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin"
BASE = 0xffffffff8a9c0000
COPYOUT = 0x2591d0
d = open(IMG,'rb').read()
print("len", len(d), hex(len(d)))
calls=[]; jumps=[]
for i in range(len(d)-5):
    op = d[i]
    if op == 0xE8:
        rel = struct.unpack_from('<i', d, i+1)[0]
        tgt = i + 5 + rel
        if tgt == COPYOUT: calls.append(i)
    elif op == 0xE9:
        rel = struct.unpack_from('<i', d, i+1)[0]
        tgt = i + 5 + rel
        if tgt == COPYOUT: jumps.append(i)
print("direct e8 calls to copyout:", len(calls))
print("e9 jumps to copyout:", len(jumps))
# also check calls that land inside copyout body (entry+0..+0x20)
inside_calls=[]
for i in range(len(d)-5):
    if d[i]==0xE8:
        rel = struct.unpack_from('<i', d, i+1)[0]
        tgt = i+5+rel
        if COPYOUT < tgt < COPYOUT+0x40: inside_calls.append((i,tgt))
print("calls into copyout interior(+0..0x40):", len(inside_calls), inside_calls[:20])
json.dump({"calls":calls,"jumps":jumps,"inside":inside_calls}, open(r"C:\PS5contrib\tools\co_sites.json","w"))
print("first20", calls[:20])
print("jumps", jumps[:20])

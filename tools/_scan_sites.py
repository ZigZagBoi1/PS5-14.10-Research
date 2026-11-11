
import struct, json, os
BASE = 0xffffffff8a9c0000
DUMP = r'C:\PS5contrib\docs\dumps_13.60\kernel_text.bin'
data = open(DUMP,'rb').read()
print('len', hex(len(data)), len(data))
COPYIN = 0x259280
sites = []
for i in range(len(data)-5):
    if data[i] == 0xe8:
        rel = struct.unpack_from('<i', data, i+1)[0]
        tgt = i + 5 + rel
        if tgt == COPYIN:
            sites.append(i)
print('direct call sites:', len(sites))
print('first 20:', [hex(x) for x in sites[:20]])
print('last 5:', [hex(x) for x in sites[-5:]])

# also count indirect pointers / lea of copyin
import re
cnt_lea = 0
# mov rax, imm64 = 48 b8 <imm64>
imm823 = 0
for i in range(len(data)-10):
    if data[i] == 0x48 and data[i+1] == 0xb8:
        v = struct.unpack_from('<Q', data, i+2)[0]
        if v == BASE + COPYIN:
            imm823 += 1
print('mov reg, imm64(copyin):', imm823)

json.dump(sites, open(r'C:\PS5contrib\tools\_copyin_sites.json','w'))

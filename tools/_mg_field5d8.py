
import capstone, json, collections, struct
P=r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin"; BASE=0xffffffff8a9c0000
data=open(P,"rb").read(); N=len(data)
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail=True
X=capstone.x86
sysent=json.load(open(r"C:\PS5contrib\docs\_mg_sysent.json"))
info={n:(narg,th,t) for n,narg,th,t in sysent}
for n in (605,532,547,362,141,341,431,1,622,59,563,564,565,566,674):
    if n in info: print("sys %d narg=%d thunk=0x%x impl=%s" % (n,info[n][0],info[n][1],hex(info[n][2]) if info[n][2] else None))
print()
# stores to +0x5d8 (dword): c7 8? d8050000 imm32   and 89 8? d8050000
pat=bytes.fromhex("d8050000")
found=[]
for m in [i for i in range(N-8) if data[i:i+4]==pat]:
    b=data[m-2:m]
    if b[0] in (0xc7,0x89,0x8b) or (b[0]&0xf8)==0x40:
        found.append((m-2,b.hex(),data[m-2:m+8].hex()))
print("raw +0x5d8 dword accesses (mem pattern):",len(found))
for rva,b,by in found[:24]:
    ii=list(md.disasm(data[rva:rva+10],BASE+rva))[:1]
    if ii: print("   %7x %-20s %s %s" % (rva,by,ii[0].mnemonic,ii[0].op_str))

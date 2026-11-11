
import capstone, json, struct
P=r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin"; BASE=0xffffffff8a9c0000
data=open(P,"rb").read(); N=len(data)
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail=True
# callers of 0xae6f90
tgt=0xae6f90
callees=[]
for i in range(N-5):
    if data[i]==0xe8:
        rel=struct.unpack_from("<i",data,i+1)[0]
        if (i+5+rel)==tgt: callees.append(i)
print("direct callers of 0xae6f90:",[hex(c) for c in callees])
for c in callees[:3]:
    print("--- caller context 0x%x"%c)
    for ins in md.disasm(data[c-0x30:c+0x10],BASE+c-0x30):
        print("   %7x %s %s"%(ins.address-BASE,ins.mnemonic,ins.op_str))
# command constants around the dispatcher
lo,hi=0xaec000,0xaee000
cmds={}
for ins in md.disasm(data[lo:hi],BASE+lo):
    if ins.mnemonic=="cmp" and "esi, 0x" in ins.op_str:
        v=int(ins.op_str.split(", ")[1],16)
        if 0x78000000<=v<0x79000000: cmds.setdefault(v,[]).append(ins.address-BASE)
print()
print("distinct 0x7802xxxx command words compared by esi in 0xaec000-0xaee000:",len(cmds))
print(", ".join("0x%x@0x%x"%(v,s[0]) for v,s in sorted(cmds.items())))

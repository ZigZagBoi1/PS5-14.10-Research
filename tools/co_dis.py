import sys, capstone
IMG = r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin"
BASE = 0xffffffff8a9c0000
d = open(IMG,'rb').read()
def dis(rva, n, maxlen=400):
    code = d[rva:rva+maxlen]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    out=[]
    for ins in md.disasm(code, BASE+rva):
        out.append("%08x  %-28s %s %s" % (ins.address-BASE, ins.bytes.hex(), ins.mnemonic, ins.op_str))
        if len(out)>=n: break
    return "\n".join(out)
if __name__=="__main__":
    rva=int(sys.argv[1],16); n=int(sys.argv[2]) if len(sys.argv)>2 else 40
    print(dis(rva,n))

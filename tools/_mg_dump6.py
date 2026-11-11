
import capstone, json, sys
P=r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin"; BASE=0xffffffff8a9c0000
data=open(P,"rb").read(); N=len(data)
md=capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail=True
def dump(f,n=0x120,label=""):
    print("=== func 0x%x %s" % (f,label))
    for i in md.disasm(data[f:f+n],BASE+f):
        tgt=""
        if i.mnemonic.startswith("j") or i.mnemonic=="call":
            t=i.op_str
            if t.startswith("0x"):
                v=int(t,16)-BASE
                tgt="   ; ->0x%x%s" % (v, " KNOWN_FUNC" if v in FS else "")
        print("  %7x %-22s %s %s%s" % (i.address-BASE, i.bytes.hex(), i.mnemonic, i.op_str, tgt))
FS=set(int(x) for x in json.load(open(r"C:\PS5contrib\docs\_mg_starts.json"))["starts"])
json.dump(sorted(FS),open(r"C:\PS5contrib\docs\_mg_fs.json","w"))
dump(0xae7050,0x70,"tail of 0xae6f90: what 0x7802c500 guards")
dump(0xaed250,0x80,"sys532 path: 0x780287ff family")

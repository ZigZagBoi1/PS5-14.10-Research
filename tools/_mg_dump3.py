
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
dump(0x99c3c0,0x90,"sys622 helper: cmp edi,0x7e000000; ja")
dump(0x9fd1d0,0x120,"sys59 exec-related: magic range ladder")


import capstone, json, struct, re
P = r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin"
BASE = 0xffffffff8a9c0000
data = open(P,"rb").read()
N = len(data)
print("size", N, hex(N))

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
md.skipdata = True

CH = 16384
hits = []
desync = 0
off = 0
n_ins = 0
while off < N:
    end = min(off+CH, N)
    look = min(end+16, N)
    for ins in md.disasm(data[off:look], BASE+off):
        rva = ins.address - BASE
        if rva >= end:
            break
        if ins.id == 0:
            continue
        n_ins += 1
        if ins.mnemonic != "cmp":
            continue
        if len(ins.operands) != 2:
            continue
        o0, o1 = ins.operands
        if o1.type != capstone.x86.X86_OP_IMM:
            continue
        imm = o1.imm & 0xffffffffffffffff
        # dword compare forms only
        is_mem = (o0.type == capstone.x86.X86_OP_MEM)
        if is_mem:
            if o0.size != 4: continue
            kind = "mem32"
            detail = {"base": ins.reg_name(o0.mem.base), "index": ins.reg_name(o0.mem.index),
                      "scale": o0.mem.scale, "disp": o0.mem.disp}
        elif o0.type == capstone.x86.X86_OP_REG:
            if o0.size != 4: continue
            kind = "reg32"
            detail = {"reg": ins.reg_name(o0.reg)}
        else:
            continue
        # dword imm view
        d = imm & 0xffffffff
        if d < 0x1000:
            continue
        hits.append({"rva": rva, "va_low": "0x%08x" % ((BASE+rva) & 0xffffffff),
                     "text": ins.mnemonic+" "+ins.op_str, "kind": kind,
                     "imm": d, "detail": detail, "bytes": data[rva:rva+ins.size].hex()})
    off = end
print("instructions decoded", n_ins)
print("raw hits", len(hits))
json.dump(hits, open(r"C:\PS5contrib\docs\_mg_raw.json","w"), indent=0)

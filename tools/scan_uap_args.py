
import json, struct, sys, collections
import capstone
from capstone import x86

BASE = 0xffffffff8a9c0000
TEXT = open(r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin","rb").read()
IDX  = json.load(open(r"C:\PS5contrib\docs\dumps_13.60\sysent_index.json"))
ENTRIES = IDX["entries"]
NOSYS = 0x265760

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

def resolve(thunk_rva):
    b = TEXT[thunk_rva:thunk_rva+5]
    if len(b) == 5 and b[0] == 0xe9:
        rel = struct.unpack("<i", b[1:5])[0]
        return thunk_rva + 5 + rel
    return thunk_rva

def is_pad(b):
    return b in (0x00, 0x90, 0xcc)

REG = {}
for r in md.reg_name(x86.X86_REG_RAX) and []:
    pass

NAMES = {}
for name in ("rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","r8","r9","r10","r11","r12","r13","r14","r15"):
    NAMES[getattr(x86, "X86_REG_"+name.upper())] = name

def ops_of(insn):
    return insn.operands

def writes_reg(insn, regname):
    for op in insn.operands:
        if op.type == x86.X86_OP_REG and NAMES.get(op.reg) == regname:
            if op.access & capstone.CS_AC_WRITE:
                return True
    return False

def sweep(start, limit=0x30000, max_insns=4000):
    """Linear sweep with direct-jmp following; returns (hits, insn_count, end_reason)"""
    hits = []
    todo = [start]
    seen = set()
    total = 0
    while todo:
        pc = todo.pop(0)
        if pc in seen or pc < start or pc >= start + limit:
            continue
        seen.add(pc)
        holders = {"rsi": 0}          # reg -> uap byte offset
        pushq = []
        stack = {}                    # (basereg,disp) -> uap offset
        code = TEXT[pc:pc+min(0x2000, len(TEXT)-pc)]
        for insn in md.disasm(code, pc):
            total += 1
            if total > max_insns:
                return hits, total, "insn-cap"
            off_start = insn.address - start
            # ---- record memory accesses through holders ----
            for i, op in enumerate(insn.operands):
                if op.type != x86.X86_OP_MEM:
                    continue
                base = NAMES.get(op.mem.base)
                index = NAMES.get(op.mem.index)
                if base in holders and (op.mem.index == 0 or index is None):
                    ua = holders[base] + op.mem.disp
                    w = bool(op.access & capstone.CS_AC_WRITE)
                    hits.append({"rva": insn.address, "uap_off": ua,
                                 "text": f"{insn.mnemonic} {insn.op_str}",
                                 "size": op.size, "write": w})
                elif base in holders and index in holders:
                    ua = holders[base] + holders[index] + op.mem.disp
                    hits.append({"rva": insn.address, "uap_off": ua,
                                 "text": f"{insn.mnemonic} {insn.op_str}",
                                 "size": op.size, "write": bool(op.access & capstone.CS_AC_WRITE),
                                 "indexed": True})
            # ---- taint propagation ----
            ops = insn.operands
            mn = insn.mnemonic
            if mn == "mov" and len(ops) == 2 and ops[0].type == x86.X86_OP_REG:
                d = NAMES.get(ops[0].reg)
                if d:
                    if ops[1].type == x86.X86_OP_REG:
                        s = NAMES.get(ops[1].reg)
                        if s and s in holders and ops[0].size == 8:
                            holders[d] = holders[s]
                        else:
                            holders.pop(d, None)
                    elif ops[1].type == x86.X86_OP_MEM:
                        mb = NAMES.get(ops[1].mem.base)
                        key = (mb, ops[1].mem.disp)
                        if mb in ("rbp","rsp") and key in stack and ops[0].size == 8:
                            holders[d] = stack[key]
                        else:
                            holders.pop(d, None)
                    else:
                        holders.pop(d, None)
            elif mn == "mov" and len(ops) == 2 and ops[0].type == x86.X86_OP_MEM:
                mb = NAMES.get(ops[0].mem.base)
                key = (mb, ops[0].mem.disp)
                if ops[1].type == x86.X86_OP_REG:
                    s = NAMES.get(ops[1].reg)
                    if mb in ("rbp","rsp") and s in holders and ops[0].size == 8:
                        stack[key] = holders[s]
                    else:
                        stack.pop(key, None)
                else:
                    stack.pop(key, None)
            elif mn == "lea" and len(ops) == 2 and ops[0].type == x86.X86_OP_REG and ops[1].type == x86.X86_OP_MEM:
                d = NAMES.get(ops[0].reg)
                mb = NAMES.get(ops[1].mem.base)
                if d:
                    if mb in holders and ops[1].mem.index == 0:
                        holders[d] = holders[mb] + ops[1].mem.disp
                    else:
                        holders.pop(d, None)
            elif mn == "call":
                for r in ("rax","rcx","rdx","rsi","rdi","r8","r9","r10","r11"):
                    holders.pop(r, None)
                for k in [k for k in stack if k[0] == "rsp"]:
                    stack.pop(k, None)
            elif mn == "push" and len(ops) == 1 and ops[0].type == x86.X86_OP_REG:
                sr = NAMES.get(ops[0].reg)
                pushq.append(holders.get(sr))
            elif mn == "pop" and len(ops) == 1 and ops[0].type == x86.X86_OP_REG:
                dr = NAMES.get(ops[0].reg)
                v = pushq.pop() if pushq else None
                if dr and v is not None: holders[dr] = v
                elif dr: holders.pop(dr, None)
            elif mn in ("add","sub") and len(ops) == 2 and ops[0].type == x86.X86_OP_REG and ops[1].type == x86.X86_OP_IMM:
                d = NAMES.get(ops[0].reg)
                if d in holders:
                    holders[d] += ops[1].imm if mn == "add" else -ops[1].imm
            else:
                # any other instruction: drop taint on every register it writes
                for op in ops:
                    if op.type == x86.X86_OP_REG and (op.access & capstone.CS_AC_WRITE):
                        r = NAMES.get(op.reg)
                        if r: holders.pop(r, None)
                if mn in ("push","pop","call","ret"):
                    if mn in ("pop","ret"):
                        holders.clear(); stack.clear(); holders["rsi"] = 0 if False else 0
                    if mn == "call":
                        pass
            # ---- termination ----
            if mn in ("ret","ud2","int3","hlt"):
                break
            if mn == "jmp" and ops and ops[0].type == x86.X86_OP_IMM:
                tgt = ops[0].imm
                if start <= tgt < start + 0x40000 and tgt != 0x5620e0:
                    todo.append(tgt)
                break
        # end for
    return hits, total, "ok"

res = []
bodies = {}
for e in ENTRIES:
    num = e["num"]; narg = e["narg"]
    th = int(e["sy_call"],16) - BASE
    body = resolve(th)
    key = body
    bodies.setdefault(key, []).append(num)
    h, n, reason = sweep(body)
    res.append({"num": num, "narg": narg, "thunk_rva": th, "body_rva": body,
                "hits": h, "insns": n, "reason": reason,
                "max_off": max([x["uap_off"] for x in h], default=None)})

acc18 = [r for r in res if any(x["uap_off"] == 0x18 for x in r["hits"])]
print("entries", len(res), "distinct bodies", len(bodies))
print("nosys entries", sum(1 for r in res if r["thunk_rva"] == NOSYS))
print("with uap+0x18 access:", len(acc18))
print("with uap+0x20 access:", sum(1 for r in res if any(x["uap_off"] == 0x20 for x in r["hits"])))
for r in res:
    r["hits"] = [h for h in r["hits"] if -0x200 <= h["uap_off"] <= 0x200]
json.dump(res, open(r"C:\PS5contrib\docs\_uap_scan_raw.json","w"), indent=0)
for r in acc18:
    hs = [x for x in r["hits"] if x["uap_off"] == 0x18]
    print(f"sys {r['num']:3d} narg {r['narg']} body {r['body_rva']:#x}  " + " | ".join(f"{x['rva']:#x} {x['text']}" for x in hs[:3]))

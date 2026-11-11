
import capstone, json, struct, bisect, time, sys
P  = r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin"
BASE = 0xffffffff8a9c0000
data = open(P,"rb").read(); N=len(data)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail=True; md.skipdata=False

# ---- seeds ----
seeds = set()
pat = b"\x55\x48\x89\xe5"
i = data.find(pat)
while i != -1:
    seeds.add(i); i = data.find(pat, i+1)
print("push rbp;mov rbp,rsp seeds:", len(seeds))
# cc-padded 16-aligned starts
ccseeds=0
for o in range(16, N-16, 16):
    if data[o-1]==0xcc and data[o]!=0xcc:
        seeds.add(o); ccseeds+=1
print("cc-padded seeds:", ccseeds)

# sysent thunks -> impl
sj = json.load(open(r"C:\PS5contrib\docs\dumps_13.60\sysent_index.json"))
sysent = []
for e in sj["entries"]:
    th = int(e["sy_call_off"],16) if isinstance(e["sy_call_off"],str) else e["sy_call_off"]
    if th+5 <= N and data[th]==0xe9:
        rel = struct.unpack_from("<i", data, th+1)[0]
        tgt = th+5+rel
        sysent.append((e["num"], e.get("narg",0), th, tgt))
    else:
        sysent.append((e["num"], e.get("narg",0), th, None))
print("sysent entries:", len(sysent), "with impl:", sum(1 for s in sysent if s[3] is not None))
impls = set(s[3] for s in sysent if s[3] is not None)
print("distinct impls:", len(impls))
seeds |= impls

t0=time.time()
intervals = []   # (start, end, func_start)
edges = {}       # callee -> set(callers)
work = list(seeds)
pending = set(work)
SENTINEL_NOP = 0
while pending:
    a = pending.pop()
    if a < 0 or a >= N: continue
    cur = a
    while True:
        if cur in pending: pending.discard(cur)
        chunk_end = min(cur+4096, N)
        insns = list(md.disasm(data[cur:chunk_end], BASE+cur))
        if not insns:
            intervals.append((cur,cur+1,a)); break
        stop = None
        for ins in insns:
            r = ins.address - BASE
            if r >= chunk_end: break
            m = ins.mnemonic; op = ins.op_str
            if m == "call" and op.startswith("0x"):
                try: t = int(op,16)-BASE
                except: t=None
                if t is not None and 0 <= t < N:
                    edges.setdefault(t,set()).add(a)
                    if t not in pending: pending.add(t)
            elif m == "jmp":
                if op.startswith("0x"):
                    try:
                        t=int(op,16)-BASE
                    except: t=None
                    if t is not None and 0<=t<N:
                        edges.setdefault(t,set()).add(a)
                        if t not in pending: pending.add(t)
                stop = ins.address-BASE+ins.size; break
            elif m.startswith("j") and op.startswith("0x") and m not in ("jmp",):
                try: t=int(op,16)-BASE
                except: t=None
                if t is not None and 0<=t<N:
                    edges.setdefault(t,set()).add(a)
                    if t not in pending: pending.add(t)
            elif m in ("ret","retf","iret","iretq","int3","ud2","hlt"):
                stop = ins.address-BASE+ins.size; break
        if stop is None:
            stop = chunk_end
            # continue from chunk end only if next byte starts a plausible insn
            if stop >= N: intervals.append((cur,stop,a)); break
            cur = stop
            continue
        intervals.append((cur,stop,a)); break
print("RDA time %.1fs  intervals=%d  edges(callees)=%d" % (time.time()-t0, len(intervals), len(edges)))
intervals.sort()
starts=[x[0] for x in intervals]
json.dump({"intervals":[list(x) for x in intervals]}, open(r"C:\PS5contrib\docs\_mg_intervals.json","w"))
json.dump({str(k):sorted(v) for k,v in edges.items()}, open(r"C:\PS5contrib\docs\_mg_edges.json","w"))
json.dump([[n,nr,th,t] for (n,nr,th,t) in sysent], open(r"C:\PS5contrib\docs\_mg_sysent.json","w"))
print("total code bytes covered:", sum(e-s for s,e,f in intervals))


import capstone, json, struct, time
P  = r"C:\PS5contrib\docs\dumps_13.60\kernel_text.bin"
BASE = 0xffffffff8a9c0000
data = open(P,"rb").read(); N=len(data)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail=True; md.skipdata=False

sj = json.load(open(r"C:\PS5contrib\docs\dumps_13.60\sysent_index.json"))
sysent=[]; impls={}
for e in sj["entries"]:
    th = int(e["sy_call_off"],16) if isinstance(e["sy_call_off"],str) else e["sy_call_off"]
    tgt=None
    if th+5<=N and data[th]==0xe9:
        tgt = th+5+struct.unpack_from("<i",data,th+1)[0]
    sysent.append([e["num"], e.get("narg",0), th, tgt])
    if tgt is not None: impls.setdefault(tgt, []).append(e["num"])
print("impls", len(impls))

t0=time.time()
intervals=[]; edges={}; depth={}
queue=[(a,0) for a in impls]
for a in impls: depth[a]=0
visited=set()
MAXD=6
while queue:
    a,d = queue.pop()
    if a in visited: continue
    visited.add(a)
    if d>MAXD: continue
    cur=a
    while True:
        end=min(cur+4096,N)
        insns=list(md.disasm(data[cur:end], BASE+cur))
        if not insns: intervals.append((cur,cur+1,a)); break
        stop=None
        for ins in insns:
            r=ins.address-BASE
            if r>=end: break
            m=ins.mnemonic; op=ins.op_str
            if m=="call" and op.startswith("0x"):
                t=int(op,16)-BASE
                if 0<=t<N:
                    edges.setdefault(t,set()).add(a)
                    if t not in visited and d+1<=MAXD:
                        depth.setdefault(t,d+1); queue.append((t,d+1))
            elif m=="jmp":
                if op.startswith("0x"):
                    t=int(op,16)-BASE
                    if 0<=t<N and t not in visited and d+1<=MAXD and cur<=t<end:
                        depth.setdefault(t,d); queue.append((t,d))
                stop=r+ins.size; break
            elif m.startswith("j") and op.startswith("0x"):
                t=int(op,16)-BASE
                if 0<=t<N and t not in visited and cur<=t<end:
                    depth.setdefault(t,d); queue.append((t,d))
            elif m in ("ret","retf","iret","iretq","int3","ud2","hlt"):
                stop=r+ins.size; break
        if stop is None:
            if end>=N: intervals.append((cur,end,a)); break
            cur=end; continue
        intervals.append((cur,stop,a)); break
print("forward BFS from sysent: %.1fs funcs=%d intervals=%d callees=%d" % (time.time()-t0, len(visited), len(intervals), len(edges)))
cov=sum(e-s for s,e,f in intervals)
print("bytes covered", cov)
json.dump({"intervals":[list(x) for x in intervals],
           "depth":{str(k):v for k,v in depth.items()},
           "impl_syscalls":{str(k):v for k,v in impls.items()}},
          open(r"C:\PS5contrib\docs\_mg_fwd.json","w"))
json.dump({str(k):sorted(v) for k,v in edges.items()}, open(r"C:\PS5contrib\docs\_mg_fwd_edges.json","w"))
json.dump(sysent, open(r"C:\PS5contrib\docs\_mg_sysent.json","w"))

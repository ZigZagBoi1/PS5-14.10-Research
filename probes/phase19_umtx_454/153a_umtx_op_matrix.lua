-- CRASH_CLASS: MODERATE
-- PROBE 153a: UMTX op matrix — test all 27 ops on syscall 454
--
-- Context: ops 5 (WAIT/MUTEX_LOCK) and 21 (NWAKE_PRIVATE) confirmed working.
-- Op 25 (SHM) is a stub. Need to find which other ops are functional.
--
-- FreeBSD 11 UMTX ops:
-- 0  LOCK      10 MUTEX_LOCK        20 SEM2_WAIT
-- 1  UNLOCK    11 MUTEX_UNLOCK      21 NWAKE_PRIVATE  ✓
-- 2  WAIT      12 SET_CEILING       22 MUTEX_WAKE2
-- 3  WAKE      13 CV_WAIT           23 SEM2_WAKE
-- 4  MUTEX_TRYLOCK  14 CV_SIGNAL    24 SHM_OPEN (removed)
-- 5  MUTEX_WAIT 15 CV_BROADCAST     25 SHM           ✗ (stub)
-- 6  -         16 WAIT_UINT         26 ROBUST_LISTS
-- 7  -         17 RW_RDLOCK
-- 8  -         18 RW_WRLOCK
-- 9  -         19 RW_UNLOCK

print("=== PROBE 153a: UMTX OP MATRIX ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

collectgarbage("stop")
local pid = to_num(syscall.getpid())
print("pid=" .. pid)

local sc_umtx = make_syscall(454)

-- Op names for reference
local op_names = {
    [0]="LOCK", [1]="UNLOCK", [2]="WAIT", [3]="WAKE",
    [4]="MUTEX_TRYLOCK", [5]="MUTEX_WAIT", [6]="?6", [7]="?7",
    [8]="?8", [9]="?9", [10]="MUTEX_LOCK", [11]="MUTEX_UNLOCK",
    [12]="SET_CEILING", [13]="CV_WAIT", [14]="CV_SIGNAL",
    [15]="CV_BROADCAST", [16]="WAIT_UINT", [17]="RW_RDLOCK",
    [18]="RW_WRLOCK", [19]="RW_UNLOCK", [20]="SEM2_WAIT",
    [21]="NWAKE_PRIVATE", [22]="MUTEX_WAKE2", [23]="SEM2_WAKE",
    [24]="SHM_OPEN", [25]="SHM", [26]="ROBUST_LISTS"
}

-- ============================================================
-- SECTION A: Quick sweep — each op with a zeroed buffer
-- Some ops will crash (caught by pcall), some block, some return
-- ============================================================
print("")
print("--- SECTION A: OP SWEEP ---")

-- Allocate a zeroed buffer for each op to use as obj
-- Using different buffers prevents one op's state from affecting another
for op = 0, 26 do
    local buf = memory.alloc(0x40)
    memory.write_qword(buf, uint64(0))

    local name = op_names[op] or ("?" .. op)

    -- Skip ops known to block (5 with matching value, 13 CV_WAIT, 20 SEM2_WAIT)
    -- For WAIT-type ops, use mismatched value so they return immediately
    local val = uint64(0xFFFFFFFF)  -- mismatched value for WAIT ops
    if op == 3 or op == 14 or op == 15 or op == 21 or op == 22 or op == 23 then
        val = uint64(1)  -- wake/signal: wake 1 waiter (none exist → returns 0 or -1)
    elseif op == 11 or op == 19 then
        val = uint64(0)  -- unlock: val=0
    elseif op == 25 then
        val = uint64(1)  -- SHM: create
    elseif op == 26 then
        val = uint64(24)  -- ROBUST_LISTS: proper struct size
    end

    local ok, ret = pcall(function()
        return sc_umtx(uint64(to_num(buf)), uint64(op), val, uint64(0), uint64(0))
    end)

    local rv = "CRASH"
    if ok then
        local h, l = get_hi_lo(ret)
        if h == 0xFFFFFFFF and l == 0xFFFFFFFF then
            rv = "-1"
        elseif h == 0 then
            rv = tostring(l)
        else
            rv = string.format("0x%X%08X", h, l)
        end
    end

    print(string.format("op%02d %-16s ret=%s", op, name, rv))
end

-- ============================================================
-- SECTION B: Deeper test on promising ops
-- ============================================================
print("")
print("--- SECTION B: MUTEX LOCK/UNLOCK ---")

-- MUTEX_LOCK (10) then MUTEX_UNLOCK (11)
local mtx = memory.alloc(0x40)
memory.write_qword(mtx, uint64(0))

local ok_lock, r_lock = pcall(function()
    return sc_umtx(uint64(to_num(mtx)), uint64(10), uint64(0), uint64(0), uint64(0))
end)
print("MUTEX_LOCK: ok=" .. tostring(ok_lock) .. " ret=" .. (ok_lock and tostring(r_lock) or "crash"))

-- Read the mutex word after lock
local mtx_val = memory.read_qword(mtx)
print("mutex_word_after_lock=" .. string.format("0x%08X_%08X", get_hi_lo(mtx_val)))

local ok_unlock, r_unlock = pcall(function()
    return sc_umtx(uint64(to_num(mtx)), uint64(11), uint64(0), uint64(0), uint64(0))
end)
print("MUTEX_UNLOCK: ok=" .. tostring(ok_unlock) .. " ret=" .. (ok_unlock and tostring(r_unlock) or "crash"))

local mtx_val2 = memory.read_qword(mtx)
print("mutex_word_after_unlock=" .. string.format("0x%08X_%08X", get_hi_lo(mtx_val2)))

-- ============================================================
-- SECTION C: RW lock test
-- ============================================================
print("")
print("--- SECTION C: RW LOCK ---")

local rwl = memory.alloc(0x40)
memory.write_qword(rwl, uint64(0))

-- RW_RDLOCK (17)
local ok_rd, r_rd = pcall(function()
    return sc_umtx(uint64(to_num(rwl)), uint64(17), uint64(0), uint64(0), uint64(0))
end)
print("RW_RDLOCK: ok=" .. tostring(ok_rd) .. " ret=" .. (ok_rd and tostring(r_rd) or "crash"))
local rwl_v1 = memory.read_qword(rwl)
print("rw_word_after_rdlock=" .. string.format("0x%08X_%08X", get_hi_lo(rwl_v1)))

-- RW_UNLOCK (19)
local ok_rwu, r_rwu = pcall(function()
    return sc_umtx(uint64(to_num(rwl)), uint64(19), uint64(0), uint64(0), uint64(0))
end)
print("RW_UNLOCK: ok=" .. tostring(ok_rwu) .. " ret=" .. (ok_rwu and tostring(r_rwu) or "crash"))

-- RW_WRLOCK (18)
local rwl2 = memory.alloc(0x40)
memory.write_qword(rwl2, uint64(0))
local ok_wr, r_wr = pcall(function()
    return sc_umtx(uint64(to_num(rwl2)), uint64(18), uint64(0), uint64(0), uint64(0))
end)
print("RW_WRLOCK: ok=" .. tostring(ok_wr) .. " ret=" .. (ok_wr and tostring(r_wr) or "crash"))
local rwl2_v = memory.read_qword(rwl2)
print("rw_word_after_wrlock=" .. string.format("0x%08X_%08X", get_hi_lo(rwl2_v)))

-- ============================================================
-- SECTION D: ROBUST_LISTS (26)
-- ============================================================
print("")
print("--- SECTION D: ROBUST LISTS ---")

-- FreeBSD 11: struct umtx_robust_lists_params {
--   uintptr_t robust_list_offset;  // +0
--   uintptr_t robust_priv_list_offset;  // +8
--   uintptr_t robust_inact_offset;  // +16
-- };
-- val = sizeof(struct) = 24
local rparams = memory.alloc(0x40)
memory.write_qword(rparams, uint64(0))
memory.write_qword(rparams + 8, uint64(0))
memory.write_qword(rparams + 16, uint64(0))

-- Register with correct size
local ok_r1, rr1 = pcall(function()
    return sc_umtx(uint64(0), uint64(26), uint64(24), uint64(to_num(rparams)), uint64(0))
end)
print("ROBUST(size=24): ok=" .. tostring(ok_r1) .. " ret=" .. (ok_r1 and tostring(rr1) or "crash"))

-- Register with wrong size (should fail per FreeBSD)
local ok_r2, rr2 = pcall(function()
    return sc_umtx(uint64(0), uint64(26), uint64(32), uint64(to_num(rparams)), uint64(0))
end)
print("ROBUST(size=32): ok=" .. tostring(ok_r2) .. " ret=" .. (ok_r2 and tostring(rr2) or "crash"))

-- ============================================================
-- SECTION E: WAIT_UINT (16) — 32-bit wait, may differ from WAIT(2)
-- ============================================================
print("")
print("--- SECTION E: WAIT_UINT ---")

local wu = memory.alloc(64)
memory.write_dword(wu, 42)

-- Mismatched value — should return immediately
local ok_wu, rwu2 = pcall(function()
    return sc_umtx(uint64(to_num(wu)), uint64(16), uint64(99), uint64(0), uint64(0))
end)
print("WAIT_UINT(mismatch): ok=" .. tostring(ok_wu) .. " ret=" .. (ok_wu and tostring(rwu2) or "crash"))

-- WAKE (3) — standard wake
local ok_wk, rwk = pcall(function()
    return sc_umtx(uint64(to_num(wu)), uint64(3), uint64(1), uint64(0), uint64(0))
end)
print("WAKE: ok=" .. tostring(ok_wk) .. " ret=" .. (ok_wk and tostring(rwk) or "crash"))

print("")
print("canary=" .. to_num(syscall.getpid()))
print("=== PROBE 153a COMPLETE ===")

-- CRASH_CLASS: MODERATE
-- PROBE 153b: UMTX safe sweep — non-blocking ops only
--
-- Context: 153a crashed (0 bytes). Some ops block or kill.
-- Test only wake/unlock/signal ops first, then carefully test
-- lock/wait with guaranteed mismatches.

print("=== PROBE 153b: UMTX SAFE SWEEP ===")
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
local function rv_str(ok, ret)
    if not ok then return "CRASH" end
    local h, l = get_hi_lo(ret)
    if h == 0xFFFFFFFF then return "-1" end
    if h == 0 then return tostring(l) end
    return string.format("0x%X%08X", h, l)
end

collectgarbage("stop")
local pid = to_num(syscall.getpid())
print("pid=" .. pid)

local sc_umtx = make_syscall(454)

-- ============================================================
-- SECTION A: Non-blocking ops (wake/signal/broadcast/unlock)
-- These should never block
-- ============================================================
print("")
print("--- SECTION A: NON-BLOCKING OPS ---")

local function test_op(name, op, val)
    local buf = memory.alloc(0x40)
    memory.write_qword(buf, uint64(0))
    print("testing op" .. op .. " " .. name .. "...")
    local ok, ret = pcall(function()
        return sc_umtx(uint64(to_num(buf)), uint64(op), uint64(val), uint64(0), uint64(0))
    end)
    local after = memory.read_qword(buf)
    local ah, al = get_hi_lo(after)
    print(string.format("  op%02d %-16s ret=%-6s word=0x%08X_%08X", op, name, rv_str(ok, ret), ah, al))
    return ok, ret, ah, al
end

-- Wake/signal ops (should return 0 or -1 with no waiters)
test_op("WAKE", 3, 1)
test_op("CV_SIGNAL", 14, 0)
test_op("CV_BROADCAST", 15, 0)
test_op("NWAKE_PRIV", 21, 1)
test_op("MUTEX_WAKE2", 22, 0)
test_op("SEM2_WAKE", 23, 1)

-- Unlock ops (buf=0, nothing locked → should fail gracefully)
test_op("UNLOCK(1)", 1, 0)
test_op("MUTEX_UNLOCK", 11, 0)
test_op("RW_UNLOCK", 19, 0)

-- SHM (known stub)
test_op("SHM_create", 25, 1)
test_op("SHM_destroy", 25, 4)

-- ROBUST_LISTS
print("testing op26 ROBUST_LISTS...")
local rp = memory.alloc(0x40)
memory.write_qword(rp, uint64(0))
memory.write_qword(rp + 8, uint64(0))
memory.write_qword(rp + 16, uint64(0))
local ok26, r26 = pcall(function()
    return sc_umtx(uint64(0), uint64(26), uint64(24), uint64(to_num(rp)), uint64(0))
end)
print(string.format("  op26 ROBUST_LISTS    ret=%-6s", rv_str(ok26, r26)))

-- Invalid op (control)
test_op("INVALID_99", 99, 0)

-- ============================================================
-- SECTION B: MUTEX LOCK/UNLOCK round trip
-- ============================================================
print("")
print("--- SECTION B: MUTEX ROUND TRIP ---")

local mtx = memory.alloc(0x40)
memory.write_qword(mtx, uint64(0))

print("MUTEX_LOCK(10)...")
local ok_ml, r_ml = pcall(function()
    return sc_umtx(uint64(to_num(mtx)), uint64(10), uint64(0), uint64(0), uint64(0))
end)
local m1h, m1l = get_hi_lo(memory.read_qword(mtx))
print(string.format("  ret=%s word=0x%08X_%08X", rv_str(ok_ml, r_ml), m1h, m1l))

if ok_ml then
    print("MUTEX_UNLOCK(11)...")
    local ok_mu, r_mu = pcall(function()
        return sc_umtx(uint64(to_num(mtx)), uint64(11), uint64(0), uint64(0), uint64(0))
    end)
    local m2h, m2l = get_hi_lo(memory.read_qword(mtx))
    print(string.format("  ret=%s word=0x%08X_%08X", rv_str(ok_mu, r_mu), m2h, m2l))
end

-- ============================================================
-- SECTION C: WAIT_UINT (16) with guaranteed mismatch
-- ============================================================
print("")
print("--- SECTION C: WAIT_UINT MISMATCH ---")

local wu = memory.alloc(64)
memory.write_dword(wu, 42)

print("WAIT_UINT(16) *=42, expect=99 (mismatch → immediate return)...")
local ok_wu, rwu = pcall(function()
    return sc_umtx(uint64(to_num(wu)), uint64(16), uint64(99), uint64(0), uint64(0))
end)
print("  ret=" .. rv_str(ok_wu, rwu))

-- ============================================================
-- SECTION D: WAIT(2) with mismatch
-- ============================================================
print("")
print("--- SECTION D: WAIT MISMATCH ---")

local w2 = memory.alloc(64)
memory.write_dword(w2, 42)

print("WAIT(2) *=42, expect=99...")
local ok_w2, rw2 = pcall(function()
    return sc_umtx(uint64(to_num(w2)), uint64(2), uint64(99), uint64(0), uint64(0))
end)
print("  ret=" .. rv_str(ok_w2, rw2))

-- ============================================================
-- SECTION E: MUTEX_TRYLOCK (4)
-- ============================================================
print("")
print("--- SECTION E: MUTEX_TRYLOCK ---")

local mtry = memory.alloc(0x40)
memory.write_qword(mtry, uint64(0))

print("MUTEX_TRYLOCK(4)...")
local ok_try, r_try = pcall(function()
    return sc_umtx(uint64(to_num(mtry)), uint64(4), uint64(0), uint64(0), uint64(0))
end)
local tryh, tryl = get_hi_lo(memory.read_qword(mtry))
print(string.format("  ret=%s word=0x%08X_%08X", rv_str(ok_try, r_try), tryh, tryl))

-- ============================================================
-- SECTION F: SET_CEILING (12)
-- ============================================================
print("")
print("--- SECTION F: SET_CEILING ---")

local ceil = memory.alloc(0x40)
memory.write_qword(ceil, uint64(0))

print("SET_CEILING(12) val=5...")
local ok_ceil, r_ceil = pcall(function()
    return sc_umtx(uint64(to_num(ceil)), uint64(12), uint64(5), uint64(0), uint64(0))
end)
local ch, cl = get_hi_lo(memory.read_qword(ceil))
print(string.format("  ret=%s word=0x%08X_%08X", rv_str(ok_ceil, r_ceil), ch, cl))

-- ============================================================
-- SECTION G: RW_RDLOCK (17) — read lock should be non-blocking on 0
-- ============================================================
print("")
print("--- SECTION G: RW_RDLOCK ---")

local rwl = memory.alloc(0x40)
memory.write_qword(rwl, uint64(0))

print("RW_RDLOCK(17)...")
local ok_rl, r_rl = pcall(function()
    return sc_umtx(uint64(to_num(rwl)), uint64(17), uint64(0), uint64(0), uint64(0))
end)
local rlh, rll = get_hi_lo(memory.read_qword(rwl))
print(string.format("  ret=%s word=0x%08X_%08X", rv_str(ok_rl, r_rl), rlh, rll))

-- RW_UNLOCK after rdlock
if ok_rl and to_num(r_rl) == 0 then
    print("RW_UNLOCK(19)...")
    local ok_ru, r_ru = pcall(function()
        return sc_umtx(uint64(to_num(rwl)), uint64(19), uint64(0), uint64(0), uint64(0))
    end)
    local ruh, rul = get_hi_lo(memory.read_qword(rwl))
    print(string.format("  ret=%s word=0x%08X_%08X", rv_str(ok_ru, r_ru), ruh, rul))
end

-- RW_WRLOCK (18)
print("RW_WRLOCK(18)...")
local rwl2 = memory.alloc(0x40)
memory.write_qword(rwl2, uint64(0))
local ok_wl, r_wl = pcall(function()
    return sc_umtx(uint64(to_num(rwl2)), uint64(18), uint64(0), uint64(0), uint64(0))
end)
local wlh, wll = get_hi_lo(memory.read_qword(rwl2))
print(string.format("  ret=%s word=0x%08X_%08X", rv_str(ok_wl, r_wl), wlh, wll))

-- ============================================================
-- SECTION H: LOCK (0) — old-style umtx lock
-- ============================================================
print("")
print("--- SECTION H: LOCK(0) ---")

local olm = memory.alloc(0x40)
memory.write_qword(olm, uint64(0))

print("LOCK(0)...")
local ok_ol, r_ol = pcall(function()
    return sc_umtx(uint64(to_num(olm)), uint64(0), uint64(0), uint64(0), uint64(0))
end)
local olh, oll = get_hi_lo(memory.read_qword(olm))
print(string.format("  ret=%s word=0x%08X_%08X", rv_str(ok_ol, r_ol), olh, oll))

print("")
print("canary=" .. to_num(syscall.getpid()))
print("=== PROBE 153b COMPLETE ===")

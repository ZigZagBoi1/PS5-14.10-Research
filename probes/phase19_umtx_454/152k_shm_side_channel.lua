-- CRASH_CLASS: LOW
-- PROBE 152k: SHM observable effects via sys 624 counter + getpid
--
-- Context: 152j crashed (fstat probably kills process on PS5).
-- 152i showed alive() returns 0 for never-created keys.
-- Need to verify SHM create/destroy has any kernel effect.
--
-- Use sys 624 (VM op counter) as side channel: each mmap adds +5.
-- If SHM create maps a page, counter should increment.

print("=== PROBE 152k: SHM SIDE CHANNEL ===")
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
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

collectgarbage("stop")
local pid = to_num(syscall.getpid())
print("pid=" .. pid)

local sc_umtx = make_syscall(454)
local sc_624 = make_syscall(624)

local function get_counter()
    local ok, ret = pcall(function()
        return sc_624(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if ok then return to_num(ret) end
    return -1
end

-- ============================================================
-- SECTION A: Counter baseline and calibration
-- ============================================================
print("")
print("--- SECTION A: COUNTER BASELINE ---")

local c0 = get_counter()
print("c0=" .. c0)

-- Do 1 mmap to calibrate
local sc_mmap = make_syscall(477)
pcall(function()
    sc_mmap(uint64(0), uint64(0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local c1 = get_counter()
print("c1=" .. c1 .. " (after 1 mmap, delta=" .. (c1 - c0) .. ")")

-- ============================================================
-- SECTION B: SHM create effect on counter
-- ============================================================
print("")
print("--- SECTION B: SHM CREATE COUNTER EFFECT ---")

local c_before = get_counter()

-- Single SHM create on fresh address
local k1 = memory.alloc(0x20)
memory.write_qword(k1, uint64(0))
local ok1, r1 = pcall(function()
    return sc_umtx(uint64(to_num(k1)), uint64(25), uint64(1), uint64(0), uint64(0))
end)
local c_after1 = get_counter()
print(string.format("1 create: ret=%s delta=%d",
    ok1 and tostring(r1) or "fail", c_after1 - c_before))

-- 5 more creates at different addresses
local c_before5 = get_counter()
for i = 1, 5 do
    local k = memory.alloc(0x20)
    memory.write_qword(k, uint64(0))
    pcall(function()
        sc_umtx(uint64(to_num(k)), uint64(25), uint64(1), uint64(0), uint64(0))
    end)
end
local c_after5 = get_counter()
print(string.format("5 creates: delta=%d (%.1f per create)",
    c_after5 - c_before5, (c_after5 - c_before5) / 5))

-- ============================================================
-- SECTION C: SHM destroy effect on counter
-- ============================================================
print("")
print("--- SECTION C: SHM DESTROY COUNTER EFFECT ---")

local c_pre_d = get_counter()
-- Destroy k1
pcall(function()
    sc_umtx(uint64(to_num(k1)), uint64(25), uint64(4), uint64(0), uint64(0))
end)
local c_post_d = get_counter()
print("1 destroy: delta=" .. (c_post_d - c_pre_d))

-- Double-destroy k1
local c_pre_dd = get_counter()
local ok_dd, rdd = pcall(function()
    return sc_umtx(uint64(to_num(k1)), uint64(25), uint64(4), uint64(0), uint64(0))
end)
local c_post_dd = get_counter()
print(string.format("double-destroy: ret=%s delta=%d",
    ok_dd and tostring(rdd) or "fail", c_post_dd - c_pre_dd))

-- ============================================================
-- SECTION D: Create vs Recreate counter delta
-- If SHM was truly destroyed, recreate should show same delta as create
-- ============================================================
print("")
print("--- SECTION D: RECREATE VS CREATE ---")

local k2 = memory.alloc(0x20)
memory.write_qword(k2, uint64(0))

-- Fresh create
local cd1 = get_counter()
pcall(function()
    sc_umtx(uint64(to_num(k2)), uint64(25), uint64(1), uint64(0), uint64(0))
end)
local cd2 = get_counter()
print("fresh create: delta=" .. (cd2 - cd1))

-- Destroy
pcall(function()
    sc_umtx(uint64(to_num(k2)), uint64(25), uint64(4), uint64(0), uint64(0))
end)

-- Recreate on same address
local cd3 = get_counter()
pcall(function()
    sc_umtx(uint64(to_num(k2)), uint64(25), uint64(1), uint64(0), uint64(0))
end)
local cd4 = get_counter()
print("recreate: delta=" .. (cd4 - cd3))

-- Create on already-existing (no destroy in between)
local cd5 = get_counter()
pcall(function()
    sc_umtx(uint64(to_num(k2)), uint64(25), uint64(1), uint64(0), uint64(0))
end)
local cd6 = get_counter()
print("dup create (no destroy): delta=" .. (cd6 - cd5))

-- ============================================================
-- SECTION E: Double-destroy then create — compare delta
-- If DD truly frees, create should allocate fresh (delta > 0)
-- If DD is no-op, create finds existing (delta = 0)
-- ============================================================
print("")
print("--- SECTION E: DD THEN CREATE ---")

local k3 = memory.alloc(0x20)
memory.write_qword(k3, uint64(0))

-- Create
pcall(function()
    sc_umtx(uint64(to_num(k3)), uint64(25), uint64(1), uint64(0), uint64(0))
end)
-- Single destroy
pcall(function()
    sc_umtx(uint64(to_num(k3)), uint64(25), uint64(4), uint64(0), uint64(0))
end)
-- Double destroy
pcall(function()
    sc_umtx(uint64(to_num(k3)), uint64(25), uint64(4), uint64(0), uint64(0))
end)
-- Recreate after DD
local ce1 = get_counter()
pcall(function()
    sc_umtx(uint64(to_num(k3)), uint64(25), uint64(1), uint64(0), uint64(0))
end)
local ce2 = get_counter()
print("create_after_dd: delta=" .. (ce2 - ce1))

-- ============================================================
-- SECTION F: Are SHM ops actually no-ops?
-- Compare return values more carefully
-- ============================================================
print("")
print("--- SECTION F: SHM RETURN VALUE ANALYSIS ---")

-- Test on an unmapped/invalid address
local ok_inv, r_inv = pcall(function()
    return sc_umtx(uint64(0), uint64(25), uint64(1), uint64(0), uint64(0))
end)
print("create(addr=0): ok=" .. tostring(ok_inv) .. " ret=" .. (ok_inv and tostring(r_inv) or "crash"))

local ok_inv2, r_inv2 = pcall(function()
    return sc_umtx(uint64(0xDEAD), uint64(25), uint64(1), uint64(0), uint64(0))
end)
print("create(addr=0xDEAD): ok=" .. tostring(ok_inv2) .. " ret=" .. (ok_inv2 and tostring(r_inv2) or "crash"))

-- Test with invalid sub-op
local ok_bad, r_bad = pcall(function()
    return sc_umtx(uint64(to_num(k3)), uint64(25), uint64(16), uint64(0), uint64(0))
end)
print("invalid_subop(16): ok=" .. tostring(ok_bad) .. " ret=" .. (ok_bad and tostring(r_bad) or "crash"))

local ok_bad2, r_bad2 = pcall(function()
    return sc_umtx(uint64(to_num(k3)), uint64(25), uint64(0), uint64(0), uint64(0))
end)
print("subop_0: ok=" .. tostring(ok_bad2) .. " ret=" .. (ok_bad2 and tostring(r_bad2) or "crash"))

-- Test with a completely invalid op (not 25)
local ok_inv3, r_inv3 = pcall(function()
    return sc_umtx(uint64(to_num(k3)), uint64(99), uint64(1), uint64(0), uint64(0))
end)
print("invalid_op(99): ok=" .. tostring(ok_inv3) .. " ret=" .. (ok_inv3 and tostring(r_inv3) or "crash"))

-- ============================================================
-- SECTION G: UMTX_OP_WAIT mismatch — confirm 454 is functional
-- ============================================================
print("")
print("--- SECTION G: UMTX FUNCTIONAL TEST ---")

local wa = memory.alloc(64)
memory.write_dword(wa, 42)

-- Wait with mismatched value — should return EWOULDBLOCK (-1)
local ok_wm, rwm = pcall(function()
    return sc_umtx(uint64(to_num(wa)), uint64(5), uint64(99), uint64(0), uint64(0))
end)
print("wait_mismatch: ok=" .. tostring(ok_wm) .. " ret=" .. (ok_wm and tostring(rwm) or "fail"))

-- Wake no waiters
local ok_wk, rwk = pcall(function()
    return sc_umtx(uint64(to_num(wa)), uint64(21), uint64(1), uint64(0), uint64(0))
end)
print("wake: ok=" .. tostring(ok_wk) .. " ret=" .. (ok_wk and tostring(rwk) or "fail"))

print("")
print("canary=" .. to_num(syscall.getpid()))
print("=== PROBE 152k COMPLETE ===")

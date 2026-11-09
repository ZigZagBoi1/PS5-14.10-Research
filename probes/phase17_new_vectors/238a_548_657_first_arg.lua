-- CRASH_CLASS: MODERATE
-- PROBE 238a: sweep the descriptor argument of 548 and 657
--
-- Context: the recovered contracts say 548 takes a descriptor as its first
-- argument and 657 requires an object whose byte at +0x9d equals 11. Both
-- returned -1 for every value tried so far, but neither probe varied that
-- first argument: 235a passed 0 to 657 and 236a passed 0 to 548, and 533 -
-- the only handler that creates a descriptor - refused every size and flag
-- combination (eight attempts, all -1), so no descriptor was ever available.
--
-- This probe asks whether the first argument has to be an existing object at
-- all, or whether some small integer or an mmap address is accepted:
--   [A] a fresh GPU page and its 547 record (the oracle).
--   [B] 548 with descriptor 0..31, one 0x20-byte operation, protection=7.
--   [C] 657 with object 0..31, one 0x20-byte record, opcode 2, protection=7.
--   [D] both again with the mmap address as the first argument.
-- The 547 record is read after every call that does not return -1, so a
-- protection change cannot be missed.

print("=== PROBE 238a: 548 / 657 FIRST-ARGUMENT SWEEP ===")
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    if type(val) == "number" then val = uint64(val) end
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function sgn(val)
    if val == nil then return "nil" end
    local ok, h, l = pcall(function() return val.h, val.l end)
    if ok and type(h) == "number" and type(l) == "number" then
        if h == 0xFFFFFFFF and l == 0xFFFFFFFF then return "-1" end
        return string.format("0x%08X_%08X", h, l)
    end
    if type(val) == "number" then
        if val < 0 then return tostring(val) end
        return string.format("0x%X", val)
    end
    return tostring(val)
end

print(string.format("PID: %d", to_num(make_syscall(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))

local sc547 = make_syscall(547)
local sc477 = make_syscall(477)
local sc548 = make_syscall(548)
local sc657 = make_syscall(657)

local region = memory.alloc(0x40)
local function region547(addr)
    for i = 0, 7 do pcall(function() memory.write_qword(region + i * 8, uint64(0)) end) end
    local ok, ret = pcall(function() return sc547(addr, uint64(region)) end)
    if not ok then return "PCALL-FAIL" end
    local raw = safe_rq(region + 0x10)
    local _, rl = get_hi_lo(raw)
    return string.format("start=%s end=%s prot=%d", sgn(safe_rq(region)), sgn(safe_rq(region + 8)), rl % 0x10000)
end

-- ============================================================
-- [A] a page and its record
-- ============================================================
print("")
print("[A] GPU page and 547 record")

local page = sc477(uint64(0), uint64(0x4000), uint64(0x33), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local ph, pl = get_hi_lo(page)
local valid = not (ph == 0xFFFFFFFF and pl == 0xFFFFFFFF) and pl ~= 0
print(string.format("  page = %s valid=%s", sgn(page), tostring(valid)))
if not valid then
    print("  mmap failed, probe stops here")
    print("=== PROBE 238a COMPLETE ===")
    return
end
safe_wd(page, 0x11223344)
print(string.format("  record: %s", region547(page)))

-- one 0x20-byte operation record: address, aux, length, prot, memtype, unknown, operation
local ops = memory.alloc(0x40)
local processed = memory.alloc(0x10)

local function build_op(addr, opcode, protection)
    safe_wq(ops, addr)
    safe_wq(ops + 8, uint64(0))
    safe_wq(ops + 16, uint64(0x4000))
    safe_wd(ops + 24, protection)
    safe_wd(ops + 25, 0)
    safe_wd(ops + 26, 0)
    safe_wd(ops + 28, opcode)
end

-- ============================================================
-- [B] 548 descriptor 0..31
-- ============================================================
print("")
print("[B] 548 { descriptor, flags, user_operations, count, user_processed }")

local accepted548 = 0
for d = 0, 31 do
    build_op(page, 2, 7)
    safe_wq(processed, uint64(0))
    local ok, ret = pcall(function()
        return sc548(uint64(d), uint64(0), uint64(ops), uint64(1), uint64(processed))
    end)
    local r = ok and sgn(ret) or "PCALL-FAIL"
    if ok and r ~= "-1" then
        accepted548 = accepted548 + 1
        print(string.format("  d=%-2d ret=%-22s processed=%s", d, r, sgn(safe_rq(processed))))
        print(string.format("       record: %s", region547(page)))
    end
end
print(string.format("  descriptors accepted: %d of 32", accepted548))

-- ============================================================
-- [C] 657 object 0..31
-- ============================================================
print("")
print("[C] 657 { commands, count, processed, flags }")

local accepted657 = 0
for obj = 0, 31 do
    build_op(page, 2, 7)
    safe_wq(processed, uint64(0))
    local ok, ret = pcall(function()
        return sc657(uint64(obj), uint64(1), uint64(processed), uint64(0))
    end)
    local r = ok and sgn(ret) or "PCALL-FAIL"
    if ok and r ~= "-1" then
        accepted657 = accepted657 + 1
        print(string.format("  obj=%-2d ret=%-22s processed=%s", obj, r, sgn(safe_rq(processed))))
        print(string.format("        record: %s", region547(page)))
    end
end
print(string.format("  objects accepted: %d of 32", accepted657))

-- ============================================================
-- [D] the mmap address as the first argument
-- ============================================================
print("")
print("[D] the page address as the first argument")

build_op(page, 2, 7)
safe_wq(processed, uint64(0))
local okD1, retD1 = pcall(function()
    return sc548(page, uint64(0), uint64(ops), uint64(1), uint64(processed))
end)
print(string.format("  548(page) ret=%s processed=%s", okD1 and sgn(retD1) or "PCALL-FAIL", sgn(safe_rq(processed))))
print(string.format("        record: %s", region547(page)))

build_op(page, 2, 7)
safe_wq(processed, uint64(0))
local okD2, retD2 = pcall(function()
    return sc657(page, uint64(1), uint64(processed), uint64(0))
end)
print(string.format("  657(page) ret=%s processed=%s", okD2 and sgn(retD2) or "PCALL-FAIL", sgn(safe_rq(processed))))
print(string.format("        record: %s", region547(page)))

print("")
print("=== PROBE 238a COMPLETE ===")

-- CRASH_CLASS: LOW
-- PROBE 237b: what mprotect actually does, read back through 547
--
-- Context: W^X on 14.10 was measured by mprotect's return value, and the
-- earlier retests record that the page stayed RW. 235a tried to use 674
-- (virtual_query_all) as the oracle and got "not-found" for every GPU mapping,
-- so the return value was all there was. 547 is the handler that reports the
-- region record for one address (contract: sys_547(address, user_region),
-- 0x18-byte record). This probe uses it as the oracle.
--
-- [A] control: 547 on a heap buffer and on a stack-ish address, to prove the
--     handler answers at all in this process.
-- [B] GPU page: 547 before, mprotect(RWX), 547 after, then a write to prove
--     the page is still mapped.
-- [C] the same page with PROT_READ|PROT_EXEC and PROT_EXEC, each followed by
--     a 547 read-back, so a refusal and a silent no-op are distinguishable.

print("=== PROBE 237b: MPROTECT READ BACK THROUGH 547 ===")
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
local sc74 = make_syscall(74)

local region = memory.alloc(0x40)

local function region547(addr)
    for i = 0, 7 do pcall(function() memory.write_qword(region + i * 8, uint64(0)) end) end
    local ok, ret = pcall(function() return sc547(uint64(addr), uint64(region)) end)
    if not ok then return "PCALL-FAIL" end
    local startq = safe_rq(region)
    local endq = safe_rq(region + 8)
    local prot = safe_rq(region + 0x10)
    local raw = safe_rq(region + 0x10)
    local _, rl = get_hi_lo(raw)
    local prot = rl % 0x10000
    return string.format("ret=%s start=%s end=%s prot=%d raw10=%s",
        sgn(ret), sgn(startq), sgn(endq), prot, sgn(raw))
end

-- ============================================================
-- [A] control addresses
-- ============================================================
print("")
print("[A] 547 control reads")

local heap = memory.alloc(0x1000)
safe_wd(heap, 0x41414141)
print(string.format("  heap  = %s", region547(uint64(heap))))



-- ============================================================
-- [B] GPU page: before, mprotect(RWX), after
-- ============================================================
print("")
print("[B] GPU page around mprotect(RWX)")

local gpu = sc477(uint64(0), uint64(0x4000), uint64(0x33), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local gh, gl = get_hi_lo(gpu)
local valid = not (gh == 0xFFFFFFFF and gl == 0xFFFFFFFF) and gl ~= 0
print(string.format("  gpu mmap = %s valid=%s", sgn(gpu), tostring(valid)))

if valid then
    safe_wd(gpu, 0x11223344)
    print(string.format("  write/read  = %s", sgn(safe_rd(gpu))))
    print(string.format("  before      : %s", region547(gpu)))
    local r7 = sc74(gpu, uint64(0x4000), uint64(7))
    print(string.format("  mprotect(7) ret=%s", sgn(r7)))
    print(string.format("  after       : %s", region547(gpu)))
    safe_wd(gpu, 0x55667788)
    print(string.format("  write/read  = %s", sgn(safe_rd(gpu))))

    -- ============================================================
    -- [C] read+exec and exec alone
    -- ============================================================
    print("")
    print("[C] PROT_READ|EXEC and PROT_EXEC")

    local r5 = sc74(gpu, uint64(0x4000), uint64(5))
    print(string.format("  mprotect(5) ret=%s", sgn(r5)))
    print(string.format("  after       : %s", region547(gpu)))

    local r4 = sc74(gpu, uint64(0x4000), uint64(4))
    print(string.format("  mprotect(4) ret=%s", sgn(r4)))
    print(string.format("  after       : %s", region547(gpu)))
else
    print("  mmap failed, B and C skipped")
end

print("")
print("=== PROBE 237b COMPLETE ===")

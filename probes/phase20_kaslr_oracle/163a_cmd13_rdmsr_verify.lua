-- CRASH_CLASS: LOW
-- PROBE 163a: Verify if sys 625 cmd 13 is rdmsr
-- Write known value to PMC via sys 565, then read via cmd 13

print("=== PROBE 163a: CMD 13 RDMSR VERIFY ===")
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
local function get_lo(val)
    if type(val) == "table" and val.l then return val.l end
    return to_num(val)
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    if h == 0 then return string.format("0x%X", l) end
    return string.format("0x%X%08X", h, l)
end

local sc563 = make_syscall(563)  -- PMU enable
local sc564 = make_syscall(564)  -- PMU disable
local sc565 = make_syscall(565)  -- PMU configure event
local sc566 = make_syscall(566)  -- PMU write counter
local sc567 = make_syscall(567)  -- PMU read counter
local sc625 = make_syscall(625)  -- MSR controller
local sc432 = make_syscall(432)  -- thr_self
local sc20  = make_syscall(20)   -- getpid

local tid_buf = memory.alloc(8)
memory.write_qword(tid_buf, uint64(0))
pcall(function() sc432(uint64(tid_buf)) end)
local our_tid = to_num(memory.read_dword(tid_buf))
local out = memory.alloc(16)

print("TID: " .. our_tid)
print("")

-- ============================================================
-- TEST 1: Read PMC event select BEFORE configuring
-- cmd 13, domain 1-3, all 6 indices should be 0
-- ============================================================
print("=== TEST 1: cmd 13 baseline (before PMU config) ===")
for dom = 1, 3 do
    local parts = {}
    for idx = 0, 5 do
        local ok, rv = pcall(function()
            return sc625(uint64(13), uint64(dom), uint64(idx), uint64(0))
        end)
        parts[#parts+1] = "i" .. idx .. "=" .. (ok and fmt(rv) or "F")
    end
    print("  dom=" .. dom .. ": " .. table.concat(parts, " "))
end
print("")

-- ============================================================
-- TEST 2: Configure PMU event 0xC0 on counter 0 via sys 565
-- Then read cmd 13 to see if value changed
-- ============================================================
print("=== TEST 2: Configure PMU, then read cmd 13 ===")
pcall(function() sc564(uint64(0)) end)
pcall(function() sc565(uint64(0), uint64(0), uint64(0xC0)) end)
pcall(function() sc563(uint64(0)) end)
print("  PMU configured: event=0xC0 on counter 0, enabled")

print("  cmd 13 after config:")
for dom = 1, 3 do
    local parts = {}
    for idx = 0, 5 do
        local ok, rv = pcall(function()
            return sc625(uint64(13), uint64(dom), uint64(idx), uint64(0))
        end)
        local val = ok and fmt(rv) or "F"
        local tag = ""
        if ok then
            local h, l = get_hi_lo(rv)
            if l ~= 0 or h ~= 0 then tag = " ***" end
        end
        parts[#parts+1] = "i" .. idx .. "=" .. val .. tag
    end
    print("    dom=" .. dom .. ": " .. table.concat(parts, " "))
end
print("")

-- ============================================================
-- TEST 3: Write counter value 0xDEAD via sys 566, read via cmd 13
-- ============================================================
print("=== TEST 3: Write counter value, read via cmd 13 ===")
pcall(function() sc566(uint64(0), uint64(0), uint64(0xDEAD)) end)
print("  Wrote 0xDEAD to counter 0")

for dom = 1, 3 do
    local parts = {}
    for idx = 0, 5 do
        local ok, rv = pcall(function()
            return sc625(uint64(13), uint64(dom), uint64(idx), uint64(0))
        end)
        local val = ok and fmt(rv) or "F"
        local tag = ""
        if ok then
            local h, l = get_hi_lo(rv)
            if l ~= 0 or h ~= 0 then tag = " ***" end
        end
        parts[#parts+1] = "i" .. idx .. "=" .. val .. tag
    end
    print("    dom=" .. dom .. ": " .. table.concat(parts, " "))
end

-- Also verify via sys 567 that the write took effect
memory.write_qword(out, uint64(0))
pcall(function() sc567(uint64(our_tid), uint64(0), uint64(out)) end)
local readback = get_lo(memory.read_qword(out))
print("  sys 567 readback: " .. readback .. " (should be >= 0xDEAD)")
print("")

-- ============================================================
-- TEST 4: Try cmd 14 as write, cmd 13 as read (paired)
-- Write 0xBEEF via cmd 14, read via cmd 13
-- ============================================================
print("=== TEST 4: cmd 14 write + cmd 13 read pair ===")
pcall(function() sc564(uint64(0)) end)  -- disable PMU first

local ok14, rv14 = pcall(function()
    return sc625(uint64(14), uint64(1), uint64(0), uint64(0xBEEF))
end)
print("  cmd 14 write 0xBEEF: " .. (ok14 and fmt(rv14) or "FAIL"))

local ok13, rv13 = pcall(function()
    return sc625(uint64(13), uint64(1), uint64(0), uint64(0))
end)
print("  cmd 13 read: " .. (ok13 and fmt(rv13) or "FAIL"))
if ok13 then
    local h, l = get_hi_lo(rv13)
    if l == 0xBEEF or h == 0xBEEF then
        print("  >>> CONFIRMED: cmd 13 IS rdmsr! <<<")
    elseif l ~= 0 or h ~= 0 then
        print("  >>> NON-ZERO returned: " .. fmt(rv13) .. " <<<")
    else
        print("  >>> Still 0 - cmd 13 might not be rdmsr <<<")
    end
end
print("")

-- ============================================================
-- TEST 5: Try writing different values per index, read back
-- ============================================================
print("=== TEST 5: Write unique values per index, read back ===")
local test_vals = {0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666}
for idx = 0, 5 do
    pcall(function()
        sc625(uint64(14), uint64(1), uint64(idx), uint64(test_vals[idx+1]))
    end)
end
print("  Wrote 0x1111-0x6666 to indices 0-5 via cmd 14")

for dom = 1, 3 do
    local parts = {}
    for idx = 0, 5 do
        local ok, rv = pcall(function()
            return sc625(uint64(13), uint64(dom), uint64(idx), uint64(0))
        end)
        parts[#parts+1] = "i" .. idx .. "=" .. (ok and fmt(rv) or "F")
    end
    print("  cmd 13 dom=" .. dom .. ": " .. table.concat(parts, " "))
end
print("")

-- ============================================================
-- TEST 6: Index overflow — try negative/large indices on cmd 13
-- If the MSR address = base + index*2, overflowing index
-- could reach LSTAR (0xC0000082)
-- ============================================================
print("=== TEST 6: cmd 13 index overflow ===")
local overflow_indices = {
    {8, "idx=8"},
    {16, "idx=16"},
    {32, "idx=32"},
    {64, "idx=64"},
    {128, "idx=128"},
    {255, "idx=255"},
    {256, "idx=256"},
    {0xFFFF, "idx=0xFFFF"},
    {0xFFFFFFF0, "idx=near-max32"},
    {0xFFFFFFFF, "idx=-1"},
    {0xFFFFFFFE, "idx=-2"},
    {0xFFFFFFFA, "idx=-6"},
}
for _, t in ipairs(overflow_indices) do
    local ok, rv = pcall(function()
        return sc625(uint64(13), uint64(1), uint64(t[1]), uint64(0))
    end)
    if ok then
        local h, l = get_hi_lo(rv)
        local tag = ""
        if h >= 0xFFFF8000 then tag = " <<< KERNEL?" end
        if (l ~= 0 or h ~= 0) and not (h == 0xFFFFFFFF and l == 0xFFFFFFFF) then
            tag = tag .. " <<< NON-ZERO/NON-NEG1"
        end
        print(string.format("  %-16s ret=%s%s", t[2], fmt(rv), tag))
    else
        print(string.format("  %-16s PCALL-FAIL", t[2]))
    end
end
print("")

-- Cleanup
pcall(function() sc564(uint64(0)) end)

print("=== PROBE 163a COMPLETE ===")

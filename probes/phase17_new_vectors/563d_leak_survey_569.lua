-- CRASH_CLASS: MODERATE
-- PROBE 563b_leak_survey_562: canary survey
--
-- Each number is called with two canary pages as its first two arguments and a length of 0x100.
-- A call that writes into either page is a candidate for a kernel-data oracle and gets followed up.
-- The number is printed before the call, so a kill names itself.

print("=== PROBE 563d: CANARY SURVEY 569-590 ===")

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
local function safe_wd(a, v)
    local ok = pcall(function() memory.write_dword(a, v) end)
    return ok
end
local function fill(addr, val)
    local base = to_num(addr)
    for off = 0, 0xF00, 4 do safe_wd(base + off, val) end
end
local function dirty(addr, val)
    local n = 0
    local base = to_num(addr)
    for off = 0, 0xF00, 4 do
        local ok, v = pcall(function() return memory.read_dword(base + off) end)
        if ok and to_num(v) ~= val then n = n + 1 end
    end
    return n
end

local P1 = memory.alloc(0x1000)
local P2 = memory.alloc(0x1000)
local TEST = {569, 570, 571, 573, 574, 575, 576, 577, 578, 579, 580, 581, 582, 583, 584, 585, 586, 587, 588, 589, 590}

for _, n in ipairs(TEST) do
    fill(P1, 0xA5A5A5A5)
    fill(P2, 0xA5A5A5A5)
    local sc = make_syscall(n)
    local u1 = uint64(string.format("0x%X%08X", 0, to_num(P1)))
    local u2 = uint64(string.format("0x%X%08X", 0, to_num(P2)))
    print(string.format("[%d] n=%d ", n, n))
    local ok, ret = pcall(function() return sc(u1, uint64(0x100), u2, uint64(0x100), uint64(0), uint64(0)) end)
    if ok then
        print(string.format("ret=%s dirty1=%d dirty2=%d", tostring(ret), dirty(P1, 0xA5A5A5A5), dirty(P2, 0xA5A5A5A5)))
    else
        print("PCALL-FAIL " .. tostring(ret))
    end
end
print("=== 563d DONE ===")

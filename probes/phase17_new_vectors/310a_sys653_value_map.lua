-- CRASH_CLASS: LOW
-- PROBE 310a: what does sys 653 return for scalar arguments?
--
-- 84a (first execution of 653 on 14.10) returned small positive numbers, not
-- errors: arg0=0 -> 0x18, arg0=0x100000 (bit 20) -> 0x19, arg0=0x400000
-- (bit 22) -> 0xEE, while arg0=1 and arg0=0x500000 returned -1. A handler that
-- the 13.60 dossier describes as an 8KB page-table attribute modifier answers
-- a one-argument call with a few dozen. This maps which argument values answer
-- and with what, before anything touches a structure.

print("=== PROBE 310a: SYS 653 VALUE MAP ===")

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
local function show(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end

local sc = make_syscall(653)

print("--- A: 0..0x20 ---")
local line = {}
for i = 0, 0x20 do
    local ok, rv = pcall(function() return sc(uint64(i)) end)
    if not ok then line[#line + 1] = string.format("%X:FAIL", i) else
        line[#line + 1] = string.format("%X:%s", i, show(rv))
    end
    if #line == 6 then print("  " .. table.concat(line, " ")) line = {} end
end
if #line > 0 then print("  " .. table.concat(line, " ")) end

print("")
print("--- B: single bits ---")
line = {}
for b = 0, 30 do
    local v = 2 ^ b
    local ok, rv = pcall(function() return sc(uint64(v)) end)
    if not ok then line[#line + 1] = string.format("b%d:FAIL", b) else
        line[#line + 1] = string.format("b%d:%s", b, show(rv))
    end
    if #line == 4 then print("  " .. table.concat(line, " ")) line = {} end
end
if #line > 0 then print("  " .. table.concat(line, " ")) end

print("")
print("--- C: larger values ---")
for _, v in ipairs({ 0x100, 0x1000, 0x10000, 0x1000000, 0x10000000, 0xFFFFFFFF,
                     0x100000000, 0x8000000000000000 }) do
    local ok, rv = pcall(function() return sc(uint64(string.format("0x%X", v))) end)
    if not ok then print(string.format("  0x%X: FAIL", v)) else
        print(string.format("  0x%X: %s", v, show(rv)))
    end
end

print("=== DONE ===")

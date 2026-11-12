-- CRASH_CLASS: MODERATE
-- PROBE 949b: sys 653 argument mapping
--
-- 98a section B showed 653 does not take an address in arg0: raw values
-- returned small codes instead of -1
--   arg0=0        -> 22
--   arg0=0x100000 -> 23
--   arg0=0x400000 -> 640
--   arg0=0x500000 -> -1
-- So arg0 behaves like a selector. This probe maps the selector space and
-- checks whether arg1 is an out buffer.

print("=== PROBE 949b: SYS 653 SELECTOR MAP ===")

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
local function call(f, ...)
    local ok, rv = pcall(f, ...)
    if not ok then return "PCALL-FAIL" end
    return to_num(rv)
end

local sc653 = make_syscall(653)
local buf = memory.alloc(0x100)

local vals = {0,1,2,3,4,8,0x10,0x20,0x40,0x80,0x100,0x1000,0x10000,
              0x100000,0x200000,0x400000,0x800000,0x1000000,0x2000000,0x4000000}

print("--- A: selector sweep (arg0 only) ---")
for _, v in ipairs(vals) do
    local r = call(sc653, uint64(v), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    print(string.format("  arg0=0x%07X ret=%s", v, tostring(r)))
end

print("")
print("--- B: with zeroed out buffer as arg1 ---")
for i = 0, 0x100 - 1, 8 do memory.write_qword(buf + i, 0) end
for _, v in ipairs({0, 0x100000, 0x400000, 0x100, 0x10}) do
    for i = 0, 0x100 - 1, 8 do memory.write_qword(buf + i, 0) end
    local r = call(sc653, uint64(v), buf, uint64(0x100), uint64(0), uint64(0), uint64(0))
    local w0 = to_num(memory.read_qword(buf))
    local w1 = to_num(memory.read_qword(buf + 8))
    print(string.format("  arg0=0x%07X ret=%s buf=%016X %016X", v, tostring(r), w0, w1))
end

print("")
print("--- C: arg1 as raw small values ---")
for _, v in ipairs({0,1,2,0x10,0x100}) do
    local r = call(sc653, uint64(0), uint64(v), uint64(0), uint64(0), uint64(0), uint64(0))
    print(string.format("  arg1=%d ret=%s", v, tostring(r)))
end

print("")
print("--- D: arg count sensitivity for arg0=0x400000 ---")
for n = 1, 5 do
    local args = {uint64(0x400000), uint64(0), uint64(0), uint64(0), uint64(0)}
    local r = call(sc653, args[1], args[2], args[3], args[4], args[5])
    print(string.format("  narg=%d ret=%s", n, tostring(r)))
end

print("")
print("=== PROBE 949b COMPLETE ===")

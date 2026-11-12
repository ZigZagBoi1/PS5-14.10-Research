-- CRASH_CLASS: MODERATE
-- PROBE 949c: sys 653 — argument-count sensitivity
--
-- 98a called 653 with exactly one argument and got 22 / 23 / 640 for
-- arg0 = 0 / 0x100000 / 0x400000; 942a passed six zeros and got -1 for all.
-- So the number of arguments changes the answer. This probe varies the count
-- deliberately and repeats calls to see whether the returns are ids or sizes.

print("=== PROBE 949c: SYS 653 NARG ===")

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
local function n1(f, a) local ok, rv = pcall(function() return f(a) end); if not ok then return "FAIL" end; return to_num(rv) end
local function n2(f, a, b) local ok, rv = pcall(function() return f(a, b) end); if not ok then return "FAIL" end; return to_num(rv) end
local function n3(f, a, b, c) local ok, rv = pcall(function() return f(a, b, c) end); if not ok then return "FAIL" end; return to_num(rv) end

local sc653 = make_syscall(653)
local buf = memory.alloc(0x100)

print("--- A: one argument, repeated twice ---")
local vals = {0,1,2,0x10,0x100,0x1000,0x10000,0x100000,0x200000,0x400000,0x800000,0x1000000}
for _, v in ipairs(vals) do
    local r1 = n1(sc653, uint64(v))
    local r2 = n1(sc653, uint64(v))
    print(string.format("  arg0=0x%07X ret=%s / %s", v, tostring(r1), tostring(r2)))
end

print("")
print("--- B: repeat arg0=0 six times (id allocator?) ---")
for i = 1, 6 do
    print(string.format("  [%d] ret=%s", i, tostring(n1(sc653, uint64(0)))))
end

print("")
print("--- C: two arguments (selector, zeroed buffer) ---")
for _, v in ipairs({0, 0x100000, 0x400000}) do
    for i = 0, 0x100 - 1, 8 do memory.write_qword(buf + i, 0) end
    local r = n2(sc653, uint64(v), buf)
    local w0 = to_num(memory.read_qword(buf))
    local w1 = to_num(memory.read_qword(buf + 8))
    print(string.format("  arg0=0x%07X ret=%s buf=%016X %016X", v, tostring(r), w0, w1))
end

print("")
print("--- D: three arguments (selector, buffer, size) ---")
for _, v in ipairs({0, 0x100000, 0x400000}) do
    for i = 0, 0x100 - 1, 8 do memory.write_qword(buf + i, 0) end
    local r = n3(sc653, uint64(v), buf, uint64(0x100))
    local w0 = to_num(memory.read_qword(buf))
    local w1 = to_num(memory.read_qword(buf + 8))
    print(string.format("  arg0=0x%07X ret=%s buf=%016X %016X", v, tostring(r), w0, w1))
end

print("")
print("=== PROBE 949c COMPLETE ===")

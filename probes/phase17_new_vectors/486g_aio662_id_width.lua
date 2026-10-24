-- CRASH_CLASS: LOW
-- PROBE 486g: does 662 read 64-bit ids, and does a zero id resolve?
--
-- 486e returned 0x80020003 for every dword id 0..63 and 65535, uniformly.
-- Either the table is empty, or the id stride is 8 bytes and our dword fill
-- made every id something else. Fill qwords this time, and compare a zero id.

print("=== PROBE 486g: 662 id width ===")
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
local function sgn(v)
    local n = to_num(v)
    if n >= 0x8000000000000000 then return n - 0x10000000000000000 end
    if n >= 0x80000000 and n < 0x100000000 then return n - 0x100000000 end
    return n
end
local function rd(a)
    local v = 0
    pcall(function() v = to_num(memory.read_dword(a)) end)
    return v
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end

local sc662 = make_syscall(662)
local ids = memory.alloc(0x1000)
local res = memory.alloc(0x1000)

local function run(n, fill, label)
    for i = 0, 0xFFF, 8 do wq(res + i, 0) end
    for i = 0, 0xFFF, 8 do wq(ids + i, 0) end
    for i = 0, n - 1 do wq(ids + i * 8, fill(i)) end
    local ok, rv = pcall(function() return sc662(uint64(ids), uint64(n), uint64(res)) end)
    local r = ok and sgn(rv) or -999
    local s = ""
    for i = 0, math.min(n, 8) - 1 do s = s .. string.format("%08X ", rd(res + i * 4)) end
    print(string.format("[%s] n=%d ret=%d statuses: %s", label, n, r, s))
end

run(8, function(i) return i end, "A qword ids 0..7")
run(4, function() return 0xFFFFFFFFFFFFFFFF end, "B all-ones ids")
run(1, function() return 0 end, "C single zero id")
run(1, function() return 0x0000000100000000 end, "D high dword id")

print("")
print("=== PROBE 486g END ===")

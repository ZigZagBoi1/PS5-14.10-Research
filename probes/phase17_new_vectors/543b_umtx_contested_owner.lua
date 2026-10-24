-- CRASH_CLASS: HIGH
-- PROBE 543b: the contested bit with an owner that does not exist
--
-- Context: 543a set UMUTEX_CONTESTED with owner 0 and the kernel locked it,
-- turning the word into 0x80018E6B (contested plus our TID). The owner field
-- is caller data, so the next question is what the kernel does when the
-- contested owner is a thread id that no thread owns.
--
-- Single case: owner 1. Reads the word back after lock and unlock.

print("=== PROBE 543b: CONTESTED WITH A FOREIGN OWNER ===")
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

wd(N(M) + 0, 0x80000001)
wd(N(M) + 4, 0)
print(string.format("[1] word=%08X", rd(N(M))))
local ret = -999
pcall(function()
    ret = N(sc454(uint64(N(M)), uint64(5), uint64(0), uint64(0), uint64(0)))
end)
print(string.format("[2] lock ret=%d word=%08X", ret, rd(N(M))))
local ret2 = -999
pcall(function()
    ret2 = N(sc454(uint64(N(M)), uint64(6), uint64(0), uint64(0), uint64(0)))
end)
print(string.format("[3] unlock ret=%d word=%08X", ret2, rd(N(M))))
print("=== DONE ===")

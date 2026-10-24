-- CRASH_CLASS: MODERATE
-- PROBE 542a: priority-inherit and priority-protect mutex flags
--
-- Context: ops 2,3,9,10,11,12,14,15,16,18,19,20,21,23,24,25 return 0 and
-- 0,1,4,5,6,7,8,13,17,22,26 return -1 with a plain word. A FreeBSD umutex is
-- {owner, flags, ceiling[2], spare}; flags 0x10 = UMUTEX_PRIO_INHERIT and
-- 0x20 = UMUTEX_PRIO_PROTECT select the umtx_pi paths that the plain mutex
-- never touches.
--
-- This probe asks whether either flag is accepted at all, single-threaded,
-- before any contention is sampled.

print("=== PROBE 542a: UMTX PI FLAGS ===")
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

local function shape(tag, flags, ceil)
    wd(N(M), 0); wd(N(M) + 4, flags); wd(N(M) + 8, ceil); wd(N(M) + 12, 0)
    local lk = N(sc454(uint64(N(M)), uint64(5), uint64(0), uint64(0), uint64(0)))
    local w0 = rd(N(M))
    local w1 = rd(N(M) + 4)
    local ul = N(sc454(uint64(N(M)), uint64(6), uint64(0), uint64(0), uint64(0)))
    local w2 = rd(N(M))
    print(string.format("%s flags=%X ceil=%d lock=%d owner=%08X f=%08X unlock=%d owner2=%08X",
        tag, flags, ceil, lk, w0, w1, ul, w2))
end

shape("[plain]", 0, 0)
shape("[PI]", 0x10, 0)
shape("[PP]", 0x20, 0)
shape("[PP-10]", 0x20, 10)
shape("[PI+ERR]", 0x50, 0)
print("=== DONE ===")

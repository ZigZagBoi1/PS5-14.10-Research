-- CRASH_CLASS: HIGH
-- PROBE 533a: block-mode aio create, 0x1F first then the boundary below it
--
-- Context: 532a ran block-mode creates 4, 8, 0x10 and then died on 0x20, on a
-- process that had already created a 0x7F non-block entry and three block
-- entries. Two explanations remain: the count 0x20 itself, or the accumulated
-- table state of four leaked entries.
--
-- This probe asks for 0x1F on a fresh process first. If that dies, the limit
-- is at or below 0x1F and history is irrelevant. If it survives, the counts
-- just below are walked so the exact boundary prints.
--
-- Creates only: the run is expected to end at the threshold, and a delete in
-- the middle would add a second unknown before the create question is answered.

print("=== PROBE 533a: AIO BLOCK BOUNDARY ===")
print("")
local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end

local sc669 = mk(669)
local BIG = memory.alloc(0x4000)
local OUT = memory.alloc(0x40)
for i = 0, 0x3FFC, 4 do wd(BIG + i, 0x41414141) end

local function one(flags, count)
    wd(N(OUT), 0)
    local ret = -999
    pcall(function()
        ret = N(sc669(uint64(flags), uint64(N(BIG)), uint64(count), uint64(1), uint64(N(OUT))))
    end)
    print(string.format("flags=%X count=%X create=%d id=%08X", flags, count, ret, rd(N(OUT)) or 0))
end

one(0x1001, 0x1F)   -- fresh process, just under the count that died
one(0x1001, 0x11)
one(0x1001, 0x14)
one(0x1001, 0x18)
one(0x1001, 0x1C)
one(0x1001, 0x1E)
one(0x1001, 0x1F)
print("=== DONE ===")

-- CRASH_CLASS: HIGH
-- PROBE 532a: where does block-mode aio create start failing
--
-- Context: 531a produced ret=0 for flags=1 at count 0x7F and 0x80, then died
-- inside flags=0x1001 count=0x7F (block mode). The loader printed a ucontext
-- dump, so the process took a fatal signal rather than the loader exiting.
-- This walks block-mode counts upward in one connection; the first count that
-- does not print is the threshold.
--
-- Each entry is created and left in place: the run is expected to die at the
-- threshold, and a delete in the middle would add a second unknown (multi-item
-- delete of a large block) before the create question is answered.

print("=== PROBE 532a: AIO BLOCK THRESHOLD ===")
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

local sc669, sc662, sc664 = mk(669), mk(662), mk(664)
local BIG = memory.alloc(0x4000)
local OUT = memory.alloc(0x40)
local IDS = memory.alloc(0x400)
local RES = memory.alloc(0x400)
for i = 0, 0x3FFC, 4 do wd(BIG + i, 0x41414141) end

local pid_val = N(native.fcall_with_rax(syscall.pipe.fn_addr, 20))
local function alive() return N(native.fcall_with_rax(syscall.pipe.fn_addr, 20)) == pid_val end

local function cycle(flags, count)
    wd(N(OUT), 0)
    local ret = -999
    pcall(function()
        ret = N(sc669(uint64(flags), uint64(N(BIG)), uint64(count), uint64(1), uint64(N(OUT))))
    end)
    local base = rd(N(OUT)) or 0
    print(string.format("flags=%X count=%X create=%d id=%08X", flags, count, ret, base))
end

cycle(1, 0x7F)          -- control: non-block, known good
cycle(0x1001, 4)        -- block, known good from 528a
cycle(0x1001, 8)
cycle(0x1001, 16)
cycle(0x1001, 32)
cycle(0x1001, 48)
cycle(0x1001, 64)
cycle(0x1001, 96)
cycle(0x1001, 0x7F)
print("=== DONE ===")

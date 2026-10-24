-- CRASH_CLASS: MODERATE
-- PROBE 530a: aio create count boundary
--
-- Context: the 13.60 create body accepts count 1..0x80 and mallocs
-- count*0x28 for the descriptor array and count*0x58 for the work items.
-- Nothing has tested count 0, the boundary values, or values whose
-- count*0x28 product wraps a 32-bit intermediate. A validator that compares
-- count with an unsigned range check (`count - 1 > 0x7f`) accepts 0 as a
-- huge value.
--
-- Prints one line per shape and a health check at the end.

print("=== PROBE 530a: AIO COUNT BOUNDS ===")
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
local DATA = memory.alloc(0x200)
local OUT = memory.alloc(0x40)
for i = 0, 0x1FC, 4 do wd(DATA + i, 0x41414141) end

local pid_val = N(native.fcall_with_rax(syscall.pipe.fn_addr, 20))
local function alive() return N(native.fcall_with_rax(syscall.pipe.fn_addr, 20)) == pid_val end

local counts = {0, 1, 0x7f, 0x80, 0x81, 0xff, 0x100, 0x7fffffff, 0xffffffff}
local flags = {1, 0x1001}
for f = 1, #flags do
    for i = 1, #counts do
        local c = counts[i]
        wd(N(OUT), 0)
        local ret = -999
        pcall(function()
            ret = N(sc669(uint64(flags[f]), uint64(N(DATA)), uint64(c), uint64(1), uint64(N(OUT))))
        end)
        print(string.format("flags=%08X count=%08X ret=%d out=%08X", flags[f], c, ret, rd(N(OUT)) or 0))
        if not alive() then print("!! process gone"); return end
    end
end

-- health: one normal request must still create, complete and delete
wd(N(OUT), 0)
local r = N(sc669(uint64(1), uint64(N(DATA)), uint64(1), uint64(1), uint64(N(OUT))))
local id = rd(N(OUT)) or 0
local ids = memory.alloc(0x10)
wd(N(ids), id)
local res = memory.alloc(0x20)
wd(N(res), 0)
local pr = N(sc664(uint64(N(ids)), uint64(1), uint64(N(res))))
local st = rd(N(res)) or 0
wd(N(res), 0)
local dr = N(sc662(uint64(N(ids)), uint64(1), uint64(N(res))))
print(string.format("[H] health create=%d id=%08X poll=%d st=%08X del=%d dst=%08X",
    r, id, pr, st, dr, rd(N(res)) or 0))
print("=== DONE ===")

-- CRASH_CLASS: LOW
-- PROBE 534a: block-mode create returns one id per item
--
-- Context: the 13.60 create tail copies count*4 bytes to the fifth argument
-- when flags & 0x1000 is set. Earlier probes sized that page for one dword, so
-- counts above 16 overwrote their own heap and the process died. This probe
-- allocates count*4 (plus slack) and reads the ids back.
--
-- Also repeats the short-descriptor-page case LAST: the kernel copyin wants
-- count*0x28 bytes from the descriptor pointer, and nothing has measured what
-- happens when that pointer's page ends early.

print("=== PROBE 534a: AIO BLOCK IDS ===")
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

local sc669, sc664, sc662 = mk(669), mk(664), mk(662)
local BIG = memory.alloc(0x4000)
local SHORT = memory.alloc(0x200)
local OUT = memory.alloc(0x400)
local RES = memory.alloc(0x400)
for i = 0, 0x3FFC, 4 do wd(BIG + i, 0x41414141) end
for i = 0, 0x1FC, 4 do wd(SHORT + i, 0x42424242) end

local pid_val = N(native.fcall_with_rax(syscall.pipe.fn_addr, 20))
local function alive() return N(native.fcall_with_rax(syscall.pipe.fn_addr, 20)) == pid_val end

local function block(count, buf)
    for i = 0, 0x3FC, 4 do wd(N(OUT) + i, 0) end
    local ret = -999
    pcall(function()
        ret = N(sc669(uint64(0x1001), uint64(N(buf)), uint64(count), uint64(1), uint64(N(OUT))))
    end)
    local b0 = rd(N(OUT)) or 0
    local b1 = rd(N(OUT) + 4) or 0
    local bl = rd(N(OUT) + (count - 1) * 4) or 0
    local step = rd(N(OUT) + 8) or 0
    print(string.format("count=%X create=%d ids=%08X %08X %08X last=%08X",
        count, ret, b0, b1, step, bl))
    if ret == 0 and b0 ~= 0 then
        for i = 0, 0x3F, 4 do wd(N(RES) + i, 0) end
        local pr = N(sc664(uint64(N(OUT)), uint64(count), uint64(N(RES))))
        local st0 = rd(N(RES)) or 0
        local stl = rd(N(RES) + (count - 1) * 4) or 0
        for i = 0, 0x3F, 4 do wd(N(RES) + i, 0) end
        local dr = N(sc662(uint64(N(OUT)), uint64(count), uint64(N(RES))))
        print(string.format("  poll=%d %08X..%08X  delete=%d %08X..%08X",
            pr, st0, stl, dr, rd(N(RES)) or 0, rd(N(RES) + (count - 1) * 4) or 0))
    end
end

block(0x10, BIG)
block(0x20, BIG)
block(0x40, BIG)
block(0x80, BIG)
block(0x7F, BIG)
print("[S] short descriptor page, non-block")
wd(N(OUT), 0)
local r = -999
pcall(function()
    r = N(sc669(uint64(1), uint64(N(SHORT)), uint64(0x7F), uint64(1), uint64(N(OUT))))
end)
print("short non-block ret=" .. tostring(r) .. " out=" .. string.format("%08X", rd(N(OUT)) or 0))
print("=== DONE ===")

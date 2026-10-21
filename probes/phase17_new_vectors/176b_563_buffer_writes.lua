-- CRASH_CLASS: LOW
-- PROBE 176b: what do 563-566 do with a real buffer?
--
-- 563, 564, 565 and 566 all return 0 to six zero uint64 arguments. A handler
-- that answers success to nothing at all is either a no-op or one that ignores
-- its arguments and writes somewhere - and only the second kind is interesting,
-- because "writes a structure the caller never asked for" is how data comes out
-- of a kernel.
--
-- This probe calls each of them with a canary-filled 0x400 page in RDI and the
-- page size in RSI, then reports every dword that changed and whether the dither
-- pattern survived. It also tries the same buffer in RSI instead of RDI, in case
-- the argument order is the other way round, and reports the return value for
-- each layout.
--
-- A changed dword or a preserved-canary-with-new-data is a keystone: it means
-- the handler may be usable as a read primitive. No change means they are
-- no-ops or gated, and the presence map is all they contribute.

print("=== PROBE 176b: 563-566 BUFFER WRITES ===")

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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return -1
end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end

local sc20 = make_syscall(20)
local sc477 = make_syscall(477)
print("[0] canary pid=" .. tostring(to_num(sc20())))

local buf = sc477(uint64(0), uint64(0x4000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
print("[0] buf=" .. string.format("0x%X", to_num(buf)))

local MARK = 0xA5A5A5A5

local function fill()
    for off = 0, 0x3FC, 4 do wd(buf + off, MARK) end
end

local function scan()
    local changed = 0
    local first_off, first_val = -1, 0
    for off = 0, 0x3FC, 4 do
        local v = rd(buf + off)
        if v ~= MARK then
            changed = changed + 1
            if first_off < 0 then first_off, first_val = off, v end
        end
    end
    return changed, first_off, first_val
end

local function call(num, layout)
    local sc = make_syscall(num)
    fill()
    local ok, rv
    if layout == "buf_rdi" then
        ok, rv = pcall(function() return sc(uint64(buf), uint64(0x400), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    elseif layout == "buf_rsi" then
        ok, rv = pcall(function() return sc(uint64(0), uint64(buf), uint64(0x400), uint64(0), uint64(0), uint64(0)) end)
    else
        ok, rv = pcall(function() return sc(uint64(buf), uint64(0x400), uint64(0x400), uint64(0), uint64(0), uint64(0)) end)
    end
    local hi, lo = 0, 0
    if ok then hi, lo = get_hi_lo(rv) end
    local changed, off, val = scan()
    print(string.format("  sys %d %-8s ok=%s ret=0x%08X%08X changed=%d first=%d:0x%08X",
        num, layout, tostring(ok), hi, lo, changed, off, val))
end

for _, num in ipairs({563, 564, 565, 566, 567}) do
    call(num, "buf_rdi")
    call(num, "buf_rsi")
    print("  canary pid=" .. tostring(to_num(sc20())))
end

print("=== PROBE 176b DONE ===")

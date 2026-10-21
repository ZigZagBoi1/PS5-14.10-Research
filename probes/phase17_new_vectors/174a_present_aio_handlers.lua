-- CRASH_CLASS: LOW
-- PROBE 174a: the six present handlers in 661-670 with real pointers
--
-- The isolation sweep called 662, 663, 664, 666, 667 and 669 with six zero
-- uint64 values and every one returned -1. Probe 173a showed that a kill means
-- the slot is absent, so those six returns prove the handlers exist and are
-- reachable - and they have never been given anything except zeros.
--
-- This probe gives each of them a zeroed 0x400 page in RDI and 0x400 in RSI,
-- then reports the return value next to the zero-argument result. A return that
-- changes from -1 (0, or a new error, or a written buffer) means the handler
-- got past argument validation, which is the first step into the code the
-- "AIO hard wall" note wrote off.
--
-- Each number is wrapped in pcall and separated by a canary, so a kill still
-- leaves the numbers that came before it.

print("=== PROBE 174a: PRESENT HANDLERS IN 661-670 ===")

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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return -1
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end

local sc20 = make_syscall(20)
print("[0] canary pid=" .. tostring(to_num(sc20())))

local buf = memory.alloc(0x400)

local function clear()
    for i = 0, 0x3FC, 4 do safe_wd(buf + i, 0) end
end

local function call(num, with_ptr)
    local sc = make_syscall(num)
    clear()
    local ok, rv
    if with_ptr then
        ok, rv = pcall(function()
            return sc(uint64(buf), uint64(0x400), uint64(0), uint64(0), uint64(0), uint64(0))
        end)
    else
        ok, rv = pcall(function()
            return sc(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
        end)
    end
    local hi, lo = 0, 0
    if ok then hi, lo = get_hi_lo(rv) end
    return ok, hi, lo
end

local numbers = {662, 663, 664, 666, 667, 669}

for _, num in ipairs(numbers) do
    print("[*] sys " .. tostring(num))
    local ok0, h0, l0 = call(num, false)
    print(string.format("    zeros  ok=%s ret=0x%08X%08X", tostring(ok0), h0, l0))
    local ok1, h1, l1 = call(num, true)
    print(string.format("    ptrs   ok=%s ret=0x%08X%08X buf[0]=0x%08X buf[4]=0x%08X",
        tostring(ok1), h1, l1, safe_rd(buf), safe_rd(buf + 4)))
    print("    canary pid=" .. tostring(to_num(sc20())))
end

print("=== PROBE 174a DONE ===")

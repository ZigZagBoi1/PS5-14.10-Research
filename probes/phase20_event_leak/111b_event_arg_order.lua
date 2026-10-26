-- CRASH_CLASS: MODERATE
-- PROBE 111b: event-family argument order — which of 661/662/664/665/666/668
--             accepts a call, and with which register order
--
-- Context: probe 111a called 662 as (input, count=0x81, output) and got -1 with
-- every buffer mapped. In the 13.60 helper a priv_check runs *before* the count
-- guard (0x3af9c6 cmp [rsi+0x4a0],1 / jne -> call 0x3b3410), so -1 can mean a
-- denied credential rather than a rejected argument. This probe separates the
-- two by trying each register order and by calling the whole family with the
-- same buffers, so a gate shows up as a shared -1 while an order error shows up
-- as one order returning 0 and the others -1.

print("=== PROBE 111b: EVENT FAMILY ARGUMENT ORDER ===")
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function hexval(val)
    if val == nil then return "nil" end
    if type(val) == "table" and val.h then
        return string.format("0x%X_%08X", val.h, val.l)
    end
    return string.format("0x%X", to_num(val))
end

local sc20 = make_syscall(20)
local pid = to_num(select(2, pcall(function() return sc20() end)))
print("PID: " .. pid)

local COUNT = 0x81
local IN_LEN = COUNT * 4
local OUT_LEN = 0x1000

local inp = memory.alloc(IN_LEN + 0x100)
local out = memory.alloc(OUT_LEN)
for i = 0, IN_LEN - 1, 4 do safe_wd(inp + i, 0) end
for i = 0, OUT_LEN - 1, 4 do safe_wd(out + i, 0) end

local function arg(tok)
    if tok == "in" then return uint64(inp) end
    if tok == "out" then return uint64(out) end
    if tok == "count" then return uint64(COUNT) end
    return uint64(0)
end

local function call(num, t1, t2, t3)
    local sc = make_syscall(num)
    local ok, ret = pcall(function()
        return sc(arg(t1), arg(t2), arg(t3), uint64(0), uint64(0), uint64(0))
    end)
    if not ok then return "PCALL-FAIL" end
    return hexval(ret)
end

local orders = {
    { "in", "count", "out" },
    { "count", "in", "out" },
    { "out", "in", "count" },
    { "in", "out", "count" },
    { "count", "out", "in" },
}

local nums = { 662, 664, 665, 666, 668 }

print("[A] ret per (syscall, register order) - printed incrementally,")
print("    because 661 is known to kill the process and a loss ends the run")
for _, num in ipairs(nums) do
    for _, o in ipairs(orders) do
        print(string.format("  %d %-16s -> %s", num,
            "(" .. o[1] .. "," .. o[2] .. "," .. o[3] .. ")",
            call(num, o[1], o[2], o[3])))
    end
end

print("")
print("[B] zero arguments, for comparison")
for _, num in ipairs(nums) do
    local sc = make_syscall(num)
    local ok, ret = pcall(function()
        return sc(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    print(string.format("  %d: %s", num, ok and hexval(ret) or "PCALL-FAIL"))
end

print("")
print("[C] buffer state after the matrix (first 0x40 of out)")
for off = 0, 0x3F, 16 do
    local line = string.format("  out+%04X:", off)
    for d = 0, 12, 4 do
        line = line .. string.format(" %08X", safe_rd(out + off + d) or 0)
    end
    print(line)
end

print("")
print("=== END PROBE 111b ===")

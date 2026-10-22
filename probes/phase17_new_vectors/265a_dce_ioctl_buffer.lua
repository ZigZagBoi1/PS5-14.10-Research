-- CRASH_CLASS: HIGH
-- PROBE 265a: dce commands with a real buffer
--
-- 264a handed /dev/dce commands 0x0-0x1F with a null buffer and every one came
-- back -1, which cannot separate "not a command" from "needs a buffer". This
-- sweeps the same codes plus 0x20-0xFF with a zeroed 0x1000-byte buffer and
-- reports both the return value and whether the driver wrote anything.
--
-- A command that returns 0 and leaves the buffer alone, or returns a positive
-- number, is a live command; anything else stays a refusal.

print("=== PROBE 265a: dce with a buffer ===")
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
local function raw(v)
    if v == nil then return "nil" end
    if type(v) == "table" and v.h then return string.format("0x%08X_%08X", v.h, v.l) end
    return "0x" .. string.format("%X", to_num(v))
end
local function n(v)
    local t = to_num(v)
    if t > 0x7FFFFFFFFFFFFFFF then t = t - 18446744073709551616 end
    return t
end
local function call(num, a, b, c, d)
    local sc = make_syscall(num)
    local ok, rv = pcall(function() return sc(a or uint64(0), b or uint64(0), c or uint64(0), d or uint64(0)) end)
    if not ok then return nil end
    return rv
end
local function path(p)
    local b = memory.alloc(0x100)
    pcall(function() memory.write_qword(b, 0) end)
    for i = 1, #p do
        local ch = string.byte(p, i)
        pcall(function() memory.write_byte(b + i - 1, ch) end)
    end
    return b
end
local function pid()
    local ok, v = pcall(function() return make_syscall(20)() end)
    if ok then return to_num(v) end
    return 0
end
local function zero(buf, len)
    pcall(function() for o = 0, len - 8, 8 do memory.write_qword(buf + o, 0) end end)
end
local function sum(buf, len)
    local s = 0
    for o = 0, len - 8, 8 do
        local ok, v = pcall(function() return memory.read_qword(buf + o) end)
        if ok and v ~= nil and not (v.h == 0 and v.l == 0) then s = s + 1 end
    end
    return s
end

print("[0] pid=" .. tostring(pid()))
local fd = n(call(5, uint64(path("/dev/dce")), uint64(2), uint64(0), uint64(0)))
print("    open(/dev/dce, O_RDWR) -> " .. tostring(fd))
if fd < 0 then
    print("=== PROBE 265a STOPPED: no descriptor ===")
    return
end

local BUF = memory.alloc(0x1000)
local live = {}
for cmd = 0, 0xFF do
    zero(BUF, 0x1000)
    local rv = call(54, uint64(fd), uint64(cmd), uint64(BUF), uint64(0x1000))
    local r = n(rv)
    if r ~= -1 then
        live[#live + 1] = string.format("0x%02X -> %s (wrote %d)", cmd, raw(rv), sum(BUF, 0x1000))
        print(string.format("[LIVE] cmd=0x%02X -> %s wrote=%d pid=%s", cmd, raw(rv), sum(BUF, 0x1000), tostring(pid())))
    end
    if cmd % 0x40 == 0x3F then print(string.format("    ... through 0x%02X, %d live, pid=%s", cmd, #live, tostring(pid()))) end
end
print("    live commands: " .. (#live == 0 and "none" or table.concat(live, "; ")))
call(6, uint64(fd), uint64(0), uint64(0), uint64(0))
print("")
print("    pid -> " .. tostring(pid()))
print("")
print("=== PROBE 265a COMPLETE ===")

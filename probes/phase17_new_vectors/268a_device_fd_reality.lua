-- CRASH_CLASS: LOW
-- PROBE 268a: are the device descriptors real, and which ioctls reach them
--
-- 267a settled that 54 is ioctl: FIOCLEX and FIONCLEX return 0 on a socket,
-- while FIONBIO returns -1. So the syscall works and /dev/dce refuses every
-- command it was offered for a reason of its own.
--
-- This separates the three possibilities on a device descriptor:
--   a real descriptor whose driver rejects every command  -> reads work, FIOCLEX 0
--   a descriptor the fdesc layer refuses for device nodes   -> FIOCLEX -1
--   a descriptor that is not backed by a driver at all      -> read -1
--
--   A  read 16 bytes from zero, null, random, urandom and dce
--   B  FIOCLEX, FIONCLEX, FIONBIO and FIONREAD on the same five
--   C  the size of a read the driver actually performs

print("=== PROBE 268a: device descriptors ===")
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
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok and v ~= nil then return string.format("0x%08X_%08X", v.h, v.l) end
    return "?"
end

print("[0] pid=" .. tostring(pid()))

local nodes = { "zero", "null", "random", "urandom", "dce" }
local B = memory.alloc(0x40)
print("")
print("[A] read 16 bytes")
for i = 1, #nodes do
    local fd = n(call(5, uint64(path("/dev/" .. nodes[i])), uint64(0), uint64(0), uint64(0)))
    if fd >= 0 then
        pcall(function() for o = 0, 0x38, 8 do memory.write_qword(B + o, 0) end end)
        local rv = call(3, uint64(fd), uint64(B), uint64(16), uint64(0))
        print(string.format("    %-8s fd=%-3d read(16) -> %-3s  [0]=%s", nodes[i], fd, tostring(n(rv)), rq(B)))
        print(string.format("             FIOCLEX -> %-3s  FIONCLEX -> %-3s  FIONBIO -> %-3s  FIONREAD -> %s",
            tostring(n(call(54, uint64(fd), uint64(0x20006601), uint64(0), uint64(0)))),
            tostring(n(call(54, uint64(fd), uint64(0x20006602), uint64(0), uint64(0)))),
            tostring(n(call(54, uint64(fd), uint64(0x8004667E), uint64(B), uint64(0)))),
            raw(call(54, uint64(fd), uint64(0x4004667F), uint64(B), uint64(0)))))
        call(6, uint64(fd), uint64(0), uint64(0), uint64(0))
    else
        print(string.format("    %-8s open -> %s", nodes[i], raw(fd)))
    end
end

print("")
print("    pid -> " .. tostring(pid()))
print("")
print("=== PROBE 268a COMPLETE ===")

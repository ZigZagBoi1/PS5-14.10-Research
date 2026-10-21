-- CRASH_CLASS: HIGH
-- PROBE 264a: first ioctl sweep on the nodes that are not the GPU core
--
-- 261a showed 34 device nodes open and ioctl(0) refused everywhere. A refusal
-- for command 0 only says 0 is not a command. This sweeps the low command space
-- with a null buffer on four nodes that are not the graphics core - dce, ajm,
-- rng and gic - and prints every code that does not answer -1, which is the
-- first step in turning an open descriptor into a driver conversation.
--
-- A null buffer is deliberate: drivers that only validate the command reach
-- their switch, and drivers that need a buffer return EFAULT (-1) rather than
-- touching memory this probe cannot describe.
--
-- gc, camera, usb, bt and hid are left out on purpose; a wrong command to those
-- can wedge the console rather than the process.

print("=== PROBE 264a: ioctl command sweep ===")
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

print("[0] pid=" .. tostring(pid()))

local nodes = { "dce", "ajm", "rng", "gic" }
print("")
for i = 1, #nodes do
    local fd = n(call(5, uint64(path("/dev/" .. nodes[i])), uint64(2), uint64(0), uint64(0)))
    print("[" .. string.upper(nodes[i]) .. "] fd=" .. tostring(fd) .. " pid=" .. tostring(pid()))
    if fd >= 0 then
        local hits = {}
        for cmd = 0, 0x1F do
            local rv = call(54, uint64(fd), uint64(cmd), uint64(0), uint64(0))
            local r = n(rv)
            if r ~= -1 then hits[#hits + 1] = string.format("0x%X->%s", cmd, raw(rv)) end
        end
        if #hits == 0 then
            print("    commands 0x0-0x1F: every one -1")
        else
            print("    commands that answered: " .. table.concat(hits, "  "))
        end
        call(6, uint64(fd), uint64(0), uint64(0), uint64(0))
    end
end

print("")
print("    pid -> " .. tostring(pid()))
print("")
print("=== PROBE 264a COMPLETE ===")

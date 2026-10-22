-- CRASH_CLASS: LOW
-- PROBE 260a: how open reports the nodes that came back as 0
--
-- 259a read the whole /dev directory (75 nodes) and every one of them "opened",
-- but about half returned 0 rather than a descriptor number. Either those opens
-- really do return 0, or the value is a refusal this probe is misreading. The
-- difference decides whether the device survey can use ioctl at all, so it is
-- settled here with raw values and a second call on the same node.
--
--   A  open on a path that cannot exist, and on a name from the listing twice
--   B  fcntl(F_GETFD) on the returned numbers - a real descriptor answers
--   C  ioctl(54) with TIOCGETA on a tty and with a zero code on a null device

print("=== PROBE 260a: read the open returns ===")
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
local function call(num, a, b, c, d)
    local sc = make_syscall(num)
    local ok, rv = pcall(function() return sc(a or uint64(0), b or uint64(0), c or uint64(0), d or uint64(0)) end)
    if not ok then return nil end
    return rv
end
local function n(v)
    local t = to_num(v)
    if t > 0x7FFFFFFFFFFFFFFF then t = t - 18446744073709551616 end
    return t
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
    return nil
end
print("[0] pid=" .. tostring(pid()))

local function try_open(p)
    local rv = call(5, uint64(path(p)), uint64(0), uint64(0), uint64(0))
    return rv, n(rv)
end

print("")
print("[A] open twice on the same nodes")
local probes = { "/dev/does_not_exist_xyz", "/dev/dbggc", "/dev/gc", "/dev/deci_stdout", "/dev/null", "/dev/uvd_enc" }
for i = 1, #probes do
    local r1, n1 = try_open(probes[i])
    local r2, n2 = try_open(probes[i])
    print(string.format("    %-26s #1 %-22s #2 %-22s", probes[i], raw(r1), raw(r2)))
end

print("")
print("[B] fcntl F_GETFD on interesting numbers")
local nums = { 0, 26, 47, 50, 55 }
for i = 1, #nums do
    local rv = call(92, uint64(nums[i]), uint64(1), uint64(0), uint64(0))
    print(string.format("    fcntl(%d, F_GETFD) -> %s", nums[i], raw(rv)))
end

print("")
print("[C] ioctl on a tty and on null")
local tf, tn = try_open("/dev/deci_stdout")
if tn ~= nil and tn >= 0 then
    local rv = call(54, uint64(tn), uint64(0x40487413), uint64(0), uint64(0))
    print(string.format("    ioctl(deci_stdout %d, TIOCGETA, NULL) -> %s", tn, raw(rv)))
end
local nf, nn = try_open("/dev/null")
if nn ~= nil and nn >= 0 then
    print(string.format("    ioctl(null %d, 0) -> %s", nn, raw(call(54, uint64(nn), uint64(0), uint64(0), uint64(0)))))
    print(string.format("    close(null %d) -> %s", nn, raw(call(6, uint64(nn), uint64(0), uint64(0), uint64(0)))))
end

print("")
print("    pid -> " .. tostring(pid()))
print("")
print("=== PROBE 260a COMPLETE ===")

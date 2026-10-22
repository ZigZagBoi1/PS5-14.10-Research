-- CRASH_CLASS: LOW
-- PROBE 267a: does ioctl work at all from this process
--
-- 265a handed /dev/dce 256 commands with a real buffer and got -1 for every
-- one, which is only interesting if the ioctl syscall works elsewhere. FIONBIO
-- on a socket is the control: it is implemented for every socket, it takes a
-- pointer to an int, and it must return 0. If that returns -1 too, then 54 is
-- not the ioctl this process can use and every device result so far is a
-- statement about the syscall rather than about the drivers.
--
--   A  socket(AF_INET, SOCK_STREAM), FIONBIO on and off
--   B  FIOCLEX and FIONCLEX on the same descriptor
--   C  dce with a pointer to a struct whose first dword is the command

print("=== PROBE 267a: is ioctl live ===")
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
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end

print("[0] pid=" .. tostring(pid()))

print("")
print("[A] FIONBIO on a fresh socket")
local sfd = n(call(97, uint64(2), uint64(1), uint64(0), uint64(0)))
print("    socket(AF_INET, SOCK_STREAM) -> " .. tostring(sfd))
local one = memory.alloc(0x10)
wd(one, 1)
print("    ioctl(fd, FIONBIO, &1) -> " .. raw(call(54, uint64(sfd), uint64(0x8004667E), uint64(one), uint64(0))))
wd(one, 0)
print("    ioctl(fd, FIONBIO, &0) -> " .. raw(call(54, uint64(sfd), uint64(0x8004667E), uint64(one), uint64(0))))

print("")
print("[B] FIOCLEX / FIONCLEX")
print("    ioctl(fd, FIOCLEX)   -> " .. raw(call(54, uint64(sfd), uint64(0x20006601), uint64(0), uint64(0))))
print("    ioctl(fd, FIONCLEX)  -> " .. raw(call(54, uint64(sfd), uint64(0x20006602), uint64(0), uint64(0))))

print("")
print("[C] dce with a request struct")
local dfd = n(call(5, uint64(path("/dev/dce")), uint64(2), uint64(0), uint64(0)))
print("    open(/dev/dce) -> " .. tostring(dfd))
if dfd >= 0 then
    local req = memory.alloc(0x40)
    for cmd = 0, 3 do
        pcall(function() for o = 0, 0x38, 8 do memory.write_qword(req + o, 0) end end)
        wd(req, cmd)
        local rv = call(54, uint64(dfd), uint64(req), uint64(0x40), uint64(0))
        print(string.format("    ioctl(fd, req{cmd=%d}, 0x40) -> %s", cmd, raw(rv)))
    end
    call(6, uint64(dfd), uint64(0), uint64(0), uint64(0))
end

call(6, uint64(sfd), uint64(0), uint64(0), uint64(0))
print("")
print("    pid -> " .. tostring(pid()))
print("")
print("=== PROBE 267a COMPLETE ===")

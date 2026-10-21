-- CRASH_CLASS: MODERATE
-- PROBE 261a: which device nodes open, and does ioctl reach the driver
--
-- 259a listed 75 nodes in /dev and 260a showed the listing's "fd 0" rows were
-- not descriptors: /dev/dbggc and /dev/deci_stdout refuse to open. Both probes
-- opened dozens of nodes without closing them, so this one opens, probes and
-- closes one node at a time and records the raw return of each call.
--
-- The ioctl control is TIOCGETA on a tty with a real termios buffer, because a
-- working ioctl that copies 0x48 bytes out proves the path reaches a driver.
-- Every other node gets ioctl(fd, 0), which is refused by any driver that does
-- not use 0 as a command.
--
--   A  listing walk again, with close after each open
--   B  per node: open, ioctl(0), close
--   C  TIOCGETA on the first tty that opens

print("=== PROBE 261a: device open and ioctl reach ===")
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
local function rd8(addr)
    local ok, v = pcall(function() return memory.read_byte(addr) end)
    if ok and v ~= nil then return to_num(v) end
    return nil
end
local function rd16(addr)
    local ok, v = pcall(function() return memory.read_word(addr) end)
    if ok and v ~= nil then return to_num(v) end
    return nil
end
local function str(addr, len)
    local out = {}
    for i = 0, len - 1 do
        local b = rd8(addr + i)
        if b == nil or b == 0 then break end
        out[#out + 1] = (b >= 32 and b < 127) and string.char(b) or "?"
    end
    return table.concat(out)
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

local names = {}
local dfd = call(5, uint64(path("/dev")), uint64(0), uint64(0), uint64(0))
print("")
print("[A] listing, close after each read")
print("    open(/dev) -> " .. raw(dfd))
local dfdn = n(dfd)
if dfdn >= 0 then
    local BUF = memory.alloc(0x4000)
    local base = memory.alloc(8)
    for round = 1, 8 do
        pcall(function() memory.write_qword(base, 0) end)
        local rv = call(196, uint64(dfdn), uint64(BUF), uint64(0x4000), uint64(base))
        local got = n(rv)
        if got <= 0 then break end
        local off = 0
        while off + 8 <= got do
            local namlen = rd8(BUF + off + 7)
            local reclen = rd16(BUF + off + 4)
            if namlen == nil or reclen == nil or reclen < 8 then break end
            local nm = str(BUF + off + 8, namlen)
            if nm ~= "" and nm ~= "." and nm ~= ".." then names[#names + 1] = nm end
            off = off + reclen
        end
    end
    call(6, uint64(dfdn), uint64(0), uint64(0), uint64(0))
end
print("    nodes: " .. tostring(#names))

print("")
print("[B] open, ioctl(0), close for each node")
local opened, ioctl_ok = 0, 0
local ttys = {}
for i = 1, #names do
    local rv = call(5, uint64(path("/dev/" .. names[i])), uint64(0), uint64(0), uint64(0))
    local fd = n(rv)
    if fd >= 0 then
        opened = opened + 1
        local irv = call(54, uint64(fd), uint64(0), uint64(0), uint64(0))
        local ir = n(irv)
        if ir ~= -1 then ioctl_ok = ioctl_ok + 1 end
        if names[i]:find("tty") or names[i]:find("stdin") then ttys[#ttys + 1] = { names[i], fd } end
        print(string.format("    %-24s fd=%-4d ioctl(0)=%s", names[i], fd, raw(irv)))
        call(6, uint64(fd), uint64(0), uint64(0), uint64(0))
    end
end
print(string.format("    %d of %d nodes opened, %d answered ioctl(0)", opened, #names, ioctl_ok))

print("")
print("[C] TIOCGETA on the first tty")
if #ttys > 0 then
    local nm, fd = ttys[1][1], ttys[1][2]
    local buf = memory.alloc(0x100)
    pcall(function() for o = 0, 0xFC, 4 do memory.write_dword(buf + o, 0) end end)
    local rv = call(54, uint64(fd), uint64(0x40487413), uint64(buf), uint64(0))
    print(string.format("    ioctl(%s, TIOCGETA) -> %s  termios[0..7]=%s %s", nm, raw(rv),
        string.format("%08X", to_num(pcall(function() return memory.read_dword(buf) end) and 0 or 0)),
        string.format("%08X", to_num(pcall(function() return memory.read_dword(buf + 4) end) and 0 or 0))))
    call(6, uint64(fd), uint64(0), uint64(0), uint64(0))
else
    print("    no tty node opened")
end

print("")
print("    pid -> " .. tostring(pid()))
print("")
print("=== PROBE 261a COMPLETE ===")

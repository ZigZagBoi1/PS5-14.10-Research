-- CRASH_CLASS: MODERATE
-- PROBE 365a: read what GnmCompositorRestricted sends before it goes away
--
-- 361b left 16 bytes readable on this socket after the daemon closed on a second
-- 8 KiB send, and the daemon then stopped listening for the rest of that boot.
-- This is one connection, one send, and then as much reading as the socket will
-- give: a greeting if there is one, the reply, and the close. The liveness check
-- afterwards says whether this is the call that takes the compositor down.

print("=== PROBE 365a: COMPOSITOR REPLY ===")
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
local function sgn(v)
    local l = to_num(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end

local AF_UNIX, SOCK_STREAM, MSG_DONTWAIT = 1, 1, 0x80
local sc_socket = make_syscall(97)
local sc_connect = make_syscall(98)
local sc_sendto = make_syscall(133)
local sc_recvfrom = make_syscall(29)
local sc_close = make_syscall(6)

local sa = memory.alloc(0x100)
for i = 0, 0xFC, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa + 0, uint64(1)) end)
pcall(function() make_syscall(416)(uint64(13), uint64(sa), uint64(0)) end)

local PATH = "/system_tmp/GnmCompositorRestricted"
local sockaddr = memory.alloc(0x80)
local chunk = memory.alloc(0x4000)
local rbuf = memory.alloc(0x1000)
for i = 0, 0x3FF8, 8 do pcall(function() memory.write_qword(chunk + i, uint64(0x4141414141414141)) end) end

local function connect_to()
    local fd = sgn(sc_socket(uint64(AF_UNIX), uint64(SOCK_STREAM), uint64(0)))
    if fd < 3 then return -1 end
    for i = 0, 0x10, 8 do pcall(function() memory.write_qword(sockaddr + i, uint64(0)) end) end
    pcall(function() memory.write_byte(sockaddr, #PATH + 2) end)
    pcall(function() memory.write_byte(sockaddr + 1, AF_UNIX) end)
    for i = 1, #PATH do pcall(function() memory.write_byte(sockaddr + 1 + i, PATH:byte(i)) end) end
    local r = sgn(sc_connect(uint64(fd), uint64(sockaddr), uint64(#PATH + 2)))
    if r ~= 0 then pcall(function() sc_close(uint64(fd)) end) return -1 end
    return fd
end

local function wait(seconds)
    local t0 = os.clock()
    while os.clock() - t0 < seconds do end
end

local function read_all(fd, tag)
    for round = 1, 8 do
        local n = sgn(sc_recvfrom(uint64(fd), uint64(rbuf), uint64(0xC00), uint64(MSG_DONTWAIT), uint64(0), uint64(0)))
        if n <= 0 then print(string.format("  %s: recv = %d", tag, n)) return end
        local hex, ascii = {}, {}
        for i = 0, n - 1 do
            local b = to_num(memory.read_byte(rbuf + i))
            if i % 4 == 0 then hex[#hex + 1] = string.format(" %08X", to_num(memory.read_dword(rbuf + i - i % 4))) end
            ascii[#ascii + 1] = (b >= 32 and b < 127) and string.char(b) or "."
        end
        print(string.format("  %s: n=%d%s | %s", tag, n, table.concat(hex), table.concat(ascii)))
    end
end

local fd = connect_to()
print(string.format("connect = %d", fd))
if fd < 3 then print("  nothing listening") else
    read_all(fd, "before send")
    local sent = sgn(sc_sendto(uint64(fd), uint64(chunk), uint64(0x2000), uint64(MSG_DONTWAIT), uint64(0), uint64(0)))
    print(string.format("  send(0x2000) = %d", sent))
    wait(0.2)
    read_all(fd, "after send")
    wait(0.5)
    read_all(fd, "after wait")
    pcall(function() sc_close(uint64(fd)) end)
end

wait(1.0)
local fd2 = connect_to()
print(string.format("reconnect = %d", fd2))
if fd2 >= 3 then
    print("  daemon still listening")
    pcall(function() sc_close(uint64(fd2)) end)
else
    print("  daemon is GONE")
end

print("")
print("=== 365a DONE ===")

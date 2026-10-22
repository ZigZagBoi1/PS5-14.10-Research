-- CRASH_CLASS: LOW
-- PROBE 361a: does anything on the far side of the three system sockets read
--
-- 297a sent zeros of 0, 1, 4, 8 and 64 bytes and got no reply and no close, which
-- cannot separate "the service is reading and ignoring us" from "nobody is
-- reading and the bytes are sitting in the socket buffer". A socket that nobody
-- reads fills up: send() stops accepting at the buffer size (roughly 100-200 KB)
-- and returns EAGAIN. One that is read keeps accepting. So the total number of
-- bytes a non-blocking send accepts before EAGAIN is the measurement, and a
-- reconnect afterwards says whether the service is still listening.

print("=== PROBE 361a: SOCKET CONSUMPTION ===")
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

local CHUNK = 0x4000
local CAP = 8 * 1024 * 1024

local sockaddr = memory.alloc(0x80)
local chunk = memory.alloc(CHUNK)
local rbuf = memory.alloc(0x200)

do
    for i = 0, CHUNK - 1, 8 do pcall(function() memory.write_qword(chunk + i, uint64(0x4141414141414141)) end) end
end

local function connect_to(path)
    local fd = sgn(sc_socket(uint64(AF_UNIX), uint64(SOCK_STREAM), uint64(0)))
    if fd < 3 then return -1 end
    for i = 0, 0x10, 8 do pcall(function() memory.write_qword(sockaddr + i, uint64(0)) end) end
    pcall(function() memory.write_byte(sockaddr, #path + 2) end)
    pcall(function() memory.write_byte(sockaddr + 1, AF_UNIX) end)
    for i = 1, #path do pcall(function() memory.write_byte(sockaddr + 1 + i, path:byte(i)) end) end
    local r = sgn(sc_connect(uint64(fd), uint64(sockaddr), uint64(#path + 2)))
    if r ~= 0 then pcall(function() sc_close(uint64(fd)) end) return -r end
    return fd
end

local function step(path)
    print("[" .. path .. "]")
    local total = 0
    local fd = connect_to(path)
    if fd < 3 then
        print(string.format("  connect refused (%d)", fd))
        return
    end
    print(string.format("  connect = 0 (fd %d)", fd))
    local refused_at = -1
    while total < CAP do
        local r = sgn(sc_sendto(uint64(fd), uint64(chunk), uint64(CHUNK), uint64(MSG_DONTWAIT), uint64(0), uint64(0)))
        if r <= 0 then refused_at = total break end
        total = total + r
    end
    if refused_at < 0 then
        print(string.format("  accepted all %d bytes (peer is reading)", total))
    else
        print(string.format("  EAGAIN after %d bytes (buffer full - nobody reading)", total))
    end
    local r = sgn(sc_recvfrom(uint64(fd), uint64(rbuf), uint64(0x200), uint64(MSG_DONTWAIT), uint64(0), uint64(0)))
    print(string.format("  recv after send = %d", r))
    pcall(function() sc_close(uint64(fd)) end)
    local again = connect_to(path)
    if again < 3 then
        print(string.format("  reconnect refused (%d) - service stopped accepting", again))
    else
        print("  reconnect = 0 - still listening")
        pcall(function() sc_close(uint64(again)) end)
    end
end

step("/system_tmp/GnmCompositorRestricted")
step("/system_tmp/VrTracker2DomainSock")
step("/system_tmp/AgcCompositorSppSocket")

print("")
print("=== 361a DONE ===")

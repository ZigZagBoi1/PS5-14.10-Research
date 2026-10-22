-- CRASH_CLASS: LOW
-- PROBE 296a: can the game process reach the system sockets
--
-- Context: 295a listed the jail. /system_tmp holds seven UNIX sockets that do
-- not belong to this process:
--
--   GnmCompositor, GnmCompositorRestricted, SceImageUtilAgent,
--   VrTracker2DomainSock, AgcCompositorSppSocket, SystemTts, redis.sock
--
-- GnmCompositor and AgcCompositor are the GPU compositor service, SceImageUtil
-- is image handling, SystemTts is speech, VrTracker2 is headset tracking, and
-- redis.sock is what it looks like.
--
-- These sockets are the only IPC endpoints this process can see that are
-- served by code outside its jail. If connect() is permitted on the
-- unrestricted names, the next question is what they accept from a game.
--
-- This probe only connects and reads with MSG_DONTWAIT. It sends nothing.

print("=== PROBE 296a: system sockets ===")
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
    local h, l = 0, to_num(v)
    if type(v) == "table" and v.h then h, l = v.h, v.l end
    if h % 0x100000000 == 0xFFFFFFFF and l % 0x100000000 == 0xFFFFFFFF then return -1 end
    if h == 0 and l >= 0x80000000 then return l - 0x100000000 end
    return l
end
local function put_str(s)
    local buf = memory.alloc(#s + 1)
    for i = 1, #s do pcall(function() memory.write_byte(buf + i - 1, s:byte(i)) end) end
    pcall(function() memory.write_byte(buf + #s, 0) end)
    return buf
end

local sc_socket = make_syscall(97)
local sc_connect = make_syscall(98)
local sc_close = make_syscall(6)
local sc_recvfrom = make_syscall(29)

local AF_UNIX = 1
local SOCK_STREAM = 1
local SOCK_DGRAM = 2
local MSG_DONTWAIT = 0x80

local names = {
    "GnmCompositor", "GnmCompositorRestricted", "SceImageUtilAgent",
    "VrTracker2DomainSock", "AgcCompositorSppSocket", "SystemTts", "redis.sock",
}

local sockaddr = memory.alloc(0x80)
local rbuf = memory.alloc(0x200)

local function try(name, path, socktype)
    local fd = sgn(sc_socket(uint64(AF_UNIX), uint64(socktype), uint64(0)))
    if fd < 0 then return -1, "socket failed" end
    for i = 0, 0x7F do pcall(function() memory.write_byte(sockaddr + i, 0) end) end
    local len = #path
    pcall(function() memory.write_byte(sockaddr + 0, len + 2) end)
    pcall(function() memory.write_byte(sockaddr + 1, AF_UNIX) end)
    for i = 1, len do pcall(function() memory.write_byte(sockaddr + 1 + i, path:byte(i)) end) end
    local r = sgn(sc_connect(uint64(fd), uint64(sockaddr), uint64(len + 2)))
    if r == 0 then
        for i = 0, 0x1FC, 4 do pcall(function() memory.write_dword(rbuf + i, 0) end) end
        local n = sgn(sc_recvfrom(uint64(fd), uint64(rbuf), uint64(0x200), uint64(MSG_DONTWAIT), uint64(0), uint64(0)))
        sc_close(uint64(fd))
        return 0, string.format("connected, read=%d", n)
    end
    sc_close(uint64(fd))
    return r, "refused"
end

for _, name in ipairs(names) do
    for _, dir in ipairs({ "/system_tmp/", "/system_tmp/" }) do
        local path = dir .. name
        local r1, note1 = try(name, path, SOCK_STREAM)
        local r2, note2 = try(name, path, SOCK_DGRAM)
        print(string.format("%-26s stream=%d (%-22s) dgram=%d (%s)", name, r1, note1, r2, note2))
    end
end

print("")
print("=== PROBE 296a COMPLETE ===")

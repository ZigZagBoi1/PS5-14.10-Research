-- CRASH_CLASS: LOW
-- PROBE 362b: which system sockets still accept a connection
--
-- 361b connected to all three, sent 8 KiB of 0x41 and saw the peer close, and
-- GnmCompositorRestricted had 16 bytes waiting. 362a then could not connect to it
-- at all - fourteen attempts in a row refused. Either the node is gone or the
-- service stopped listening, and the two look the same from connect() alone, so
-- this probe stats every socket in /system_tmp first and then connects once to
-- each without sending a byte.

print("=== PROBE 362b: SYSTEM SOCKET STATE ===")
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
local U = function(h, l) return uint64(string.format("0x%X%08X", h, l)) end
local Z = uint64(0)
local AF_UNIX, SOCK_STREAM = 1, 1

local sc_socket = make_syscall(97)
local sc_connect = make_syscall(98)
local sc_close = make_syscall(6)
local sc_stat = make_syscall(188)

local names = {"GnmCompositor", "GnmCompositorRestricted", "SceImageUtilAgent",
               "VrTracker2DomainSock", "AgcCompositorSppSocket", "SystemTts", "redis.sock"}

local sockaddr = memory.alloc(0x80)
local path = memory.alloc(0x80)
local st = memory.alloc(0x100)

local function str_at(addr, s)
    for i = 1, #s do pcall(function() memory.write_byte(addr + i - 1, s:byte(i)) end) end
    pcall(function() memory.write_byte(addr + #s, 0) end)
end

for _, name in ipairs(names) do
    local full = "/system_tmp/" .. name
    str_at(path, full)
    local st_ret = sgn(sc_stat(U(0, to_num(path)), U(0, to_num(st)), Z, Z, Z, Z))
    local mode = to_num(memory.read_dword(st + 8)) % 0x10000
    local fd = sgn(sc_socket(uint64(AF_UNIX), uint64(SOCK_STREAM), uint64(0)))
    local cr = -100
    if fd >= 3 then
        for i = 0, 0x10, 8 do pcall(function() memory.write_qword(sockaddr + i, uint64(0)) end) end
        pcall(function() memory.write_byte(sockaddr, #full + 2) end)
        pcall(function() memory.write_byte(sockaddr + 1, AF_UNIX) end)
        for i = 1, #full do pcall(function() memory.write_byte(sockaddr + 1 + i, full:byte(i)) end) end
        cr = sgn(sc_connect(uint64(fd), uint64(sockaddr), uint64(#full + 2)))
        pcall(function() sc_close(uint64(fd)) end)
    end
    print(string.format("%-24s stat=%d mode=0x%04X connect=%d", name, st_ret, mode, cr))
end

print("")
print("=== 362b DONE ===")

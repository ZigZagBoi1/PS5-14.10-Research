-- CRASH_CLASS: MODERATE
-- PROBE 372a: maybe command 1 has to come first
--
-- Every previous probe opened a connection, sent one message and closed it. The
-- replies were: cmd 1 -> 16 bytes with NO error word, cmd 2-5 -> 16 bytes ending
-- 80D40009, cmd 6 -> 32 bytes ending 80D40009, cmd 7+ -> 80FF unknown. A command
-- that answers cleanly while every other one answers with an error is what a
-- handshake looks like, and a handshake only matters if the connection is kept.
-- This probe sends command 1 and then every other command ON THE SAME SOCKET.

print("=== PROBE 372a: COMPOSITOR SESSION ===")
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
local msg = memory.alloc(0x400)
local rbuf = memory.alloc(0x500)

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

local function wait(t)
    local t0 = os.clock()
    while os.clock() - t0 < t do end
end

local function recv_reply(fd)
    local out = {}
    for round = 1, 2 do
        local r = sgn(sc_recvfrom(uint64(fd), uint64(rbuf), uint64(0x400), uint64(MSG_DONTWAIT), uint64(0), uint64(0)))
        if r <= 0 then out[#out + 1] = string.format("recv=%d", r) break end
        local p = {}
        for i = 0, math.min(r, 40) - 1, 4 do
            p[#p + 1] = string.format("%08X", to_num(memory.read_dword(rbuf + i)))
        end
        out[#out + 1] = string.format("recv=%d %s", r, table.concat(p, " "))
    end
    return table.concat(out, " | ")
end

local function send_cmd(fd, cmd, n)
    for i = 0, 0x3FC, 4 do pcall(function() memory.write_dword(msg + i, 0) end) end
    pcall(function() memory.write_dword(msg + 0, n) end)
    pcall(function() memory.write_dword(msg + 4, cmd) end)
    return sgn(sc_sendto(uint64(fd), uint64(msg), uint64(n), uint64(MSG_DONTWAIT), uint64(0), uint64(0)))
end

local fd = connect_to()
print(string.format("connect = %d", fd))
if fd >= 3 then
    for _, cmd in ipairs({1, 2, 3, 4, 5, 6, 0, 1}) do
        local sent = send_cmd(fd, cmd, 0x30)
        wait(0.15)
        print(string.format("  cmd=%-2d send=%-3d %s", cmd, sent, recv_reply(fd)))
        wait(0.1)
    end
    pcall(function() sc_close(uint64(fd)) end)
end

print("")
print("--- control: same commands, one connection each ---")
for _, cmd in ipairs({1, 2, 6}) do
    local f2 = connect_to()
    if f2 >= 3 then
        local sent = send_cmd(f2, cmd, 0x30)
        wait(0.15)
        print(string.format("  cmd=%-2d send=%-3d %s", cmd, sent, recv_reply(f2)))
        pcall(function() sc_close(uint64(f2)) end)
    end
    wait(0.15)
end

print("")
print("=== 372a DONE ===")

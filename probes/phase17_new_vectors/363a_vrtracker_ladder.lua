-- CRASH_CLASS: MODERATE
-- PROBE 363a: VrTracker2DomainSock, one length at a time
--
-- The two compositor sockets stopped listening after 361b sent them 8 KiB of
-- 0x41, and GnmCompositorRestricted had left 16 bytes readable that we never
-- read. VrTracker2DomainSock is the only one of the seven still accepting, so it
-- is the only place left to learn the shape of the daemons' input handling.
--
-- For each length: connect, send that many 0x41, read up to 0x100 back, close,
-- then reconnect once to see whether the daemon is still listening. It stops at
-- the first length after which nothing accepts, so the daemon is not ground down
-- past the point that answers the question.

print("=== PROBE 363a: VRTRACKER LADDER ===")
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

local PATH = "/system_tmp/VrTracker2DomainSock"
local sockaddr = memory.alloc(0x80)
local chunk = memory.alloc(0x4000)
local rbuf = memory.alloc(0x400)
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

local function drain(fd)
    local out = {}
    for round = 1, 4 do
        local n = sgn(sc_recvfrom(uint64(fd), uint64(rbuf), uint64(0x400), uint64(MSG_DONTWAIT), uint64(0), uint64(0)))
        if n <= 0 then out[#out + 1] = string.format("%d", n) break end
        local s = {}
        for i = 0, math.min(n, 32) - 1, 4 do
            s[#s + 1] = string.format("%08X", to_num(memory.read_dword(rbuf + i)))
        end
        out[#out + 1] = string.format("n=%d %s", n, table.concat(s, " "))
    end
    return table.concat(out, " | ")
end

for _, n in ipairs({0, 1, 2, 4, 8, 12, 16, 24, 32, 64, 128, 256, 0x200, 0x400, 0x800, 0x1000, 0x2000}) do
    local fd = connect_to()
    if fd < 3 then
        print(string.format("n=%-5d CONNECT REFUSED - daemon gone", n))
        break
    end
    local sent = 0
    if n > 0 then sent = sgn(sc_sendto(uint64(fd), uint64(chunk), uint64(n), uint64(MSG_DONTWAIT), uint64(0), uint64(0))) end
    local reply = drain(fd)
    pcall(function() sc_close(uint64(fd)) end)
    local alive = connect_to()
    local alive_s = "gone"
    if alive >= 3 then
        alive_s = "listening"
        drain(alive)
        pcall(function() sc_close(uint64(alive)) end)
    end
    print(string.format("n=%-5d send=%-4d reply[%s]  after: %s", n, sent, reply, alive_s))
    if alive < 3 then break end
end

print("")
print("=== 363a DONE ===")
